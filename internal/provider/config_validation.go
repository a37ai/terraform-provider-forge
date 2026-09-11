package provider

import (
	"context"
	"errors"
	"regexp"

	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/types"
)

var boundedJSONPathPattern = regexp.MustCompile(`^\$(?:\.[A-Za-z_][A-Za-z0-9_-]*|\[[0-9]+\])+$`)

func (r *regoPolicyResource) ValidateConfig(ctx context.Context, request resource.ValidateConfigRequest, response *resource.ValidateConfigResponse) {
	var model regoPolicyModel
	response.Diagnostics.Append(r.readModel(ctx, request.Config, &model)...)
	if response.Diagnostics.HasError() {
		return
	}
	for _, problem := range validateRegoPolicyConfig(ctx, r.family, model) {
		response.Diagnostics.AddError("Invalid Forge "+r.family+" policy", problem)
	}
}

func validateRegoPolicyConfig(ctx context.Context, family string, m regoPolicyModel) []string {
	var problems []string
	moduleSet := !m.Module.IsNull() && !m.Module.IsUnknown() && m.Module.ValueString() != ""
	conditionsSet := !m.Conditions.IsNull() && !m.Conditions.IsUnknown() && !m.Conditions.IsUnderlyingValueNull()
	if !m.Module.IsUnknown() && !m.Conditions.IsUnknown() && moduleSet == conditionsSet {
		problems = append(problems, "set exactly one of module or conditions")
	}
	if conditionsSet {
		customFieldTypes := map[string]string{}
		if family == "content" {
			var customErr error
			_, customFieldTypes, customErr = customFieldsFromTerraform(m.CustomFields, family)
			if customErr != nil && !errors.Is(customErr, errDynamicValueUnknown) {
				problems = append(problems, customErr.Error())
			}
		}
		if _, err := nativeConditionsFromTerraform(m.Conditions, family, customFieldTypes); err != nil {
			if !errors.Is(err, errDynamicValueUnknown) {
				problems = append(problems, err.Error())
			}
		}
	}
	if family == "content" && !m.EvaluateOn.IsNull() && !m.EvaluateOn.IsUnknown() {
		var values []string
		_ = m.EvaluateOn.ElementsAs(ctx, &values, false)
		allowed, seen := stringSetOf(canonicalContentEvaluationPoints), map[string]bool{}
		for _, value := range values {
			if !allowed[value] {
				problems = append(problems, "evaluate_on contains unsupported value "+value)
			}
			if seen[value] {
				problems = append(problems, "evaluate_on values must be unique")
			}
			seen[value] = true
		}
	}
	action := m.Action.ValueString()
	if family == "content" && !m.Enabled.IsUnknown() && m.Enabled.ValueBool() && !m.AcknowledgeBroadScope.ValueBool() &&
		len(m.Users.Elements()) == 0 && len(m.Groups.Elements()) == 0 && len(m.ServiceAccounts.Elements()) == 0 && len(m.Agents.Elements()) == 0 && len(m.Products.Elements()) == 0 &&
		map[string]bool{"block": true, "redact": true, "filter": true, "nudge": true, "require_approval": true}[action] {
		problems = append(problems, "acknowledge_broad_scope must be true before enabling a broad disruptive Content policy")
	}
	resourceScopeKnown := !m.Users.IsUnknown() && !m.Groups.IsUnknown() && !m.ServiceAccounts.IsUnknown() && !m.Devices.IsUnknown() && !m.Resources.IsUnknown()
	if family == "resource" && resourceScopeKnown && !m.Enabled.IsUnknown() && m.Enabled.ValueBool() && !m.AcknowledgeBroadScope.ValueBool() &&
		len(m.Users.Elements()) == 0 && len(m.Groups.Elements()) == 0 && len(m.ServiceAccounts.Elements()) == 0 && len(m.Devices.Elements()) == 0 && len(m.Resources.Elements()) == 0 &&
		map[string]bool{"block": true, "redact": true, "filter": true, "require_approval": true}[action] {
		problems = append(problems, "acknowledge_broad_scope must be true before enabling a broad disruptive Resource policy")
	}
	knownString := func(value types.String) bool { return !value.IsNull() && !value.IsUnknown() }
	knownInt := func(value types.Int64) bool { return !value.IsNull() && !value.IsUnknown() }
	redactionSet := knownString(m.RedactionStrategy) || knownString(m.RedactionReplacement) || (!m.RedactionPaths.IsNull() && !m.RedactionPaths.IsUnknown()) || knownInt(m.RedactionKeepStart) || knownInt(m.RedactionKeepEnd) || knownString(m.RedactionMask) || knownString(m.RedactionSaltRef) || knownString(m.RedactionFakeSubtype) || knownString(m.RedactionApplyTo) || knownString(m.RedactionPattern)
	filterSet := knownString(m.FilterCollectionPath) || knownString(m.FilterPath) || knownString(m.FilterOperator) || (!m.FilterValue.IsNull() && !m.FilterValue.IsUnknown()) || knownString(m.FilterOnUnavailable)
	if action != "redact" && redactionSet {
		problems = append(problems, "redaction attributes are only valid when action is redact")
	}
	if action != "filter" && filterSet {
		problems = append(problems, "filter attributes are only valid when action is filter")
	}
	if family == "content" && action != "require_approval" && !m.AutoApprove.IsNull() && !m.AutoApprove.IsUnknown() {
		problems = append(problems, "auto_approve_on_request is only valid when action is require_approval")
	}
	if (family == "access" || family == "resource") && action != "require_approval" && !m.ApprovalMode.IsNull() && !m.ApprovalMode.IsUnknown() {
		problems = append(problems, "approval_mode is only valid when action is require_approval")
	}
	dataTargetSet := knownString(m.DataTarget)
	if family == "resource" {
		if dataTargetSet && !m.Resources.IsUnknown() && len(m.Resources.Elements()) == 0 {
			problems = append(problems, "data_target requires at least one selected Resource")
		}
		if (action == "redact" || action == "filter") && !dataTargetSet {
			problems = append(problems, "data_target is required when action is redact or filter")
		}
		if action != "redact" && action != "filter" && dataTargetSet {
			problems = append(problems, "data_target is only valid when action is redact or filter")
		}
		if action == "filter" && dataTargetSet && m.DataTarget.ValueString() == "http_request_body" {
			problems = append(problems, "filter does not support data_target http_request_body")
		}
	}
	if (family == "content" || family == "resource") && action == "redact" {
		strategy := m.RedactionStrategy.ValueString()
		if strategy == "" {
			strategy = "constant"
		}
		redactionAttributeSet := map[string]bool{
			"redaction_replacement":  knownString(m.RedactionReplacement),
			"redaction_keep_start":   knownInt(m.RedactionKeepStart),
			"redaction_keep_end":     knownInt(m.RedactionKeepEnd),
			"redaction_mask":         knownString(m.RedactionMask),
			"redaction_salt_ref":     knownString(m.RedactionSaltRef),
			"redaction_fake_subtype": knownString(m.RedactionFakeSubtype),
		}
		rejectRedactionAttributes := func(allowed ...string) {
			allowedSet := map[string]bool{}
			for _, name := range allowed {
				allowedSet[name] = true
			}
			for name, set := range redactionAttributeSet {
				if set && !allowedSet[name] {
					problems = append(problems, name+" is not valid for "+strategy+" redaction")
				}
			}
		}
		switch strategy {
		case "constant":
			rejectRedactionAttributes("redaction_replacement")
			if m.RedactionReplacement.IsNull() {
				problems = append(problems, "redaction_replacement is required for constant redaction")
			}
		case "partial":
			rejectRedactionAttributes("redaction_keep_start", "redaction_keep_end", "redaction_mask")
			if m.RedactionKeepStart.IsNull() && m.RedactionKeepEnd.IsNull() {
				problems = append(problems, "partial redaction requires redaction_keep_start or redaction_keep_end")
			}
			for name, value := range map[string]types.Int64{"redaction_keep_start": m.RedactionKeepStart, "redaction_keep_end": m.RedactionKeepEnd} {
				if !value.IsNull() && !value.IsUnknown() && (value.ValueInt64() < 0 || value.ValueInt64() > 256) {
					problems = append(problems, name+" must be between 0 and 256")
				}
			}
		case "hash":
			rejectRedactionAttributes("redaction_salt_ref")
		case "nullify":
			rejectRedactionAttributes()
		case "fake":
			rejectRedactionAttributes("redaction_fake_subtype")
			if !map[string]bool{"string": true, "email": true, "phone": true, "ipv4": true, "payment_card": true}[m.RedactionFakeSubtype.ValueString()] {
				problems = append(problems, "redaction_fake_subtype must be string, email, phone, ipv4, or payment_card")
			}
		}
		if !m.RedactionApplyTo.IsNull() && m.RedactionApplyTo.ValueString() == "matches" && m.RedactionPattern.IsNull() {
			problems = append(problems, "redaction_pattern is required when redaction_apply_to is matches")
		}
		if m.RedactionApplyTo.IsNull() && !m.RedactionPattern.IsNull() {
			problems = append(problems, "redaction_apply_to = matches is required when redaction_pattern is set")
		}
		if strategy == "nullify" && (!m.RedactionApplyTo.IsNull() || !m.RedactionPattern.IsNull()) {
			problems = append(problems, "nullify redaction does not support match-only redaction")
		}
	}
	if (family == "content" || family == "resource") && action == "filter" && (m.FilterCollectionPath.IsNull() || m.FilterPath.IsNull() || m.FilterOperator.IsNull() || m.FilterValue.IsNull() || m.FilterOnUnavailable.IsNull()) {
		problems = append(problems, "filter_collection_path, filter_path, filter_operator, filter_value, and filter_on_unavailable are required for filter")
	}
	if family == "resource" && dataTargetSet && (m.DataTarget.ValueString() == "postgres_result" || m.DataTarget.ValueString() == "mysql_result") {
		resultName := "PostgreSQL"
		if m.DataTarget.ValueString() == "mysql_result" {
			resultName = "MySQL"
		}
		if action == "redact" && (m.RedactionPaths.IsNull() || m.RedactionPaths.IsUnknown()) {
			problems = append(problems, "redaction_paths is required for "+resultName+" results")
		}
		if action == "filter" && knownString(m.FilterCollectionPath) && m.FilterCollectionPath.ValueString() != "$.rows" {
			problems = append(problems, "filter_collection_path must be $.rows for "+resultName+" results")
		}
	}
	for name, value := range map[string]types.String{"filter_collection_path": m.FilterCollectionPath, "filter_path": m.FilterPath} {
		if !value.IsNull() && !value.IsUnknown() && !boundedJSONPathPattern.MatchString(value.ValueString()) {
			problems = append(problems, name+" must be a bounded Forge JSON path")
		}
	}
	if !m.RedactionPaths.IsNull() && !m.RedactionPaths.IsUnknown() {
		var paths []string
		_ = m.RedactionPaths.ElementsAs(ctx, &paths, false)
		for _, value := range paths {
			if !boundedJSONPathPattern.MatchString(value) {
				problems = append(problems, "redaction_paths contains invalid path "+value)
			}
		}
	}
	if family == "access" && !m.RemediationAction.IsNull() && !m.RemediationAction.IsUnknown() && !validAccessRemediationAction(m.RemediationAction.ValueString()) {
		problems = append(problems, "remediation_action is not a supported Forge access remediation")
	}
	return uniqueStrings(problems)
}

func validAccessRemediationAction(value string) bool {
	return stringSetOf(canonicalAccessRemediationActions)[value]
}

func stringSetOf(values []string) map[string]bool {
	result := make(map[string]bool, len(values))
	for _, value := range values {
		result[value] = true
	}
	return result
}

func uniqueStrings(values []string) []string {
	seen, result := map[string]bool{}, make([]string, 0, len(values))
	for _, value := range values {
		if !seen[value] {
			seen[value], result = true, append(result, value)
		}
	}
	return result
}

var _ resource.ResourceWithValidateConfig = (*regoPolicyResource)(nil)
