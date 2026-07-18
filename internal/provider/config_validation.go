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
	response.Diagnostics.Append(request.Config.Get(ctx, &model)...)
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
		_, customFieldTypes, customErr := customFieldsFromTerraform(m.CustomFields, family)
		if customErr != nil && !errors.Is(customErr, errDynamicValueUnknown) {
			problems = append(problems, customErr.Error())
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
	redactionSet := !m.RedactionStrategy.IsNull() || !m.RedactionReplacement.IsNull() || !m.RedactionPaths.IsNull() || !m.RedactionKeepStart.IsNull() || !m.RedactionKeepEnd.IsNull() || !m.RedactionMask.IsNull() || !m.RedactionSaltRef.IsNull() || !m.RedactionFakeSubtype.IsNull()
	filterSet := !m.FilterCollectionPath.IsNull() || !m.FilterPath.IsNull() || !m.FilterOperator.IsNull() || !m.FilterValue.IsNull() || !m.FilterOnUnavailable.IsNull()
	if action != "redact" && redactionSet {
		problems = append(problems, "redaction attributes are only valid when action is redact")
	}
	if action != "filter" && filterSet {
		problems = append(problems, "filter attributes are only valid when action is filter")
	}
	if family == "content" && action == "redact" {
		strategy := m.RedactionStrategy.ValueString()
		if strategy == "" {
			strategy = "constant"
		}
		switch strategy {
		case "constant":
			if m.RedactionReplacement.IsNull() {
				problems = append(problems, "redaction_replacement is required for constant redaction")
			}
		case "partial":
			if m.RedactionKeepStart.IsNull() && m.RedactionKeepEnd.IsNull() {
				problems = append(problems, "partial redaction requires redaction_keep_start or redaction_keep_end")
			}
			for name, value := range map[string]types.Int64{"redaction_keep_start": m.RedactionKeepStart, "redaction_keep_end": m.RedactionKeepEnd} {
				if !value.IsNull() && !value.IsUnknown() && (value.ValueInt64() < 0 || value.ValueInt64() > 256) {
					problems = append(problems, name+" must be between 0 and 256")
				}
			}
		case "fake":
			if !map[string]bool{"string": true, "email": true, "phone": true, "ipv4": true, "payment_card": true}[m.RedactionFakeSubtype.ValueString()] {
				problems = append(problems, "redaction_fake_subtype must be string, email, phone, ipv4, or payment_card")
			}
		}
	}
	if family == "content" && action == "filter" && (m.FilterCollectionPath.IsNull() || m.FilterPath.IsNull() || m.FilterOperator.IsNull() || m.FilterValue.IsNull() || m.FilterOnUnavailable.IsNull()) {
		problems = append(problems, "filter_collection_path, filter_path, filter_operator, filter_value, and filter_on_unavailable are required for filter")
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
