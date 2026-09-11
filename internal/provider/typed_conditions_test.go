package provider

import (
	"context"
	"fmt"
	"strings"
	"testing"

	"github.com/hashicorp/terraform-plugin-framework/attr"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/types"
)

func TestTypedConditionsAcceptEveryCanonicalShape(t *testing.T) {
	predicate := func(field, op string, value any) map[string]any {
		result := map[string]any{"field": field, "op": op}
		if value != nil {
			result["value"] = value
		}
		return result
	}
	cases := map[string]map[string]any{
		"predicate": predicate("request.prompt", "contains", "secret"),
		"exists":    predicate("tool.result", "exists", nil),
		"boolean": {
			"all": []any{
				predicate("request.prompt", "matches", `(?i)secret`),
				map[string]any{"any": []any{
					predicate("llm.provider", "in", []any{"openai", "anthropic"}),
					map[string]any{"not": predicate("tool.id", "eq", "approved.tool")},
				}},
			},
		},
		"prior event": {"hasPriorEvent": predicate("event.kind", "eq", "tool_call")},
		"sequence": {"hasEventSequence": map[string]any{
			"within": "15m", "ordered": true,
			"events": []any{predicate("event.kind", "eq", "prompt"), predicate("event.kind", "eq", "tool_call")},
		}},
		"event count": {"eventCount": map[string]any{
			"within": "1h", "where": predicate("event.severity", "eq", "high"), "op": "gte", "value": float64(3),
		}},
		"distinct values": {"priorDistinctValues": map[string]any{
			"within": "30d", "field": "tool.input.url", "where": predicate("event.kind", "eq", "tool_call"), "op": "gt", "value": float64(5),
		}},
	}
	for name, condition := range cases {
		t.Run(name, func(t *testing.T) {
			value := testDynamic(t, condition)
			got, err := nativeConditionsFromTerraform(value, "content")
			if err != nil {
				t.Fatalf("condition rejected: %v", err)
			}
			if fmt.Sprint(got) != fmt.Sprint(condition) {
				t.Fatalf("round trip mismatch\n got: %#v\nwant: %#v", got, condition)
			}
		})
	}
}

func TestTypedResourceConditionsAcceptEveryHistoryShape(t *testing.T) {
	predicate := func(field, op string, value any) map[string]any {
		return map[string]any{"field": field, "op": op, "value": value}
	}
	cases := map[string]map[string]any{
		"prior event": {"hasPriorEvent": predicate("request.http.method", "eq", "POST")},
		"sequence": {"hasEventSequence": map[string]any{
			"within": "15m", "ordered": true,
			"events": []any{predicate("process.id", "eq", "client.1"), predicate("request.postgres.command", "eq", "DELETE")},
		}},
		"event count": {"eventCount": map[string]any{
			"within": "1h", "where": predicate("destination.domain", "eq", "db.internal.example"), "op": "gte", "value": float64(3),
		}},
		"distinct values": {"priorDistinctValues": map[string]any{
			"within": "30d", "field": "resource.id", "where": predicate("request.postgres.command", "eq", "SELECT"), "op": "gt", "value": float64(5),
		}},
	}
	for name, condition := range cases {
		t.Run(name, func(t *testing.T) {
			value := testDynamic(t, condition)
			got, err := nativeConditionsFromTerraform(value, "resource")
			if err != nil {
				t.Fatalf("Resource condition rejected: %v", err)
			}
			if fmt.Sprint(got) != fmt.Sprint(condition) {
				t.Fatalf("round trip mismatch\n got: %#v\nwant: %#v", got, condition)
			}
		})
	}
}

func TestTypedConditionsValidateFamiliesShapesAndLimits(t *testing.T) {
	predicate := func(field, op string, value any) map[string]any {
		return map[string]any{"field": field, "op": op, "value": value}
	}
	tooMany := make([]any, canonicalConditionMaxChildren+1)
	for i := range tooMany {
		tooMany[i] = predicate("request.prompt", "eq", "x")
	}
	tests := []struct {
		name, family, want string
		condition          map[string]any
	}{
		{"access predicate", "access", "", predicate("device.platform", "eq", "darwin")},
		{"family field", "access", "not available", predicate("request.prompt", "eq", "x")},
		{"stateful access", "access", "only available", map[string]any{"hasPriorEvent": predicate("device.id", "eq", "x")}},
		{"sequence access", "access", "only available", map[string]any{"hasEventSequence": map[string]any{"within": "1h", "ordered": true, "events": []any{predicate("device.id", "eq", "x"), predicate("device.id", "eq", "y")}}}},
		{"event count access", "access", "only available", map[string]any{"eventCount": map[string]any{"within": "1h", "where": predicate("device.id", "eq", "x"), "op": "gte", "value": float64(1)}}},
		{"distinct values access", "access", "only available", map[string]any{"priorDistinctValues": map[string]any{"within": "1h", "field": "device.id", "op": "gte", "value": float64(1)}}},
		{"resource history content field", "resource", "not available", map[string]any{"hasPriorEvent": predicate("request.prompt", "eq", "x")}},
		{"resource distinct content field", "resource", "not available", map[string]any{"priorDistinctValues": map[string]any{"within": "1h", "field": "request.prompt", "op": "gte", "value": float64(1)}}},
		{"unknown field", "content", "not available", predicate("unknown.field", "eq", "x")},
		{"unknown operator", "content", "not supported", predicate("request.prompt", "wat", "x")},
		{"operator for field type", "content", "not valid for boolean", predicate("classification.has_unresolved_sensitive_content", "matches", "true")},
		{"wrong scalar type", "content", "must be a number", predicate("llm.input_tokens", "gte", "many")},
		{"wrong tuple item", "content", "items must be numbers", predicate("llm.input_tokens", "in", []any{float64(1), "two"})},
		{"empty membership", "content", "must be a non-empty tuple", predicate("llm.input_tokens", "in", []any{})},
		{"set equality scalar", "content", "tuple for set equality", predicate("identity.group_ids", "eq", "Finance")},
		{"exists value", "content", "must omit value", predicate("request.prompt", "exists", true)},
		{"missing value", "content", "requires value", map[string]any{"field": "request.prompt", "op": "eq"}},
		{"invalid regex", "content", "not a valid regular expression", predicate("request.prompt", "matches", "[")},
		{"extra predicate key", "content", "predicate requires", map[string]any{"field": "request.prompt", "op": "eq", "value": "x", "extra": true}},
		{"unknown shape", "content", "unknown condition operator", map[string]any{"xor": []any{}}},
		{"multiple shapes", "content", "exactly one", map[string]any{"all": []any{predicate("request.prompt", "eq", "x")}, "not": predicate("request.prompt", "eq", "y")}},
		{"empty all", "content", "must contain 1", map[string]any{"all": []any{}}},
		{"too many children", "content", "must contain 1", map[string]any{"all": tooMany}},
		{"bad duration", "content", "must match", map[string]any{"eventCount": map[string]any{"within": "one hour", "where": predicate("event.kind", "eq", "x"), "op": "gte", "value": float64(1)}}},
		{"long duration", "content", "exceeds 30 days", map[string]any{"eventCount": map[string]any{"within": "31d", "where": predicate("event.kind", "eq", "x"), "op": "gte", "value": float64(1)}}},
		{"fractional count", "content", "must be an integer", map[string]any{"eventCount": map[string]any{"within": "1h", "where": predicate("event.kind", "eq", "x"), "op": "gte", "value": 1.5}}},
		{"sequence too short", "content", "must contain 2", map[string]any{"hasEventSequence": map[string]any{"within": "1h", "ordered": false, "events": []any{predicate("event.kind", "eq", "x")}}}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			_, err := nativeConditionsFromTerraform(testDynamic(t, test.condition), test.family)
			if test.want == "" && err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if test.want != "" && (err == nil || !strings.Contains(err.Error(), test.want)) {
				t.Fatalf("error = %v, want substring %q", err, test.want)
			}
		})
	}
}

func TestTypedConditionsEnforceDepthAndNodeBudgets(t *testing.T) {
	leaf := map[string]any{"field": "request.prompt", "op": "eq", "value": "x"}
	deep := leaf
	for range terraformConditionMaxDepth {
		deep = map[string]any{"not": deep}
	}
	if _, err := nativeConditionsFromTerraform(testDynamic(t, deep), "content"); err == nil || !strings.Contains(err.Error(), "maximum depth") {
		t.Fatalf("depth error = %v", err)
	}

	wide := make([]any, 64)
	for i := range wide {
		wide[i] = map[string]any{"all": []any{leaf, leaf, leaf, leaf, leaf, leaf, leaf, leaf}}
	}
	if _, err := nativeConditionsFromTerraform(testDynamic(t, map[string]any{"all": wide}), "content"); err == nil || !strings.Contains(err.Error(), "maximum node count") {
		t.Fatalf("node error = %v", err)
	}
}

func TestTypedConditionsPreserveCollectionPredicateValues(t *testing.T) {
	condition := map[string]any{"field": "llm.input_tokens", "op": "in", "value": []any{float64(100), float64(200)}}
	got, err := nativeConditionsFromTerraform(testDynamic(t, condition), "content")
	if err != nil {
		t.Fatal(err)
	}
	if fmt.Sprint(got) != fmt.Sprint(condition) {
		t.Fatalf("collection value changed: got %#v want %#v", got, condition)
	}
}

func TestTypedConditionsAcceptRegisteredNestedToolInputField(t *testing.T) {
	descriptors := []any{map[string]any{
		"field": "tool.input.repositories[0].name", "label": "GitHub Actions repository name",
		"valueType": "string", "sourceType": "known_schema",
		"toolName": "mcp__github_actions_get", "schemaVersionId": "governance-known-tool-schemas@1",
	}}
	raw, fieldTypes, err := customFieldsFromTerraform(testDynamic(t, descriptors), "content")
	if err != nil || len(raw) != 1 {
		t.Fatalf("custom fields = %#v, err = %v", raw, err)
	}
	condition := map[string]any{"field": "tool.input.repositories[0].name", "op": "eq", "value": "forge"}
	if _, err := nativeConditionsFromTerraform(testDynamic(t, condition), "content", fieldTypes); err != nil {
		t.Fatalf("registered nested condition rejected: %v", err)
	}
	if _, err := nativeConditionsFromTerraform(testDynamic(t, condition), "content"); err == nil {
		t.Fatal("unregistered nested condition unexpectedly succeeded")
	}
}

func TestTypedConditionsRefreshRoundTripPreservesNestedFieldDescriptor(t *testing.T) {
	descriptor := map[string]any{
		"field": "tool.input.repositories[0].name", "label": "GitHub Actions repository name",
		"valueType": "string", "sourceType": "known_schema",
		"toolName": "mcp__github_actions_get", "schemaVersionId": "governance-known-tool-schemas@1",
	}
	condition := map[string]any{"field": "tool.input.repositories[0].name", "op": "eq", "value": "forge/security-agent"}
	item := policyAPIItem{Definition: map[string]any{
		"id": "nested-terraform", "name": "Nested Terraform", "enabled": true,
		"appliesTo": map[string]any{}, "evaluateOn": []any{"pre_tool"},
		"customFields": []any{descriptor}, "conditions": condition, "action": "block",
	}}
	model := regoPolicyModel{}
	var diagnostics diag.Diagnostics
	resource := &regoPolicyResource{family: "content"}
	resource.flatten(context.Background(), item, &model, &diagnostics)
	if diagnostics.HasError() {
		t.Fatalf("flatten diagnostics: %v", diagnostics)
	}
	customFields, fieldTypes, err := customFieldsFromTerraform(model.CustomFields, "content")
	if err != nil || len(customFields) != 1 || fmt.Sprint(customFields[0]) != fmt.Sprint(descriptor) {
		t.Fatalf("custom field round trip = %#v, err = %v", customFields, err)
	}
	conditions, err := nativeConditionsFromTerraform(model.Conditions, "content", fieldTypes)
	if err != nil || fmt.Sprint(conditions) != fmt.Sprint(condition) {
		t.Fatalf("condition round trip = %#v, err = %v", conditions, err)
	}
}

func TestTypedConditionsRefreshRoundTripPreservesNativeHCL(t *testing.T) {
	condition := map[string]any{"all": []any{
		map[string]any{"field": "device.platform", "op": "eq", "value": "darwin"},
		map[string]any{"not": map[string]any{"field": "device.id", "op": "in", "value": []any{"break-glass"}}},
	}}
	item := policyAPIItem{
		Definition: map[string]any{
			"id": "managed-device", "name": "Managed device", "enabled": true,
			"appliesTo": map[string]any{"devices": []any{"device-a"}},
			"action":    "block", "conditions": condition,
		},
		SourceRef:       map[string]any{"selectors": map[string]any{"appliesTo": map[string]any{"devices": []any{"device-a"}}}},
		CurrentRevision: 2,
		DefinitionSHA:   "digest",
	}
	model := regoPolicyModel{}
	var diagnostics diag.Diagnostics
	resource := &regoPolicyResource{family: "access"}
	resource.flatten(context.Background(), item, &model, &diagnostics)
	if diagnostics.HasError() {
		t.Fatalf("flatten diagnostics: %v", diagnostics)
	}
	if !model.Module.IsNull() || model.Conditions.IsNull() || !model.ModuleSHA.IsNull() {
		t.Fatalf("unexpected language state: module=%v conditions=%v digest=%v", model.Module, model.Conditions, model.ModuleSHA)
	}
	roundTrip, err := nativeConditionsFromTerraform(model.Conditions, "access")
	if err != nil {
		t.Fatal(err)
	}
	if fmt.Sprint(roundTrip) != fmt.Sprint(condition) {
		t.Fatalf("refresh changed conditions: got %#v want %#v", roundTrip, condition)
	}
}

func TestTypedResourceHistoryConditionsRefreshRoundTrip(t *testing.T) {
	condition := map[string]any{"eventCount": map[string]any{
		"within": "1h",
		"where": map[string]any{"all": []any{
			map[string]any{"field": "process.id", "op": "eq", "value": "client.1"},
			map[string]any{"field": "destination.domain", "op": "eq", "value": "db.internal.example"},
		}},
		"op": "gte", "value": float64(3),
	}}
	item := policyAPIItem{
		Definition: map[string]any{
			"id": "repeated-resource-use", "name": "Repeated Resource use", "enabled": true,
			"appliesTo": map[string]any{"resources": []any{"resource-a"}},
			"action":    "flag_for_review", "conditions": condition,
		},
		SourceRef: map[string]any{"selectors": map[string]any{"appliesTo": map[string]any{"resources": []any{"resource-a"}}}},
	}
	model := regoPolicyModel{}
	var diagnostics diag.Diagnostics
	resource := &regoPolicyResource{family: "resource"}
	resource.flatten(context.Background(), item, &model, &diagnostics)
	if diagnostics.HasError() {
		t.Fatalf("flatten diagnostics: %v", diagnostics)
	}
	roundTrip, err := nativeConditionsFromTerraform(model.Conditions, "resource")
	if err != nil {
		t.Fatal(err)
	}
	if fmt.Sprint(roundTrip) != fmt.Sprint(condition) {
		t.Fatalf("refresh changed Resource history conditions: got %#v want %#v", roundTrip, condition)
	}
}

func TestTypedConditionsDeferNestedUnknownsDuringPlanning(t *testing.T) {
	condition := types.DynamicValue(types.ObjectValueMust(
		map[string]attr.Type{"field": types.StringType, "op": types.StringType, "value": types.StringType},
		map[string]attr.Value{
			"field": types.StringValue("request.prompt"),
			"op":    types.StringValue("eq"),
			"value": types.StringUnknown(),
		},
	))
	model := regoPolicyModel{Module: types.StringNull(), Conditions: condition}
	if problems := validateRegoPolicyConfig(context.Background(), "content", model); len(problems) != 0 {
		t.Fatalf("nested unknown should be deferred during config validation: %v", problems)
	}
	if _, err := nativeConditionsFromTerraform(condition, "content"); err == nil || !strings.Contains(err.Error(), "unknown") {
		t.Fatalf("apply conversion must retain unknown signal: %v", err)
	}
}

func TestTypedAccessConditionsRejectUnknownCanonicalValue(t *testing.T) {
	var diagnostics diag.Diagnostics
	condition := dynamicFromGo(map[string]any{
		"field": "route.posture",
		"op":    "eq",
		"value": "managed-ish",
	}, &diagnostics)
	if diagnostics.HasError() {
		t.Fatalf("dynamic condition diagnostics: %v", diagnostics)
	}
	if _, err := nativeConditionsFromTerraform(condition, "access"); err == nil || !strings.Contains(err.Error(), "canonical value") {
		t.Fatalf("unknown canonical value error = %v", err)
	}
}

func TestTypedResourceConditionsAreSeparateFromAccess(t *testing.T) {
	var diagnostics diag.Diagnostics
	condition := dynamicFromGo(map[string]any{
		"field": "request.postgres.command",
		"op":    "eq",
		"value": "DELETE",
	}, &diagnostics)
	if diagnostics.HasError() {
		t.Fatalf("dynamic condition diagnostics: %v", diagnostics)
	}
	if _, err := nativeConditionsFromTerraform(condition, "resource"); err != nil {
		t.Fatalf("Resource condition was rejected: %v", err)
	}
	if _, err := nativeConditionsFromTerraform(condition, "access"); err == nil || !strings.Contains(err.Error(), "not available") {
		t.Fatalf("Access unexpectedly accepted a Resource condition: %v", err)
	}
}

func FuzzTypedConditionsNeverPanic(f *testing.F) {
	f.Add("request.prompt", "eq", "hello")
	f.Add("device.platform", "matches", "[")
	f.Fuzz(func(t *testing.T, field, op, value string) {
		var diagnostics diag.Diagnostics
		dynamic := dynamicFromGo(map[string]any{"field": field, "op": op, "value": value}, &diagnostics)
		if !diagnostics.HasError() {
			_, _ = nativeConditionsFromTerraform(dynamic, "content")
			_, _ = nativeConditionsFromTerraform(dynamic, "access")
			_, _ = nativeConditionsFromTerraform(dynamic, "resource")
		}
	})
}
