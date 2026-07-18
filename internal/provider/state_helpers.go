package provider

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"

	"github.com/hashicorp/terraform-plugin-framework/attr"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/types"
)

var errDynamicValueUnknown = errors.New("dynamic value contains an unknown value")

func policyPlanPayloadChanged(definition, sourceRef, priorDefinition, priorSourceRef map[string]any) bool {
	return !canonicalTerraformPayloadEqual(definition, priorDefinition) || !canonicalTerraformPayloadEqual(sourceRef, priorSourceRef)
}

func canonicalTerraformPayloadEqual(left, right map[string]any) bool {
	leftJSON, leftErr := json.Marshal(left)
	rightJSON, rightErr := json.Marshal(right)
	return leftErr == nil && rightErr == nil && bytes.Equal(leftJSON, rightJSON)
}

func (item policyAPIItem) verifyAuthority(client *Client) error {
	if item.ManagementMode == "" {
		return fmt.Errorf("policy response did not include management authority; refusing to manage it without an explicit Terraform binding")
	}
	if item.ManagementMode != "terraform" {
		return fmt.Errorf("policy is managed by %s; explicitly claim it with forge_policy_authority before import", item.ManagementMode)
	}
	if item.ManagerID != client.managerID || item.ManagerInstance != client.managerInstance {
		return fmt.Errorf("policy is managed by Terraform manager %q instance %q, not this provider", item.ManagerID, item.ManagerInstance)
	}
	return nil
}

func object(value any) map[string]any {
	result, _ := value.(map[string]any)
	return result
}

func stringsFrom(value any) []string {
	if values, ok := value.([]string); ok {
		return append([]string(nil), values...)
	}
	values, _ := value.([]any)
	result := make([]string, 0, len(values))
	for _, value := range values {
		if text, ok := value.(string); ok {
			result = append(result, text)
		}
	}
	return result
}

func boolFrom(value any) bool {
	result, _ := value.(bool)
	return result
}

func stringFrom(value any) string {
	result, _ := value.(string)
	return result
}

func int64From(value any) int64 {
	result, _ := value.(float64)
	return int64(result)
}

func float64From(value any) float64 {
	result, _ := value.(float64)
	return result
}

func selectorObject(item policyAPIItem) map[string]any {
	return object(item.SourceRef["selectors"])
}

func selected(selectors, fallback map[string]any, key string) any {
	if value, ok := selectors[key]; ok {
		return value
	}
	return fallback[key]
}

func setStringState(ctx context.Context, value any, diagnostics *diag.Diagnostics) types.Set {
	if value == nil {
		return types.SetNull(types.StringType)
	}
	result, diags := types.SetValueFrom(ctx, types.StringType, stringsFrom(value))
	diagnostics.Append(diags...)
	return result
}

func setStringStateDefaultEmpty(ctx context.Context, value any, diagnostics *diag.Diagnostics) types.Set {
	if value == nil {
		return types.SetValueMust(types.StringType, nil)
	}
	return setStringState(ctx, value, diagnostics)
}

func setStringStatePreserveConfiguredNull(ctx context.Context, value any, configured types.Set, diagnostics *diag.Diagnostics) types.Set {
	result := setStringState(ctx, value, diagnostics)
	if configured.IsNull() && !result.IsNull() && !result.IsUnknown() && len(result.Elements()) == 0 {
		return types.SetNull(types.StringType)
	}
	return result
}

func qualifiedSelectorState(ctx context.Context, value any, diagnostics *diag.Diagnostics) (types.Set, types.Map) {
	if value == nil {
		return types.SetValueMust(types.StringType, nil), types.MapValueMust(types.StringType, nil)
	}
	values, _ := value.([]any)
	names := make([]string, 0, len(values))
	qualifiers := map[string]string{}
	for _, value := range values {
		switch typed := value.(type) {
		case string:
			names = append(names, typed)
		case map[string]any:
			name, directoryID := stringFrom(typed["name"]), stringFrom(typed["directoryId"])
			if name != "" {
				names = append(names, name)
				if directoryID != "" {
					qualifiers[name] = directoryID
				}
			}
		}
	}
	nameState, nameDiags := types.SetValueFrom(ctx, types.StringType, names)
	qualifierState, qualifierDiags := types.MapValueFrom(ctx, types.StringType, qualifiers)
	diagnostics.Append(nameDiags...)
	diagnostics.Append(qualifierDiags...)
	return nameState, qualifierState
}

func qualifiedSelectorValues(ctx context.Context, names types.Set, qualifierMap types.Map, kind string, diagnostics *diag.Diagnostics) []any {
	var values []string
	var qualifiers map[string]string
	diagnostics.Append(names.ElementsAs(ctx, &values, false)...)
	if !qualifierMap.IsNull() && !qualifierMap.IsUnknown() {
		diagnostics.Append(qualifierMap.ElementsAs(ctx, &qualifiers, false)...)
	}
	known := make(map[string]struct{}, len(values))
	for _, value := range values {
		known[value] = struct{}{}
	}
	for name, directoryID := range qualifiers {
		if _, ok := known[name]; !ok {
			diagnostics.AddError("Invalid "+kind+" directory qualifier", fmt.Sprintf("%q must also appear in %ss", name, kind))
		}
		if directoryID == "" {
			diagnostics.AddError("Invalid "+kind+" directory qualifier", fmt.Sprintf("directory ID for %q must not be empty", name))
		}
	}
	result := make([]any, 0, len(values))
	for _, value := range values {
		if directoryID := qualifiers[value]; directoryID != "" {
			result = append(result, map[string]any{"name": value, "directoryId": directoryID})
		} else {
			result = append(result, value)
		}
	}
	return result
}

func listStringState(ctx context.Context, value any, diagnostics *diag.Diagnostics) types.List {
	if value == nil {
		return types.ListNull(types.StringType)
	}
	result, diags := types.ListValueFrom(ctx, types.StringType, stringsFrom(value))
	diagnostics.Append(diags...)
	return result
}

func optionalString(value any) types.String {
	if value == nil {
		return types.StringNull()
	}
	return types.StringValue(stringFrom(value))
}

func optionalInt64(value any) types.Int64 {
	if value == nil {
		return types.Int64Null()
	}
	return types.Int64Value(int64From(value))
}

func optionalFloat64(value any) types.Float64 {
	if value == nil {
		return types.Float64Null()
	}
	return types.Float64Value(float64From(value))
}

func nonemptyMap(values map[string]any) map[string]any {
	result := map[string]any{}
	for key, value := range values {
		switch typed := value.(type) {
		case []string:
			if len(typed) > 0 {
				result[key] = typed
			}
		case string:
			if typed != "" {
				result[key] = typed
			}
		default:
			if typed != nil {
				result[key] = typed
			}
		}
	}
	return result
}

func conditionValues(node map[string]any, field string) []string {
	var result []string
	if stringFrom(node["field"]) == field {
		if value, ok := node["value"].(string); ok {
			result = append(result, value)
		} else {
			result = append(result, stringsFrom(node["value"])...)
		}
	}
	for _, key := range []string{"all", "any"} {
		for _, child := range objectSlice(node[key]) {
			result = append(result, conditionValues(child, field)...)
		}
	}
	for _, key := range []string{"not", "hasPriorEvent"} {
		if child := object(node[key]); child != nil {
			result = append(result, conditionValues(child, field)...)
		}
	}
	return result
}

func objectSlice(value any) []map[string]any {
	values, _ := value.([]any)
	result := make([]map[string]any, 0, len(values))
	for _, value := range values {
		if item := object(value); item != nil {
			result = append(result, item)
		}
	}
	return result
}

func terraformDynamicToGo(value types.Dynamic) (any, error) {
	if value.IsNull() || value.IsUnderlyingValueNull() {
		return nil, nil
	}
	if value.IsUnknown() || value.IsUnderlyingValueUnknown() {
		return nil, errDynamicValueUnknown
	}
	return terraformAttrToGo(value.UnderlyingValue())
}

func terraformAttrToGo(value attr.Value) (any, error) {
	if value.IsUnknown() {
		return nil, errDynamicValueUnknown
	}
	if value.IsNull() {
		return nil, nil
	}
	switch typed := value.(type) {
	case types.Dynamic:
		if typed.IsNull() || typed.IsUnderlyingValueNull() {
			return nil, nil
		}
		return terraformAttrToGo(typed.UnderlyingValue())
	case types.String:
		return typed.ValueString(), nil
	case types.Bool:
		return typed.ValueBool(), nil
	case types.Int64:
		return typed.ValueInt64(), nil
	case types.Float64:
		return typed.ValueFloat64(), nil
	case types.Number:
		return json.Number(typed.ValueBigFloat().Text('g', -1)), nil
	case types.List:
		return terraformValuesToGo(typed.Elements())
	case types.Set:
		return terraformValuesToGo(typed.Elements())
	case types.Tuple:
		return terraformValuesToGo(typed.Elements())
	case types.Map:
		return terraformMapToGo(typed.Elements())
	case types.Object:
		return terraformMapToGo(typed.Attributes())
	default:
		return nil, fmt.Errorf("dynamic value uses unsupported Terraform type %T", value)
	}
}

func terraformValuesToGo(values []attr.Value) ([]any, error) {
	result := make([]any, 0, len(values))
	for _, value := range values {
		item, err := terraformAttrToGo(value)
		if err != nil {
			return nil, err
		}
		result = append(result, item)
	}
	return result, nil
}

func terraformMapToGo(values map[string]attr.Value) (map[string]any, error) {
	result := make(map[string]any, len(values))
	for key, value := range values {
		item, err := terraformAttrToGo(value)
		if err != nil {
			return nil, err
		}
		result[key] = item
	}
	return result, nil
}

func dynamicFromGo(value any, diagnostics *diag.Diagnostics) types.Dynamic {
	attribute, err := goToTerraformAttr(value)
	if err != nil {
		diagnostics.AddError("Read Forge dynamic value", err.Error())
		return types.DynamicUnknown()
	}
	if attribute == nil {
		return types.DynamicNull()
	}
	return types.DynamicValue(attribute)
}

func goToTerraformAttr(value any) (attr.Value, error) {
	switch typed := value.(type) {
	case nil:
		return nil, nil
	case string:
		return types.StringValue(typed), nil
	case bool:
		return types.BoolValue(typed), nil
	case float64:
		return types.NumberValue(big.NewFloat(typed)), nil
	case json.Number:
		parsed, _, err := big.ParseFloat(typed.String(), 10, 256, big.ToNearestEven)
		if err != nil {
			return nil, err
		}
		return types.NumberValue(parsed), nil
	case []any:
		values := make([]attr.Value, 0, len(typed))
		typesList := make([]attr.Type, 0, len(typed))
		for _, item := range typed {
			converted, err := goToTerraformAttr(item)
			if err != nil {
				return nil, err
			}
			if converted == nil {
				converted = types.DynamicNull()
			}
			values, typesList = append(values, converted), append(typesList, converted.Type(context.Background()))
		}
		return types.TupleValueMust(typesList, values), nil
	case map[string]any:
		values, typesMap := map[string]attr.Value{}, map[string]attr.Type{}
		for key, item := range typed {
			converted, err := goToTerraformAttr(item)
			if err != nil {
				return nil, err
			}
			if converted == nil {
				converted = types.DynamicNull()
			}
			values[key], typesMap[key] = converted, converted.Type(context.Background())
		}
		return types.ObjectValueMust(typesMap, values), nil
	default:
		return nil, fmt.Errorf("Forge returned unsupported filter value type %T", value)
	}
}
