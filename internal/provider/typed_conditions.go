package provider

import (
	"encoding/json"
	"fmt"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/hashicorp/terraform-plugin-framework/types"
)

const (
	terraformConditionMaxDepth = 16
	terraformConditionMaxNodes = 512
)

var conditionDurationPattern = regexp.MustCompile(canonicalConditionDurationPattern)
var customToolInputFieldPattern = regexp.MustCompile(`^tool\.input\.(?:[A-Za-z_][A-Za-z0-9_]*(?:\[[0-9]+\])?)(?:\.[A-Za-z_][A-Za-z0-9_]*(?:\[[0-9]+\])?)*$`)

func customFieldsFromTerraform(value types.Dynamic, family string) ([]any, map[string]string, error) {
	if value.IsNull() || value.IsUnderlyingValueNull() {
		return nil, map[string]string{}, nil
	}
	if family != "content" {
		return nil, nil, fmt.Errorf("custom_fields is only available to content policies")
	}
	if value.IsUnknown() || value.IsUnderlyingValueUnknown() {
		return nil, nil, fmt.Errorf("custom_fields must be known before apply")
	}
	raw, err := terraformDynamicToGo(value)
	if err != nil {
		return nil, nil, err
	}
	items, ok := raw.([]any)
	if !ok {
		return nil, nil, fmt.Errorf("custom_fields must be an HCL tuple")
	}
	if len(items) > 256 {
		return nil, nil, fmt.Errorf("custom_fields must contain at most 256 descriptors")
	}
	fieldTypes := make(map[string]string, len(items))
	for index, item := range items {
		descriptor, ok := item.(map[string]any)
		if !ok {
			return nil, nil, fmt.Errorf("custom_fields[%d] must be an object", index)
		}
		field := stringFrom(descriptor["field"])
		valueType := stringFrom(descriptor["valueType"])
		if !customToolInputFieldPattern.MatchString(field) {
			return nil, nil, fmt.Errorf("custom_fields[%d].field must be a nested tool.input path", index)
		}
		lower := strings.ToLower(field)
		for _, token := range []string{"secret", "password", "passwd", "token", "credential", "api_key", "apikey", "private_key"} {
			if strings.Contains(lower, token) {
				return nil, nil, fmt.Errorf("custom_fields[%d].field contains a sensitive path segment", index)
			}
		}
		if _, exists := fieldTypes[field]; exists {
			return nil, nil, fmt.Errorf("custom_fields[%d].field duplicates %q", index, field)
		}
		if !stringSetOf([]string{"string", "string_set", "number", "boolean", "object", "content"})[valueType] {
			return nil, nil, fmt.Errorf("custom_fields[%d].valueType %q is unsupported", index, valueType)
		}
		fieldTypes[field] = valueType
	}
	return items, fieldTypes, nil
}

// nativeConditionsFromTerraform converts an HCL-native, recursively typed
// Terraform value to the canonical family condition object. Values remain
// Terraform scalars, tuples, objects, and collections in plans/state; policy
// authors never serialize or escape JSON.
func nativeConditionsFromTerraform(value types.Dynamic, family string, customFieldTypes ...map[string]string) (map[string]any, error) {
	if value.IsNull() || value.IsUnderlyingValueNull() {
		return nil, nil
	}
	if value.IsUnknown() || value.IsUnderlyingValueUnknown() {
		return nil, fmt.Errorf("conditions must be known before apply")
	}
	raw, err := terraformDynamicToGo(value)
	if err != nil {
		return nil, err
	}
	root, ok := raw.(map[string]any)
	if !ok {
		return nil, fmt.Errorf("conditions must be an HCL object")
	}
	nodes := 0
	registered := map[string]string{}
	if len(customFieldTypes) > 0 && customFieldTypes[0] != nil {
		registered = customFieldTypes[0]
	}
	if err := validateTypedCondition(root, family, registered, "conditions", 1, &nodes); err != nil {
		return nil, err
	}
	return root, nil
}

func validateTypedCondition(node map[string]any, family string, customFieldTypes map[string]string, path string, depth int, nodes *int) error {
	if depth > terraformConditionMaxDepth {
		return fmt.Errorf("%s exceeds maximum depth %d", path, terraformConditionMaxDepth)
	}
	(*nodes)++
	if *nodes > terraformConditionMaxNodes {
		return fmt.Errorf("conditions exceed maximum node count %d", terraformConditionMaxNodes)
	}
	if len(node) == 0 {
		return fmt.Errorf("%s must not be empty", path)
	}
	if _, hasField := node["field"]; hasField {
		return validateTypedPredicate(node, family, customFieldTypes, path)
	}
	if len(node) != 1 {
		return fmt.Errorf("%s must contain exactly one boolean or stateful operator", path)
	}
	for _, key := range []string{"all", "any"} {
		if value, ok := node[key]; ok {
			children, ok := value.([]any)
			if !ok || len(children) < 1 || len(children) > canonicalConditionMaxChildren {
				return fmt.Errorf("%s.%s must contain 1 to %d conditions", path, key, canonicalConditionMaxChildren)
			}
			for index, child := range children {
				object, ok := child.(map[string]any)
				if !ok {
					return fmt.Errorf("%s.%s[%d] must be an object", path, key, index)
				}
				if err := validateTypedCondition(object, family, customFieldTypes, fmt.Sprintf("%s.%s[%d]", path, key, index), depth+1, nodes); err != nil {
					return err
				}
			}
			return nil
		}
	}
	for _, key := range []string{"not", "hasPriorEvent"} {
		if value, ok := node[key]; ok {
			if key == "hasPriorEvent" && !supportsHistoryConditions(family) {
				return fmt.Errorf("%s.%s is only available to Content and Resource policies", path, key)
			}
			child, ok := value.(map[string]any)
			if !ok {
				return fmt.Errorf("%s.%s must be an object", path, key)
			}
			return validateTypedCondition(child, family, customFieldTypes, path+"."+key, depth+1, nodes)
		}
	}
	if value, ok := node["hasEventSequence"]; ok {
		if !supportsHistoryConditions(family) {
			return fmt.Errorf("%s.hasEventSequence is only available to Content and Resource policies", path)
		}
		config, ok := value.(map[string]any)
		if !ok || !exactKeys(config, "within", "ordered", "events") {
			return fmt.Errorf("%s.hasEventSequence requires exactly within, ordered, and events", path)
		}
		if err := validateConditionDuration(config["within"], path+".hasEventSequence.within"); err != nil {
			return err
		}
		if _, ok := config["ordered"].(bool); !ok {
			return fmt.Errorf("%s.hasEventSequence.ordered must be a boolean", path)
		}
		events, ok := config["events"].([]any)
		if !ok || len(events) < 2 || len(events) > canonicalSequenceMaxEvents {
			return fmt.Errorf("%s.hasEventSequence.events must contain 2 to %d conditions", path, canonicalSequenceMaxEvents)
		}
		for index, event := range events {
			object, ok := event.(map[string]any)
			if !ok {
				return fmt.Errorf("%s.hasEventSequence.events[%d] must be an object", path, index)
			}
			if err := validateTypedCondition(object, family, customFieldTypes, fmt.Sprintf("%s.hasEventSequence.events[%d]", path, index), depth+1, nodes); err != nil {
				return err
			}
		}
		return nil
	}
	if value, ok := node["eventCount"]; ok {
		if !supportsHistoryConditions(family) {
			return fmt.Errorf("%s.eventCount is only available to Content and Resource policies", path)
		}
		config, ok := value.(map[string]any)
		if !ok || !exactKeys(config, "within", "where", "op", "value") {
			return fmt.Errorf("%s.eventCount requires exactly within, where, op, and value", path)
		}
		if err := validateConditionDuration(config["within"], path+".eventCount.within"); err != nil {
			return err
		}
		if err := validateCountComparison(config, path+".eventCount"); err != nil {
			return err
		}
		where, ok := config["where"].(map[string]any)
		if !ok {
			return fmt.Errorf("%s.eventCount.where must be an object", path)
		}
		return validateTypedCondition(where, family, customFieldTypes, path+".eventCount.where", depth+1, nodes)
	}
	if value, ok := node["priorDistinctValues"]; ok {
		if !supportsHistoryConditions(family) {
			return fmt.Errorf("%s.priorDistinctValues is only available to Content and Resource policies", path)
		}
		config, ok := value.(map[string]any)
		if !ok || !(exactKeys(config, "within", "field", "op", "value") || exactKeys(config, "within", "field", "where", "op", "value")) {
			return fmt.Errorf("%s.priorDistinctValues requires within, field, op, value, and optional where", path)
		}
		if err := validateConditionDuration(config["within"], path+".priorDistinctValues.within"); err != nil {
			return err
		}
		field := stringFrom(config["field"])
		fields, _, _ := policyConditionCatalog(family)
		if !stringSetOf(fields)[field] && !(family == "content" && customFieldTypes[field] != "") {
			return fmt.Errorf("%s.priorDistinctValues.field %q is not available to %s policies", path, field, family)
		}
		if err := validateCountComparison(config, path+".priorDistinctValues"); err != nil {
			return err
		}
		if rawWhere, ok := config["where"]; ok {
			where, ok := rawWhere.(map[string]any)
			if !ok {
				return fmt.Errorf("%s.priorDistinctValues.where must be an object", path)
			}
			return validateTypedCondition(where, family, customFieldTypes, path+".priorDistinctValues.where", depth+1, nodes)
		}
		return nil
	}
	return fmt.Errorf("%s uses an unknown condition operator", path)
}

func supportsHistoryConditions(family string) bool {
	return family == "content" || family == "resource"
}

func policyConditionCatalog(family string) ([]string, map[string]string, map[string][]string) {
	switch family {
	case "access":
		return canonicalAccessFields, canonicalAccessFieldTypes, canonicalAccessFieldValueOptions
	case "resource":
		return canonicalResourceFields, canonicalResourceFieldTypes, canonicalResourceFieldValueOptions
	default:
		return canonicalContentFields, canonicalContentFieldTypes, nil
	}
}

func validateTypedPredicate(node map[string]any, family string, customFieldTypes map[string]string, path string) error {
	if !(exactKeys(node, "field", "op") || exactKeys(node, "field", "op", "value")) {
		return fmt.Errorf("%s predicate requires field, op, and value except for exists", path)
	}
	field, fieldOK := node["field"].(string)
	op, opOK := node["op"].(string)
	if !fieldOK || !opOK {
		return fmt.Errorf("%s.field and %s.op must be strings", path, path)
	}
	fields, fieldTypes, fieldValueOptions := policyConditionCatalog(family)
	if !stringSetOf(fields)[field] && !(family == "content" && customFieldTypes[field] != "") {
		return fmt.Errorf("%s.field %q is not available to %s policies", path, field, family)
	}
	if !stringSetOf(canonicalConditionOperators)[op] {
		return fmt.Errorf("%s.op %q is not supported", path, op)
	}
	valueType := fieldTypes[field]
	if valueType == "" && family == "content" {
		valueType = customFieldTypes[field]
	}
	if !stringSetOf(canonicalOperatorsByFieldType[valueType])[op] {
		return fmt.Errorf("%s.op %q is not valid for %s field %q", path, op, valueType, field)
	}
	_, hasValue := node["value"]
	if op == "exists" && hasValue {
		return fmt.Errorf("%s with exists must omit value", path)
	}
	if op != "exists" && !hasValue {
		return fmt.Errorf("%s with %s requires value", path, op)
	}
	if hasValue {
		if err := validateTypedConditionValue(node["value"], valueType, op, path+".value"); err != nil {
			return err
		}
		if fieldValueOptions != nil {
			if err := validateTypedFieldValueOption(fieldValueOptions, field, op, node["value"], path+".value"); err != nil {
				return err
			}
		}
	}
	if pattern, ok := node["value"].(string); ok && op == "matches" {
		if len(pattern) > 1024 {
			return fmt.Errorf("%s.value regular expression exceeds 1024 bytes", path)
		}
		if _, err := regexp.Compile(pattern); err != nil {
			return fmt.Errorf("%s.value is not a valid regular expression: %w", path, err)
		}
	}
	return nil
}

func validateTypedFieldValueOption(fieldOptions map[string][]string, field, op string, value any, path string) error {
	options := fieldOptions[field]
	if len(options) == 0 || op == "exists" || op == "matches" || op == "contains" || op == "starts_with" || op == "ends_with" {
		return nil
	}
	allowed := stringSetOf(options)
	values := []any{value}
	if items, ok := value.([]any); ok {
		values = items
	}
	for _, item := range values {
		text, ok := item.(string)
		if !ok || !allowed[text] {
			return fmt.Errorf("%s %q is not a canonical value for %s", path, text, field)
		}
	}
	return nil
}

func validateTypedConditionValue(value any, valueType, op, path string) error {
	if op == "in" || op == "not_in" || op == "contains_any" || op == "contains_all" {
		items, ok := value.([]any)
		if !ok || len(items) == 0 {
			return fmt.Errorf("%s must be a non-empty tuple for %s", path, op)
		}
		for _, item := range items {
			if valueType == "number" {
				if !conditionNumber(item) {
					return fmt.Errorf("%s items must be numbers", path)
				}
			} else if _, ok := item.(string); !ok {
				return fmt.Errorf("%s items must be strings", path)
			}
		}
		return nil
	}
	switch valueType {
	case "string", "content":
		if _, ok := value.(string); !ok {
			return fmt.Errorf("%s must be a string", path)
		}
	case "string_set":
		if op == "eq" || op == "neq" {
			items, ok := value.([]any)
			if !ok {
				return fmt.Errorf("%s must be a tuple for set equality", path)
			}
			for _, item := range items {
				if _, ok := item.(string); !ok {
					return fmt.Errorf("%s items must be strings", path)
				}
			}
		} else if _, ok := value.(string); !ok {
			return fmt.Errorf("%s must be a string", path)
		}
	case "number":
		if !conditionNumber(value) {
			return fmt.Errorf("%s must be a number", path)
		}
	case "boolean":
		if _, ok := value.(bool); !ok {
			return fmt.Errorf("%s must be a boolean", path)
		}
	case "object":
		return fmt.Errorf("%s is not valid because object fields support only exists", path)
	}
	return nil
}

func conditionNumber(value any) bool {
	switch value.(type) {
	case int64, float64, json.Number:
		return true
	default:
		return false
	}
}

func validateCountComparison(config map[string]any, path string) error {
	op, ok := config["op"].(string)
	if !ok || !stringSetOf(canonicalCountOperators)[op] {
		return fmt.Errorf("%s.op must be one of %v", path, canonicalCountOperators)
	}
	value, ok := conditionInteger(config["value"])
	if !ok || value < 0 || value > canonicalConditionCountMaximum {
		return fmt.Errorf("%s.value must be an integer from 0 to %d", path, canonicalConditionCountMaximum)
	}
	return nil
}

func validateConditionDuration(value any, path string) error {
	text, ok := value.(string)
	if !ok || !conditionDurationPattern.MatchString(text) {
		return fmt.Errorf("%s must match %s", path, canonicalConditionDurationPattern)
	}
	amount, _ := strconv.ParseInt(text[:len(text)-1], 10, 64)
	multiplier := time.Second
	switch text[len(text)-1] {
	case 'm':
		multiplier = time.Minute
	case 'h':
		multiplier = time.Hour
	case 'd':
		multiplier = 24 * time.Hour
	}
	if time.Duration(amount)*multiplier > 30*24*time.Hour {
		return fmt.Errorf("%s exceeds 30 days", path)
	}
	return nil
}

func conditionInteger(value any) (int64, bool) {
	switch typed := value.(type) {
	case int64:
		return typed, true
	case json.Number:
		parsed, err := typed.Int64()
		return parsed, err == nil
	case float64:
		return int64(typed), typed == float64(int64(typed))
	default:
		return 0, false
	}
}

func exactKeys(value map[string]any, keys ...string) bool {
	if len(value) != len(keys) {
		return false
	}
	for _, key := range keys {
		if _, ok := value[key]; !ok {
			return false
		}
	}
	return true
}
