package provider

import (
	"github.com/hashicorp/terraform-plugin-framework-validators/mapvalidator"
	"github.com/hashicorp/terraform-plugin-framework-validators/setvalidator"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/mapdefault"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/setdefault"
	"github.com/hashicorp/terraform-plugin-framework/schema/validator"
	"github.com/hashicorp/terraform-plugin-framework/types"
)

func directoryQualifierAttribute(kind string) schema.MapAttribute {
	return schema.MapAttribute{
		Optional: true, Computed: true,
		Default:     mapdefault.StaticValue(types.MapValueMust(types.StringType, nil)),
		ElementType: types.StringType,
		Validators:  []validator.Map{mapvalidator.SizeAtMost(256)},
		Description: "Optional map from a configured " + kind + " name to a Forge directory ID, used only to disambiguate duplicate exact matches.",
	}
}

func optionalSubjectSetAttribute(description string) schema.SetAttribute {
	return schema.SetAttribute{
		Optional: true, Computed: true,
		Default:     setdefault.StaticValue(types.SetValueMust(types.StringType, nil)),
		ElementType: types.StringType,
		Validators:  []validator.Set{setvalidator.SizeAtMost(256)},
		Description: description,
	}
}
