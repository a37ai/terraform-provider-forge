package provider

import (
	"context"
	"fmt"

	"github.com/hashicorp/terraform-plugin-framework-validators/stringvalidator"
	"github.com/hashicorp/terraform-plugin-framework/datasource"
	"github.com/hashicorp/terraform-plugin-framework/datasource/schema"
	"github.com/hashicorp/terraform-plugin-framework/schema/validator"
	"github.com/hashicorp/terraform-plugin-framework/types"
)

type regoTestDataSource struct{ client *Client }

type regoTestDataSourceModel struct {
	ID            types.String  `tfsdk:"id"`
	Family        types.String  `tfsdk:"family"`
	Module        types.String  `tfsdk:"module"`
	EvaluateOn    types.Set     `tfsdk:"evaluate_on"`
	Input         types.Dynamic `tfsdk:"input"`
	ExpectedMatch types.Bool    `tfsdk:"expected_match"`
	Matched       types.Bool    `tfsdk:"matched"`
	ReasonCode    types.String  `tfsdk:"reason_code"`
}

func newRegoTestDataSource() datasource.DataSource { return &regoTestDataSource{} }

func (d *regoTestDataSource) Metadata(_ context.Context, request datasource.MetadataRequest, response *datasource.MetadataResponse) {
	response.TypeName = request.ProviderTypeName + "_rego_test"
}

func (d *regoTestDataSource) Schema(_ context.Context, _ datasource.SchemaRequest, response *datasource.SchemaResponse) {
	response.Schema = schema.Schema{Description: "Compile and evaluate Forge Rego authoritatively during Terraform tests.", Attributes: map[string]schema.Attribute{
		"id":             schema.StringAttribute{Computed: true},
		"family":         schema.StringAttribute{Required: true, Validators: []validator.String{stringvalidator.OneOf("content", "access")}},
		"module":         schema.StringAttribute{Required: true, Description: "forge.rego.v1 module source."},
		"evaluate_on":    schema.SetAttribute{Optional: true, ElementType: types.StringType},
		"input":          schema.DynamicAttribute{Required: true, Description: "Native HCL value supplied as the Forge Rego input."},
		"expected_match": schema.BoolAttribute{Required: true},
		"matched":        schema.BoolAttribute{Computed: true},
		"reason_code":    schema.StringAttribute{Computed: true},
	}}
}

func (d *regoTestDataSource) Configure(_ context.Context, request datasource.ConfigureRequest, response *datasource.ConfigureResponse) {
	if request.ProviderData == nil {
		return
	}
	client, ok := request.ProviderData.(*Client)
	if !ok {
		response.Diagnostics.AddError("Unexpected provider data", "Forge client not configured")
		return
	}
	d.client = client
}

func (d *regoTestDataSource) Read(ctx context.Context, request datasource.ReadRequest, response *datasource.ReadResponse) {
	var model regoTestDataSourceModel
	response.Diagnostics.Append(request.Config.Get(ctx, &model)...)
	if response.Diagnostics.HasError() {
		return
	}
	input, err := terraformDynamicToGo(model.Input)
	if err != nil {
		response.Diagnostics.AddError("Invalid Forge Rego test input", err.Error())
		return
	}
	var evaluateOn []string
	if !model.EvaluateOn.IsNull() && !model.EvaluateOn.IsUnknown() {
		response.Diagnostics.Append(model.EvaluateOn.ElementsAs(ctx, &evaluateOn, false)...)
	}
	if response.Diagnostics.HasError() {
		return
	}
	result, err := d.client.EvaluateRego(ctx, model.Family.ValueString(), model.Module.ValueString(), input, evaluateOn...)
	if err != nil {
		response.Diagnostics.AddError("Evaluate Forge Rego test", err.Error())
		return
	}
	if err := assertRegoMatch(model.ExpectedMatch.ValueBool(), result.Result.Matched); err != nil {
		response.Diagnostics.AddError("Forge Rego assertion failed", err.Error())
		return
	}
	model.ID = types.StringValue(result.ArtifactFingerprint)
	model.Matched = types.BoolValue(result.Result.Matched)
	if result.Result.ReasonCode == "" {
		model.ReasonCode = types.StringNull()
	} else {
		model.ReasonCode = types.StringValue(result.Result.ReasonCode)
	}
	response.Diagnostics.Append(response.State.Set(ctx, &model)...)
}

func assertRegoMatch(expected, actual bool) error {
	if expected != actual {
		return fmt.Errorf("expected matched=%t, got %t", expected, actual)
	}
	return nil
}

var _ datasource.DataSourceWithConfigure = (*regoTestDataSource)(nil)
