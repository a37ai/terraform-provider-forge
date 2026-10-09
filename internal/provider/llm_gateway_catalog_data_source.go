package provider

import (
	"context"
	"fmt"
	"net/http"

	"github.com/hashicorp/terraform-plugin-framework/datasource"
	"github.com/hashicorp/terraform-plugin-framework/datasource/schema"
	"github.com/hashicorp/terraform-plugin-framework/types"
)

type llmGatewayCatalogDataSource struct{ client *Client }

type llmGatewayCatalogDataSourceModel struct {
	ID            types.String                  `tfsdk:"id"`
	CatalogDigest types.String                  `tfsdk:"catalog_digest"`
	SchemaVersion types.String                  `tfsdk:"schema_version"`
	Models        []llmGatewayCatalogModelState `tfsdk:"models"`
}

type llmGatewayCatalogModelState struct {
	ID                types.String `tfsdk:"id"`
	ProviderKind      types.String `tfsdk:"provider_kind"`
	SupportedSurfaces types.Set    `tfsdk:"supported_surfaces"`
}

type llmGatewayCatalogAPI struct {
	CatalogDigest string `json:"catalogDigest"`
	SchemaVersion string `json:"schemaVersion"`
	Models        []struct {
		ID                string   `json:"id"`
		ProviderKind      string   `json:"providerKind"`
		SupportedSurfaces []string `json:"supportedSurfaces"`
	} `json:"models"`
}

func newLLMGatewayCatalogDataSource() datasource.DataSource { return &llmGatewayCatalogDataSource{} }

func (d *llmGatewayCatalogDataSource) Metadata(_ context.Context, request datasource.MetadataRequest, response *datasource.MetadataResponse) {
	response.TypeName = request.ProviderTypeName + "_llm_gateway_catalog"
}

func (d *llmGatewayCatalogDataSource) Schema(_ context.Context, _ datasource.SchemaRequest, response *datasource.SchemaResponse) {
	response.Schema = schema.Schema{Description: "Discover reviewed Forge LLM Gateway models and the catalog revision. Model fields in resources remain free-form.", Attributes: map[string]schema.Attribute{
		"id":             schema.StringAttribute{Computed: true, Description: "Catalog digest; changes when the reviewed catalog changes."},
		"catalog_digest": schema.StringAttribute{Computed: true, Description: "SHA-256 digest of the Forge catalog."},
		"schema_version": schema.StringAttribute{Computed: true},
		"models": schema.ListNestedAttribute{Computed: true, NestedObject: schema.NestedAttributeObject{Attributes: map[string]schema.Attribute{
			"id":                 schema.StringAttribute{Computed: true},
			"provider_kind":      schema.StringAttribute{Computed: true},
			"supported_surfaces": schema.SetAttribute{Computed: true, ElementType: types.StringType},
		}}},
	}}
}

func (d *llmGatewayCatalogDataSource) Configure(_ context.Context, request datasource.ConfigureRequest, response *datasource.ConfigureResponse) {
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

func (d *llmGatewayCatalogDataSource) Read(ctx context.Context, _ datasource.ReadRequest, response *datasource.ReadResponse) {
	var catalog llmGatewayCatalogAPI
	if err := d.client.Do(ctx, http.MethodGet, "llm-gateway/catalog", nil, &catalog); err != nil {
		response.Diagnostics.AddError("Read Forge LLM Gateway catalog", err.Error())
		return
	}
	if catalog.SchemaVersion == "" || catalog.CatalogDigest == "" {
		response.Diagnostics.AddError("Invalid Forge LLM Gateway catalog", "Missing schema version or digest")
		return
	}
	model := llmGatewayCatalogDataSourceModel{
		ID: types.StringValue(catalog.CatalogDigest), CatalogDigest: types.StringValue(catalog.CatalogDigest),
		SchemaVersion: types.StringValue(catalog.SchemaVersion), Models: make([]llmGatewayCatalogModelState, 0, len(catalog.Models)),
	}
	for _, item := range catalog.Models {
		surfaces, diagnostics := types.SetValueFrom(ctx, types.StringType, item.SupportedSurfaces)
		response.Diagnostics.Append(diagnostics...)
		if response.Diagnostics.HasError() {
			return
		}
		if item.ID == "" || item.ProviderKind == "" {
			response.Diagnostics.AddError("Invalid Forge LLM Gateway catalog", fmt.Sprintf("model %q has no provider or ID", item.ID))
			return
		}
		model.Models = append(model.Models, llmGatewayCatalogModelState{ID: types.StringValue(item.ID), ProviderKind: types.StringValue(item.ProviderKind), SupportedSurfaces: surfaces})
	}
	response.Diagnostics.Append(response.State.Set(ctx, &model)...)
}

var _ datasource.DataSourceWithConfigure = (*llmGatewayCatalogDataSource)(nil)
