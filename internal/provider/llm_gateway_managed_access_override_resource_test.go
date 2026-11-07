package provider

import (
	"context"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-go/tfprotov6"
	"testing"
)

func TestLLMGatewayAssignmentDefaultAndIdentity(t *testing.T) {
	r := llmGatewayManagedAccessOverrideResource{}
	var model llmGatewayManagedAccessOverrideModel
	r.refresh(&model, managedAccessOverrideAPI{TargetKind: "group", TargetID: "group_1", AccessProfileID: "legal", HostedDefault: true})
	if model.ID.ValueString() != "group:group_1:legal" || !model.HostedDefault.ValueBool() {
		t.Fatal("profile assignment identity/default lost")
	}
}

func TestManagedAssignmentStateUpgradePreservesRemoteIdentity(t *testing.T) {
	ctx := context.Background()
	r := &llmGatewayManagedAccessOverrideResource{}
	response := resource.UpgradeStateResponse{}
	r.UpgradeState(ctx)[0].StateUpgrader(ctx, resource.UpgradeStateRequest{RawState: &tfprotov6.RawState{JSON: []byte(`{"id":"group:engineering:research","target_kind":"group","target_id":"engineering","access_profile_id":"research","hosted_default":true,"budget_window":"monthly","amount_usd":100,"total_token_limit":null,"alert_threshold_percent":80}`)}}, &response)
	if response.Diagnostics.HasError() {
		t.Fatal(response.Diagnostics)
	}
	var state llmGatewayManagedAccessOverrideModel
	response.Diagnostics.Append(response.State.Get(ctx, &state)...)
	if response.Diagnostics.HasError() || state.ID.ValueString() != "group:engineering:research" || !state.HostedDefault.ValueBool() {
		t.Fatalf("assignment state lost: %+v %v", state, response.Diagnostics)
	}
}
