package provider

import "testing"

func TestLLMGatewayAssignmentDefaultAndIdentity(t *testing.T) {
	r := llmGatewayManagedAccessOverrideResource{}
	var model llmGatewayManagedAccessOverrideModel
	r.refresh(&model, managedAccessOverrideAPI{TargetKind: "group", TargetID: "group_1", AccessProfileID: "legal", HostedDefault: true})
	if model.ID.ValueString() != "group:group_1:legal" || !model.HostedDefault.ValueBool() {
		t.Fatal("profile assignment identity/default lost")
	}
}
