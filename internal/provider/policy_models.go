package provider

import (
	"context"

	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/types"
)

type terraformModelReader interface {
	Get(context.Context, any) diag.Diagnostics
}

type contentPolicyModel struct {
	ID                    types.String  `tfsdk:"id"`
	Name                  types.String  `tfsdk:"name"`
	Description           types.String  `tfsdk:"description"`
	Rationale             types.String  `tfsdk:"rationale"`
	UseCases              types.Set     `tfsdk:"use_cases"`
	ComplianceFrameworks  types.Set     `tfsdk:"compliance_frameworks"`
	Labels                types.Set     `tfsdk:"labels"`
	Enabled               types.Bool    `tfsdk:"enabled"`
	AcknowledgeBroadScope types.Bool    `tfsdk:"acknowledge_broad_scope"`
	Users                 types.Set     `tfsdk:"users"`
	Groups                types.Set     `tfsdk:"groups"`
	UserDirectoryIDs      types.Map     `tfsdk:"user_directory_ids"`
	GroupDirectoryIDs     types.Map     `tfsdk:"group_directory_ids"`
	ServiceAccounts       types.Set     `tfsdk:"service_accounts"`
	Agents                types.Set     `tfsdk:"agents"`
	Products              types.Set     `tfsdk:"products"`
	EvaluateOn            types.List    `tfsdk:"evaluate_on"`
	Action                types.String  `tfsdk:"action"`
	Message               types.String  `tfsdk:"message"`
	AutoApprove           types.Bool    `tfsdk:"auto_approve_on_request"`
	RedactionReplacement  types.String  `tfsdk:"redaction_replacement"`
	RedactionStrategy     types.String  `tfsdk:"redaction_strategy"`
	RedactionPaths        types.Set     `tfsdk:"redaction_paths"`
	RedactionKeepStart    types.Int64   `tfsdk:"redaction_keep_start"`
	RedactionKeepEnd      types.Int64   `tfsdk:"redaction_keep_end"`
	RedactionMask         types.String  `tfsdk:"redaction_mask_character"`
	RedactionSaltRef      types.String  `tfsdk:"redaction_salt_ref"`
	RedactionFakeSubtype  types.String  `tfsdk:"redaction_fake_subtype"`
	RedactionApplyTo      types.String  `tfsdk:"redaction_apply_to"`
	RedactionPattern      types.String  `tfsdk:"redaction_pattern"`
	FilterCollectionPath  types.String  `tfsdk:"filter_collection_path"`
	FilterPath            types.String  `tfsdk:"filter_path"`
	FilterOperator        types.String  `tfsdk:"filter_operator"`
	FilterValue           types.Dynamic `tfsdk:"filter_value"`
	FilterOnUnavailable   types.String  `tfsdk:"filter_on_unavailable"`
	Module                types.String  `tfsdk:"module"`
	Conditions            types.Dynamic `tfsdk:"conditions"`
	CustomFields          types.Dynamic `tfsdk:"custom_fields"`
	Except                types.Dynamic `tfsdk:"except"`
	Exceptions            types.Dynamic `tfsdk:"exceptions"`
	CurrentRevision       types.Int64   `tfsdk:"current_revision"`
	DefinitionSHA         types.String  `tfsdk:"definition_sha256"`
	ValidationToken       types.String  `tfsdk:"validation_token"`
	ModuleSHA             types.String  `tfsdk:"module_sha256"`
}

type accessPolicyModel struct {
	ID                    types.String  `tfsdk:"id"`
	Name                  types.String  `tfsdk:"name"`
	Description           types.String  `tfsdk:"description"`
	Rationale             types.String  `tfsdk:"rationale"`
	UseCases              types.Set     `tfsdk:"use_cases"`
	ComplianceFrameworks  types.Set     `tfsdk:"compliance_frameworks"`
	Labels                types.Set     `tfsdk:"labels"`
	Enabled               types.Bool    `tfsdk:"enabled"`
	Severity              types.String  `tfsdk:"severity"`
	AcknowledgeBroadScope types.Bool    `tfsdk:"acknowledge_broad_scope"`
	EnforcementSurfaces   types.Set     `tfsdk:"enforcement_surfaces"`
	Runtime               types.Dynamic `tfsdk:"runtime"`
	Notification          types.Dynamic `tfsdk:"notification"`
	ApprovalMode          types.String  `tfsdk:"approval_mode"`
	Remediation           types.Dynamic `tfsdk:"remediation"`
	Users                 types.Set     `tfsdk:"users"`
	Groups                types.Set     `tfsdk:"groups"`
	UserDirectoryIDs      types.Map     `tfsdk:"user_directory_ids"`
	GroupDirectoryIDs     types.Map     `tfsdk:"group_directory_ids"`
	Devices               types.Set     `tfsdk:"devices"`
	ServiceAccounts       types.Set     `tfsdk:"service_accounts"`
	Action                types.String  `tfsdk:"action"`
	Module                types.String  `tfsdk:"module"`
	Conditions            types.Dynamic `tfsdk:"conditions"`
	Except                types.Dynamic `tfsdk:"except"`
	Exceptions            types.Dynamic `tfsdk:"exceptions"`
	EnforcedBy            types.Set     `tfsdk:"enforced_by"`
	CurrentRevision       types.Int64   `tfsdk:"current_revision"`
	DefinitionSHA         types.String  `tfsdk:"definition_sha256"`
	ValidationToken       types.String  `tfsdk:"validation_token"`
	ModuleSHA             types.String  `tfsdk:"module_sha256"`
}

type resourcePolicyModel struct {
	ID                    types.String  `tfsdk:"id"`
	Name                  types.String  `tfsdk:"name"`
	Description           types.String  `tfsdk:"description"`
	Rationale             types.String  `tfsdk:"rationale"`
	UseCases              types.Set     `tfsdk:"use_cases"`
	ComplianceFrameworks  types.Set     `tfsdk:"compliance_frameworks"`
	Labels                types.Set     `tfsdk:"labels"`
	Enabled               types.Bool    `tfsdk:"enabled"`
	Enforcement           types.String  `tfsdk:"enforcement"`
	Severity              types.String  `tfsdk:"severity"`
	AcknowledgeBroadScope types.Bool    `tfsdk:"acknowledge_broad_scope"`
	Users                 types.Set     `tfsdk:"users"`
	Groups                types.Set     `tfsdk:"groups"`
	UserDirectoryIDs      types.Map     `tfsdk:"user_directory_ids"`
	GroupDirectoryIDs     types.Map     `tfsdk:"group_directory_ids"`
	ServiceAccounts       types.Set     `tfsdk:"service_accounts"`
	Devices               types.Set     `tfsdk:"devices"`
	Resources             types.Set     `tfsdk:"resources"`
	Action                types.String  `tfsdk:"action"`
	DataTarget            types.String  `tfsdk:"data_target"`
	Message               types.String  `tfsdk:"message"`
	ApprovalMode          types.String  `tfsdk:"approval_mode"`
	RedactionReplacement  types.String  `tfsdk:"redaction_replacement"`
	RedactionStrategy     types.String  `tfsdk:"redaction_strategy"`
	RedactionPaths        types.Set     `tfsdk:"redaction_paths"`
	RedactionKeepStart    types.Int64   `tfsdk:"redaction_keep_start"`
	RedactionKeepEnd      types.Int64   `tfsdk:"redaction_keep_end"`
	RedactionMask         types.String  `tfsdk:"redaction_mask_character"`
	RedactionSaltRef      types.String  `tfsdk:"redaction_salt_ref"`
	RedactionFakeSubtype  types.String  `tfsdk:"redaction_fake_subtype"`
	RedactionApplyTo      types.String  `tfsdk:"redaction_apply_to"`
	RedactionPattern      types.String  `tfsdk:"redaction_pattern"`
	FilterCollectionPath  types.String  `tfsdk:"filter_collection_path"`
	FilterPath            types.String  `tfsdk:"filter_path"`
	FilterOperator        types.String  `tfsdk:"filter_operator"`
	FilterValue           types.Dynamic `tfsdk:"filter_value"`
	FilterOnUnavailable   types.String  `tfsdk:"filter_on_unavailable"`
	Module                types.String  `tfsdk:"module"`
	Conditions            types.Dynamic `tfsdk:"conditions"`
	Except                types.Dynamic `tfsdk:"except"`
	Exceptions            types.Dynamic `tfsdk:"exceptions"`
	CurrentRevision       types.Int64   `tfsdk:"current_revision"`
	DefinitionSHA         types.String  `tfsdk:"definition_sha256"`
	ValidationToken       types.String  `tfsdk:"validation_token"`
	ModuleSHA             types.String  `tfsdk:"module_sha256"`
}

func (r *regoPolicyResource) readModel(ctx context.Context, source terraformModelReader, out *regoPolicyModel) diag.Diagnostics {
	switch r.family {
	case "content":
		var model contentPolicyModel
		diagnostics := source.Get(ctx, &model)
		*out = regoPolicyModel{
			ID: model.ID, Name: model.Name, Description: model.Description, Rationale: model.Rationale, UseCases: model.UseCases, ComplianceFrameworks: model.ComplianceFrameworks, Labels: model.Labels,
			Enabled: model.Enabled, AcknowledgeBroadScope: model.AcknowledgeBroadScope, Users: model.Users, Groups: model.Groups, UserDirectoryIDs: model.UserDirectoryIDs, GroupDirectoryIDs: model.GroupDirectoryIDs,
			ServiceAccounts: model.ServiceAccounts, Agents: model.Agents, Products: model.Products, EvaluateOn: model.EvaluateOn, Action: model.Action, Message: model.Message, AutoApprove: model.AutoApprove,
			RedactionReplacement: model.RedactionReplacement, RedactionStrategy: model.RedactionStrategy, RedactionPaths: model.RedactionPaths, RedactionKeepStart: model.RedactionKeepStart, RedactionKeepEnd: model.RedactionKeepEnd,
			RedactionMask: model.RedactionMask, RedactionSaltRef: model.RedactionSaltRef, RedactionFakeSubtype: model.RedactionFakeSubtype, RedactionApplyTo: model.RedactionApplyTo, RedactionPattern: model.RedactionPattern,
			FilterCollectionPath: model.FilterCollectionPath, FilterPath: model.FilterPath, FilterOperator: model.FilterOperator, FilterValue: model.FilterValue, FilterOnUnavailable: model.FilterOnUnavailable,
			Module: model.Module, Conditions: model.Conditions, CustomFields: model.CustomFields, Except: model.Except, Exceptions: model.Exceptions, CurrentRevision: model.CurrentRevision, DefinitionSHA: model.DefinitionSHA, ValidationToken: model.ValidationToken, ModuleSHA: model.ModuleSHA,
		}
		return diagnostics
	case "access":
		var model accessPolicyModel
		diagnostics := source.Get(ctx, &model)
		*out = regoPolicyModel{
			ID: model.ID, Name: model.Name, Description: model.Description, Rationale: model.Rationale, UseCases: model.UseCases, ComplianceFrameworks: model.ComplianceFrameworks, Labels: model.Labels,
			Enabled: model.Enabled, Severity: model.Severity, AcknowledgeBroadScope: model.AcknowledgeBroadScope, EnforcementSurfaces: model.EnforcementSurfaces, Runtime: model.Runtime, Notification: model.Notification, ApprovalMode: model.ApprovalMode, Remediation: model.Remediation,
			Users: model.Users, Groups: model.Groups, UserDirectoryIDs: model.UserDirectoryIDs, GroupDirectoryIDs: model.GroupDirectoryIDs, Devices: model.Devices, ServiceAccounts: model.ServiceAccounts, Action: model.Action, Module: model.Module, Conditions: model.Conditions, Except: model.Except, Exceptions: model.Exceptions, EnforcedBy: model.EnforcedBy,
			CurrentRevision: model.CurrentRevision, DefinitionSHA: model.DefinitionSHA, ValidationToken: model.ValidationToken, ModuleSHA: model.ModuleSHA,
		}
		return diagnostics
	case "resource":
		var model resourcePolicyModel
		diagnostics := source.Get(ctx, &model)
		*out = regoPolicyModel{
			ID: model.ID, Name: model.Name, Description: model.Description, Rationale: model.Rationale, UseCases: model.UseCases, ComplianceFrameworks: model.ComplianceFrameworks, Labels: model.Labels,
			Enabled: model.Enabled, Enforcement: model.Enforcement, Severity: model.Severity, AcknowledgeBroadScope: model.AcknowledgeBroadScope, Users: model.Users, Groups: model.Groups, UserDirectoryIDs: model.UserDirectoryIDs, GroupDirectoryIDs: model.GroupDirectoryIDs,
			Devices: model.Devices, ServiceAccounts: model.ServiceAccounts, Resources: model.Resources, Action: model.Action, DataTarget: model.DataTarget, Message: model.Message, ApprovalMode: model.ApprovalMode,
			RedactionReplacement: model.RedactionReplacement, RedactionStrategy: model.RedactionStrategy, RedactionPaths: model.RedactionPaths, RedactionKeepStart: model.RedactionKeepStart, RedactionKeepEnd: model.RedactionKeepEnd, RedactionMask: model.RedactionMask, RedactionSaltRef: model.RedactionSaltRef, RedactionFakeSubtype: model.RedactionFakeSubtype, RedactionApplyTo: model.RedactionApplyTo, RedactionPattern: model.RedactionPattern,
			FilterCollectionPath: model.FilterCollectionPath, FilterPath: model.FilterPath, FilterOperator: model.FilterOperator, FilterValue: model.FilterValue, FilterOnUnavailable: model.FilterOnUnavailable, Module: model.Module, Conditions: model.Conditions, Except: model.Except, Exceptions: model.Exceptions,
			CurrentRevision: model.CurrentRevision, DefinitionSHA: model.DefinitionSHA, ValidationToken: model.ValidationToken, ModuleSHA: model.ModuleSHA,
		}
		return diagnostics
	default:
		return diag.Diagnostics{diag.NewErrorDiagnostic("Unsupported policy family", r.family)}
	}
}

func (r *regoPolicyResource) stateModel(model regoPolicyModel) any {
	switch r.family {
	case "content":
		return contentPolicyModel{
			ID: model.ID, Name: model.Name, Description: model.Description, Rationale: model.Rationale, UseCases: model.UseCases, ComplianceFrameworks: model.ComplianceFrameworks, Labels: model.Labels,
			Enabled: model.Enabled, AcknowledgeBroadScope: model.AcknowledgeBroadScope, Users: model.Users, Groups: model.Groups, UserDirectoryIDs: model.UserDirectoryIDs, GroupDirectoryIDs: model.GroupDirectoryIDs,
			ServiceAccounts: model.ServiceAccounts, Agents: model.Agents, Products: model.Products, EvaluateOn: model.EvaluateOn, Action: model.Action, Message: model.Message, AutoApprove: model.AutoApprove,
			RedactionReplacement: model.RedactionReplacement, RedactionStrategy: model.RedactionStrategy, RedactionPaths: model.RedactionPaths, RedactionKeepStart: model.RedactionKeepStart, RedactionKeepEnd: model.RedactionKeepEnd,
			RedactionMask: model.RedactionMask, RedactionSaltRef: model.RedactionSaltRef, RedactionFakeSubtype: model.RedactionFakeSubtype, RedactionApplyTo: model.RedactionApplyTo, RedactionPattern: model.RedactionPattern,
			FilterCollectionPath: model.FilterCollectionPath, FilterPath: model.FilterPath, FilterOperator: model.FilterOperator, FilterValue: model.FilterValue, FilterOnUnavailable: model.FilterOnUnavailable,
			Module: model.Module, Conditions: model.Conditions, CustomFields: model.CustomFields, Except: model.Except, Exceptions: model.Exceptions, CurrentRevision: model.CurrentRevision, DefinitionSHA: model.DefinitionSHA, ValidationToken: model.ValidationToken, ModuleSHA: model.ModuleSHA,
		}
	case "access":
		return accessPolicyModel{
			ID: model.ID, Name: model.Name, Description: model.Description, Rationale: model.Rationale, UseCases: model.UseCases, ComplianceFrameworks: model.ComplianceFrameworks, Labels: model.Labels,
			Enabled: model.Enabled, Severity: model.Severity, AcknowledgeBroadScope: model.AcknowledgeBroadScope, EnforcementSurfaces: model.EnforcementSurfaces, Runtime: model.Runtime, Notification: model.Notification, ApprovalMode: model.ApprovalMode, Remediation: model.Remediation,
			Users: model.Users, Groups: model.Groups, UserDirectoryIDs: model.UserDirectoryIDs, GroupDirectoryIDs: model.GroupDirectoryIDs, Devices: model.Devices, ServiceAccounts: model.ServiceAccounts, Action: model.Action, Module: model.Module, Conditions: model.Conditions, Except: model.Except, Exceptions: model.Exceptions, EnforcedBy: model.EnforcedBy,
			CurrentRevision: model.CurrentRevision, DefinitionSHA: model.DefinitionSHA, ValidationToken: model.ValidationToken, ModuleSHA: model.ModuleSHA,
		}
	case "resource":
		return resourcePolicyModel{
			ID: model.ID, Name: model.Name, Description: model.Description, Rationale: model.Rationale, UseCases: model.UseCases, ComplianceFrameworks: model.ComplianceFrameworks, Labels: model.Labels,
			Enabled: model.Enabled, Enforcement: model.Enforcement, Severity: model.Severity, AcknowledgeBroadScope: model.AcknowledgeBroadScope, Users: model.Users, Groups: model.Groups, UserDirectoryIDs: model.UserDirectoryIDs, GroupDirectoryIDs: model.GroupDirectoryIDs,
			Devices: model.Devices, ServiceAccounts: model.ServiceAccounts, Resources: model.Resources, Action: model.Action, DataTarget: model.DataTarget, Message: model.Message, ApprovalMode: model.ApprovalMode,
			RedactionReplacement: model.RedactionReplacement, RedactionStrategy: model.RedactionStrategy, RedactionPaths: model.RedactionPaths, RedactionKeepStart: model.RedactionKeepStart, RedactionKeepEnd: model.RedactionKeepEnd, RedactionMask: model.RedactionMask, RedactionSaltRef: model.RedactionSaltRef, RedactionFakeSubtype: model.RedactionFakeSubtype, RedactionApplyTo: model.RedactionApplyTo, RedactionPattern: model.RedactionPattern,
			FilterCollectionPath: model.FilterCollectionPath, FilterPath: model.FilterPath, FilterOperator: model.FilterOperator, FilterValue: model.FilterValue, FilterOnUnavailable: model.FilterOnUnavailable, Module: model.Module, Conditions: model.Conditions, Except: model.Except, Exceptions: model.Exceptions,
			CurrentRevision: model.CurrentRevision, DefinitionSHA: model.DefinitionSHA, ValidationToken: model.ValidationToken, ModuleSHA: model.ModuleSHA,
		}
	default:
		return nil
	}
}
