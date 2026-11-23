package provider

import (
	"context"
	"fmt"
	"net/netip"
	"slices"
	"strings"

	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/schema/validator"
	"github.com/hashicorp/terraform-plugin-framework/types"
)

type allowedClientNetworksValidator struct{}

func (allowedClientNetworksValidator) Description(context.Context) string {
	return "Up to 128 IPv4 or IPv6 addresses or CIDR ranges."
}

func (v allowedClientNetworksValidator) MarkdownDescription(ctx context.Context) string {
	return v.Description(ctx)
}

func (allowedClientNetworksValidator) ValidateSet(ctx context.Context, request validator.SetRequest, response *validator.SetResponse) {
	_, diagnostics := normalizedAllowedClientNetworks(ctx, request.ConfigValue, request.Path)
	response.Diagnostics.Append(diagnostics...)
}

func normalizedAllowedClientNetworks(ctx context.Context, value types.Set, attribute path.Path) ([]string, diag.Diagnostics) {
	var diagnostics diag.Diagnostics
	if value.IsNull() || value.IsUnknown() {
		return nil, diagnostics
	}
	if len(value.Elements()) > 128 {
		diagnostics.AddAttributeError(attribute, "Too many client networks", "Configure at most 128 client networks.")
		return nil, diagnostics
	}

	var entries []types.String
	diagnostics.Append(value.ElementsAs(ctx, &entries, false)...)
	if diagnostics.HasError() {
		return nil, diagnostics
	}
	prefixes := make([]string, 0, len(entries))
	for _, entry := range entries {
		if entry.IsUnknown() {
			return nil, diagnostics
		}
		prefix, err := parseAllowedClientNetwork(entry.ValueString())
		if err != nil {
			diagnostics.AddAttributeError(attribute, "Invalid client network", err.Error())
			continue
		}
		prefixes = append(prefixes, prefix.String())
	}
	slices.Sort(prefixes)
	return slices.Compact(prefixes), diagnostics
}

func parseAllowedClientNetwork(value string) (netip.Prefix, error) {
	trimmed := strings.TrimSpace(value)
	if addr, err := netip.ParseAddr(trimmed); err == nil && addr.Zone() == "" {
		addr = addr.Unmap()
		return netip.PrefixFrom(addr, addr.BitLen()), nil
	}
	prefix, err := netip.ParsePrefix(trimmed)
	if err != nil {
		return netip.Prefix{}, fmt.Errorf("%q must be an IPv4 or IPv6 address or CIDR range", value)
	}
	if prefix.Addr().Is4In6() {
		if prefix.Bits() < 96 {
			return netip.Prefix{}, fmt.Errorf("%q must use a /96 or longer IPv4-mapped IPv6 prefix", value)
		}
		prefix = netip.PrefixFrom(prefix.Addr().Unmap(), prefix.Bits()-96)
	}
	return prefix.Masked(), nil
}

func allowedClientNetworksState(ctx context.Context, previous types.Set, actual []string, diagnostics *diag.Diagnostics) types.Set {
	normalized, _ := normalizedAllowedClientNetworks(ctx, previous, path.Root("allowed_client_networks"))
	sortedActual := slices.Clone(actual)
	slices.Sort(sortedActual)
	if normalized != nil && slices.Equal(normalized, sortedActual) {
		return previous
	}
	if len(actual) == 0 {
		return types.SetValueMust(types.StringType, nil)
	}
	return setStringState(ctx, actual, diagnostics)
}
