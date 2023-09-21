package mseingress

import (
	lrlhttppb "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/http/local_ratelimit/v3"
	rbachttppb "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/http/rbac/v3"
	httppb "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/network/http_connection_manager/v3"

	"istio.io/istio/pilot/pkg/model"
	"istio.io/istio/pilot/pkg/networking"
	"istio.io/istio/pilot/pkg/networking/core/v1alpha3/mseingress"
	"istio.io/istio/pilot/pkg/networking/plugin"
	"istio.io/istio/pilot/pkg/networking/util"
	authzmodel "istio.io/istio/pilot/pkg/security/authz/model"
)

var (
	DefaultRBACFilter = &httppb.HttpFilter{
		Name: authzmodel.RBACHTTPFilterName,
		ConfigType: &httppb.HttpFilter_TypedConfig{
			TypedConfig: util.MessageToAny(&rbachttppb.RBAC{}),
		},
	}

	GlobalLocalRateLimitFilter = &httppb.HttpFilter{
		Name: mseingress.LocalRateLimitFilterName,
		ConfigType: &httppb.HttpFilter_TypedConfig{
			TypedConfig: util.MessageToAny(&lrlhttppb.LocalRateLimit{
				StatPrefix: mseingress.DefaultLocalRateLimitStatPrefix,
			}),
		},
	}
)

type Plugin struct{}

// NewPlugin returns an instance of the extension plugin for alibaba case.
func NewPlugin() plugin.Plugin {
	return Plugin{}
}

func (p Plugin) OnOutboundListener(in *plugin.InputParams, mutable *networking.MutableObjects) error {
	if in.Node.Type != model.Router {
		return nil
	}

	insertRBACWithNeed(in, mutable)
	insertLocalRateLimitWithNeed(in, mutable)

	return nil
}

func insertRBACWithNeed(in *plugin.InputParams, mutable *networking.MutableObjects) {
	hasRBAC := false
	httpFilters := in.Push.GetHTTPFiltersFromEnvoyFilter(in.Node)
	for _, filter := range httpFilters {
		if mseingress.GetRBACFilter(filter) != nil {
			hasRBAC = true
			break
		}
	}
	if hasRBAC {
		return
	}

	for idx := range mutable.FilterChains {
		// Only care about http network filter
		if mutable.FilterChains[idx].ListenerProtocol != networking.ListenerProtocolHTTP {
			continue
		}

		hasRBAC = false
		for _, httpFilter := range mutable.FilterChains[idx].HTTP {
			if httpFilter.Name == authzmodel.RBACHTTPFilterName {
				hasRBAC = true
				break
			}
		}

		// Just make sure host-scoped or route-scoped rbac filters works.
		if !hasRBAC {
			mutable.FilterChains[idx].HTTP = append(mutable.FilterChains[idx].HTTP, DefaultRBACFilter)
		}
	}
}

func insertLocalRateLimitWithNeed(in *plugin.InputParams, mutable *networking.MutableObjects) {
	hasLocalRateLimit := false
	httpFilters := in.Push.GetHTTPFiltersFromEnvoyFilter(in.Node)
	for _, filter := range httpFilters {
		if mseingress.GetLocalRateLimitFilter(filter) != nil {
			hasLocalRateLimit = true
			break
		}
	}
	if hasLocalRateLimit {
		return
	}

	for idx := range mutable.FilterChains {
		// Only care about http network filter
		if mutable.FilterChains[idx].ListenerProtocol != networking.ListenerProtocolHTTP {
			continue
		}

		hasLocalRateLimit = false
		for _, httpFilter := range mutable.FilterChains[idx].HTTP {
			if httpFilter.Name == mseingress.LocalRateLimitFilterName {
				hasLocalRateLimit = true
				break
			}
		}

		// Just make sure host-scoped or route-scoped localRateLimit filters works.
		if !hasLocalRateLimit {
			mutable.FilterChains[idx].HTTP = append(mutable.FilterChains[idx].HTTP, GlobalLocalRateLimitFilter)
		}
	}
}

func (p Plugin) OnInboundListener(*plugin.InputParams, *networking.MutableObjects) error {
	return nil
}

func (p Plugin) OnInboundPassthrough(*plugin.InputParams, *networking.MutableObjects) error {
	return nil
}

func (p Plugin) InboundMTLSConfiguration(*plugin.InputParams, bool) []plugin.MTLSSettings {
	return nil
}
