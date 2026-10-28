package core

import (
	"fmt"
	"testing"
	"time"

	networking "istio.io/api/networking/v1alpha3"
	"istio.io/istio/pilot/pkg/model"
	"istio.io/istio/pkg/config"
	"istio.io/istio/pkg/config/constants"
	"istio.io/istio/pkg/config/schema/gvk"
)

// hostRDSGatewayAndVirtualService mirrors what Higress generates for one Ingress:
// a dedicated Gateway with an HTTP server for the host, and a VirtualService bound to it.
func hostRDSGatewayAndVirtualService(name, selector, host string) []config.Config {
	return []config.Config{
		{
			Meta: config.Meta{Name: name, Namespace: "default", GroupVersionKind: gvk.Gateway},
			Spec: &networking.Gateway{
				Selector: map[string]string{"istio": selector},
				Servers: []*networking.Server{{
					Hosts: []string{host},
					Port:  &networking.Port{Name: "http", Number: 80, Protocol: "HTTP"},
				}},
			},
		},
		{
			Meta: config.Meta{Name: name, Namespace: "default", GroupVersionKind: gvk.VirtualService},
			Spec: &networking.VirtualService{
				Hosts:    []string{host},
				Gateways: []string{"default/" + name},
				Http: []*networking.HTTPRoute{{
					Route: []*networking.HTTPRouteDestination{{
						Destination: &networking.Destination{Host: name + ".default.svc.cluster.local", Port: &networking.PortSelector{Number: 8080}},
					}},
				}},
			},
		},
	}
}

// newHostRDSTestProxy returns a fresh gateway proxy selected by the given "istio" label.
// A new value is built each time because model.Proxy contains a lock and must not be copied.
func newHostRDSTestProxy(id, gatewayLabel string) *model.Proxy {
	meta := proxyGatewayMetadata
	meta.Labels = map[string]string{"istio": gatewayLabel}
	return &model.Proxy{
		Type:            model.Router,
		IPAddresses:     []string{"1.1.1.1"},
		ID:              id,
		DNSDomain:       "default.example.org",
		Labels:          meta.Labels,
		Metadata:        &meta,
		ConfigNamespace: "not-default",
	}
}

func buildHostRDSWithCache(t *testing.T, cache model.XdsCache, configs []config.Config, proxy *model.Proxy, host string) (*model.Proxy, bool) {
	t.Helper()
	cg := NewConfigGenTest(t, TestOptions{Configs: configs})
	cg.ConfigGen = NewConfigGenerator(cache)
	p := cg.SetupProxy(proxy)
	routeName := constants.HigressHostRDSNamePrefix + "80." + host
	resource, cacheHit := cg.ConfigGen.buildGatewayHTTPRouteConfig(p,
		&model.PushRequest{Push: cg.PushContext(), Start: time.Now()}, routeName, map[int][]virtualServiceContext{}, nil, nil)
	if resource == nil {
		t.Fatalf("no route generated for %s", routeName)
	}
	return p, cacheHit
}

// Adding an Ingress (a new Gateway for an unrelated host) must not invalidate the cached host
// routes of existing hosts. When every merged gateway name was part of each host's cache key,
// it did, so every push rebuilt all host routes: O(#hosts * #gateways) work and memory.
func TestHostRDSCacheNotInvalidatedByUnrelatedGateway(t *testing.T) {
	cache := model.NewXdsCache()
	var configs []config.Config
	for i := 0; i < 3; i++ {
		configs = append(configs, hostRDSGatewayAndVirtualService(fmt.Sprintf("gw-%d", i), "ingressgateway", fmt.Sprintf("host-%d.example.com", i))...)
	}

	if _, hit := buildHostRDSWithCache(t, cache, configs, newHostRDSTestProxy("v0.default", "ingressgateway"), "host-0.example.com"); hit {
		t.Fatal("first build should not be a cache hit")
	}
	if _, hit := buildHostRDSWithCache(t, cache, configs, newHostRDSTestProxy("v0.default", "ingressgateway"), "host-0.example.com"); !hit {
		t.Fatal("unchanged config should hit the cache")
	}

	configs = append(configs, hostRDSGatewayAndVirtualService("gw-new", "ingressgateway", "host-new.example.com")...)
	p, hit := buildHostRDSWithCache(t, cache, configs, newHostRDSTestProxy("v0.default", "ingressgateway"), "host-0.example.com")
	// Use GatewayNameForServer (not the new GatewayNames field) so this test also compiles against the
	// unfixed code and demonstrates the regression there.
	merged := map[string]struct{}{}
	for _, name := range p.MergedGateway.GatewayNameForServer {
		merged[name] = struct{}{}
	}
	if len(merged) != 4 {
		t.Fatalf("expected the new gateway to be merged for the proxy, got %v", merged)
	}
	if !hit {
		t.Fatal("adding an unrelated gateway must not invalidate the cached route of host-0")
	}
}

// Gateways served by different proxies must still get separate cache entries for the same host,
// otherwise a route built for one gateway could be served to another.
func TestHostRDSCacheStillIsolatedByGateway(t *testing.T) {
	cache := model.NewXdsCache()
	const host = "shared.example.com"
	// gw-a binds a VirtualService for the host; gw-b only has a server for the same host.
	configs := hostRDSGatewayAndVirtualService("gw-a", "gateway-a", host)
	configs = append(configs, hostRDSGatewayAndVirtualService("gw-b", "gateway-b", host)[0])

	if _, hit := buildHostRDSWithCache(t, cache, configs, newHostRDSTestProxy("v0.default", "gateway-a"), host); hit {
		t.Fatal("first build for gateway-a should not be a cache hit")
	}
	if _, hit := buildHostRDSWithCache(t, cache, configs, newHostRDSTestProxy("v1.default", "gateway-b"), host); hit {
		t.Fatal("gateway-b must not reuse the cached route built for gateway-a")
	}
}
