package core

import (
	"fmt"
	"reflect"
	"strings"
	"testing"
	"time"

	route "github.com/envoyproxy/go-control-plane/envoy/config/route/v3"
	discovery "github.com/envoyproxy/go-control-plane/envoy/service/discovery/v3"

	meshconfig "istio.io/api/mesh/v1alpha1"
	networking "istio.io/api/networking/v1alpha3"
	"istio.io/istio/pilot/pkg/features"
	"istio.io/istio/pilot/pkg/model"
	istio_route "istio.io/istio/pilot/pkg/networking/core/route"
	"istio.io/istio/pkg/config"
	"istio.io/istio/pkg/config/constants"
	"istio.io/istio/pkg/config/mesh"
	"istio.io/istio/pkg/config/schema/gvk"
	"istio.io/istio/pkg/config/schema/kind"
	"istio.io/istio/pkg/test"
	"istio.io/istio/pkg/util/sets"
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

func hostRDSTLSGatewayAndVirtualService(name, selector, host string) []config.Config {
	configs := hostRDSGatewayAndVirtualService(name, selector, host)
	server := configs[0].Spec.(*networking.Gateway).Servers[0]
	server.Port = &networking.Port{Name: "https", Number: 443, Protocol: "HTTPS"}
	server.Tls = &networking.ServerTLSSettings{Mode: networking.ServerTLSSettings_SIMPLE}
	return configs
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
	p, _, cacheHit := buildHostRDSWithCacheOnPort(t, cache, configs, nil, proxy, host, 80)
	return p, cacheHit
}

func buildHostRDSWithCacheOnPort(
	t *testing.T,
	cache model.XdsCache,
	configs []config.Config,
	meshConfig *meshconfig.MeshConfig,
	proxy *model.Proxy,
	host string,
	port int,
) (*model.Proxy, *discovery.Resource, bool) {
	t.Helper()
	cg := NewConfigGenTest(t, TestOptions{Configs: configs, MeshConfig: meshConfig})
	cg.ConfigGen = NewConfigGenerator(cache)
	p := cg.SetupProxy(proxy)
	routeName := fmt.Sprintf("%s%d.%s", constants.HigressHostRDSNamePrefix, port, host)
	resource, cacheHit := cg.ConfigGen.buildGatewayHTTPRouteConfig(p,
		&model.PushRequest{Push: cg.PushContext(), Start: time.Now()}, routeName, map[int][]virtualServiceContext{}, nil, nil)
	if resource == nil {
		t.Fatalf("no route generated for %s", routeName)
	}
	return p, resource, cacheHit
}

func hostRDSRouteConfiguration(t *testing.T, resource *discovery.Resource) *route.RouteConfiguration {
	t.Helper()
	routeConfig := &route.RouteConfiguration{}
	if err := resource.Resource.UnmarshalTo(routeConfig); err != nil {
		t.Fatalf("unmarshal route configuration: %v", err)
	}
	return routeConfig
}

type hostRDSCacheRecorder struct {
	model.XdsCache
	gatewayNames          [][]string
	dependentConfigCounts []int
}

func (c *hostRDSCacheRecorder) Add(entry model.XdsCacheEntry, pushRequest *model.PushRequest, resource *discovery.Resource) {
	if routeEntry, ok := entry.(*istio_route.Cache); ok {
		c.gatewayNames = append(c.gatewayNames, append([]string(nil), routeEntry.GatewayNames...))
		c.dependentConfigCounts = append(c.dependentConfigCounts, len(routeEntry.DependentConfigs()))
	}
	c.XdsCache.Add(entry, pushRequest, resource)
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

func TestHostRDSCacheTracksUnboundConflictingGateway(t *testing.T) {
	cache := model.NewXdsCache()
	const host = "shared.example.com"
	boundConfigs := hostRDSTLSGatewayAndVirtualService("bound", "ingressgateway", host)
	boundConfigs[0].CreationTimestamp = time.Now()
	conflictingGateway := hostRDSTLSGatewayAndVirtualService("conflicting", "ingressgateway", host)[0]
	conflictingGateway.CreationTimestamp = boundConfigs[0].CreationTimestamp.Add(-time.Hour)
	configs := append([]config.Config{conflictingGateway}, boundConfigs...)

	p, _, cacheHit := buildHostRDSWithCacheOnPort(t, cache, configs, nil,
		newHostRDSTestProxy("v0.default", "ingressgateway"), host, 443)
	if cacheHit {
		t.Fatal("first build should not be a cache hit")
	}
	var selectedGateways []string
	for _, mergedServers := range p.MergedGateway.MergedServers {
		for _, server := range mergedServers.Servers {
			selectedGateways = append(selectedGateways, p.MergedGateway.GatewayNameForServer[server])
		}
	}
	if !reflect.DeepEqual(selectedGateways, []string{"default/conflicting"}) {
		t.Fatalf("test setup must select only the unbound conflicting Gateway, got %v", selectedGateways)
	}

	cache.Clear(sets.New(model.ConfigKey{Kind: kind.Gateway, Name: "conflicting", Namespace: "default"}))
	_, _, cacheHit = buildHostRDSWithCacheOnPort(t, cache, configs, nil,
		newHostRDSTestProxy("v0.default", "ingressgateway"), host, 443)
	if cacheHit {
		t.Fatal("changing the selected unbound Gateway must invalidate the host RDS cache")
	}

	changedConfigs := append([]config.Config(nil), configs...)
	changedConfigs[0] = conflictingGateway.DeepCopy()
	changedConfigs[0].Spec.(*networking.Gateway).Servers[0].Hosts = []string{"other.example.com"}
	_, resource, cacheHit := buildHostRDSWithCacheOnPort(t, cache, changedConfigs, nil,
		newHostRDSTestProxy("v0.default", "ingressgateway"), host, 443)
	if cacheHit {
		t.Fatal("changing the conflicting Gateway so the bound server wins must rebuild the host RDS")
	}
	routeConfig := hostRDSRouteConfiguration(t, resource)
	if len(routeConfig.VirtualHosts) != 1 || !reflect.DeepEqual(routeConfig.VirtualHosts[0].Domains, []string{host}) {
		t.Fatalf("expected the bound VirtualService route after the conflict is removed, got %v", routeConfig.VirtualHosts)
	}
}

func TestHostRDSHTTP3DependenciesStayHostScoped(t *testing.T) {
	test.SetForTest(t, &features.EnableQUICListeners, true)
	const gatewayCount = 8
	configs := make([]config.Config, 0, gatewayCount*2)
	for i := 0; i < gatewayCount; i++ {
		configs = append(configs, hostRDSTLSGatewayAndVirtualService(
			fmt.Sprintf("gw-%d", i), "ingressgateway", fmt.Sprintf("host-%d.example.com", i))...)
	}
	meshConfig := mesh.DefaultMeshConfig()
	meshConfig.MseIngressGlobalConfig.EnableH3 = true
	cache := &hostRDSCacheRecorder{XdsCache: model.NewXdsCache()}
	cg := NewConfigGenTest(t, TestOptions{Configs: configs, MeshConfig: meshConfig})
	cg.ConfigGen = NewConfigGenerator(cache)
	proxy := cg.SetupProxy(newHostRDSTestProxy("v0.default", "ingressgateway"))

	quicGateways := sets.New[string]()
	for _, mergedServers := range proxy.MergedGateway.MergedQUICTransportServers {
		for _, server := range mergedServers.Servers {
			quicGateways.Insert(proxy.MergedGateway.GatewayNameForServer[server])
		}
	}
	if len(quicGateways) != gatewayCount {
		t.Fatalf("test setup must merge %d QUIC Gateways, got %d", gatewayCount, len(quicGateways))
	}

	vsCache := map[int][]virtualServiceContext{}
	for i := 0; i < gatewayCount; i++ {
		host := fmt.Sprintf("host-%d.example.com", i)
		routeName := constants.HigressHostRDSNamePrefix + "443." + host
		resource, cacheHit := cg.ConfigGen.buildGatewayHTTPRouteConfig(proxy,
			&model.PushRequest{Push: cg.PushContext(), Start: time.Now()}, routeName, vsCache, nil, nil)
		if resource == nil || cacheHit {
			t.Fatalf("first build for %s should generate an uncached route", host)
		}
		routeConfig := hostRDSRouteConfiguration(t, resource)
		if !strings.Contains(routeConfig.String(), "alt-svc") {
			t.Fatalf("selected HTTP/3 Gateway must still advertise alt-svc for %s", host)
		}
	}

	if len(cache.gatewayNames) != gatewayCount {
		t.Fatalf("recorded %d cache entries, want %d", len(cache.gatewayNames), gatewayCount)
	}
	for i, gatewayNames := range cache.gatewayNames {
		wantGatewayNames := []string{fmt.Sprintf("default/gw-%d", i)}
		if !reflect.DeepEqual(gatewayNames, wantGatewayNames) {
			t.Errorf("host %d cache key Gateway set = %v, want %v", i, gatewayNames, wantGatewayNames)
		}
		if cache.dependentConfigCounts[i] != 2 {
			t.Errorf("host %d dependency count = %d, want 2 (one VirtualService and one selected Gateway)",
				i, cache.dependentConfigCounts[i])
		}
	}
}

func TestHostRDSCacheRouteUpdateStillPropagates(t *testing.T) {
	cache := model.NewXdsCache()
	const host = "update.example.com"
	configs := hostRDSGatewayAndVirtualService("gw-update", "ingressgateway", host)
	_, _, cacheHit := buildHostRDSWithCacheOnPort(t, cache, configs, nil,
		newHostRDSTestProxy("v0.default", "ingressgateway"), host, 80)
	if cacheHit {
		t.Fatal("first build should not be a cache hit")
	}

	updatedVirtualService := configs[1].DeepCopy()
	updatedVirtualService.Spec.(*networking.VirtualService).Http[0].Route[0].Destination.Host = "updated.default.svc.cluster.local"
	updatedConfigs := []config.Config{configs[0], updatedVirtualService}
	cache.Clear(sets.New(model.ConfigKey{Kind: kind.VirtualService, Name: "gw-update", Namespace: "default"}))
	_, resource, cacheHit := buildHostRDSWithCacheOnPort(t, cache, updatedConfigs, nil,
		newHostRDSTestProxy("v0.default", "ingressgateway"), host, 80)
	if cacheHit {
		t.Fatal("VirtualService update must invalidate the host RDS cache")
	}
	routeConfig := hostRDSRouteConfiguration(t, resource)
	if !strings.Contains(routeConfig.String(), "updated.default.svc.cluster.local") {
		t.Fatalf("updated destination did not propagate to the host RDS: %v", routeConfig)
	}
}
