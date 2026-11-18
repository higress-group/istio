// Copyright Istio Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package xds_test

import (
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	discovery "github.com/envoyproxy/go-control-plane/envoy/service/discovery/v3"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/kubernetes/fake"

	credentials "istio.io/istio/pilot/pkg/credentials/kube"
	"istio.io/istio/pilot/pkg/model"
	v3 "istio.io/istio/pilot/pkg/xds/v3"
	xdsfake "istio.io/istio/pilot/test/xds"
	"istio.io/istio/pilot/test/xdstest"
	"istio.io/istio/pkg/config/constants"
	"istio.io/istio/pkg/kube"
	"istio.io/istio/pkg/spiffe"
	"istio.io/istio/pkg/test/env"
)

// setVerifiedIdentity gives bufconn ADS connections the identity and cluster
// metadata that production gateways would carry over TLS, so SDS generation
// is authorized for them.
func setVerifiedIdentity(s *xdsfake.FakeDiscoveryServer) {
	for _, c := range s.Discovery.Clients() {
		p := c.Proxy()
		p.VerifiedIdentity = &spiffe.Identity{Namespace: "default"}
		if p.Metadata == nil {
			p.Metadata = &model.NodeMetadata{}
		}
		p.Metadata.ClusterID = constants.DefaultClusterName
	}
}

// Regression test for https://github.com/higress-group/higress/issues/5368
// (upstream: https://github.com/istio/istio/issues/57789).
// The SDS config dump must redact private keys in the dump output without
// mutating the resource objects shared with the xDS cache. Otherwise a gateway
// that (re)subscribes to SDS afterwards receives the "[redacted]" placeholder
// instead of the real private key and TLS handshakes start failing.
func TestConfigDumpDoesNotPolluteSDSCache(t *testing.T) {
	dumpSecret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "dump-cache-test",
			Namespace: "default",
		},
		Data: map[string][]byte{
			credentials.GenericScrtCert: []byte(readFile(filepath.Join(env.IstioSrc, "./tests/testdata/certs/default/cert-chain.pem"))),
			credentials.GenericScrtKey:  []byte(readFile(filepath.Join(env.IstioSrc, "./tests/testdata/certs/default/key.pem"))),
		},
	}
	s := xdsfake.NewFakeDiscoveryServer(t, xdsfake.FakeOptions{
		KubernetesObjects: []runtime.Object{dumpSecret},
		KubeClientModifier: func(c kube.Client) {
			cc := c.Kube().(*fake.Clientset)
			xdsfake.DisableAuthorizationForSecret(cc)
		},
	})

	// A gateway connects over ADS and subscribes to the secret; the server
	// caches the resource. The bufconn connection has no TLS identity, so
	// give the proxy a verified identity (same as production SDS would).
	ads := s.ConnectADS()
	ads.RequestResponseAck(t, &discovery.DiscoveryRequest{TypeUrl: v3.ClusterType})
	setVerifiedIdentity(s)
	resp := ads.RequestResponseAck(t, &discovery.DiscoveryRequest{
		TypeUrl:       v3.SecretType,
		ResourceNames: []string{"kubernetes://dump-cache-test"},
	})
	secrets := xdstest.ExtractTLSSecrets(t, resp.Resources)
	scrt, ok := secrets["kubernetes://dump-cache-test"]
	if !ok {
		t.Fatalf("expected SDS response to contain kubernetes://dump-cache-test, got %d resources", len(secrets))
	}
	originalKey := string(scrt.GetTlsCertificate().GetPrivateKey().GetInlineBytes())
	if originalKey == "" {
		t.Fatal("original private key is empty")
	}

	// istioctl proxy-status requests a per-type config dump (?types=sds), which
	// exercises the redaction path over the cached SDS resources.
	dumpReq, err := http.NewRequest(http.MethodGet, "/config_dump?proxyID=test.default&types=sds", nil)
	if err != nil {
		t.Fatal(err)
	}
	rec := httptest.NewRecorder()
	http.HandlerFunc(s.Discovery.ConfigDump).ServeHTTP(rec, dumpReq)
	if rec.Code != http.StatusOK {
		t.Fatalf("config dump returned %d: %s", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), "dump-cache-test") {
		t.Fatal("config dump did not include the subscribed secret; redaction path not exercised")
	}

	// A restarted gateway resubscribes to SDS and must still receive the
	// original private key, not the "[redacted]" placeholder.
	ads2 := s.ConnectADS()
	ads2.RequestResponseAck(t, &discovery.DiscoveryRequest{TypeUrl: v3.ClusterType})
	setVerifiedIdentity(s)
	resp2 := ads2.RequestResponseAck(t, &discovery.DiscoveryRequest{
		TypeUrl:       v3.SecretType,
		ResourceNames: []string{"kubernetes://dump-cache-test"},
	})
	secrets2 := xdstest.ExtractTLSSecrets(t, resp2.Resources)
	scrt2, ok := secrets2["kubernetes://dump-cache-test"]
	if !ok {
		t.Fatalf("expected resubscribe response to contain kubernetes://dump-cache-test, got %d resources", len(secrets2))
	}
	if key := string(scrt2.GetTlsCertificate().GetPrivateKey().GetInlineBytes()); key != originalKey {
		t.Errorf("SDS cache polluted by config dump: resubscribed gateway got private key %q instead of the original PEM", key)
	}
}
