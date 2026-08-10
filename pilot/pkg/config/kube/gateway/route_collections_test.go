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

package gateway

import (
	"strings"
	"testing"
	"time"

	istio "istio.io/api/networking/v1alpha3"
	"istio.io/istio/pkg/config"
	"istio.io/istio/pkg/kube/krt"
	"istio.io/istio/pkg/test"
)

func TestSelectOldestRoute(t *testing.T) {
	stop := test.NewStop(t)
	key := "default/gateway/tcp/*"
	baseVirtualServices := krt.NewStaticCollection[RouteWithKey](nil, []RouteWithKey{
		{
			Config: &config.Config{
				Meta: config.Meta{Name: "newer", Namespace: "default", CreationTimestamp: time.Unix(2, 0)},
				Spec: &istio.VirtualService{Hosts: []string{"newer"}},
			},
			Key: key,
		},
		{
			Config: &config.Config{
				Meta: config.Meta{Name: "older", Namespace: "default", CreationTimestamp: time.Unix(1, 0)},
				Spec: &istio.VirtualService{Hosts: []string{"older"}},
			},
			Key: key,
		},
	}, krt.WithStop(stop), krt.WithName("tcp-routes"))

	selected := selectOldestRoute(baseVirtualServices, krt.WithStop(stop), krt.WithName("selected-tcp-route"))
	selected.WaitUntilSynced(stop)
	got := selected.List()
	if len(got) != 1 {
		t.Fatalf("expected one selected VirtualService, got %d", len(got))
	}
	if got[0].Name != strings.ReplaceAll(key, "/", "~") {
		t.Fatalf("expected deterministic name %q, got %q", strings.ReplaceAll(key, "/", "~"), got[0].Name)
	}
	if hosts := got[0].Spec.(*istio.VirtualService).Hosts; len(hosts) != 1 || hosts[0] != "older" {
		t.Fatalf("expected oldest route to be selected, got hosts %v", hosts)
	}
}
