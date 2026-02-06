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

package core

import (
	networking "istio.io/api/networking/v1alpha3"
	istionetworking "istio.io/istio/pilot/pkg/networking"
)

func patchContextForListenerClass(class istionetworking.ListenerClass) networking.EnvoyFilter_PatchContext {
	switch class {
	case istionetworking.ListenerClassGateway:
		return networking.EnvoyFilter_GATEWAY
	case istionetworking.ListenerClassSidecarInbound:
		return networking.EnvoyFilter_SIDECAR_INBOUND
	case istionetworking.ListenerClassSidecarOutbound:
		return networking.EnvoyFilter_SIDECAR_OUTBOUND
	default:
		return networking.EnvoyFilter_ANY
	}
}
