package aliext

import (
	envoyapi "github.com/envoyproxy/go-control-plane/envoy/config/listener/v3"

	"istio.io/istio/pilot/pkg/model"
	"istio.io/istio/pilot/pkg/networking"
	"istio.io/istio/pilot/pkg/networking/plugin"
)

// Plugin implements extension for LDS output in alibaba case.
type Plugin struct{}

// NewPlugin returns an instance of the extension plugin for alibaba case.
func NewPlugin() plugin.Plugin {
	return Plugin{}
}

func (p Plugin) OnOutboundListener(in *plugin.InputParams, mutable *networking.MutableObjects) error {
	if in.Node.Type == model.Router {
		// Support load balance within workers in per listener.
		mutable.Listener.ConnectionBalanceConfig = &envoyapi.Listener_ConnectionBalanceConfig{
			BalanceType: &envoyapi.Listener_ConnectionBalanceConfig_ExactBalance_{
				ExactBalance: &envoyapi.Listener_ConnectionBalanceConfig_ExactBalance{},
			},
		}
	}

	return nil
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
