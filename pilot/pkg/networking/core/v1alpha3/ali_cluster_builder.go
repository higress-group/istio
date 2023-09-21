package v1alpha3

import (
	"strings"

	cluster "github.com/envoyproxy/go-control-plane/envoy/config/cluster/v3"
	auth "github.com/envoyproxy/go-control-plane/envoy/extensions/transport_sockets/tls/v3"
	structpb "github.com/golang/protobuf/ptypes/struct"

	"istio.io/istio/pilot/pkg/networking/core/v1alpha3/loadbalancer"
)

const (
	AliTlsCipherSuites = "istiod.ingress.ali/tls-cipher-suites"

	AliTlsMinVersion = "istiod.ingress.ali/tls-min-version"

	AliTlsMaxVersion = "istiod.ingress.ali/tls-max-version"

	AliTlsTrustedChain = "istiod.ingress.ali/tls-trusted-chain"
)

type tlsAnnotationParams struct {
	trustedChain    *auth.CertificateValidationContext_TrustChainVerification
	tlsMaxParameter *auth.TlsParameters_TlsProtocol
	tlsMinParameter *auth.TlsParameters_TlsProtocol
	cipherSuites    []string
}

func getTlsParamsFromAnnotation(annotations map[string]string) *tlsAnnotationParams {
	extendParams := &tlsAnnotationParams{}
	hasParamFlag := false
	if tlsMaxParamterValue, ok := annotations[AliTlsMaxVersion]; ok {
		tlsMaxParameter, ok := auth.TlsParameters_TlsProtocol_value[tlsMaxParamterValue]
		if ok {
			hasParamFlag = true
			extendParams.tlsMaxParameter = auth.TlsParameters_TlsProtocol(tlsMaxParameter).Enum()
		}
	}

	if tlsMinParameterValue, ok := annotations[AliTlsMinVersion]; ok {
		tlsMinParameter, ok := auth.TlsParameters_TlsProtocol_value[tlsMinParameterValue]
		if ok {
			hasParamFlag = true
			extendParams.tlsMinParameter = auth.TlsParameters_TlsProtocol(tlsMinParameter).Enum()
		}
	}

	if trustedChainValue, ok := annotations[AliTlsTrustedChain]; ok {
		if trustedChain, ok := auth.CertificateValidationContext_TrustChainVerification_value[trustedChainValue]; ok {
			hasParamFlag = true
			extendParams.trustedChain = auth.CertificateValidationContext_TrustChainVerification(trustedChain).Enum()
		}
	}

	if cipherSuitesValue, ok := annotations[AliTlsCipherSuites]; ok {
		hasParamFlag = true
		extendParams.cipherSuites = strings.Split(cipherSuitesValue, ",")
	}

	if hasParamFlag {
		return extendParams
	}

	return nil
}

func addExtensionLoadBalanceMeta(cluster *cluster.Cluster, annotations map[string]string) {
	lbType := annotations[loadbalancer.AliIngressIstiodLoadBalanceAnnotation]
	if loadbalancer.IsExtensionLB(lbType) {
		im := getOrCreateIstioMetadata(cluster)
		im.Fields[loadbalancer.AliIngressIstiodLoadBalanceAnnotation] = &structpb.Value{
			Kind: &structpb.Value_StringValue{
				StringValue: lbType,
			},
		}
	}
}

func extractExtensionLoadBalanceMeta(cluster *cluster.Cluster) string {
	im := getOrCreateIstioMetadata(cluster)
	if value, exist := im.Fields[loadbalancer.AliIngressIstiodLoadBalanceAnnotation]; exist {
		return value.GetStringValue()
	}
	return ""
}
