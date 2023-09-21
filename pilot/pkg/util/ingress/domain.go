package utils

import (
	"strings"
)

const (
	RootDomain            = "aliservice.com"
	NacosRootDomain       = ".nacos"
	ZookeeperRootDomain   = ".zookeeper"
	SharedNacosRootDomain = ".nacos-ext"
)

var RootDomains = [4]string{
	RootDomain,
	NacosRootDomain,
	ZookeeperRootDomain,
	SharedNacosRootDomain,
}

func HostShouldSkipValidation(domain string) bool {
	for _, rootDomain := range RootDomains {
		if strings.HasSuffix(domain, rootDomain) {
			return true
		}
	}

	return false
}
