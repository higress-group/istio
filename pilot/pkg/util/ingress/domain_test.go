package utils

import (
	"testing"

	. "github.com/onsi/gomega"
)

func TestHostShouldSkipValidation(t *testing.T) {
	cases := []struct {
		domain       string
		expectResult bool
	}{
		{
			domain:       "com.alibaba.charity.service.triple.FamilyCharityTripleService.1.0.0.TRI.tri.aliservice.com",
			expectResult: true,
		},
		{
			domain:       "providers:com.alibabacloud.hipstershop.checkoutserviceapi.service.CurrencyService:0.0.1:.DEFAULT-GROUP.public.nacos",
			expectResult: true,
		},
		{
			domain:       "test",
			expectResult: false,
		},
		{
			domain:       "test.com",
			expectResult: false,
		},
	}

	for _, c := range cases {
		t.Run("", func(t *testing.T) {
			g := NewWithT(t)
			g.Expect(HostShouldSkipValidation(c.domain)).To(Equal(c.expectResult))
		})
	}
}
