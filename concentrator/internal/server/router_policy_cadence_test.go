package server

import (
	"testing"
	"time"
)

func TestPolicyFallbackIsSlowerThanCircuitExpiryTick(t *testing.T) {
	if policyFallbackInterval < 30*time.Second {
		t.Fatalf("policy fallback interval %s would restore a hot database poll", policyFallbackInterval)
	}
	if policyFallbackInterval%time.Second != 0 {
		t.Fatalf("policy fallback interval should be an integral number of circuit ticks: %s", policyFallbackInterval)
	}
}
