package contracts_test

import (
	"testing"

	contracts "github.com/bare-metal-cloud/runner-contracts"
)

func TestReasonVocabularyValues(t *testing.T) {
	// The wire values are the contract; golden consumers match on these
	// exact strings.
	want := map[contracts.ReasonClass]contracts.Disposition{
		contracts.ReasonQuota:              contracts.DispositionFallback,
		contracts.ReasonMinutesCeiling:     contracts.DispositionHardFail,
		contracts.ReasonGate:               contracts.DispositionFallback,
		contracts.ReasonNoCapacity:         contracts.DispositionFallback,
		contracts.ReasonDispatchFailure:    contracts.DispositionFallback,
		contracts.ReasonPlatformTimeout:    contracts.DispositionPlatformFault,
		contracts.ReasonDiskPressure:       contracts.DispositionHardFail,
		contracts.ReasonCustomerConfig:     contracts.DispositionHardFail,
		contracts.ReasonCustomerCapability: contracts.DispositionFallback,
	}
	if len(want) != 9 {
		t.Fatalf("vocabulary is %d classes, want 9", len(want))
	}
	for class, disposition := range want {
		got, ok := contracts.DispositionFor(class)
		if !ok {
			t.Fatalf("class %q has no disposition; the class-to-disposition map must cover every class", class)
		}
		if got != disposition {
			t.Errorf("DispositionFor(%q) = %q, want %q", class, got, disposition)
		}
	}
}

func TestDispositionValues(t *testing.T) {
	want := map[contracts.Disposition]string{
		contracts.DispositionFallback:      "fallback",
		contracts.DispositionPlatformFault: "platform_fault",
		contracts.DispositionHardFail:      "hard_fail",
	}
	for disposition, wire := range want {
		if string(disposition) != wire {
			t.Errorf("disposition %q wire value is %q, want %q", disposition, string(disposition), wire)
		}
	}
}

func TestUnknownReasonClassHasNoDisposition(t *testing.T) {
	if _, ok := contracts.DispositionFor("mystery"); ok {
		t.Fatal("DispositionFor returned a disposition for an unknown class")
	}
}

func TestReasonValidate(t *testing.T) {
	if err := (contracts.Reason{Class: contracts.ReasonQuota, Message: "monthly minutes exhausted"}).Validate(); err != nil {
		t.Fatalf("valid reason refused: %v", err)
	}
	if err := (contracts.Reason{Class: "mystery", Message: "x"}).Validate(); err == nil {
		t.Fatal("unknown reason class accepted")
	}
	if err := (contracts.Reason{Class: contracts.ReasonQuota, Message: ""}).Validate(); err == nil {
		t.Fatal("a reason without a human message was accepted; every reason carries one")
	}
	if err := (contracts.Reason{Class: "", Message: "x"}).Validate(); err == nil {
		t.Fatal("empty reason class accepted")
	}
}
