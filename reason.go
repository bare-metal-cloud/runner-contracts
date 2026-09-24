package contracts

// ReasonClass is the typed refusal and failure vocabulary. The wire
// values are the contract: the engine's fallback switch, the pool's
// refusals, and the ledger's rendering all match on these strings.
type ReasonClass string

// The reason classes. Each carries a human message wherever it travels
// (the message is required by Reason.Validate).
//
//	quota             — the org's admission quota is exhausted
//	minutes_ceiling   — the monthly metered-minutes ceiling is reached
//	gate              — the hosted-runner feature gate is off
//	no_capacity       — cold provisioning found no capacity
//	dispatch_failure  — the pool could not deliver the job (platform fault)
//	platform_timeout  — the CP watchdog breached (platform fault)
//	disk_pressure     — the job exceeded its disk cap
//	customer_config   — a customer-side configuration failure
//	customer_capability — the platform removed the capability
const (
	ReasonQuota              ReasonClass = "quota"
	ReasonMinutesCeiling     ReasonClass = "minutes_ceiling"
	ReasonGate               ReasonClass = "gate"
	ReasonNoCapacity         ReasonClass = "no_capacity"
	ReasonDispatchFailure    ReasonClass = "dispatch_failure"
	ReasonPlatformTimeout    ReasonClass = "platform_timeout"
	ReasonDiskPressure       ReasonClass = "disk_pressure"
	ReasonCustomerConfig     ReasonClass = "customer_config"
	ReasonCustomerCapability ReasonClass = "customer_capability"
)

// Reason is a refusal or failure with its human message.
type Reason struct {
	Class   ReasonClass `json:"class"`
	Message string      `json:"message"`
}

// Validate checks the reason's shape: the class must be part of the
// vocabulary and the human message must be present.
func (r Reason) Validate() error {
	if r.Class == "" {
		return ValidationError{Field: "reason.class", Rule: RuleReasonClass, Message: "reason class is required"}
	}
	if !isReasonClass(r.Class) {
		return ValidationError{Field: "reason.class", Rule: RuleReasonClass, Message: "unknown reason class " + string(r.Class)}
	}
	if r.Message == "" {
		return ValidationError{Field: "reason.message", Rule: RuleReasonMessage, Message: "every reason carries a human message"}
	}
	return nil
}

func isReasonClass(c ReasonClass) bool {
	switch c {
	case ReasonQuota, ReasonMinutesCeiling, ReasonGate, ReasonNoCapacity,
		ReasonDispatchFailure, ReasonPlatformTimeout, ReasonDiskPressure,
		ReasonCustomerConfig, ReasonCustomerCapability:
		return true
	}
	return false
}

// Disposition is the engine behavior a reason class dictates when a
// hosted job is refused or lost.
type Disposition string

const (
	// DispositionFallback means the engine falls back to Tier P (the
	// customer's in-cluster runner): the job still runs, on the
	// customer's own compute.
	DispositionFallback Disposition = "fallback"

	// DispositionPlatformFault means the engine falls back to Tier P
	// the same way, AND the run renders as a platform-fault ledger
	// fact, never a customer failure. Platform faults also never burn
	// the customer's prepaid minutes ceiling.
	DispositionPlatformFault Disposition = "platform_fault"

	// DispositionHardFail means the run fails with no fallback: the
	// job does not silently reroute to Tier P.
	DispositionHardFail Disposition = "hard_fail"
)

// DispositionFor maps a reason class to the engine behavior it
// dictates. The map covers every class in the vocabulary.
//
//	Dispositions of record (the fold from the Tier H review loops):
//
//	- FALLBACK — no_capacity, quota, dispatch_failure,
//	  customer_capability: the engine falls back to Tier P.
//	  Dispatch-failure additionally renders as a platform-fault ledger
//	  fact (the pool could not deliver; that is never the customer's
//	  failure). Capability refusals fall back because the platform
//	  removed the capability, not the customer.
//
//	- PLATFORM-FAULT — platform_timeout: the CP watchdog breached the
//	  heartbeat deadline or the platform maximum wall-clock, or drift
//	  detection lost a bound VM. The engine falls back to Tier P the
//	  same way and the run renders as a platform-fault ledger fact.
//	  The class is kept distinct from customer timeouts so a runaway
//	  customer build is never classed as BMC losing hardware.
//
//	- HARD-FAIL — minutes_ceiling, customer_config, disk_pressure:
//	  the run fails with no fallback. A minutes ceiling that silently
//	  reroutes builds is not a ceiling; a customer-configuration
//	  failure (such as an unresolvable secret reference) cannot
//	  succeed on Tier P until fixed; disk pressure means the job
//	  exceeded its own declared cap.
//
//	  The gate class also falls back: a gated feature refusal means
//	  hosted execution is unavailable for the (org, project), and the
//	  customer's pipeline still runs on its existing tiers. (The
//	  plan's class-to-disposition paragraph does not bucket gate
//	  explicitly; fallback is the only posture consistent with the
//	  other platform-side refusals. Flagged in the TH.1 PR.)
func DispositionFor(class ReasonClass) (Disposition, bool) {
	switch class {
	case ReasonNoCapacity, ReasonQuota, ReasonDispatchFailure,
		ReasonCustomerCapability, ReasonGate:
		return DispositionFallback, true
	case ReasonPlatformTimeout:
		return DispositionPlatformFault, true
	case ReasonMinutesCeiling, ReasonCustomerConfig, ReasonDiskPressure:
		return DispositionHardFail, true
	}
	return "", false
}
