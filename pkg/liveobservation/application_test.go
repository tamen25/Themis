package liveobservation

import (
	"testing"
	"time"
)

func TestFixtureHoldWithoutIndependentApplicationEffectCannotCorroborate(t *testing.T) {
	reg, records, policy, key := protocolFixture(t)
	now, _ := UTC(reg.NotBefore)
	for i := range records {
		if records[i].Phase == "intervention" {
			p := &records[i].Probes[2]
			p.CompletedNS = p.StartedNS + int64(10*time.Millisecond)
		}
	}
	records = reseal(records, key)
	f, _ := Analyze(reg, stream(records), &policy, now)
	if f.SignatureChain != "VALID" || f.WitnessTrust != "TRUSTED" || f.EffectSamples != 0 || f.Status == "OBSERVED_AND_CORRELATED" || f.ApplicationVerdict == "PASS" {
		t.Fatal("fixture hold was confused with measured application effect", f)
	}
}

func TestApplicationTimingThresholdUsesInclusiveCeiling(t *testing.T) {
	for _, over := range []int64{0, 1} {
		t.Run(map[int64]string{0: "equal", 1: "one-nanosecond-over"}[over], func(t *testing.T) {
			reg, records, policy, key := protocolFixture(t)
			reg.MaxApplicationMillis = 50
			reg = SignRegistration(reg, key)
			for i := range records {
				records[i].RegistrationDigest = RegistrationDigest(reg)
				if records[i].Phase == "intervention" {
					p := &records[i].Probes[2]
					p.CompletedNS = p.StartedNS + int64(50*time.Millisecond) + over
				}
			}
			records = reseal(records, key)
			now, _ := UTC(reg.NotBefore)
			f, _ := Analyze(reg, stream(records), &policy, now)
			want := "PASS"
			if over > 0 {
				want = "FAIL"
			}
			if f.ApplicationVerdict != want || f.Status != "OBSERVED_AND_CORRELATED" {
				t.Fatal("application ceiling comparison", over, f)
			}
		})
	}
}

func TestFixtureClockCannotClaimLongerHoldThanWitnessElapsed(t *testing.T) {
	reg, records, policy, key := protocolFixture(t)
	now, _ := UTC(reg.NotBefore)
	records[5].Probes[1].CompletedNS = records[5].Probes[1].StartedNS + int64(150*time.Millisecond)
	records = reseal(records, key)
	f, _ := Analyze(reg, stream(records), &policy, now)
	if f.Status != "OBSERVATIONS_CONTRADICTORY" {
		t.Fatal("contradictory fixture/client clock claim accepted", f)
	}
}
