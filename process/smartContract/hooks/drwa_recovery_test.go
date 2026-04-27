package hooks

import (
	"bytes"
	"testing"
)

func TestInspectDRWARecoveryStateReportsInSync(t *testing.T) {
	t.Parallel()

	adapter := newMockDRWASyncStateAdapter()
	adapter.tokenVersions["CARBON-1"] = 3
	adapter.tokenBodies["CARBON-1"] = []byte(`{"regulated":true}`)
	adapter.holderVersions["CARBON-1|erd1a"] = 2
	adapter.holderBodies["CARBON-1|erd1a"] = []byte(`{"kyc":"approved"}`)

	manifest := &drwaRecoveryManifest{
		TokenID:       "CARBON-1",
		PolicyVersion: 3,
		PolicyBody:    []byte(`{"regulated":true}`),
		Holders: []drwaRecoveryHolder{
			{Address: "erd1a", Version: 2, Body: []byte(`{"kyc":"approved"}`)},
		},
	}

	report, err := inspectDRWARecoveryState(adapter, manifest, nil)
	if err != nil {
		t.Fatalf("inspect recovery: %v", err)
	}
	if len(report.Findings) != 1 || report.Findings[0].Status != drwaRecoveryStatusInSync {
		t.Fatalf("expected in-sync finding, got %+v", report.Findings)
	}
	if report.RequiresSafeMode {
		t.Fatalf("did not expect safe mode for in-sync report")
	}
}

func TestInspectDRWARecoveryStateReportsCriticalPolicyDrift(t *testing.T) {
	t.Parallel()

	adapter := newMockDRWASyncStateAdapter()
	adapter.tokenVersions["CARBON-1"] = 2
	adapter.tokenBodies["CARBON-1"] = []byte(`{"regulated":false}`)

	manifest := &drwaRecoveryManifest{
		TokenID:       "CARBON-1",
		PolicyVersion: 3,
		PolicyBody:    []byte(`{"regulated":true}`),
		Holders: []drwaRecoveryHolder{
			{Address: "erd1a", Version: 1, Body: []byte(`{"kyc":"approved"}`)},
		},
	}

	report, err := inspectDRWARecoveryState(adapter, manifest, nil)
	if err != nil {
		t.Fatalf("inspect recovery: %v", err)
	}
	if !report.RequiresSafeMode {
		t.Fatalf("expected safe mode for policy drift")
	}
	if len(report.Findings) == 0 {
		t.Fatalf("expected findings")
	}
}

func TestInspectDRWARecoveryStateReportsHolderBodyDrift(t *testing.T) {
	t.Parallel()

	adapter := newMockDRWASyncStateAdapter()
	adapter.tokenVersions["CARBON-1"] = 3
	adapter.tokenBodies["CARBON-1"] = []byte(`{"regulated":true}`)
	adapter.holderVersions["CARBON-1|erd1a"] = 2
	adapter.holderBodies["CARBON-1|erd1a"] = []byte(`{"kyc":"pending"}`)

	manifest := &drwaRecoveryManifest{
		TokenID:       "CARBON-1",
		PolicyVersion: 3,
		PolicyBody:    []byte(`{"regulated":true}`),
		Holders: []drwaRecoveryHolder{
			{Address: "erd1a", Version: 2, Body: []byte(`{"kyc":"approved"}`)},
		},
	}

	report, err := inspectDRWARecoveryState(adapter, manifest, nil)
	if err != nil {
		t.Fatalf("inspect recovery: %v", err)
	}
	if len(report.Findings) != 1 || report.Findings[0].Status != drwaRecoveryStatusHolderBodyDrift {
		t.Fatalf("unexpected findings: %+v", report.Findings)
	}
	if report.RequiresSafeMode {
		t.Fatalf("holder body drift alone should not force safe mode")
	}
}

func TestInspectDRWARecoveryStateReportsUnexpectedMirrorAndMarksNonRepairable(t *testing.T) {
	t.Parallel()

	adapter := newMockDRWASyncStateAdapter()
	adapter.tokenVersions["CARBON-1"] = 3
	adapter.tokenBodies["CARBON-1"] = []byte(`{"regulated":true}`)
	adapter.holderVersions["CARBON-1|erd1a"] = 2
	adapter.holderBodies["CARBON-1|erd1a"] = []byte(`{"kyc":"approved"}`)
	adapter.ensureHolderIndexed("CARBON-1", "erd1a")
	adapter.holderVersions["CARBON-1|erd1ghost"] = 5
	adapter.holderBodies["CARBON-1|erd1ghost"] = []byte(`{"kyc":"approved"}`)
	adapter.ensureHolderIndexed("CARBON-1", "erd1ghost")

	manifest := &drwaRecoveryManifest{
		TokenID:       "CARBON-1",
		PolicyVersion: 3,
		PolicyBody:    []byte(`{"regulated":true}`),
		Holders: []drwaRecoveryHolder{
			{Address: "erd1a", Version: 2, Body: []byte(`{"kyc":"approved"}`)},
		},
	}

	report, err := inspectDRWARecoveryState(adapter, manifest, nil)
	if err != nil {
		t.Fatalf("inspect recovery: %v", err)
	}
	if !report.Repairable {
		t.Fatalf("unexpected extra mirror should remain repairable through governed cleanup")
	}
	if len(report.Findings) != 1 || report.Findings[0].Status != drwaRecoveryStatusUnexpectedHolderMirror {
		t.Fatalf("unexpected findings: %+v", report.Findings)
	}
}

func TestInspectDRWARecoveryStateMarksCorruptMirrorNonRepairable(t *testing.T) {
	t.Parallel()

	adapter := newMockDRWASyncStateAdapter()
	adapter.tokenVersions["CARBON-1"] = 3
	adapter.tokenBodies["CARBON-1"] = []byte(`{"regulated":true}`)
	adapter.holderVersions["CARBON-1|erd1a"] = 2
	adapter.holderBodies["CARBON-1|erd1a"] = nil

	manifest := &drwaRecoveryManifest{
		TokenID:       "CARBON-1",
		PolicyVersion: 3,
		PolicyBody:    []byte(`{"regulated":true}`),
		Holders: []drwaRecoveryHolder{
			{Address: "erd1a", Version: 2, Body: []byte(`{"kyc":"approved"}`)},
		},
	}

	report, err := inspectDRWARecoveryState(adapter, manifest, nil)
	if err != nil {
		t.Fatalf("inspect recovery: %v", err)
	}
	if report.Repairable {
		t.Fatalf("expected corrupt mirror report to be non-repairable")
	}
	if len(report.Findings) != 1 || report.Findings[0].Status != drwaRecoveryStatusHolderMirrorCorrupt {
		t.Fatalf("unexpected findings: %+v", report.Findings)
	}
}

func TestBuildDRWARecoveryEnvelopeReturnsNoopForInSync(t *testing.T) {
	t.Parallel()

	envelope, err := buildDRWARecoveryEnvelope(&drwaRecoveryManifest{
		TokenID:       "CARBON-1",
		PolicyVersion: 1,
		PolicyBody:    []byte(`{"regulated":true}`),
	}, &drwaRecoveryReport{
		TokenID: "CARBON-1",
		Findings: []drwaRecoveryFinding{{
			Status:          drwaRecoveryStatusInSync,
			TokenID:         "CARBON-1",
			ExpectedVersion: 1,
			ObservedVersion: 1,
		}},
		Repairable: true,
	})
	if err != nil {
		t.Fatalf("build recovery envelope: %v", err)
	}
	if len(envelope.Operations) != 0 {
		t.Fatalf("expected no-op envelope, got %d operations", len(envelope.Operations))
	}
	if !envelope.Noop {
		t.Fatalf("expected typed noop recovery envelope")
	}
	expectedHash, err := computeDRWASyncHash(drwaSyncCallerRecoveryAdmin, nil)
	if err != nil {
		t.Fatalf("compute noop hash: %v", err)
	}
	if !bytes.Equal(envelope.PayloadHash, expectedHash) {
		t.Fatalf("unexpected noop payload hash: got %x want %x", envelope.PayloadHash, expectedHash)
	}
}

func TestBuildDRWARecoveryEnvelopeRejectsUnexpectedHolderConflict(t *testing.T) {
	t.Parallel()

	_, err := buildDRWARecoveryEnvelope(&drwaRecoveryManifest{
		TokenID:       "CARBON-1",
		PolicyVersion: 1,
		PolicyBody:    []byte(`{"regulated":true}`),
		Holders: []drwaRecoveryHolder{
			{Address: "erd1a", Version: 1, Body: []byte(`{"kyc":"approved"}`)},
		},
	}, &drwaRecoveryReport{
		TokenID: "CARBON-1",
		Findings: []drwaRecoveryFinding{{
			Status:          drwaRecoveryStatusUnexpectedHolderMirror,
			TokenID:         "CARBON-1",
			Holder:          "erd1a",
			ObservedVersion: 1,
		}},
		Repairable: true,
	})
	if err != errDRWARecoveryUnexpectedHolderConflict {
		t.Fatalf("expected unexpected holder conflict, got %v", err)
	}
}

func TestBuildDRWARecoveryEnvelopeBuildsRepairBatch(t *testing.T) {
	t.Parallel()

	manifest := &drwaRecoveryManifest{
		TokenID:       "CARBON-1",
		PolicyVersion: 3,
		PolicyBody:    []byte(`{"regulated":true}`),
		Holders: []drwaRecoveryHolder{
			{Address: "erd1b", Version: 2, Body: []byte(`{"kyc":"approved"}`)},
			{Address: "erd1a", Version: 1, Body: []byte(`{"kyc":"approved"}`)},
		},
	}

	envelope, err := buildDRWARecoveryEnvelope(manifest, &drwaRecoveryReport{
		TokenID: "CARBON-1",
		Findings: []drwaRecoveryFinding{{
			Status:          drwaRecoveryStatusHolderMirrorMissing,
			TokenID:         "CARBON-1",
			Holder:          "erd1a",
			ExpectedVersion: 1,
		}},
		Repairable: true,
	})
	if err != nil {
		t.Fatalf("build recovery envelope: %v", err)
	}
	if len(envelope.Operations) != 3 {
		t.Fatalf("expected repair operations, got %d", len(envelope.Operations))
	}
	if envelope.Operations[1].Holder != "erd1a" || envelope.Operations[2].Holder != "erd1b" {
		t.Fatalf("holders not sorted in recovery envelope: %+v", envelope.Operations)
	}
}

func TestBuildDRWARecoveryEnvelopeAddsCleanupDeleteOperations(t *testing.T) {
	t.Parallel()

	manifest := &drwaRecoveryManifest{
		TokenID:       "CARBON-1",
		PolicyVersion: 3,
		PolicyBody:    []byte(`{"regulated":true}`),
		Holders: []drwaRecoveryHolder{
			{Address: "erd1a", Version: 1, Body: []byte(`{"kyc":"approved"}`)},
		},
	}

	envelope, err := buildDRWARecoveryEnvelope(manifest, &drwaRecoveryReport{
		TokenID: "CARBON-1",
		Findings: []drwaRecoveryFinding{
			{
				Status:          drwaRecoveryStatusUnexpectedHolderMirror,
				TokenID:         "CARBON-1",
				Holder:          "erd1ghost",
				ObservedVersion: 5,
			},
		},
		Repairable: true,
	})
	if err != nil {
		t.Fatalf("build recovery envelope: %v", err)
	}

	foundDelete := false
	for _, operation := range envelope.Operations {
		if operation.OperationType == drwaSyncOpHolderMirrorDelete {
			foundDelete = true
			if operation.Holder != "erd1ghost" || operation.Version != 6 {
				t.Fatalf("unexpected delete operation: %+v", operation)
			}
		}
	}
	if !foundDelete {
		t.Fatalf("expected cleanup delete operation")
	}
}

func TestApplyDRWARecoveryEnvelopeRollsBackAfterPartialProgress(t *testing.T) {
	t.Parallel()

	adapter := newMockDRWASyncStateAdapter()
	adapter.tokenVersions["CARBON-1"] = 3
	adapter.tokenBodies["CARBON-1"] = []byte(`{"regulated":false}`)
	adapter.holderVersions["CARBON-1|erd1legacy"] = 2
	adapter.holderBodies["CARBON-1|erd1legacy"] = []byte(`{"kyc":"approved"}`)
	adapter.ensureHolderIndexed("CARBON-1", "erd1legacy")

	manifest := &drwaRecoveryManifest{
		TokenID:       "CARBON-1",
		PolicyVersion: 4,
		PolicyBody:    []byte(`{"regulated":true}`),
		Holders: []drwaRecoveryHolder{
			{Address: "erd1a", Version: 1, Body: []byte(`{"kyc":"approved"}`)},
			{Address: "erd1b", Version: 1, Body: []byte(`{"kyc":"approved"}`)},
		},
	}

	report, err := inspectDRWARecoveryState(adapter, manifest, nil)
	if err != nil {
		t.Fatalf("inspect recovery state: %v", err)
	}

	envelope, err := buildDRWARecoveryEnvelope(manifest, report)
	if err != nil {
		t.Fatalf("build recovery envelope: %v", err)
	}
	envelope.RecoveryScope = []string{manifest.TokenID}
	envelope.PreRecoveryStateHash = nil

	callCount := 0
	adapter.putHolderHook = func(tokenID, holder string, version uint64, body []byte) error {
		callCount++
		if callCount == 2 {
			return errDRWATestFailPut
		}
		key := tokenID + "|" + holder
		adapter.holderVersions[key] = version
		adapter.holderBodies[key] = body
		adapter.ensureHolderIndexed(tokenID, holder)
		return nil
	}

	_, err = applyDRWASyncEnvelope(adapter, envelope, drwaSyncMaxOperations, testDRWACallerAddress(drwaSyncCallerRecoveryAdmin))
	if err == nil {
		t.Fatalf("expected recovery apply failure")
	}
	if !adapter.rolledBack {
		t.Fatalf("expected rollback after partial recovery progress")
	}

	if adapter.tokenVersions["CARBON-1"] != 3 || !bytes.Equal(adapter.tokenBodies["CARBON-1"], []byte(`{"regulated":false}`)) {
		t.Fatalf("expected token policy restored after rollback")
	}
	if _, exists := adapter.holderVersions["CARBON-1|erd1a"]; exists {
		t.Fatalf("expected newly repaired holder a to be absent after rollback")
	}
	if _, exists := adapter.holderVersions["CARBON-1|erd1b"]; exists {
		t.Fatalf("expected newly repaired holder b to be absent after rollback")
	}
	if adapter.holderVersions["CARBON-1|erd1legacy"] != 2 || !bytes.Equal(adapter.holderBodies["CARBON-1|erd1legacy"], []byte(`{"kyc":"approved"}`)) {
		t.Fatalf("expected legacy holder mirror restored after rollback")
	}
}

// ---------------------------------------------------------------------------
// computeRecoveryManifestHash tests (0% → covered)
// ---------------------------------------------------------------------------

func TestComputeRecoveryManifestHashDeterministic(t *testing.T) {
	t.Parallel()

	manifest := &drwaRecoveryManifest{
		TokenID:       "CARBON-1",
		PolicyVersion: 3,
		PolicyBody:    []byte(`{"regulated":true}`),
		Holders: []drwaRecoveryHolder{
			{Address: "erd1a", Version: 1, Body: []byte(`{"kyc":"approved"}`)},
			{Address: "erd1b", Version: 2, Body: []byte(`{"kyc":"approved"}`)},
		},
	}

	hash1, err := computeRecoveryManifestHash(manifest)
	if err != nil {
		t.Fatalf("first hash: %v", err)
	}
	hash2, err := computeRecoveryManifestHash(manifest)
	if err != nil {
		t.Fatalf("second hash: %v", err)
	}
	if !bytes.Equal(hash1, hash2) {
		t.Fatalf("hash not deterministic: %x vs %x", hash1, hash2)
	}
	if len(hash1) == 0 {
		t.Fatal("expected non-empty hash")
	}
}

func TestComputeRecoveryManifestHashSortedHolders(t *testing.T) {
	t.Parallel()

	manifest1 := &drwaRecoveryManifest{
		TokenID:       "CARBON-1",
		PolicyVersion: 1,
		PolicyBody:    []byte(`{}`),
		Holders: []drwaRecoveryHolder{
			{Address: "erd1z", Version: 1, Body: []byte(`{}`)},
			{Address: "erd1a", Version: 1, Body: []byte(`{}`)},
		},
	}
	manifest2 := &drwaRecoveryManifest{
		TokenID:       "CARBON-1",
		PolicyVersion: 1,
		PolicyBody:    []byte(`{}`),
		Holders: []drwaRecoveryHolder{
			{Address: "erd1a", Version: 1, Body: []byte(`{}`)},
			{Address: "erd1z", Version: 1, Body: []byte(`{}`)},
		},
	}

	hash1, err := computeRecoveryManifestHash(manifest1)
	if err != nil {
		t.Fatalf("hash1: %v", err)
	}
	hash2, err := computeRecoveryManifestHash(manifest2)
	if err != nil {
		t.Fatalf("hash2: %v", err)
	}
	if !bytes.Equal(hash1, hash2) {
		t.Fatalf("different holder order should produce same hash: %x vs %x", hash1, hash2)
	}
}

func TestComputeRecoveryManifestHashDifferentManifests(t *testing.T) {
	t.Parallel()

	manifest1 := &drwaRecoveryManifest{
		TokenID:       "CARBON-1",
		PolicyVersion: 1,
		PolicyBody:    []byte(`{"a":1}`),
		Holders: []drwaRecoveryHolder{
			{Address: "erd1a", Version: 1, Body: []byte(`{}`)},
		},
	}
	manifest2 := &drwaRecoveryManifest{
		TokenID:       "CARBON-2",
		PolicyVersion: 1,
		PolicyBody:    []byte(`{"a":1}`),
		Holders: []drwaRecoveryHolder{
			{Address: "erd1a", Version: 1, Body: []byte(`{}`)},
		},
	}

	hash1, _ := computeRecoveryManifestHash(manifest1)
	hash2, _ := computeRecoveryManifestHash(manifest2)
	if bytes.Equal(hash1, hash2) {
		t.Fatal("different manifests should produce different hashes")
	}
}

// ---------------------------------------------------------------------------
// sanitizeDRWARecoveryManifest tests (0% → covered)
// ---------------------------------------------------------------------------

func TestSanitizeDRWARecoveryManifestTrimsWhitespace(t *testing.T) {
	t.Parallel()

	manifest := &drwaRecoveryManifest{
		TokenID:       "  CARBON-1  ",
		PolicyVersion: 1,
		PolicyBody:    []byte(`{}`),
		Holders: []drwaRecoveryHolder{
			{Address: "  erd1a  ", Version: 1, Body: []byte(`{}`)},
			{Address: "\terd1b\n", Version: 2, Body: []byte(`{}`)},
		},
	}

	sanitizeDRWARecoveryManifest(manifest)

	if manifest.TokenID != "CARBON-1" {
		t.Fatalf("expected trimmed token ID, got %q", manifest.TokenID)
	}
	if manifest.Holders[0].Address != "erd1a" {
		t.Fatalf("expected trimmed holder 0, got %q", manifest.Holders[0].Address)
	}
	if manifest.Holders[1].Address != "erd1b" {
		t.Fatalf("expected trimmed holder 1, got %q", manifest.Holders[1].Address)
	}
}

func TestSanitizeDRWARecoveryManifestNilSafe(t *testing.T) {
	t.Parallel()

	// Must not panic on nil.
	sanitizeDRWARecoveryManifest(nil)
}

func TestSanitizeDRWARecoveryManifestNoHolders(t *testing.T) {
	t.Parallel()

	manifest := &drwaRecoveryManifest{
		TokenID:       " TOKEN ",
		PolicyVersion: 1,
		PolicyBody:    []byte(`{}`),
	}
	sanitizeDRWARecoveryManifest(manifest)
	if manifest.TokenID != "TOKEN" {
		t.Fatalf("expected trimmed token ID, got %q", manifest.TokenID)
	}
}

func TestMarshalDRWARecoveryEvidence(t *testing.T) {
	t.Parallel()

	payload, err := marshalDRWARecoveryEvidence(&drwaRecoveryReport{
		TokenID: "CARBON-1",
		Findings: []drwaRecoveryFinding{{
			Status:          drwaRecoveryStatusHolderMirrorMissing,
			TokenID:         "CARBON-1",
			Holder:          "erd1a",
			ExpectedVersion: 1,
		}},
		Repairable: true,
	})
	if err != nil {
		t.Fatalf("marshal evidence: %v", err)
	}
	if len(payload) == 0 {
		t.Fatalf("expected evidence payload")
	}
}

func TestPersistDRWARecoveryEvidence(t *testing.T) {
	t.Parallel()

	adapter := newMockDRWASyncStateAdapter()
	report := &drwaRecoveryReport{
		TokenID: "CARBON-1",
		Findings: []drwaRecoveryFinding{{
			Status:          drwaRecoveryStatusHolderMirrorMissing,
			TokenID:         "CARBON-1",
			Holder:          "erd1a",
			ExpectedVersion: 1,
		}},
		Repairable: true,
	}

	err := persistDRWARecoveryEvidence(adapter, report)
	if err != nil {
		t.Fatalf("persist evidence: %v", err)
	}

	payload := adapter.recoveryEvidence["CARBON-1"]
	if len(payload) == 0 {
		t.Fatalf("expected persisted recovery evidence")
	}
}
