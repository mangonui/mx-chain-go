package hooks

import "testing"

// NOTE: This test must NOT use t.Parallel() — it mutates shared package-level metric counters.
func TestApplyDRWASyncEnvelopeRecordsUnauthorizedCallerMetric(t *testing.T) {
	resetDRWAMetrics()
	adapter := newMockDRWASyncStateAdapter()
	envelope := &drwaSyncEnvelope{
		CallerDomain: "random_caller",
		Operations: []drwaSyncOperation{{
			OperationType: drwaSyncOpTokenPolicy,
			TokenID:       "CARBON-1",
			Version:       1,
			Body:          []byte(`{}`),
		}},
	}
	hash, _ := computeDRWASyncHash(envelope.CallerDomain, envelope.Operations)
	envelope.PayloadHash = hash

	_, err := applyDRWASyncEnvelope(adapter, envelope, 16, []byte("random_caller"))
	if err == nil {
		t.Fatalf("expected unauthorized caller rejection")
	}

	metrics := snapshotDRWAMetrics()
	if metrics[drwaMetricSyncUnauthorizedCaller] != 1 {
		t.Fatalf("expected unauthorized caller metric, got %+v", metrics)
	}
	if metrics[drwaMetricSyncApplyFailure] != 1 {
		t.Fatalf("expected sync apply failure metric, got %+v", metrics)
	}
}

// NOTE: This test must NOT use t.Parallel() — it mutates shared package-level metric counters.
func TestApplyDRWASyncEnvelopeRecordsHashMismatchMetric(t *testing.T) {
	resetDRWAMetrics()
	adapter := newMockDRWASyncStateAdapter()
	envelope := &drwaSyncEnvelope{
		CallerDomain: drwaSyncCallerPolicyRegistry,
		PayloadHash:  []byte("wrong"),
		Operations: []drwaSyncOperation{{
			OperationType: drwaSyncOpTokenPolicy,
			TokenID:       "CARBON-1",
			Version:       1,
			Body:          []byte(`{}`),
		}},
	}

	_, err := applyDRWASyncEnvelope(adapter, envelope, 16, testDRWACallerAddress(drwaSyncCallerPolicyRegistry))
	if err == nil {
		t.Fatalf("expected hash mismatch rejection")
	}

	metrics := snapshotDRWAMetrics()
	if metrics[drwaMetricSyncHashMismatch] != 1 {
		t.Fatalf("expected hash mismatch metric, got %+v", metrics)
	}
	if metrics[drwaMetricSyncApplyFailure] != 1 {
		t.Fatalf("expected sync apply failure metric, got %+v", metrics)
	}
}

// NOTE: This test must NOT use t.Parallel() — it mutates shared package-level metric counters.
func TestApplyDRWASyncEnvelopeRecordsSuccessMetric(t *testing.T) {
	resetDRWAMetrics()
	adapter := newMockDRWASyncStateAdapter()
	envelope := &drwaSyncEnvelope{
		CallerDomain: drwaSyncCallerPolicyRegistry,
		Operations: []drwaSyncOperation{{
			OperationType: drwaSyncOpTokenPolicy,
			TokenID:       "CARBON-1",
			Version:       1,
			Body:          []byte(`{}`),
		}},
	}
	hash, _ := computeDRWASyncHash(envelope.CallerDomain, envelope.Operations)
	envelope.PayloadHash = hash

	_, err := applyDRWASyncEnvelope(adapter, envelope, 16, testDRWACallerAddress(drwaSyncCallerPolicyRegistry))
	if err != nil {
		t.Fatalf("expected successful sync apply, got %v", err)
	}

	metrics := snapshotDRWAMetrics()
	if metrics[drwaMetricSyncApplySuccess] != 1 {
		t.Fatalf("expected sync apply success metric, got %+v", metrics)
	}
}

// NOTE: This test must NOT use t.Parallel() — it mutates shared package-level metric counters.
func TestValidateDRWASyncVersionRecordsReplayMetric(t *testing.T) {
	resetDRWAMetrics()
	err := validateDRWASyncVersion(2, 2)
	if err == nil {
		t.Fatalf("expected replay conflict")
	}

	metrics := snapshotDRWAMetrics()
	if metrics[drwaMetricSyncReplayRejected] != 1 {
		t.Fatalf("expected replay rejection metric, got %+v", metrics)
	}
}

// NOTE: This test must NOT use t.Parallel() — it mutates shared package-level metric counters.
func TestInspectDRWARecoveryStateRecordsSafeModeAndNonRepairableMetrics(t *testing.T) {
	resetDRWAMetrics()
	adapter := newMockDRWASyncStateAdapter()
	adapter.tokenVersions["CARBON-1"] = 2
	adapter.tokenBodies["CARBON-1"] = []byte(`{"regulated":false}`)
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

	_, err := inspectDRWARecoveryState(adapter, manifest, nil)
	if err != nil {
		t.Fatalf("inspect recovery: %v", err)
	}

	metrics := snapshotDRWAMetrics()
	if metrics[drwaMetricRecoverySafeModeReport] != 1 {
		t.Fatalf("expected safe-mode metric, got %+v", metrics)
	}
	if metrics[drwaMetricRecoveryNonRepairable] != 1 {
		t.Fatalf("expected non-repairable metric, got %+v", metrics)
	}
}

// NOTE: This test must NOT use t.Parallel() — it mutates shared package-level metric counters.
func TestSnapshotDRWASyncMetricsReturnsCorrectMetrics(t *testing.T) {
	resetDRWAMetrics()

	// Record some metrics
	recordDRWAMetric(drwaMetricSyncApplySuccess)
	recordDRWAMetric(drwaMetricSyncApplySuccess)
	recordDRWAMetric(drwaMetricSyncApplyFailure)

	metrics := SnapshotDRWASyncMetrics()
	if metrics[drwaMetricSyncApplySuccess] != 2 {
		t.Fatalf("expected sync_apply_success=2, got %d", metrics[drwaMetricSyncApplySuccess])
	}
	if metrics[drwaMetricSyncApplyFailure] != 1 {
		t.Fatalf("expected sync_apply_failure=1, got %d", metrics[drwaMetricSyncApplyFailure])
	}

	// Verify snapshot is isolated (mutation does not affect source)
	metrics[drwaMetricSyncApplySuccess] = 999
	metrics2 := SnapshotDRWASyncMetrics()
	if metrics2[drwaMetricSyncApplySuccess] != 2 {
		t.Fatalf("snapshot mutation leaked: expected 2, got %d", metrics2[drwaMetricSyncApplySuccess])
	}
}

// NOTE: This test must NOT use t.Parallel() — it mutates shared package-level metric counters.
func TestSnapshotDRWASyncMetricsEmptyAfterReset(t *testing.T) {
	resetDRWAMetrics()
	recordDRWAMetric(drwaMetricSyncApplySuccess)
	resetDRWAMetrics()

	metrics := SnapshotDRWASyncMetrics()
	if len(metrics) != 0 {
		t.Fatalf("expected empty metrics after reset, got %d entries", len(metrics))
	}
}

// NOTE: This test must NOT use t.Parallel() — it mutates shared package-level metric counters.
func TestBuildDRWARolloutVerificationReportRecordsPassAndRejectMetrics(t *testing.T) {
	resetDRWAMetrics()
	healthyManifest := &drwaRolloutManifest{
		TokenID:                "CARBON-1",
		Issuer:                 "issuer-1",
		Stage:                  drwaRolloutStageCanary,
		MaxSyncFailureRateBps:  10,
		MaxAPIErrorRateBps:     10,
		MaxDenialMismatchRateBps: 1,
	}

	_, err := buildDRWARolloutVerificationReport(healthyManifest, &drwaRolloutObservedMetrics{
		SyncFailureRateBps:  1,
		APIErrorRateBps:     1,
		DenialMismatchCount: 0,
		DenialComparisonsTotal: 100,
	})
	if err != nil {
		t.Fatalf("build healthy verification report: %v", err)
	}

	_, err = buildDRWARolloutVerificationReport(healthyManifest, &drwaRolloutObservedMetrics{
		SyncFailureRateBps:  11,
		APIErrorRateBps:     1,
		DenialMismatchCount: 0,
		DenialComparisonsTotal: 100,
	})
	if err != nil {
		t.Fatalf("build rejected verification report: %v", err)
	}

	metrics := snapshotDRWAMetrics()
	if metrics[drwaMetricRolloutVerificationPass] != 1 {
		t.Fatalf("expected rollout pass metric, got %+v", metrics)
	}
	if metrics[drwaMetricRolloutVerificationReject] != 1 {
		t.Fatalf("expected rollout reject metric, got %+v", metrics)
	}
}
