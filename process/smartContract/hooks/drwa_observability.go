package hooks

import (
	"sync"

	builtInFunctions "github.com/multiversx/mx-chain-vm-common-go/builtInFunctions"
)

const (
	drwaMetricSyncApplySuccess          = "sync_apply_success"
	drwaMetricSyncApplyNoop             = "sync_apply_noop"
	drwaMetricSyncApplyFailure          = "sync_apply_failure"
	drwaMetricSyncUnauthorizedCaller    = "sync_unauthorized_caller"
	drwaMetricSyncHashMismatch          = "sync_hash_mismatch"
	drwaMetricSyncReplayRejected        = "sync_replay_rejected"
	drwaMetricSyncDecodeFailure         = "sync_decode_failure"
	drwaMetricRecoverySafeModeReport    = "recovery_safe_mode_report"
	drwaMetricRecoveryNonRepairable     = "recovery_non_repairable_report"
	drwaMetricRolloutVerificationPass      = "rollout_verification_pass"
	drwaMetricRolloutVerificationReject    = "rollout_verification_reject"
	drwaMetricSyncAdapterCrossShardAttempt  = "sync_adapter_cross_shard_attempt"
	drwaMetricSyncRecoveryTimelockReject      = "sync_recovery_timelock_reject"
	drwaMetricRolloutThresholdConfigFallback = "rollout_threshold_config_fallback"
	drwaMetricNonGovernanceSyncWrite         = "sync_non_governance_write"          // F-001
	drwaMetricRecoveryTimelockSkipped        = "sync_recovery_timelock_skipped"     // F-002
	drwaMetricRecoveryStateHashSkipped       = "sync_recovery_state_hash_skipped"   // C-35
	drwaMetricJSONStateWrite                 = "sync_json_state_write"              // F-006
	drwaMetricDeleteHolderRevertFailure      = "sync_delete_holder_revert_failure"  // F-019
	drwaMetricAuthorizedCallerMalformed      = "sync_authorized_caller_malformed"   // M-08
	drwaMetricGovernanceApprovalStaleAfterRotation = "governance_approval_stale_after_rotation" // B-10
	drwaMetricGovernanceEnvelopeHashMismatch       = "governance_envelope_hash_mismatch"       // M-13
)

// drwaMetrics is safe for concurrent use: DrwaCounterSet guards all
// operations (Increment, Snapshot, Reset) with a sync.Mutex internally.
var drwaMetrics = builtInFunctions.NewDrwaCounterSet()
var drwaSyncMetricsExporterState = struct {
	mut      sync.RWMutex
	exporter func(metric string, delta uint64)
}{}

// SetDRWASyncMetricsExporter configures an optional callback invoked on every
// sync metric increment. Passing nil disables the callback.
func SetDRWASyncMetricsExporter(exporter func(metric string, delta uint64)) {
	drwaSyncMetricsExporterState.mut.Lock()
	drwaSyncMetricsExporterState.exporter = exporter
	drwaSyncMetricsExporterState.mut.Unlock()
}

func recordDRWAMetric(metric string) {
	drwaMetrics.Increment(metric)

	drwaSyncMetricsExporterState.mut.RLock()
	exporter := drwaSyncMetricsExporterState.exporter
	drwaSyncMetricsExporterState.mut.RUnlock()
	if exporter == nil {
		return
	}

	defer func() {
		if recovered := recover(); recovered != nil {
			log.Warn("drwa sync metrics exporter callback panicked", "panic", recovered)
		}
	}()

	exporter(metric, 1)
}

func snapshotDRWAMetrics() map[string]uint64 {
	return drwaMetrics.Snapshot()
}

// SnapshotDRWASyncMetrics returns a point-in-time copy of all sync-layer
// metrics. This is the sync-side counterpart to builtInFunctions.SnapshotDRWAGateMetrics().
func SnapshotDRWASyncMetrics() map[string]uint64 {
	return drwaMetrics.Snapshot()
}

func resetDRWAMetrics() {
	drwaMetrics.Reset()
}
