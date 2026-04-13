package hooks

import (
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
	drwaMetricJSONStateWrite                 = "sync_json_state_write"              // F-006
	drwaMetricDeleteHolderRevertFailure      = "sync_delete_holder_revert_failure"  // F-019
)

// drwaMetrics is safe for concurrent use: DrwaCounterSet guards all
// operations (Increment, Snapshot, Reset) with a sync.Mutex internally.
var drwaMetrics = builtInFunctions.NewDrwaCounterSet()

func recordDRWAMetric(metric string) {
	drwaMetrics.Increment(metric)
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
