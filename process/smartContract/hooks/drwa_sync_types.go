package hooks

import (
	"errors"

	coredrwa "github.com/multiversx/mx-chain-core-go/data/drwa"
	builtInFunctions "github.com/multiversx/mx-chain-vm-common-go/builtInFunctions"
)

var (
	errDRWARecoveryTimelockActive     = errors.New(drwaSyncRejectRecoveryTimelock)
	errDRWARecoveryStateChanged       = errors.New(drwaSyncRejectRecoveryStateChanged)
	errDRWASyncMissingPayloadHash     = errors.New(drwaSyncRejectMissingPayloadHash)
	errDRWARecoveryGovernanceRequired = errors.New(drwaSyncGovernanceRequired)
)

// Validate at startup that the prefix constants in this module match
// the exported constants in mx-chain-vm-common-go/builtInFunctions/drwa.go.
// A divergence here silently breaks the entire enforcement system because the
// sync adapter writes keys that the transfer gate cannot read.
func init() {
	pairs := [][2]string{
		{drwaSyncTokenPolicyPrefix, builtInFunctions.DRWATokenPolicyPrefix},
		{drwaSyncHolderMirrorPrefix, builtInFunctions.DRWAHolderMirrorPrefix},
		{drwaSyncHolderProfilePrefix, builtInFunctions.DRWAHolderProfilePrefix},
		{drwaSyncHolderAuditorAuthPrefix, builtInFunctions.DRWAHolderAuditorAuthPrefix},
		{drwaSyncAssetRecordPrefix, builtInFunctions.DRWAAssetRecordPrefix},
	}
	for _, p := range pairs {
		if p[0] != p[1] {
			// F-028: Removed redundant os.Stderr write — Go's runtime prints the
			// panic message to stderr automatically. The panic alone is sufficient.
			panic("CRIT-03: DRWA prefix mismatch between mx-chain-go and mx-chain-vm-common-go: " +
				"local=" + p[0] + " expected=" + p[1])
		}
	}
}

type drwaSyncOperationType string

const (
	drwaSyncOpTokenPolicy            drwaSyncOperationType = "token_policy"
	drwaSyncOpAssetRecord            drwaSyncOperationType = "asset_record"
	drwaSyncOpHolderMirror           drwaSyncOperationType = "holder_mirror"
	drwaSyncOpHolderProfile          drwaSyncOperationType = "holder_profile"
	drwaSyncOpHolderAuditorAuth      drwaSyncOperationType = "holder_auditor_authorization"
	drwaSyncOpHolderMirrorDelete     drwaSyncOperationType = "holder_mirror_delete"
	drwaSyncOpGovernanceApprove      drwaSyncOperationType = "drwa_governance_approve"
	drwaSyncOpGovernanceExecute      drwaSyncOperationType = "drwa_governance_execute"
	drwaSyncOpAuthorizedCallerUpdate drwaSyncOperationType = "authorized_caller_update"
)

const (
	drwaSyncCallerPolicyRegistry   = "policy_registry"
	drwaSyncCallerAssetManager     = "asset_manager"
	drwaSyncCallerIdentityRegistry = "identity_registry"
	drwaSyncCallerAttestation      = "attestation"
	drwaSyncCallerRecoveryAdmin    = "recovery_admin"
	drwaSyncCallerAuthAdmin        = "auth_admin"
)

const (
	drwaSyncRejectUnauthorizedCaller     = "DRWA_SYNC_UNAUTHORIZED_CALLER"
	drwaSyncRejectPayloadTooLarge        = "DRWA_SYNC_PAYLOAD_TOO_LARGE"
	drwaSyncRejectHashMismatch           = "DRWA_SYNC_HASH_MISMATCH"
	drwaSyncRejectReplayStale            = "DRWA_SYNC_REPLAY_STALE"
	drwaSyncRejectReplayDuplicate        = "DRWA_SYNC_REPLAY_DUPLICATE"
	drwaSyncRejectVersionOverflow        = "DRWA_SYNC_VERSION_OVERFLOW"
	drwaSyncRejectVersionGap             = "DRWA_SYNC_VERSION_GAP"
	drwaSyncRejectBatchAtomicity         = "DRWA_SYNC_BATCH_ATOMICITY_ABORT"
	drwaSyncRejectMissingPayloadHash     = "DRWA_SYNC_MISSING_PAYLOAD_HASH"
	drwaSyncRejectRecoveryTimelock       = "DRWA_SYNC_RECOVERY_TIMELOCK_ACTIVE"
	drwaSyncRejectRecoveryStateChanged   = "DRWA_SYNC_RECOVERY_STATE_CHANGED"
	drwaSyncRejectRecoveryScopeRequired  = "DRWA_SYNC_RECOVERY_SCOPE_REQUIRED"
	drwaSyncRejectRecoveryScopeViolation = "DRWA_SYNC_RECOVERY_SCOPE_VIOLATION"
	// F1 (closes N3 + N7): recovery_admin envelopes must contain exactly one
	// token in scope. Multi-token recovery would let governance routing decide
	// on the first token while the apply path mutates all of them, and would
	// let pre-recovery state-hash verification bind only the first token.
	// Single-token recovery envelopes are also what every existing builder
	// produces (buildDRWAMigrationEnvelope, buildDRWARecoveryEnvelope), so
	// this restriction matches the actual usage model.
	drwaSyncRejectRecoveryScopeMultiToken = "DRWA_SYNC_RECOVERY_SCOPE_MULTI_TOKEN"
	drwaSyncGovernanceRequired            = "DRWA_SYNC_GOVERNANCE_REQUIRED"
	drwaSyncGovernanceProposalCreated     = "DRWA_SYNC_GOVERNANCE_PROPOSAL_CREATED"
)

const (
	drwaMetricRecoveryGovernanceRequired = "recovery_governance_required"
)

const (
	// MUST match DRWATokenPolicyPrefix et al. in
	// mx-chain-vm-common-go/builtInFunctions/drwa.go.
	// Validated at startup by init(); panics on divergence.
	drwaSyncTokenPolicyPrefix       = string(coredrwa.TokenPolicyPrefix)
	drwaSyncAssetRecordPrefix       = string(coredrwa.AssetRecordPrefix)
	drwaSyncHolderMirrorPrefix      = string(coredrwa.HolderMirrorPrefix)
	drwaSyncHolderProfilePrefix     = string(coredrwa.HolderProfilePrefix)
	drwaSyncHolderAuditorAuthPrefix = string(coredrwa.HolderAuditorAuthPrefix)
	drwaSyncMaxOperations           = 256
	// 1 MB payload limit. With 256 max operations x ~4KB average per
	// holder mirror (token ID + address + compliance fields + body), this
	// supports ~250 holder updates per envelope. Tokens with >250 regulated
	// holders must use multiple sync envelopes across multiple transactions.
	drwaSyncMaxPayloadBytes = 1 << 20

	// drwaSyncRecoveryTimelockBlocks is the minimum number of blocks that must
	// elapse between consecutive recovery_admin writes for the same token.
	// At ~6 seconds per block, 600 blocks ≈ 1 hour. This limits the blast
	// radius of a compromised recovery key by rate-limiting state overwrites.
	drwaSyncRecoveryTimelockBlocks uint64 = 600

	// drwaSyncMaxTokenIDLen caps tokenID length in binary payloads to prevent
	// abuse. MultiversX token identifiers are at most ~32 chars (ticker-hex).
	drwaSyncMaxTokenIDLen = 64

	// drwaSyncMaxHolderLen caps holder address length. Bech32 addresses are
	// 62 chars; hex-encoded 32-byte addresses are 64 chars.
	drwaSyncMaxHolderLen = 128

	drwaSyncEnvelopeSchemaVersion             uint16 = 1
	drwaSyncEnvelopeSchemaVersionWithRecovery uint16 = 2
)

// Multi-sig governance for sync operations.
//
// CURRENT STATE (audit-validated):
//   1. Single-address authorization is enforced for every caller domain by
//      isDRWASyncCallerAuthorized in drwa_sync.go (single bytes.Equal match
//      against the address registered for the domain).
//   2. An M-of-N governance engine for recovery_admin operations exists in
//      drwa_governance.go (DRWAGovernanceEngine, propose/approve/execute) and
//      a routing layer above isDRWASyncCallerAuthorized invokes it via the
//      optional drwaSyncGovernanceProvider interface (see maybeRouteToGovernance).
//
// PRODUCTION STATE:
//   The production drwaHookStateAdapter implements drwaSyncGovernanceProvider,
//   so recovery_admin envelopes now route through governance when a config is
//   present, and fail closed with DRWA_SYNC_GOVERNANCE_REQUIRED otherwise.
//
// Compensating controls active today:
//   1. Recovery timelock rate-limits writes (drwaSyncRecoveryTimelockBlocks = 600 blocks).
//   2. All sync operations require hash verification (keccak256 envelope).
//   3. Recovery envelopes are restricted to a single token in scope (F1 fix).
//   4. Authorized caller addresses are registered via migration manifests with
//      bech32 checksum verification (note: production caller path unverified —
//      see audit finding N8).
//   5. Sync operations are fully auditable via event emission.
//   6. Rollout stage admission gates prevent unauthorized activation.
//   7. Asset record existence check prevents policy corruption escape.
//
// Storage key: drwa:governance:quorum:<hex(tokenID)>
// Body (JSON): DRWAGovernanceConfig per drwa_governance.go (Threshold,
// Signers, ProposalTTL, MaxSigners; Version field pending N6 fix).

type drwaSyncEnvelope struct {
	SchemaVersion uint16              `json:"schema_version"`
	CallerDomain  string              `json:"caller_domain"`
	PayloadHash   []byte              `json:"payload_hash"`
	Operations    []drwaSyncOperation `json:"operations"`
	Noop          bool                `json:"noop,omitempty"`
	// PreRecoveryStateHash binds a recovery_admin envelope to the on-chain
	// state that was inspected when the envelope was built. If state changes
	// between inspection and apply, the hash mismatch rejects the apply.
	// This field does NOT participate in PayloadHash computation.
	PreRecoveryStateHash []byte `json:"pre_recovery_state_hash,omitempty"`
	// RecoveryScope restricts a recovery_admin envelope to specific token IDs.
	// Required for recovery_admin callers — empty scope is rejected (C-7 fix).
	// Prevents a compromised recovery key from modifying arbitrary tokens.
	RecoveryScope []string `json:"recovery_scope,omitempty"`
}

type drwaSyncOperation struct {
	OperationType drwaSyncOperationType `json:"operation_type"`
	TokenID       string                `json:"token_id"`
	Holder        string                `json:"holder,omitempty"`
	Version       uint64                `json:"version"`
	Body          []byte                `json:"body"`
}

type drwaSyncStoredValue struct {
	Version uint64 `json:"version"`
	Body    []byte `json:"body"`
}

type drwaAuthorizedCallerRecord struct {
	Version uint64 `json:"version"`
	Address []byte `json:"address"`
}

type drwaSyncApplyResult struct {
	AppliedOperations    int
	LastTokenID          string
	Noop                 bool
	GovernanceProposalID [32]byte
	GovernancePending    bool
}
