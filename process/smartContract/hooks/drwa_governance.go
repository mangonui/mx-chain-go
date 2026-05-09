package hooks

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/multiversx/mx-chain-core-go/hashing/keccak"
)

var (
	errDRWAGovernanceNilStore              = errors.New("nil DRWA governance store")
	errDRWAGovernanceNilCaller             = errors.New("nil caller address for governance operation")
	errDRWAGovernanceNilEnvelope           = errors.New("nil envelope for governance proposal")
	errDRWAGovernanceNotEnabled            = errors.New("DRWA governance not enabled for token")
	errDRWAGovernanceSignerNotAuthorized   = errors.New("caller is not an authorized governance signer")
	errDRWAGovernanceDuplicateApproval     = errors.New("caller has already approved this proposal")
	errDRWAGovernanceProposalNotFound      = errors.New("governance proposal not found")
	errDRWAGovernanceProposalIDCollision   = errors.New("governance proposal id collision")
	errDRWAGovernanceProposalExpired       = errors.New("governance proposal has expired (TTL exceeded)")
	errDRWAGovernanceProposalExecuted      = errors.New("governance proposal has already been executed")
	errDRWAGovernanceThresholdNotMet       = errors.New("governance approval threshold not met")
	errDRWAGovernanceInvalidThreshold      = errors.New("governance threshold must be >= 2")
	errDRWAGovernanceThresholdExceedsLen   = errors.New("governance threshold exceeds number of signers")
	errDRWAGovernanceDuplicateSigner       = errors.New("governance config contains duplicate signer")
	errDRWAGovernanceNoSigners             = errors.New("governance config has no signers")
	errDRWAGovernanceTooManySigners        = errors.New("governance config exceeds maximum signer count")
	errDRWAGovernanceInvalidMaxSigners     = errors.New("governance MaxSigners must be >= threshold and <= drwaGovernanceAbsoluteMaxSigners")
	errDRWAGovernanceInvalidProposalTTL    = errors.New("governance ProposalTTL must be > 0")
	errDRWAGovernanceConfigVersionMismatch = errors.New("governance config version mismatch")
	errDRWAGovernanceEnvelopeHashMismatch  = errors.New("governance envelope payload hash does not match stored hash (M-13: storage tampering or serde drift)")
)

const (
	// drwaGovernanceAbsoluteMaxSigners is the hard cap on governance signers.
	// This prevents unbounded storage growth and gas consumption during
	// signer iteration in approval checks.
	drwaGovernanceAbsoluteMaxSigners uint32 = 10

	// drwaGovernanceDefaultProposalTTL is the default TTL in blocks if not
	// explicitly set. 2400 blocks at ~6s/block = ~4 hours.
	drwaGovernanceDefaultProposalTTL uint64 = 2400

	// drwaGovernancePruneRetentionBlocks is the minimum number of blocks
	// that must elapse after execution or expiry before a proposal
	// becomes eligible for pruning via `PruneProposal`. 432_000 blocks
	// at ~6s/block = ~30 days. The window gives operators time to
	// inspect anomalies before the full envelope payload is deleted,
	// and matches the retention floor recommended in
	// `DRWA-Key-Rotation-Procedures.md` for incident investigation.
	drwaGovernancePruneRetentionBlocks uint64 = 432_000

	// Metric names for governance operations.
	drwaMetricGovernanceProposalCreated    = "governance_proposal_created"
	drwaMetricGovernanceApprovalAdded      = "governance_approval_added"
	drwaMetricGovernanceProposalExecuted   = "governance_proposal_executed"
	drwaMetricGovernanceProposalExpired    = "governance_proposal_expired"
	drwaMetricGovernanceThresholdNotMet    = "governance_threshold_not_met"
	drwaMetricGovernanceUnauthorizedSigner = "governance_unauthorized_signer"
	// M-14: fires on every successful `PruneProposal` call.
	drwaMetricGovernanceProposalPruned = "governance_proposal_pruned"
)

var (
	// M-14: used by PruneProposal to reject a prune attempt against a
	// proposal that has not yet cleared the retention window.
	errDRWAGovernancePruneNotEligible = errors.New("governance proposal is not yet eligible for pruning (executed/expired + retention window not elapsed)")
)

// DRWAGovernanceConfig defines the M-of-N multi-sig quorum for a governed token.
type DRWAGovernanceConfig struct {
	Version           uint64                      `json:"version"`
	Threshold         uint32                      `json:"threshold"`
	Signers           [][]byte                    `json:"signers"`
	ProposalTTL       uint64                      `json:"proposal_ttl"`
	MaxSigners        uint32                      `json:"max_signers"`
	RolloutThresholds *drwaRolloutThresholdConfig `json:"rollout_thresholds,omitempty"`
}

// DRWAGovernanceProposal tracks a pending recovery operation awaiting quorum.
type DRWAGovernanceProposal struct {
	ProposalID     [32]byte `json:"proposal_id"`
	EnvelopeHash   [32]byte `json:"envelope_hash"`
	Proposer       []byte   `json:"proposer"`
	Approvals      [][]byte `json:"approvals"`
	CreatedAtBlock uint64   `json:"created_at_block"`
	Executed       bool     `json:"executed"`
	// M-14: set when the proposal transitions to `Executed = true`.
	// Used by `PruneProposal` to enforce the post-execution retention
	// window. Legacy proposals serialized before M-14 unmarshal with
	// `ExecutedAtBlock = 0`, which correctly marks them as immediately
	// prune-eligible (they were stored without retention tracking).
	ExecutedAtBlock uint64 `json:"executed_at_block,omitempty"`
	// EnvelopePayload stores the serialized envelope so it can be reconstructed
	// at execution time without requiring the executor to re-submit it.
	EnvelopePayload []byte `json:"envelope_payload"`
}

// DRWAGovernanceAuditRecord is the compact forensic trail written when
// a proposal is executed. It survives `PruneProposal` so operators can
// still answer "did proposal X execute, when, with how many approvals,
// and against which envelope hash?" long after the full payload is
// deleted. The struct is intentionally small (~72 bytes per record)
// to keep long-horizon storage cost bounded.
//
// M-14 (R-01-F-05).
type DRWAGovernanceAuditRecord struct {
	ProposalID      [32]byte `json:"proposal_id"`
	EnvelopeHash    [32]byte `json:"envelope_hash"`
	ExecutedAtBlock uint64   `json:"executed_at_block"`
	ApprovalCount   uint32   `json:"approval_count"`
	Outcome         string   `json:"outcome"` // "executed"
}

// DRWAGovernanceStore abstracts persistence for governance config and proposals.
type DRWAGovernanceStore interface {
	GetGovernanceConfig(tokenID string) (*DRWAGovernanceConfig, error)
	SaveGovernanceConfig(tokenID string, cfg *DRWAGovernanceConfig, expectedVersion ...uint64) error
	GetProposal(proposalID [32]byte) (*DRWAGovernanceProposal, error)
	SaveProposal(proposal *DRWAGovernanceProposal) error
	DeleteProposal(proposalID [32]byte) error
	// M-14: persistent audit trail keyed by proposal ID. Implementations
	// MUST return (nil, nil) when no record exists for the given ID.
	SaveAuditRecord(record *DRWAGovernanceAuditRecord) error
	GetAuditRecord(proposalID [32]byte) (*DRWAGovernanceAuditRecord, error)
}

// DRWAGovernanceEngine implements M-of-N multi-sig governance for DRWA
// recovery operations. It mediates between the sync layer and the governance
// store, enforcing quorum requirements before any recovery envelope is applied.
type DRWAGovernanceEngine struct {
	store DRWAGovernanceStore
}

// NewDRWAGovernanceEngine creates a governance engine backed by the given store.
func NewDRWAGovernanceEngine(store DRWAGovernanceStore) *DRWAGovernanceEngine {
	return &DRWAGovernanceEngine{store: store}
}

// ValidateGovernanceConfig validates a governance configuration for correctness.
// Rejects: threshold < 2, threshold > len(signers), duplicate signers,
// empty signer list, signer count exceeding MaxSigners or absolute cap.
func ValidateGovernanceConfig(cfg *DRWAGovernanceConfig) error {
	if cfg == nil {
		return errDRWAGovernanceNilStore
	}
	if len(cfg.Signers) == 0 {
		return errDRWAGovernanceNoSigners
	}
	if cfg.Threshold < 2 {
		return errDRWAGovernanceInvalidThreshold
	}
	if cfg.Threshold > uint32(len(cfg.Signers)) {
		return errDRWAGovernanceThresholdExceedsLen
	}
	if cfg.ProposalTTL == 0 {
		return errDRWAGovernanceInvalidProposalTTL
	}
	if cfg.MaxSigners == 0 {
		cfg.MaxSigners = drwaGovernanceAbsoluteMaxSigners
	}
	if cfg.MaxSigners > drwaGovernanceAbsoluteMaxSigners {
		return errDRWAGovernanceInvalidMaxSigners
	}
	if cfg.MaxSigners < cfg.Threshold {
		return errDRWAGovernanceInvalidMaxSigners
	}
	if uint32(len(cfg.Signers)) > cfg.MaxSigners {
		return errDRWAGovernanceTooManySigners
	}

	// Check for duplicate signers.
	seen := make(map[string]struct{}, len(cfg.Signers))
	for _, signer := range cfg.Signers {
		key := string(signer)
		if _, exists := seen[key]; exists {
			return errDRWAGovernanceDuplicateSigner
		}
		seen[key] = struct{}{}
	}

	return nil
}

// ProposeRecoveryOperation creates a governance proposal for a recovery envelope.
// The caller must be an authorized signer. The proposal is automatically approved
// by the proposer (counts as the first approval).
func (e *DRWAGovernanceEngine) ProposeRecoveryOperation(
	caller []byte,
	envelope drwaSyncEnvelope,
	currentBlock uint64,
) ([32]byte, error) {
	if e.store == nil {
		return [32]byte{}, errDRWAGovernanceNilStore
	}
	if len(caller) == 0 {
		return [32]byte{}, errDRWAGovernanceNilCaller
	}

	// Determine token ID from the envelope's recovery scope or first operation.
	tokenID := extractGovernanceTokenID(&envelope)
	if tokenID == "" {
		return [32]byte{}, errDRWAGovernanceNilEnvelope
	}

	cfg, err := e.store.GetGovernanceConfig(tokenID)
	if err != nil {
		return [32]byte{}, err
	}
	if cfg == nil {
		return [32]byte{}, errDRWAGovernanceNotEnabled
	}

	if !isGovernanceSigner(caller, cfg.Signers) {
		recordDRWAMetric(drwaMetricGovernanceUnauthorizedSigner)
		return [32]byte{}, errDRWAGovernanceSignerNotAuthorized
	}

	// Compute envelope hash for binding.
	envelopeHash, err := computeDRWASyncHash(envelope.CallerDomain, envelope.Operations)
	if err != nil {
		return [32]byte{}, fmt.Errorf("governance proposal: envelope hash computation failed: %w", err)
	}

	var envHash [32]byte
	copy(envHash[:], envelopeHash)

	// Compute proposal ID = keccak256(envelope_hash || currentBlock as 8 bytes).
	proposalID := computeProposalID(envHash, currentBlock)

	// Proposal IDs must never silently overwrite existing governance state.
	// The current derivation uses envelopeHash + currentBlock, so proposing the
	// same envelope twice in the same block would otherwise collide and replace
	// the original proposal record.
	existingProposal, err := e.store.GetProposal(proposalID)
	if err != nil {
		return [32]byte{}, err
	}
	if existingProposal != nil {
		return [32]byte{}, errDRWAGovernanceProposalIDCollision
	}

	// Serialize the envelope for later retrieval at execution time.
	envelopePayload, err := serializeGovernanceEnvelope(&envelope)
	if err != nil {
		return [32]byte{}, fmt.Errorf("governance proposal: envelope serialization failed: %w", err)
	}

	proposal := &DRWAGovernanceProposal{
		ProposalID:      proposalID,
		EnvelopeHash:    envHash,
		Proposer:        append([]byte(nil), caller...),
		Approvals:       [][]byte{append([]byte(nil), caller...)},
		CreatedAtBlock:  currentBlock,
		Executed:        false,
		EnvelopePayload: envelopePayload,
	}

	if err = e.store.SaveProposal(proposal); err != nil {
		return [32]byte{}, err
	}

	recordDRWAMetric(drwaMetricGovernanceProposalCreated)
	return proposalID, nil
}

// ApproveRecoveryOperation adds an approval to an existing proposal.
// Rejects duplicate approvals and non-authorized signers.
func (e *DRWAGovernanceEngine) ApproveRecoveryOperation(
	caller []byte,
	proposalID [32]byte,
	currentBlock ...uint64,
) error {
	if e.store == nil {
		return errDRWAGovernanceNilStore
	}
	if len(caller) == 0 {
		return errDRWAGovernanceNilCaller
	}

	proposal, err := e.store.GetProposal(proposalID)
	if err != nil {
		return err
	}
	if proposal == nil {
		return errDRWAGovernanceProposalNotFound
	}
	if proposal.Executed {
		return errDRWAGovernanceProposalExecuted
	}

	// We need the token ID to look up the governance config.
	// Deserialize the stored envelope to extract it.
	envelope, err := deserializeGovernanceEnvelope(proposal.EnvelopePayload)
	if err != nil {
		return fmt.Errorf("governance approve: envelope deserialization failed: %w", err)
	}

	tokenID := extractGovernanceTokenID(envelope)
	if tokenID == "" {
		return errDRWAGovernanceNilEnvelope
	}

	cfg, err := e.store.GetGovernanceConfig(tokenID)
	if err != nil {
		return err
	}
	if cfg == nil {
		return errDRWAGovernanceNotEnabled
	}

	approvalBlock := proposal.CreatedAtBlock
	if len(currentBlock) > 0 {
		approvalBlock = currentBlock[0]
	}

	if approvalBlock > proposal.CreatedAtBlock+cfg.ProposalTTL {
		recordDRWAMetric(drwaMetricGovernanceProposalExpired)
		return errDRWAGovernanceProposalExpired
	}

	if !isGovernanceSigner(caller, cfg.Signers) {
		recordDRWAMetric(drwaMetricGovernanceUnauthorizedSigner)
		return errDRWAGovernanceSignerNotAuthorized
	}

	// Check duplicate approval.
	for _, existing := range proposal.Approvals {
		if bytes.Equal(existing, caller) {
			return errDRWAGovernanceDuplicateApproval
		}
	}

	proposal.Approvals = append(proposal.Approvals, append([]byte(nil), caller...))

	if err = e.store.SaveProposal(proposal); err != nil {
		return err
	}

	recordDRWAMetric(drwaMetricGovernanceApprovalAdded)
	return nil
}

// ExecuteRecoveryOperation checks that quorum is met, the proposal is not
// expired, and has not been previously executed. Returns the deserialized
// envelope ready for application via applyDRWASyncEnvelope.
func (e *DRWAGovernanceEngine) ExecuteRecoveryOperation(
	caller []byte,
	proposalID [32]byte,
	currentBlock uint64,
) (*drwaSyncEnvelope, error) {
	if e.store == nil {
		return nil, errDRWAGovernanceNilStore
	}
	if len(caller) == 0 {
		return nil, errDRWAGovernanceNilCaller
	}

	proposal, err := e.store.GetProposal(proposalID)
	if err != nil {
		return nil, err
	}
	if proposal == nil {
		return nil, errDRWAGovernanceProposalNotFound
	}
	if proposal.Executed {
		return nil, errDRWAGovernanceProposalExecuted
	}

	// Deserialize the stored envelope to get token ID and the envelope itself.
	envelope, err := deserializeGovernanceEnvelope(proposal.EnvelopePayload)
	if err != nil {
		return nil, fmt.Errorf("governance execute: envelope deserialization failed: %w", err)
	}

	// M-13 (R-01-F-04): re-verify that the deserialized envelope still
	// hashes to the `EnvelopeHash` captured at propose time. The
	// propose path derived that hash from the caller's envelope and
	// stored it atomically alongside the payload; any divergence here
	// means the stored payload has drifted between propose and execute
	// (trie rewrite, migration bug, serde-layer change, storage
	// tampering). Fail closed and surface the anomaly on a dedicated
	// metric so post-mortem analysis has a signal.
	reverifiedHash, err := computeDRWASyncHash(envelope.CallerDomain, envelope.Operations)
	if err != nil {
		return nil, fmt.Errorf("governance execute: envelope hash re-verification failed: %w", err)
	}
	if !bytes.Equal(reverifiedHash, proposal.EnvelopeHash[:]) {
		recordDRWAMetric(drwaMetricGovernanceEnvelopeHashMismatch)
		return nil, errDRWAGovernanceEnvelopeHashMismatch
	}

	tokenID := extractGovernanceTokenID(envelope)
	if tokenID == "" {
		return nil, errDRWAGovernanceNilEnvelope
	}

	cfg, err := e.store.GetGovernanceConfig(tokenID)
	if err != nil {
		return nil, err
	}
	if cfg == nil {
		return nil, errDRWAGovernanceNotEnabled
	}

	// The executor must also be an authorized signer.
	if !isGovernanceSigner(caller, cfg.Signers) {
		recordDRWAMetric(drwaMetricGovernanceUnauthorizedSigner)
		return nil, errDRWAGovernanceSignerNotAuthorized
	}

	// Check TTL expiry.
	if currentBlock > proposal.CreatedAtBlock+cfg.ProposalTTL {
		recordDRWAMetric(drwaMetricGovernanceProposalExpired)
		return nil, errDRWAGovernanceProposalExpired
	}

	// B-10 (R-01-F-02): re-validate every stored approval against the
	// CURRENT signer set. A signer whose key was rotated out between
	// propose and execute MUST not retain voting power — otherwise a
	// compromised-then-rotated key still authorizes a catastrophic
	// recovery operation, which defeats the rotation control the key-
	// rotation procedure is designed to provide. Stale approvals are
	// dropped and counted on a dedicated metric so operators have a
	// post-mortem signal; the threshold check below then runs against
	// the filtered count only.
	validApprovals, staleDropped := filterCurrentSignerApprovals(proposal.Approvals, cfg.Signers)
	if staleDropped > 0 {
		for i := uint32(0); i < staleDropped; i++ {
			recordDRWAMetric(drwaMetricGovernanceApprovalStaleAfterRotation)
		}
	}

	// Check threshold against the post-rotation-filtered approval set.
	if uint32(len(validApprovals)) < cfg.Threshold {
		recordDRWAMetric(drwaMetricGovernanceThresholdNotMet)
		return nil, errDRWAGovernanceThresholdNotMet
	}

	// Persist the filtered approvals so any subsequent read of the
	// proposal reflects post-rotation truth, and mark as executed.
	proposal.Approvals = validApprovals
	proposal.Executed = true
	proposal.ExecutedAtBlock = currentBlock
	if err = e.store.SaveProposal(proposal); err != nil {
		return nil, err
	}

	// M-14: write the compact forensic audit record alongside the full
	// proposal. This record survives `PruneProposal`, so operators can
	// answer "did proposal X execute, when, with how many approvals,
	// and against which envelope hash?" long after the payload is
	// deleted. Audit-record failure does NOT revert the execution —
	// the authoritative state is already committed in the proposal.
	auditRecord := &DRWAGovernanceAuditRecord{
		ProposalID:      proposal.ProposalID,
		EnvelopeHash:    proposal.EnvelopeHash,
		ExecutedAtBlock: currentBlock,
		ApprovalCount:   uint32(len(validApprovals)),
		Outcome:         "executed",
	}
	if auditErr := e.store.SaveAuditRecord(auditRecord); auditErr != nil {
		// Emit as a metric on the sync layer (M-14 operational note)
		// but do not fail the execute — the main state change is
		// already in place.
		recordDRWAMetric(drwaMetricSyncApplyFailure)
	}

	recordDRWAMetric(drwaMetricGovernanceProposalExecuted)
	return envelope, nil
}

// PruneProposal removes the full proposal payload for `proposalID`
// once the M-14 retention window has elapsed. The accompanying audit
// record (`DRWAGovernanceAuditRecord`) persists, so the forensic
// trail survives.
//
// Eligibility:
//   - Executed proposals: `currentBlock >= ExecutedAtBlock + drwaGovernancePruneRetentionBlocks`.
//   - Non-executed proposals: must be expired AND
//     `currentBlock >= CreatedAtBlock + ProposalTTL + drwaGovernancePruneRetentionBlocks`.
//
// Any other state rejects with `errDRWAGovernancePruneNotEligible`.
// A missing proposal returns `errDRWAGovernanceProposalNotFound`.
//
// The retention window is a compile-time constant
// (`drwaGovernancePruneRetentionBlocks`) to prevent an operator from
// shortening the window for a proposal that is currently under dispute.
//
// M-14 (R-01-F-05).
func (e *DRWAGovernanceEngine) PruneProposal(
	proposalID [32]byte,
	currentBlock uint64,
) error {
	if e.store == nil {
		return errDRWAGovernanceNilStore
	}

	proposal, err := e.store.GetProposal(proposalID)
	if err != nil {
		return err
	}
	if proposal == nil {
		return errDRWAGovernanceProposalNotFound
	}

	eligible, err := e.isProposalPruneEligible(proposal, currentBlock)
	if err != nil {
		return err
	}
	if !eligible {
		return errDRWAGovernancePruneNotEligible
	}

	if err = e.store.DeleteProposal(proposalID); err != nil {
		return err
	}

	recordDRWAMetric(drwaMetricGovernanceProposalPruned)
	return nil
}

// isProposalPruneEligible encapsulates the retention-window check. An
// executed proposal is eligible once `currentBlock` is at least
// `ExecutedAtBlock + drwaGovernancePruneRetentionBlocks` rounds past
// execution. A non-executed proposal is eligible only if it is
// expired AND the same retention window has elapsed past the expiry.
func (e *DRWAGovernanceEngine) isProposalPruneEligible(
	proposal *DRWAGovernanceProposal,
	currentBlock uint64,
) (bool, error) {
	if proposal.Executed {
		return currentBlock >= proposal.ExecutedAtBlock+drwaGovernancePruneRetentionBlocks, nil
	}

	// Non-executed path — need the config's TTL to compute expiry.
	envelope, err := deserializeGovernanceEnvelope(proposal.EnvelopePayload)
	if err != nil {
		return false, fmt.Errorf("governance prune: envelope deserialization failed: %w", err)
	}
	tokenID := extractGovernanceTokenID(envelope)
	if tokenID == "" {
		return false, errDRWAGovernanceNilEnvelope
	}
	cfg, err := e.store.GetGovernanceConfig(tokenID)
	if err != nil {
		return false, err
	}
	if cfg == nil {
		// Config missing — treat as maximally-conservative "not eligible"
		// rather than silently prune a proposal whose governance state
		// we cannot verify.
		return false, nil
	}

	expiryBlock := proposal.CreatedAtBlock + cfg.ProposalTTL
	return currentBlock >= expiryBlock+drwaGovernancePruneRetentionBlocks, nil
}

// filterCurrentSignerApprovals returns the subset of `approvals` whose
// caller address is still a member of `currentSigners`, together with
// the count of approvals dropped because the caller is no longer a
// signer. The returned slice is a freshly-allocated copy to avoid
// aliasing the original proposal.Approvals storage.
//
// B-10 (R-01-F-02): called from `ExecuteRecoveryOperation` to
// invalidate stale approvals when the signer set has rotated between
// propose and execute.
func filterCurrentSignerApprovals(
	approvals [][]byte,
	currentSigners [][]byte,
) ([][]byte, uint32) {
	valid := make([][]byte, 0, len(approvals))
	var staleDropped uint32
	for _, approval := range approvals {
		if isGovernanceSigner(approval, currentSigners) {
			valid = append(valid, append([]byte(nil), approval...))
		} else {
			staleDropped++
		}
	}
	return valid, staleDropped
}

// IsSignerAuthorized checks whether caller is in the signer set for tokenID.
func (e *DRWAGovernanceEngine) IsSignerAuthorized(caller []byte, tokenID string) bool {
	if e.store == nil || len(caller) == 0 {
		return false
	}

	cfg, err := e.store.GetGovernanceConfig(tokenID)
	if err != nil || cfg == nil {
		return false
	}

	return isGovernanceSigner(caller, cfg.Signers)
}

// IsGovernanceEnabled returns true if there is a valid governance config for
// the given token.
func (e *DRWAGovernanceEngine) IsGovernanceEnabled(tokenID string) bool {
	if e.store == nil {
		return false
	}
	cfg, err := e.store.GetGovernanceConfig(tokenID)
	return err == nil && cfg != nil
}

// --- internal helpers ---

func isGovernanceSigner(caller []byte, signers [][]byte) bool {
	for _, signer := range signers {
		if bytes.Equal(signer, caller) {
			return true
		}
	}
	return false
}

func computeProposalID(envelopeHash [32]byte, nonce uint64) [32]byte {
	hasher := keccak.NewKeccak()
	var nonceBuf [8]byte
	nonceBuf[0] = byte(nonce >> 56)
	nonceBuf[1] = byte(nonce >> 48)
	nonceBuf[2] = byte(nonce >> 40)
	nonceBuf[3] = byte(nonce >> 32)
	nonceBuf[4] = byte(nonce >> 24)
	nonceBuf[5] = byte(nonce >> 16)
	nonceBuf[6] = byte(nonce >> 8)
	nonceBuf[7] = byte(nonce)

	input := append(envelopeHash[:], nonceBuf[:]...)
	hash := hasher.Compute(string(input))

	var id [32]byte
	copy(id[:], hash)
	return id
}

func extractGovernanceTokenID(envelope *drwaSyncEnvelope) string {
	if envelope == nil {
		return ""
	}
	// Prefer RecoveryScope (always set for recovery_admin envelopes).
	if len(envelope.RecoveryScope) > 0 {
		return envelope.RecoveryScope[0]
	}
	// Fallback: first operation's token ID.
	if len(envelope.Operations) > 0 {
		return envelope.Operations[0].TokenID
	}
	return ""
}

// maybeRouteToGovernance checks if governance is enabled for the token in a
// recovery_admin envelope. If enabled, creates a proposal instead of applying
// directly. Returns (result, true, nil) if handled, or (nil, false, nil) to
// fall through to single-key recovery.
func maybeRouteToGovernance(
	adapter drwaSyncStateAdapter,
	envelope *drwaSyncEnvelope,
	callerAddress []byte,
) (*drwaSyncApplyResult, bool, error) {
	govProvider, ok := adapter.(drwaSyncGovernanceProvider)
	if !ok {
		return nil, false, nil
	}

	engine := govProvider.GetGovernanceEngine()
	if engine == nil {
		return nil, false, nil
	}

	tokenID := extractGovernanceTokenID(envelope)
	if tokenID == "" {
		return nil, false, nil
	}

	if !engine.IsGovernanceEnabled(tokenID) {
		return nil, false, nil
	}

	currentBlock, err := govProvider.GetCurrentBlockNonceForGovernance()
	if err != nil {
		return nil, false, fmt.Errorf("governance: cannot read current block: %w", err)
	}

	proposalID, err := engine.ProposeRecoveryOperation(callerAddress, *envelope, currentBlock)
	if err != nil {
		return nil, false, err
	}

	return &drwaSyncApplyResult{
		GovernanceProposalID: proposalID,
		GovernancePending:    true,
	}, true, nil
}

// handleDRWAGovernanceOperation processes drwa_governance_approve and
// drwa_governance_execute operations. The first operation in the envelope
// determines the governance action. The operation's Body contains the
// 32-byte proposal ID.
func handleDRWAGovernanceOperation(
	adapter drwaSyncStateAdapter,
	envelope *drwaSyncEnvelope,
	callerAddress []byte,
) (*drwaSyncApplyResult, error) {
	govProvider, ok := adapter.(drwaSyncGovernanceProvider)
	if !ok {
		return nil, errors.New("governance operations require a governance-capable adapter")
	}

	engine := govProvider.GetGovernanceEngine()
	if engine == nil {
		return nil, errors.New("governance engine not configured")
	}

	if len(envelope.Operations) != 1 {
		return nil, errors.New("governance operations must contain exactly one operation")
	}

	op := envelope.Operations[0]
	if len(op.Body) != 32 {
		return nil, errors.New("governance operation body must be a 32-byte proposal ID")
	}

	var proposalID [32]byte
	copy(proposalID[:], op.Body)

	switch op.OperationType {
	case drwaSyncOpGovernanceApprove:
		currentBlock, err := govProvider.GetCurrentBlockNonceForGovernance()
		if err != nil {
			return nil, fmt.Errorf("governance approve: cannot read current block: %w", err)
		}

		if err := engine.ApproveRecoveryOperation(callerAddress, proposalID, currentBlock); err != nil {
			recordDRWAMetric(drwaMetricSyncApplyFailure)
			return nil, err
		}
		return &drwaSyncApplyResult{
			AppliedOperations:    1,
			GovernanceProposalID: proposalID,
			GovernancePending:    true,
		}, nil

	case drwaSyncOpGovernanceExecute:
		currentBlock, err := govProvider.GetCurrentBlockNonceForGovernance()
		if err != nil {
			return nil, fmt.Errorf("governance execute: cannot read current block: %w", err)
		}

		resolvedEnvelope, err := engine.ExecuteRecoveryOperation(callerAddress, proposalID, currentBlock)
		if err != nil {
			recordDRWAMetric(drwaMetricSyncApplyFailure)
			return nil, err
		}

		// The resolved envelope has CallerDomain = recovery_admin. The
		// applyDRWASyncEnvelope authorization check compares callerAddress
		// against the registered recovery_admin address. Since governance
		// quorum has already authorized this operation, we must use the
		// registered recovery_admin address for the apply path.
		registeredAddr, addrErr := adapter.GetAuthorizedCallerAddress(drwaSyncCallerRecoveryAdmin)
		if addrErr != nil || len(registeredAddr) == 0 {
			return nil, fmt.Errorf("governance execute: cannot resolve registered recovery_admin address: %v", addrErr)
		}

		result, err := applyDRWASyncEnvelopeGovernanceApproved(adapter, resolvedEnvelope, drwaSyncMaxOperations, registeredAddr)
		if err != nil {
			return nil, err
		}
		result.GovernanceProposalID = proposalID
		return result, nil

	default:
		return nil, fmt.Errorf("unexpected governance operation type: %s", op.OperationType)
	}
}

func serializeGovernanceEnvelope(envelope *drwaSyncEnvelope) ([]byte, error) {
	return json.Marshal(envelope)
}

func deserializeGovernanceEnvelope(data []byte) (*drwaSyncEnvelope, error) {
	if len(data) == 0 {
		return nil, errors.New("empty governance envelope payload")
	}

	envelope := &drwaSyncEnvelope{}
	if err := json.Unmarshal(data, envelope); err != nil {
		return nil, err
	}

	return envelope, nil
}
