package hooks

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"sync"

	"github.com/multiversx/mx-chain-core-go/hashing/keccak"
)

// F-023: Pool Keccak hashers to reduce allocation pressure during sync
// hash computation. Each hasher is stateless after Compute(), so reuse is safe.
var drwaKeccakPool = sync.Pool{
	New: func() interface{} { return keccak.NewKeccak() },
}

// drwaBinaryHashSize is the byte length of the keccak256 hash prefix in the
// binary hook payload produced by the Rust managedDRWASyncMirror call.
const drwaBinaryHashSize = 32

// drwaAuthorizedCallerAddressLen is the expected byte length of a
// MultiversX authorized-caller address. Used by M-08 (AUD-014) to
// structurally validate stored/caller addresses at runtime before the
// bytes.Equal comparison in `isDRWASyncCallerAuthorized`, catching
// malformed provisioning artifacts instead of silently deny-all.
const drwaAuthorizedCallerAddressLen = 32

type drwaSyncStateAdapter interface {
	GetTokenPolicyVersion(tokenID string) (uint64, error)
	GetAssetRecordVersion(tokenID string) (uint64, error)
	GetHolderMirrorVersion(tokenID, holder string) (uint64, error)
	GetHolderProfileVersion(holder string) (uint64, error)
	GetHolderAuditorAuthorizationVersion(tokenID, holder string) (uint64, error)
	GetAuthorizedCallerAddress(domain string) ([]byte, error)
	GetAuthorizedCallerAddressVersioned(domain string) ([]byte, uint64, error)
	PutTokenPolicyBody(tokenID string, version uint64, body []byte) error
	PutAssetRecordBody(tokenID string, version uint64, body []byte) error
	PutHolderMirrorBody(tokenID, holder string, version uint64, body []byte) error
	PutHolderProfileBody(holder string, version uint64, body []byte) error
	PutHolderAuditorAuthorizationBody(tokenID, holder string, version uint64, body []byte) error
	SetDRWAActive(tokenID string) error
	SetAuthorizedCallerAddressVersioned(domain string, address []byte, version uint64) error
	DeleteHolderMirror(tokenID, holder string, version uint64) error
	Snapshot() int
	Rollback(snapshot int) error
	IsInterfaceNil() bool
}

func decodeDRWASyncEnvelope(payload []byte) (*drwaSyncEnvelope, error) {
	if len(payload) == 0 {
		return nil, errors.New("nil DRWA sync payload")
	}
	if len(payload) > drwaSyncMaxPayloadBytes {
		return nil, errors.New(drwaSyncRejectPayloadTooLarge)
	}

	// Binary path: payload produced by the Rust managedDRWASyncMirror hook.
	// Format: [32-byte keccak256 hash] || [schema_version:u16] || [canonical binary payload].
	// Detected by the first byte not being '{' (JSON always starts with '{').
	if payload[0] != '{' {
		envelope, err := decodeDRWASyncEnvelopeBinary(payload)
		if err != nil {
			recordDRWAMetric(drwaMetricSyncDecodeFailure)
		}
		return envelope, err
	}

	envelope := &drwaSyncEnvelope{}
	err := json.Unmarshal(payload, envelope)
	if err != nil {
		recordDRWAMetric(drwaMetricSyncDecodeFailure)
		return nil, err
	}

	// SH-1: Reject JSON envelopes that carry operations but omit PayloadHash.
	// This catches truncated or hand-crafted payloads early, before they reach
	// the apply path where a missing hash would cause a less-specific mismatch error.
	if len(envelope.Operations) > 0 && len(envelope.PayloadHash) == 0 {
		recordDRWAMetric(drwaMetricSyncDecodeFailure)
		return nil, errDRWASyncMissingPayloadHash
	}

	// Check operation count immediately after unmarshal, before any
	// further processing. Bounds memory from malicious JSON payloads that could
	// contain thousands of tiny operations within the 1 MB size limit.
	if len(envelope.Operations) > drwaSyncMaxOperations {
		recordDRWAMetric(drwaMetricSyncDecodeFailure)
		return nil, fmt.Errorf("DRWA JSON sync envelope contains %d operations, exceeding limit of %d",
			len(envelope.Operations), drwaSyncMaxOperations)
	}

	return envelope, nil
}

func decodeDRWASyncEnvelopeBinary(payload []byte) (*drwaSyncEnvelope, error) {
	if len(payload) < drwaBinaryHashSize+3 {
		return nil, errors.New("DRWA binary sync payload too short")
	}

	payloadHash := make([]byte, drwaBinaryHashSize)
	copy(payloadHash, payload[:drwaBinaryHashSize])
	canonicalPayload := payload[drwaBinaryHashSize:]

	envelope, err := parseDRWABinaryPayload(canonicalPayload)
	if err != nil {
		return nil, fmt.Errorf("DRWA binary payload parse error: %w", err)
	}
	envelope.PayloadHash = payloadHash

	return envelope, nil
}

func parseDRWABinaryPayload(data []byte) (*drwaSyncEnvelope, error) {
	if len(data) == 0 {
		return nil, errors.New("empty DRWA binary canonical payload")
	}

	r := bytes.NewReader(data)

	var versionBuf [2]byte
	if _, err := io.ReadFull(r, versionBuf[:]); err != nil {
		return nil, fmt.Errorf("reading schema version: %w", err)
	}
	schemaVersion := binary.BigEndian.Uint16(versionBuf[:])
	if schemaVersion != drwaSyncEnvelopeSchemaVersion &&
		schemaVersion != drwaSyncEnvelopeSchemaVersionWithRecovery {
		return nil, fmt.Errorf("unsupported DRWA binary sync schema version: %d", schemaVersion)
	}

	callerTagByte, err := r.ReadByte()
	if err != nil {
		return nil, fmt.Errorf("reading caller tag: %w", err)
	}
	callerDomain, err := drwaCallerDomainFromTag(callerTagByte)
	if err != nil {
		return nil, err
	}

	if schemaVersion == drwaSyncEnvelopeSchemaVersionWithRecovery {
		return parseDRWABinaryPayloadV2(r, schemaVersion, callerDomain)
	}

	var operations []drwaSyncOperation
	for r.Len() > 0 {
		// Cap operations before full allocation (matches JSON path).
		if len(operations) >= drwaSyncMaxOperations {
			return nil, fmt.Errorf("DRWA binary payload exceeds %d operations", drwaSyncMaxOperations)
		}
		op, err := readDRWABinaryOperation(r)
		if err != nil {
			return nil, err
		}
		operations = append(operations, op)
	}

	return &drwaSyncEnvelope{
		SchemaVersion: schemaVersion,
		CallerDomain:  callerDomain,
		Operations:    operations,
	}, nil
}

func readDRWABinaryOperation(r *bytes.Reader) (drwaSyncOperation, error) {
	opTagByte, err := r.ReadByte()
	if err != nil {
		return drwaSyncOperation{}, fmt.Errorf("reading operation tag: %w", err)
	}
	opType, err := drwaOperationTypeFromTag(opTagByte)
	if err != nil {
		return drwaSyncOperation{}, err
	}

	tokenIDBytes, err := readDRWABinaryLenPrefixed(r)
	if err != nil {
		return drwaSyncOperation{}, fmt.Errorf("reading token_id: %w", err)
	}

	holderBytes, err := readDRWABinaryLenPrefixed(r)
	if err != nil {
		return drwaSyncOperation{}, fmt.Errorf("reading holder: %w", err)
	}

	var versionBuf [8]byte
	if _, err = io.ReadFull(r, versionBuf[:]); err != nil {
		return drwaSyncOperation{}, fmt.Errorf("reading version: %w", err)
	}
	version := binary.BigEndian.Uint64(versionBuf[:])

	body, err := readDRWABinaryLenPrefixed(r)
	if err != nil {
		return drwaSyncOperation{}, fmt.Errorf("reading body: %w", err)
	}

	// HolderProfile is the one canonical tokenless DRWA sync operation.
	// Its Rust serializer intentionally emits a zero-length token_id field,
	// and the Go side must preserve that contract to avoid rejecting valid
	// identity-profile sync envelopes at runtime.
	if opType != drwaSyncOpHolderProfile &&
		opType != drwaSyncOpGovernanceApprove &&
		opType != drwaSyncOpGovernanceExecute {
		// SM-3: Validate tokenID after decoding from binary. Reject empty,
		// oversized, or control-character-containing identifiers early.
		if err = validateDRWASyncField(string(tokenIDBytes), drwaSyncMaxTokenIDLen); err != nil {
			return drwaSyncOperation{}, fmt.Errorf("invalid token_id: %w", err)
		}
	}

	// For token_policy, asset_record, and authorized_caller_update the holder
	// field is 32 zero bytes
	// (canonical placeholder). Represent as empty string in-memory, matching
	// JSON behaviour and the encoder in drwaSerializedHolder.
	holder := ""
	if opType != drwaSyncOpTokenPolicy &&
		opType != drwaSyncOpAssetRecord &&
		opType != drwaSyncOpAuthorizedCallerUpdate &&
		opType != drwaSyncOpGovernanceApprove &&
		opType != drwaSyncOpGovernanceExecute {
		holder = string(holderBytes)
		// Binary holder fields carry raw address bytes, not printable text.
		// Real ManagedAddress payloads can contain 0x00 and other low bytes,
		// so the binary path must validate holder length without applying the
		// textual control-character rules used for token identifiers.
		if err = validateDRWABinaryHolderField(holderBytes, drwaSyncMaxHolderLen); err != nil {
			return drwaSyncOperation{}, fmt.Errorf("invalid holder: %w", err)
		}
	}

	return drwaSyncOperation{
		OperationType: opType,
		TokenID:       string(tokenIDBytes),
		Holder:        holder,
		Version:       version,
		Body:          body,
	}, nil
}

// validateDRWASyncField rejects empty strings, strings exceeding maxLen, and
// strings containing NUL or control characters (bytes < 0x20). This catches
// corrupted or malicious binary payloads before they reach storage.
func validateDRWASyncField(s string, maxLen int) error {
	if len(s) == 0 {
		return fmt.Errorf("empty field")
	}
	if len(s) > maxLen {
		return fmt.Errorf("field too long: %d > %d", len(s), maxLen)
	}
	for _, b := range []byte(s) {
		if b == 0 || b < 0x20 {
			return fmt.Errorf("field contains control character: 0x%02x", b)
		}
	}
	return nil
}

func validateDRWABinaryHolderField(holder []byte, maxLen int) error {
	if len(holder) == 0 {
		return fmt.Errorf("empty field")
	}
	if len(holder) > maxLen {
		return fmt.Errorf("field too long: %d > %d", len(holder), maxLen)
	}
	return nil
}

// drwaSyncMaxFieldBytes caps the length of any single binary field to prevent
// memory exhaustion from corrupted length prefixes. Set to 64 KB — no legitimate
// DRWA field (token ID, holder address, policy body) exceeds this.
// F-022: Canonical constant is builtInFunctions.DRWAMaxFieldBytes. Kept as a
// local alias to avoid changing all call sites. Value parity is ensured by the
// init() prefix check in drwa_sync_types.go.
const drwaSyncMaxFieldBytes = 64 * 1024

func readDRWABinaryLenPrefixed(r *bytes.Reader) ([]byte, error) {
	var lenBuf [4]byte
	if _, err := io.ReadFull(r, lenBuf[:]); err != nil {
		return nil, fmt.Errorf("reading length prefix: %w", err)
	}
	length := binary.BigEndian.Uint32(lenBuf[:])
	if length == 0 {
		return []byte{}, nil
	}
	if length > drwaSyncMaxFieldBytes {
		return nil, fmt.Errorf("DRWA binary field length %d exceeds max %d", length, drwaSyncMaxFieldBytes)
	}
	value := make([]byte, length)
	if _, err := io.ReadFull(r, value); err != nil {
		return nil, fmt.Errorf("reading %d-byte value: %w", length, err)
	}
	return value, nil
}

func drwaCallerDomainFromTag(tag byte) (string, error) {
	switch tag {
	case 0:
		return drwaSyncCallerPolicyRegistry, nil
	case 1:
		return drwaSyncCallerAssetManager, nil
	case 2:
		return drwaSyncCallerIdentityRegistry, nil
	case 3:
		return drwaSyncCallerAttestation, nil
	case 4:
		return drwaSyncCallerRecoveryAdmin, nil
	case 5:
		return drwaSyncCallerAuthAdmin, nil
	default:
		return "", fmt.Errorf("unknown DRWA caller domain tag: %d", tag)
	}
}

func parseDRWABinaryPayloadV2(
	r *bytes.Reader,
	schemaVersion uint16,
	callerDomain string,
) (*drwaSyncEnvelope, error) {
	preRecoveryStateHash, err := readDRWABinaryLenPrefixed(r)
	if err != nil {
		return nil, fmt.Errorf("reading pre_recovery_state_hash: %w", err)
	}

	var scopeCountBuf [2]byte
	if _, err = io.ReadFull(r, scopeCountBuf[:]); err != nil {
		return nil, fmt.Errorf("reading recovery scope count: %w", err)
	}
	scopeCount := int(binary.BigEndian.Uint16(scopeCountBuf[:]))
	recoveryScope := make([]string, 0, scopeCount)
	for idx := 0; idx < scopeCount; idx++ {
		scopeValue, readErr := readDRWABinaryLenPrefixed(r)
		if readErr != nil {
			return nil, fmt.Errorf("reading recovery scope %d: %w", idx, readErr)
		}
		if err = validateDRWASyncField(string(scopeValue), drwaSyncMaxTokenIDLen); err != nil {
			return nil, fmt.Errorf("invalid recovery scope %d: %w", idx, err)
		}
		recoveryScope = append(recoveryScope, string(scopeValue))
	}

	var opCountBuf [2]byte
	if _, err = io.ReadFull(r, opCountBuf[:]); err != nil {
		return nil, fmt.Errorf("reading operation count: %w", err)
	}
	opCount := int(binary.BigEndian.Uint16(opCountBuf[:]))
	if opCount > drwaSyncMaxOperations {
		return nil, fmt.Errorf("DRWA binary payload exceeds %d operations", drwaSyncMaxOperations)
	}

	operations := make([]drwaSyncOperation, 0, opCount)
	for idx := 0; idx < opCount; idx++ {
		op, readErr := readDRWABinaryOperation(r)
		if readErr != nil {
			return nil, fmt.Errorf("reading operation %d: %w", idx, readErr)
		}
		operations = append(operations, op)
	}
	if r.Len() != 0 {
		return nil, fmt.Errorf("DRWA binary payload has %d trailing bytes", r.Len())
	}

	return &drwaSyncEnvelope{
		SchemaVersion:        schemaVersion,
		CallerDomain:         callerDomain,
		Operations:           operations,
		PreRecoveryStateHash: preRecoveryStateHash,
		RecoveryScope:        recoveryScope,
	}, nil
}

func drwaOperationTypeFromTag(tag byte) (drwaSyncOperationType, error) {
	switch tag {
	case 0:
		return drwaSyncOpTokenPolicy, nil
	case 1:
		return drwaSyncOpAssetRecord, nil
	case 2:
		return drwaSyncOpHolderMirror, nil
	case 3:
		return drwaSyncOpHolderProfile, nil
	case 4:
		return drwaSyncOpHolderAuditorAuth, nil
	case 5:
		return drwaSyncOpHolderMirrorDelete, nil
	case 6:
		return drwaSyncOpAuthorizedCallerUpdate, nil
	case 7:
		return drwaSyncOpGovernanceApprove, nil
	case 8:
		return drwaSyncOpGovernanceExecute, nil
	default:
		return "", fmt.Errorf("unknown DRWA operation type tag: %d", tag)
	}
}

func applyDRWASyncEnvelope(
	adapter drwaSyncStateAdapter,
	envelope *drwaSyncEnvelope,
	maxOperations int,
	callerAddress []byte,
) (*drwaSyncApplyResult, error) {
	return applyDRWASyncEnvelopeInternal(adapter, envelope, maxOperations, callerAddress, false)
}

// applyDRWASyncEnvelopeGovernanceApproved is used by the governance execute
// path. The envelope has already passed M-of-N quorum verification, so
// governance routing is skipped to prevent re-entry into the proposal flow.
func applyDRWASyncEnvelopeGovernanceApproved(
	adapter drwaSyncStateAdapter,
	envelope *drwaSyncEnvelope,
	maxOperations int,
	callerAddress []byte,
) (*drwaSyncApplyResult, error) {
	return applyDRWASyncEnvelopeInternal(adapter, envelope, maxOperations, callerAddress, true)
}

func applyDRWASyncEnvelopeInternal(
	adapter drwaSyncStateAdapter,
	envelope *drwaSyncEnvelope,
	maxOperations int,
	callerAddress []byte,
	skipGovernance bool,
) (*drwaSyncApplyResult, error) {
	if adapter == nil {
		return nil, errors.New("nil DRWA sync adapter")
	}
	if envelope == nil {
		return nil, errors.New("nil DRWA sync envelope")
	}
	if len(envelope.Operations) == 0 {
		if err := verifyDRWANoopEnvelopeHash(envelope); err != nil {
			recordDRWAMetric(drwaMetricSyncApplyFailure)
			return nil, err
		}
		recordDRWAMetric(drwaMetricSyncApplyNoop)
		return &drwaSyncApplyResult{Noop: true}, nil
	}
	if len(envelope.Operations) > maxOperations {
		recordDRWAMetric(drwaMetricSyncApplyFailure)
		return nil, errors.New(drwaSyncRejectPayloadTooLarge)
	}
	if !isDRWASyncCallerAuthorized(adapter, envelope.CallerDomain, envelope.Operations, callerAddress) {
		recordDRWAMetric(drwaMetricSyncApplyFailure)
		recordDRWAMetric(drwaMetricSyncUnauthorizedCaller)
		return nil, errors.New(drwaSyncRejectUnauthorizedCaller)
	}

	// Phase 6 (G-11): Governance routing. Skipped when applying a
	// governance-approved envelope to prevent re-entry into the proposal flow.
	if !skipGovernance {
		// Route governance operation types through the governance engine.
		if len(envelope.Operations) > 0 {
			firstOp := envelope.Operations[0].OperationType
			if firstOp == drwaSyncOpGovernanceApprove || firstOp == drwaSyncOpGovernanceExecute {
				return handleDRWAGovernanceOperation(adapter, envelope, callerAddress)
			}
		}

		// When the caller is recovery_admin, check if governance is enabled
		// for the token. If so, create a proposal instead of applying the
		// envelope directly. If governance cannot handle the envelope, reject
		// instead of falling back to single-key recovery.
		if envelope.CallerDomain == drwaSyncCallerRecoveryAdmin {
			result, handled, govErr := maybeRouteToGovernance(adapter, envelope, callerAddress)
			if govErr != nil {
				recordDRWAMetric(drwaMetricSyncApplyFailure)
				return nil, govErr
			}
			if handled {
				return result, nil
			}
			if _, governanceCapable := adapter.(drwaSyncGovernanceProvider); governanceCapable {
				recordDRWAMetric(drwaMetricSyncApplyFailure)
				recordDRWAMetric(drwaMetricRecoveryGovernanceRequired)
				return nil, errDRWARecoveryGovernanceRequired
			}
		}
	}

	// : Enforce recovery scope — recovery_admin must specify which tokens
	// the recovery applies to. Operations on out-of-scope tokens are rejected.
	//
	// F1 (closes N3 + N7): the scope MUST contain exactly one token. Multi-token
	// recovery envelopes break two invariants: (1) governance routing in
	// extractGovernanceTokenID() decides on the first token only while the apply
	// path mutates all tokens in scope, allowing cross-token signer escalation
	// or single-key bypass; (2) verifyDRWAPreRecoveryStateHash() reconstructs a
	// manifest from the first token only, leaving subsequent tokens unbound by
	// the stale-state guard. Both bug classes disappear by construction once
	// scope is restricted to a single token. Every existing recovery/migration
	// envelope builder already produces single-token envelopes, so this matches
	// real usage.
	if envelope.CallerDomain == drwaSyncCallerRecoveryAdmin {
		if len(envelope.RecoveryScope) == 0 {
			recordDRWAMetric(drwaMetricSyncApplyFailure)
			return nil, errors.New(drwaSyncRejectRecoveryScopeRequired)
		}
		if len(envelope.RecoveryScope) != 1 {
			recordDRWAMetric(drwaMetricSyncApplyFailure)
			return nil, fmt.Errorf("%s: got %d tokens, expected exactly 1", drwaSyncRejectRecoveryScopeMultiToken, len(envelope.RecoveryScope))
		}
		scopeSet := make(map[string]struct{}, len(envelope.RecoveryScope))
		for _, tokenID := range envelope.RecoveryScope {
			scopeSet[tokenID] = struct{}{}
		}
		for _, op := range envelope.Operations {
			if _, inScope := scopeSet[op.TokenID]; !inScope {
				recordDRWAMetric(drwaMetricSyncApplyFailure)
				return nil, fmt.Errorf("%s: token %q not in recovery scope", drwaSyncRejectRecoveryScopeViolation, op.TokenID)
			}
		}
	}

	payloadHash, err := computeDRWASyncHash(envelope.CallerDomain, envelope.Operations)
	if err != nil {
		return nil, err
	}
	if !bytes.Equal(payloadHash, envelope.PayloadHash) {
		recordDRWAMetric(drwaMetricSyncApplyFailure)
		recordDRWAMetric(drwaMetricSyncHashMismatch)
		return nil, errors.New(drwaSyncRejectHashMismatch)
	}

	// : Enforce time-lock for recovery_admin writes. A compromised recovery
	// key can only overwrite state once per drwaSyncRecoveryTimelockBlocks window
	// per token. The time-lock check uses an optional interface so that adapters
	// without block context (e.g. test mocks) skip the check gracefully.
	if envelope.CallerDomain == drwaSyncCallerRecoveryAdmin {
		if err = enforceDRWARecoveryTimelock(adapter, envelope.Operations); err != nil {
			recordDRWAMetric(drwaMetricSyncApplyFailure)
			return nil, err
		}
	}

	// : Verify pre-recovery state hash for recovery_admin envelopes.
	// If the envelope carries a PreRecoveryStateHash (set by buildDRWARecoveryEnvelope),
	// recompute the current on-chain state hash and reject if it differs.
	// This prevents applying a stale recovery envelope after concurrent state changes.
	if envelope.CallerDomain == drwaSyncCallerRecoveryAdmin && len(envelope.PreRecoveryStateHash) > 0 {
		if err = verifyDRWAPreRecoveryStateHash(adapter, envelope); err != nil {
			recordDRWAMetric(drwaMetricSyncApplyFailure)
			return nil, err
		}
	}

	// SH-4: Log authorization scope for privileged domains. Every recovery_admin
	// and asset_manager write is logged with the specific operation types to
	// enable forensic analysis. The asset_manager domain is permitted both
	// drwaSyncOpHolderMirror and drwaSyncOpAssetRecord because the same Rust
	// contract (asset-manager) emits both via syncHolderCompliance and
	// syncAssetRecord. Splitting into separate caller domains would require a
	// cross-layer Rust contract change. This combined scope is an accepted risk
	// documented here; the authorization logging below provides auditability.
	if envelope.CallerDomain == drwaSyncCallerRecoveryAdmin ||
		envelope.CallerDomain == drwaSyncCallerAssetManager {
		logDRWASyncAuthorizationScope(envelope.CallerDomain, envelope.Operations)
	}

	// Capture journal snapshot before the batch loop. If any operation fails,
	// RevertToSnapshot rolls back ALL SaveAccount calls made by operations
	// 0..K-1, guaranteeing batch atomicity (C-6). The AccountsDB journal tracks
	// every SaveAccount as an entry; RevertToSnapshot truncates back to the
	// captured length, undoing all intermediate trie mutations.
	snapshot := adapter.Snapshot()
	result := &drwaSyncApplyResult{}

	for _, operation := range envelope.Operations {
		err = applyDRWASyncOperation(adapter, operation)
		if err != nil {
			rollbackErr := adapter.Rollback(snapshot)
			if rollbackErr != nil {
				recordDRWAMetric(drwaMetricSyncApplyFailure)
				return nil, fmt.Errorf("%s: %w", drwaSyncRejectBatchAtomicity, rollbackErr)
			}

			recordDRWAMetric(drwaMetricSyncApplyFailure)
			return nil, err
		}

		result.AppliedOperations++
		result.LastTokenID = operation.TokenID
	}

	// : After successful recovery_admin apply, record the current block nonce
	// so subsequent recovery attempts within the timelock window are rejected.
	// G-07: Timelock commit failure is a hard error — without the commit,
	// rate-limiting is silently disabled for all future recovery operations.
	if envelope.CallerDomain == drwaSyncCallerRecoveryAdmin {
		if timelockErr := commitDRWARecoveryTimelockBlock(adapter, envelope.Operations); timelockErr != nil {
			rollbackErr := adapter.Rollback(snapshot)
			if rollbackErr != nil {
				recordDRWAMetric(drwaMetricSyncApplyFailure)
				return nil, fmt.Errorf("%s: %w", drwaSyncRejectBatchAtomicity, rollbackErr)
			}
			recordDRWAMetric(drwaMetricSyncApplyFailure)
			return nil, timelockErr
		}
	}

	recordDRWAMetric(drwaMetricSyncApplySuccess)
	return result, nil
}

func applyDRWASyncOperation(adapter drwaSyncStateAdapter, operation drwaSyncOperation) error {
	if operation.OperationType == drwaSyncOpAuthorizedCallerUpdate {
		if err := validateDRWASyncField(operation.TokenID, drwaSyncMaxTokenIDLen); err != nil {
			return fmt.Errorf("invalid authorized caller domain in operation: %w", err)
		}
		normalizedAddress, err := NormalizeDRWAAuthorizedCallerAddress(string(operation.Body))
		if err != nil {
			return err
		}
		_, currentVersion, err := adapter.GetAuthorizedCallerAddressVersioned(operation.TokenID)
		if err != nil {
			return err
		}
		if err = validateDRWASyncVersion(currentVersion, operation.Version); err != nil {
			return err
		}

		return adapter.SetAuthorizedCallerAddressVersioned(operation.TokenID, normalizedAddress, operation.Version)
	}

	// SM-3: Validate operation fields regardless of decode path (JSON or binary).
	// Binary decode validates during parsing; this ensures JSON-decoded operations
	// also have validated fields before storage key construction.
	if operation.OperationType != drwaSyncOpHolderProfile {
		if err := validateDRWASyncField(operation.TokenID, drwaSyncMaxTokenIDLen); err != nil {
			return fmt.Errorf("invalid TokenID in operation: %w", err)
		}
	}
	if operation.Holder != "" {
		switch operation.OperationType {
		case drwaSyncOpHolderMirror,
			drwaSyncOpHolderProfile,
			drwaSyncOpHolderAuditorAuth,
			drwaSyncOpHolderMirrorDelete:
			if err := validateDRWABinaryHolderField([]byte(operation.Holder), drwaSyncMaxHolderLen); err != nil {
				return fmt.Errorf("invalid Holder in operation: %w", err)
			}
		default:
			if err := validateDRWASyncField(operation.Holder, drwaSyncMaxHolderLen); err != nil {
				return fmt.Errorf("invalid Holder in operation: %w", err)
			}
		}
	}

	switch operation.OperationType {
	case drwaSyncOpTokenPolicy:
		currentVersion, err := adapter.GetTokenPolicyVersion(operation.TokenID)
		if err != nil {
			return fmt.Errorf("DRWA token policy version read failed for %q: %w", operation.TokenID, err)
		}
		err = validateDRWASyncVersion(currentVersion, operation.Version)
		if err != nil {
			return err
		}
		err = adapter.PutTokenPolicyBody(operation.TokenID, operation.Version, operation.Body)
		if err != nil {
			return fmt.Errorf("DRWA token policy write failed for %q: %w", operation.TokenID, err)
		}
		if currentVersion == 0 {
			err = adapter.SetDRWAActive(operation.TokenID)
			if err != nil {
				return fmt.Errorf("DRWA active-flag write failed for %q: %w", operation.TokenID, err)
			}
			return nil
		}

		return nil
	case drwaSyncOpAssetRecord:
		currentVersion, err := adapter.GetAssetRecordVersion(operation.TokenID)
		if err != nil {
			return fmt.Errorf("DRWA asset record version read failed for %q: %w", operation.TokenID, err)
		}
		err = validateDRWASyncVersion(currentVersion, operation.Version)
		if err != nil {
			return err
		}

		err = adapter.PutAssetRecordBody(operation.TokenID, operation.Version, operation.Body)
		if err != nil {
			return fmt.Errorf("DRWA asset record write failed for %q: %w", operation.TokenID, err)
		}
		return nil
	case drwaSyncOpHolderMirror:
		currentVersion, err := adapter.GetHolderMirrorVersion(operation.TokenID, operation.Holder)
		if err != nil {
			return fmt.Errorf("DRWA holder mirror version read failed for token %q holder %x: %w", operation.TokenID, []byte(operation.Holder), err)
		}
		err = validateDRWASyncVersion(currentVersion, operation.Version)
		if err != nil {
			return err
		}

		err = adapter.PutHolderMirrorBody(operation.TokenID, operation.Holder, operation.Version, operation.Body)
		if err != nil {
			return fmt.Errorf("DRWA holder mirror write failed for token %q holder %x: %w", operation.TokenID, []byte(operation.Holder), err)
		}
		return nil
	case drwaSyncOpHolderProfile:
		currentVersion, err := adapter.GetHolderProfileVersion(operation.Holder)
		if err != nil {
			return fmt.Errorf("DRWA holder profile version read failed for holder %x: %w", []byte(operation.Holder), err)
		}
		err = validateDRWASyncVersion(currentVersion, operation.Version)
		if err != nil {
			return err
		}

		err = adapter.PutHolderProfileBody(operation.Holder, operation.Version, operation.Body)
		if err != nil {
			return fmt.Errorf("DRWA holder profile write failed for holder %x: %w", []byte(operation.Holder), err)
		}
		return nil
	case drwaSyncOpHolderAuditorAuth:
		currentVersion, err := adapter.GetHolderAuditorAuthorizationVersion(operation.TokenID, operation.Holder)
		if err != nil {
			return fmt.Errorf("DRWA holder auditor-auth version read failed for token %q holder %x: %w", operation.TokenID, []byte(operation.Holder), err)
		}
		err = validateDRWASyncVersion(currentVersion, operation.Version)
		if err != nil {
			return err
		}

		err = adapter.PutHolderAuditorAuthorizationBody(operation.TokenID, operation.Holder, operation.Version, operation.Body)
		if err != nil {
			return fmt.Errorf("DRWA holder auditor-auth write failed for token %q holder %x: %w", operation.TokenID, []byte(operation.Holder), err)
		}
		return nil
	case drwaSyncOpHolderMirrorDelete:
		currentVersion, err := adapter.GetHolderMirrorVersion(operation.TokenID, operation.Holder)
		if err != nil {
			return fmt.Errorf("DRWA holder mirror delete version read failed for token %q holder %x: %w", operation.TokenID, []byte(operation.Holder), err)
		}
		err = validateDRWASyncVersion(currentVersion, operation.Version)
		if err != nil {
			return err
		}

		err = adapter.DeleteHolderMirror(operation.TokenID, operation.Holder, operation.Version)
		if err != nil {
			return fmt.Errorf("DRWA holder mirror delete failed for token %q holder %x: %w", operation.TokenID, []byte(operation.Holder), err)
		}
		return nil
	default:
		return fmt.Errorf("unknown DRWA sync operation type: %s", operation.OperationType)
	}
}

// Each rejection reason has a distinct error constant for
// unambiguous diagnostics: overflow, stale, duplicate, non-sequential.
func validateDRWASyncVersion(currentVersion, nextVersion uint64) error {
	if currentVersion == math.MaxUint64 {
		recordDRWAMetric(drwaMetricSyncReplayRejected)
		return errors.New(drwaSyncRejectVersionOverflow)
	}
	if nextVersion < currentVersion {
		recordDRWAMetric(drwaMetricSyncReplayRejected)
		return errors.New(drwaSyncRejectReplayStale)
	}
	if nextVersion == currentVersion {
		recordDRWAMetric(drwaMetricSyncReplayRejected)
		return errors.New(drwaSyncRejectReplayDuplicate)
	}
	if nextVersion != currentVersion+1 {
		recordDRWAMetric(drwaMetricSyncReplayRejected)
		return errors.New(drwaSyncRejectVersionGap)
	}

	return nil
}

func isDRWASyncCallerAuthorized(
	adapter drwaSyncStateAdapter,
	callerDomain string,
	operations []drwaSyncOperation,
	callerAddress []byte,
) bool {
	// AUTHORIZATION MODEL: This function performs single-address authorization
	// per caller domain — it matches the calling tx sender against the address
	// registered for the declared domain via PutAuthorizedCallerAddress. The
	// match itself is a single bytes.Equal at the bottom of this function.
	//
	// M-of-N QUORUM: An M-of-N governance layer is implemented in
	// drwa_governance.go (DRWAGovernanceEngine, ProposeRecoveryOperation,
	// ApproveRecoveryOperation, ExecuteRecoveryOperation). For recovery_admin
	// envelopes, that engine is invoked from a separate routing layer above
	// this function (see maybeRouteToGovernance in drwa_governance.go and the
	// call site in applyDRWASyncEnvelopeInternal). The two layers are gated by
	// the optional drwaSyncGovernanceProvider interface.
	//
	// PRODUCTION STATE: drwaHookStateAdapter implements
	// drwaSyncGovernanceProvider, so recovery_admin envelopes either route
	// through governance or fail closed with DRWA_SYNC_GOVERNANCE_REQUIRED.
	if len(callerAddress) == 0 {
		return false
	}

	validOperations := false
	switch callerDomain {
	case drwaSyncCallerPolicyRegistry:
		for _, operation := range operations {
			if operation.OperationType != drwaSyncOpTokenPolicy {
				return false
			}
		}
		validOperations = true
	case drwaSyncCallerAssetManager:
		for _, operation := range operations {
			if operation.OperationType != drwaSyncOpHolderMirror && operation.OperationType != drwaSyncOpAssetRecord {
				return false
			}
		}
		validOperations = true
	case drwaSyncCallerIdentityRegistry:
		for _, operation := range operations {
			if operation.OperationType != drwaSyncOpHolderProfile {
				return false
			}
		}
		validOperations = true
	case drwaSyncCallerAttestation:
		for _, operation := range operations {
			if operation.OperationType != drwaSyncOpHolderAuditorAuth {
				return false
			}
		}
		validOperations = true
	case drwaSyncCallerRecoveryAdmin:
		// SECURITY — recovery_admin has the broadest write scope
		// (token_policy, holder_mirror, holder_mirror_delete). A compromised
		// recovery admin key can override ALL compliance state.
		// DEPLOYMENT: key MUST be in HSM with multi-party access control.
		// All recovery_admin operations MUST emit high-priority alerts.
		//
		// RH-9: KEY MANAGEMENT REQUIREMENTS
		// The recovery_admin private key MUST be stored in a FIPS 140-2 Level 3
		// (or higher) Hardware Security Module (HSM). Acceptable HSM providers:
		// AWS CloudHSM, Azure Dedicated HSM, Thales Luna, or equivalent.
		// Key ceremonies MUST follow a Shamir Secret Sharing (SSS) or multi-party
		// computation (MPC) split with a minimum 3-of-5 threshold.
		// HSM audit logs MUST be forwarded to the SIEM and retained for 7 years.
		// Key rotation: annual rotation required; the old key must remain valid
		// for one drwaSyncRecoveryTimelockBlocks window after rotation to allow
		// in-flight transactions to complete.
		// See also: RH-7 (multi-sig governance) for M-of-N authorization at the
		// contract level before recovery_admin operations reach the sync layer.
		for _, operation := range operations {
			if operation.OperationType != drwaSyncOpTokenPolicy &&
				operation.OperationType != drwaSyncOpHolderMirror &&
				operation.OperationType != drwaSyncOpHolderMirrorDelete &&
				operation.OperationType != drwaSyncOpGovernanceApprove &&
				operation.OperationType != drwaSyncOpGovernanceExecute {
				return false
			}
		}
		validOperations = true
	case drwaSyncCallerAuthAdmin:
		for _, operation := range operations {
			if operation.OperationType != drwaSyncOpAuthorizedCallerUpdate {
				return false
			}
		}
		validOperations = true
	default:
		return false
	}
	if !validOperations {
		return false
	}

	expectedAddress, err := adapter.GetAuthorizedCallerAddress(callerDomain)
	// Fail-closed: if the authorized caller address cannot be read (storage error
	// or missing configuration), deny the operation. This is intentional — a
	// transient read failure must never grant unauthorized access.
	if err != nil || len(expectedAddress) == 0 {
		return false
	}

	// M-08 (AUD-014): runtime structural validation. `bytes.Equal` silently
	// treats a length mismatch as "not equal" — which is safe, but it
	// masks provisioning bugs (truncated migration manifest, accidental
	// bech32 payload write, short-read from storage) as routine caller
	// rejections. We detect length mismatches explicitly and count them
	// on a dedicated metric so operators can distinguish "caller is wrong"
	// from "stored expected address is corrupt."
	//
	// Additionally, production MultiversX addresses are always
	// `drwaAuthorizedCallerAddressLen` (32) bytes. If either side deviates
	// from that length while being non-empty, the provisioning record is
	// malformed and authorization must fail closed.
	if len(expectedAddress) != len(callerAddress) ||
		len(expectedAddress) != drwaAuthorizedCallerAddressLen {
		recordDRWAMetric(drwaMetricAuthorizedCallerMalformed)
		return false
	}

	authorized := bytes.Equal(expectedAddress, callerAddress)
	// F-001: Track non-governance-protected sync writes. Full M-of-N quorum
	// extension is Phase 6; this metric provides pre-mainnet visibility into
	// single-address authorized writes that will require governance upgrade.
	if authorized && callerDomain != drwaSyncCallerRecoveryAdmin {
		recordDRWAMetric(drwaMetricNonGovernanceSyncWrite)
	}
	return authorized
}

// verifyDRWANoopEnvelopeHash verifies the hash of a noop (zero-operation)
// envelope when a PayloadHash is present. Detects corrupted or tampered
// payloads even when the operation list is empty.
func verifyDRWANoopEnvelopeHash(envelope *drwaSyncEnvelope) error {
	if len(envelope.PayloadHash) == 0 {
		return fmt.Errorf("DRWA_NOOP_ENVELOPE_HASH_REQUIRED: noop envelopes must include a non-empty PayloadHash")
	}
	expectedHash, err := computeDRWASyncHash(envelope.CallerDomain, nil)
	if err != nil {
		return fmt.Errorf("noop envelope hash computation failed: %w", err)
	}
	if !bytes.Equal(envelope.PayloadHash, expectedHash) {
		return errors.New("noop envelope hash mismatch")
	}
	return nil
}

func computeDRWASyncHash(callerDomain string, operations []drwaSyncOperation) ([]byte, error) {
	payload, err := serializeDRWASyncEnvelopePayload(callerDomain, operations)
	if err != nil {
		return nil, err
	}

	// F-023: Reuse Keccak hasher from pool.
	hasher := drwaKeccakPool.Get().(interface{ Compute(string) []byte })
	result := hasher.Compute(string(payload))
	drwaKeccakPool.Put(hasher)
	return result, nil
}

func serializeDRWASyncEnvelopePayload(callerDomain string, operations []drwaSyncOperation) ([]byte, error) {
	var payload bytes.Buffer

	callerTag, err := drwaCallerDomainTag(callerDomain)
	if err != nil {
		return nil, err
	}

	versionBytes := make([]byte, 2)
	binary.BigEndian.PutUint16(versionBytes, drwaSyncEnvelopeSchemaVersion)
	payload.Write(versionBytes)
	payload.WriteByte(callerTag)
	for _, operation := range operations {
		opTag, err := drwaOperationTypeTag(operation.OperationType)
		if err != nil {
			return nil, err
		}

		payload.WriteByte(opTag)
		writeDRWALengthPrefixed(&payload, []byte(operation.TokenID))
		writeDRWALengthPrefixed(&payload, drwaSerializedHolder(operation))

		versionBytes := make([]byte, 8)
		binary.BigEndian.PutUint64(versionBytes, operation.Version)
		payload.Write(versionBytes)
		writeDRWALengthPrefixed(&payload, operation.Body)
	}

	return payload.Bytes(), nil
}

func drwaCallerDomainTag(callerDomain string) (byte, error) {
	switch callerDomain {
	case drwaSyncCallerPolicyRegistry:
		return 0, nil
	case drwaSyncCallerAssetManager:
		return 1, nil
	case drwaSyncCallerIdentityRegistry:
		return 2, nil
	case drwaSyncCallerAttestation:
		return 3, nil
	case drwaSyncCallerRecoveryAdmin:
		return 4, nil
	case drwaSyncCallerAuthAdmin:
		return 5, nil
	default:
		return 0, fmt.Errorf("unknown DRWA sync caller domain: %s", callerDomain)
	}
}

func drwaOperationTypeTag(operationType drwaSyncOperationType) (byte, error) {
	switch operationType {
	case drwaSyncOpTokenPolicy:
		return 0, nil
	case drwaSyncOpHolderMirror:
		return 2, nil
	case drwaSyncOpHolderProfile:
		return 3, nil
	case drwaSyncOpHolderAuditorAuth:
		return 4, nil
	case drwaSyncOpHolderMirrorDelete:
		return 5, nil
	case drwaSyncOpAuthorizedCallerUpdate:
		return 6, nil
	case drwaSyncOpGovernanceApprove:
		return 7, nil
	case drwaSyncOpGovernanceExecute:
		return 8, nil
	case drwaSyncOpAssetRecord:
		return 1, nil
	default:
		return 0, fmt.Errorf("unknown DRWA sync operation type: %s", operationType)
	}
}

func drwaSerializedHolder(operation drwaSyncOperation) []byte {
	if operation.OperationType == drwaSyncOpTokenPolicy ||
		operation.OperationType == drwaSyncOpAssetRecord ||
		operation.OperationType == drwaSyncOpAuthorizedCallerUpdate ||
		operation.OperationType == drwaSyncOpGovernanceApprove ||
		operation.OperationType == drwaSyncOpGovernanceExecute {
		return make([]byte, 32)
	}

	return []byte(operation.Holder)
}

func writeDRWALengthPrefixed(payload *bytes.Buffer, value []byte) {
	lengthBytes := make([]byte, 4)
	binary.BigEndian.PutUint32(lengthBytes, uint32(len(value)))
	payload.Write(lengthBytes)
	payload.Write(value)
}

// drwaSyncGovernanceProvider is an optional interface that adapters can
// implement to supply a governance engine. When present and governance is
// configured for a token, recovery_admin envelopes are routed through the
// multi-sig quorum flow. Adapters that do not implement this interface
// (e.g. legacy or test mocks) fall through to single-key recovery.
type drwaSyncGovernanceProvider interface {
	GetGovernanceEngine() *DRWAGovernanceEngine
	GetCurrentBlockNonceForGovernance() (uint64, error)
}

// drwaSyncRecoveryTimelockProvider is an optional interface that adapters can
// implement to support the C-1 recovery time-lock. Adapters that do not
// implement this interface (e.g. test mocks) skip the time-lock check.
type drwaSyncRecoveryTimelockProvider interface {
	GetRecoveryLastBlock(tokenID string) (uint64, error)
	PutRecoveryLastBlock(tokenID string, blockNonce uint64) error
	GetCurrentBlockNonce() (uint64, error)
}

// F-002: Compile-time assertion that drwaHookStateAdapter satisfies
// drwaSyncRecoveryTimelockProvider. Prevents silent regression if the
// interface changes or the adapter implementation is removed.
var _ drwaSyncRecoveryTimelockProvider = (*drwaHookStateAdapter)(nil)
var _ drwaSyncGovernanceProvider = (*drwaHookStateAdapter)(nil)
var _ drwaMigrationStateReader = (*drwaHookStateAdapter)(nil)

// buildDRWARecoveryLastBlockKey returns the system account key that stores the
// block nonce of the last recovery_admin write for a given token.
func buildDRWARecoveryLastBlockKey(tokenID string) []byte {
	return []byte("drwa:recovery:lastBlock:" + tokenID)
}

// enforceDRWARecoveryTimelock checks whether the recovery_admin time-lock has
// elapsed for each token referenced in the operations. If the adapter does not
// implement drwaSyncRecoveryTimelockProvider, the check is skipped (test path).
func enforceDRWARecoveryTimelock(adapter drwaSyncStateAdapter, operations []drwaSyncOperation) error {
	timelockAdapter, ok := adapter.(drwaSyncRecoveryTimelockProvider)
	if !ok {
		// INTENTIONAL FALLBACK: Adapter does not implement the optional
		// drwaSyncRecoveryTimelockProvider interface (test mocks, legacy adapters).
		// F-002: Emit metric so operators can detect when timelock is skipped.
		recordDRWAMetric(drwaMetricRecoveryTimelockSkipped)
		return nil
	}

	currentBlock, err := timelockAdapter.GetCurrentBlockNonce()
	if err != nil {
		return fmt.Errorf("recovery timelock: cannot read current block: %w", err)
	}

	// Deduplicate tokenIDs to avoid redundant reads.
	checked := make(map[string]struct{})
	for _, op := range operations {
		if _, done := checked[op.TokenID]; done {
			continue
		}
		checked[op.TokenID] = struct{}{}

		lastBlock, readErr := timelockAdapter.GetRecoveryLastBlock(op.TokenID)
		if readErr != nil {
			return fmt.Errorf("recovery timelock: cannot read last block for %s: %w", op.TokenID, readErr)
		}
		// Guard against uint64 underflow when currentBlock < lastBlock (chain
		// reorganization or testnet rollback). Without this guard the subtraction
		// wraps to near-MaxUint64, silently bypassing the timelock.
		if lastBlock > 0 && currentBlock < lastBlock {
			recordDRWAMetric(drwaMetricSyncRecoveryTimelockReject)
			return fmt.Errorf("%w: token %s, current block %d < last recovery block %d (possible chain reorg — timelock enforced conservatively)",
				errDRWARecoveryTimelockActive, op.TokenID, currentBlock, lastBlock)
		}
		if lastBlock > 0 && currentBlock-lastBlock < drwaSyncRecoveryTimelockBlocks {
			recordDRWAMetric(drwaMetricSyncRecoveryTimelockReject)
			return fmt.Errorf("%w: token %s, last recovery at block %d, current block %d, required gap %d",
				errDRWARecoveryTimelockActive, op.TokenID, lastBlock, currentBlock, drwaSyncRecoveryTimelockBlocks)
		}
	}

	return nil
}

// commitDRWARecoveryTimelockBlock writes the current block nonce as the last
// recovery block for each token after a successful recovery_admin apply.
// G-07: Returns an error if the timelock commit fails. A silent skip would
// disable rate-limiting for all future recovery operations on the affected
// token, so the caller MUST treat this as a hard failure and revert.
func commitDRWARecoveryTimelockBlock(adapter drwaSyncStateAdapter, operations []drwaSyncOperation) error {
	timelockAdapter, ok := adapter.(drwaSyncRecoveryTimelockProvider)
	if !ok {
		// INTENTIONAL FALLBACK: Same opt-in pattern as enforceDRWARecoveryTimelock.
		// F-002: Emit metric so operators can detect when timelock commit is skipped.
		recordDRWAMetric(drwaMetricRecoveryTimelockSkipped)
		return nil
	}

	currentBlock, err := timelockAdapter.GetCurrentBlockNonce()
	if err != nil {
		return fmt.Errorf("recovery timelock commit: cannot read current block: %w", err)
	}

	committed := make(map[string]struct{})
	for _, op := range operations {
		if _, done := committed[op.TokenID]; done {
			continue
		}
		committed[op.TokenID] = struct{}{}
		if putErr := timelockAdapter.PutRecoveryLastBlock(op.TokenID, currentBlock); putErr != nil {
			return fmt.Errorf("recovery timelock commit: failed to persist for token %s at block %d: %w",
				op.TokenID, currentBlock, putErr)
		}
	}
	return nil
}

// logDRWASyncAuthorizationScope records a metric for each operation type used
// by a privileged caller domain. This enables forensic auditing of exactly
// which operation types were exercised by recovery_admin or asset_manager.
func logDRWASyncAuthorizationScope(callerDomain string, operations []drwaSyncOperation) {
	for _, op := range operations {
		recordDRWAMetric(fmt.Sprintf("auth_scope:%s:%s", callerDomain, op.OperationType))
	}
}

// verifyDRWAPreRecoveryStateHash checks that the on-chain state has not changed
// since the recovery envelope was built (C-2). The adapter must implement
// drwaMigrationStateReader to support this check; if it does not, the check is
// skipped (test path).
func verifyDRWAPreRecoveryStateHash(adapter drwaSyncStateAdapter, envelope *drwaSyncEnvelope) error {
	reader, ok := adapter.(drwaMigrationStateReader)
	if !ok {
		// Adapter does not support stored-value reads (test mock) — skip check.
		recordDRWAMetric(drwaMetricRecoveryStateHashSkipped)
		return nil
	}

	// Reconstruct a minimal manifest from the envelope operations to compute
	// the current state hash using the same algorithm as inspectDRWARecoveryState.
	tokenID := ""
	holderSet := make(map[string]struct{})
	for _, op := range envelope.Operations {
		if tokenID == "" {
			tokenID = op.TokenID
		}
		if op.Holder != "" {
			holderSet[op.Holder] = struct{}{}
		}
	}

	holders := make([]drwaMigrationHolder, 0, len(holderSet))
	for addr := range holderSet {
		holders = append(holders, drwaMigrationHolder{Address: addr})
	}

	manifest := &drwaRecoveryManifest{
		TokenID: tokenID,
		Holders: holders,
	}

	currentHash, err := computeDRWARecoveryStateHash(reader, manifest)
	if err != nil {
		return fmt.Errorf("pre-recovery state hash recomputation failed: %w", err)
	}

	if !bytes.Equal(currentHash, envelope.PreRecoveryStateHash) {
		return errDRWARecoveryStateChanged
	}

	return nil
}
