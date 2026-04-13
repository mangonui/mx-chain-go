package hooks

// Recovery scope limitation:
// recovery_admin can fix token_policy and holder_mirror only.
// holder_profile, holder_auditor_auth, and asset_record are managed by
// their respective Rust contracts (identity-registry, attestation, asset-manager).
// If these types are corrupted, recovery requires contract-level intervention.

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"sort"
	"strings"

	// F-023: keccak import removed — now using drwaKeccakPool from drwa_sync.go
)

var (
	errDRWANilRecoveryManifest              = errors.New("nil DRWA recovery manifest")
	errDRWANilRecoveryStateReader           = errors.New("nil DRWA recovery state reader")
	errDRWANilRecoveryReport                = errors.New("nil DRWA recovery report")
	errDRWARecoveryNotRepairable            = errors.New("DRWA recovery report not repairable")
	errDRWARecoveryEnumeratorError          = errors.New("DRWA recovery mirror enumeration failed")
	errDRWANilRecoveryEvidenceSink          = errors.New("nil DRWA recovery evidence sink")
	errDRWARecoveryUnexpectedHolderConflict = errors.New("DRWA recovery report contains unexpected holder also present in manifest")
	errDRWARecoveryManifestHashConflict     = errors.New("DRWA recovery manifest hash conflicts with previously applied manifest")
)

const (
	drwaRecoveryStatusInSync                  = "in_sync"
	drwaRecoveryStatusTokenPolicyMissing      = "token_policy_missing"
	drwaRecoveryStatusTokenPolicyCorrupt      = "token_policy_corrupt"
	drwaRecoveryStatusTokenPolicyVersionDrift = "token_policy_version_drift"
	drwaRecoveryStatusTokenPolicyBodyDrift    = "token_policy_body_drift"
	drwaRecoveryStatusHolderMirrorMissing     = "holder_mirror_missing"
	drwaRecoveryStatusHolderMirrorCorrupt     = "holder_mirror_corrupt"
	drwaRecoveryStatusHolderVersionDrift      = "holder_mirror_version_drift"
	drwaRecoveryStatusHolderBodyDrift         = "holder_mirror_body_drift"
	drwaRecoveryStatusUnexpectedHolderMirror  = "unexpected_holder_mirror"
)

type drwaRecoveryManifest = drwaMigrationManifest
type drwaRecoveryHolder = drwaMigrationHolder

type drwaRecoveryFinding struct {
	Status          string `json:"status"`
	TokenID         string `json:"token_id"`
	Holder          string `json:"holder,omitempty"`
	ExpectedVersion uint64 `json:"expected_version"`
	ObservedVersion uint64 `json:"observed_version"`
}

type drwaRecoveryReport struct {
	TokenID          string                `json:"token_id"`
	Findings         []drwaRecoveryFinding `json:"findings"`
	RequiresSafeMode bool                  `json:"requires_safe_mode"`
	Repairable       bool                  `json:"repairable"`
	// : StateHash is a keccak256 digest of the on-chain state at inspection
	// time. buildDRWARecoveryEnvelope embeds this hash into the envelope;
	// applyDRWASyncEnvelope verifies it still matches before applying, rejecting
	// the recovery if state changed between inspection and application.
	StateHash []byte `json:"state_hash,omitempty"`
}

type drwaRecoveryMirrorEnumerator interface {
	ListHolderMirrorAddresses(tokenID string) ([]string, error)
}

type drwaRecoveryEvidenceSink interface {
	PersistRecoveryEvidence(tokenID string, payload []byte) error
}

func validateDRWARecoveryManifest(manifest *drwaRecoveryManifest) error {
	if manifest == nil {
		return errDRWANilRecoveryManifest
	}

	return validateDRWAMigrationManifest((*drwaMigrationManifest)(manifest))
}

// computeRecoveryManifestHash returns a SHA-256 digest of the manifest JSON
// for immutability enforcement. Callers should persist this hash per token
// after the first successful recovery and reject mismatches on subsequent calls.
func computeRecoveryManifestHash(manifest *drwaRecoveryManifest) ([]byte, error) {
	// Build a canonical representation WITHOUT the non-deterministic map.
	// Sort AuthorizedCallers keys to ensure consistent hashing across nodes.
	type canonicalManifest struct {
		TokenID       string                `json:"token_id"`
		PolicyVersion uint64                `json:"policy_version"`
		PolicyBody    []byte                `json:"policy_body"`
		Holders       []drwaMigrationHolder `json:"holders"`
		SortedCallers [][2]string           `json:"authorized_callers_sorted,omitempty"`
	}
	// Sort holders by address to ensure deterministic hashing across nodes.
	sortedHolders := make([]drwaMigrationHolder, len(manifest.Holders))
	copy(sortedHolders, manifest.Holders)
	sort.SliceStable(sortedHolders, func(i, j int) bool {
		return sortedHolders[i].Address < sortedHolders[j].Address
	})

	cm := &canonicalManifest{
		TokenID:       manifest.TokenID,
		PolicyVersion: manifest.PolicyVersion,
		PolicyBody:    manifest.PolicyBody,
		Holders:       sortedHolders,
	}
	if len(manifest.AuthorizedCallers) > 0 {
		keys := make([]string, 0, len(manifest.AuthorizedCallers))
		for k := range manifest.AuthorizedCallers {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		sorted := make([][2]string, 0, len(keys))
		for _, k := range keys {
			sorted = append(sorted, [2]string{k, manifest.AuthorizedCallers[k]})
		}
		cm.SortedCallers = sorted
	}
	data, err := json.Marshal(cm)
	if err != nil {
		return nil, fmt.Errorf("manifest marshal for hash: %w", err)
	}
	// F-023: Reuse Keccak hasher from pool.
	hasher := drwaKeccakPool.Get().(interface{ Compute(string) []byte })
	result := hasher.Compute(string(data))
	drwaKeccakPool.Put(hasher)
	return result, nil
}

func inspectDRWARecoveryState(reader drwaMigrationStateReader, manifest *drwaRecoveryManifest, previousManifestHash []byte) (*drwaRecoveryReport, error) {
	if reader == nil {
		return nil, errDRWANilRecoveryStateReader
	}

	err := validateDRWARecoveryManifest(manifest)
	if err != nil {
		return nil, err
	}

	// If a previous manifest was applied for this token,
	// verify the current manifest matches. Prevents conflicting manifests
	// from overwriting each other's state.
	if len(previousManifestHash) > 0 {
		currentHash, hashErr := computeRecoveryManifestHash(manifest)
		if hashErr != nil {
			return nil, hashErr
		}
		if !bytes.Equal(currentHash, previousManifestHash) {
			return nil, errDRWARecoveryManifestHashConflict
		}
	}

	report := &drwaRecoveryReport{
		TokenID:    manifest.TokenID,
		Repairable: true,
	}

	if err = inspectDRWATokenPolicyState(reader, manifest, report); err != nil {
		return nil, err
	}

	if err = inspectDRWAHolderStates(reader, manifest, report); err != nil {
		return nil, err
	}

	if len(report.Findings) == 0 {
		report.Findings = append(report.Findings, drwaRecoveryFinding{
			Status:          drwaRecoveryStatusInSync,
			TokenID:         manifest.TokenID,
			ExpectedVersion: manifest.PolicyVersion,
			ObservedVersion: manifest.PolicyVersion,
		})
		report.RequiresSafeMode = false
	}

	sort.Slice(report.Findings, func(i, j int) bool {
		left := report.Findings[i].Status + "|" + report.Findings[i].Holder
		right := report.Findings[j].Status + "|" + report.Findings[j].Holder
		return left < right
	})

	if report.RequiresSafeMode {
		recordDRWAMetric(drwaMetricRecoverySafeModeReport)
	}
	if !report.Repairable {
		recordDRWAMetric(drwaMetricRecoveryNonRepairable)
	}

	// : Compute a hash of the current on-chain state so that
	// buildDRWARecoveryEnvelope can bind the envelope to this exact state.
	// If state changes between inspection and apply, the hash won't match.
	stateHash, hashErr := computeDRWARecoveryStateHash(reader, manifest)
	if hashErr != nil {
		return nil, hashErr
	}
	report.StateHash = stateHash

	return report, nil
}

// inspectDRWATokenPolicyState checks the on-chain token policy against the
// manifest's expected state and appends findings to the report.
func inspectDRWATokenPolicyState(reader drwaMigrationStateReader, manifest *drwaRecoveryManifest, report *drwaRecoveryReport) error {
	tokenPolicy, err := reader.GetTokenPolicyStored(manifest.TokenID)
	if err != nil {
		return err
	}

	switch {
	case tokenPolicy == nil:
		report.Findings = append(report.Findings, drwaRecoveryFinding{
			Status:          drwaRecoveryStatusTokenPolicyMissing,
			TokenID:         manifest.TokenID,
			ExpectedVersion: manifest.PolicyVersion,
		})
		report.RequiresSafeMode = true
	case tokenPolicy.Version > 0 && len(tokenPolicy.Body) == 0:
		report.Findings = append(report.Findings, drwaRecoveryFinding{
			Status:          drwaRecoveryStatusTokenPolicyCorrupt,
			TokenID:         manifest.TokenID,
			ExpectedVersion: manifest.PolicyVersion,
			ObservedVersion: tokenPolicy.Version,
		})
		report.RequiresSafeMode = true
		report.Repairable = false
	case tokenPolicy.Version != manifest.PolicyVersion:
		report.Findings = append(report.Findings, drwaRecoveryFinding{
			Status:          drwaRecoveryStatusTokenPolicyVersionDrift,
			TokenID:         manifest.TokenID,
			ExpectedVersion: manifest.PolicyVersion,
			ObservedVersion: tokenPolicy.Version,
		})
		report.RequiresSafeMode = true
	case !bytes.Equal(tokenPolicy.Body, manifest.PolicyBody):
		report.Findings = append(report.Findings, drwaRecoveryFinding{
			Status:          drwaRecoveryStatusTokenPolicyBodyDrift,
			TokenID:         manifest.TokenID,
			ExpectedVersion: manifest.PolicyVersion,
			ObservedVersion: tokenPolicy.Version,
		})
		report.RequiresSafeMode = true
	}

	return nil
}

// inspectDRWAHolderStates checks each holder's on-chain mirror against the
// manifest and detects unexpected holder mirrors not listed in the manifest.
func inspectDRWAHolderStates(reader drwaMigrationStateReader, manifest *drwaRecoveryManifest, report *drwaRecoveryReport) error {
	for _, holder := range manifest.Holders {
		if err := inspectDRWASingleHolderState(reader, manifest.TokenID, holder, report); err != nil {
			return err
		}
	}

	return inspectDRWAUnexpectedHolders(reader, manifest, report)
}

// inspectDRWASingleHolderState compares one holder's on-chain mirror against
// the manifest entry and appends a finding to the report if they diverge.
func inspectDRWASingleHolderState(reader drwaMigrationStateReader, tokenID string, holder drwaRecoveryHolder, report *drwaRecoveryReport) error {
	stored, err := reader.GetHolderMirrorStored(tokenID, holder.Address)
	if err != nil {
		return err
	}

	switch {
	case stored == nil:
		report.Findings = append(report.Findings, drwaRecoveryFinding{
			Status:          drwaRecoveryStatusHolderMirrorMissing,
			TokenID:         tokenID,
			Holder:          holder.Address,
			ExpectedVersion: holder.Version,
		})
	case stored.Version > 0 && len(stored.Body) == 0:
		report.Findings = append(report.Findings, drwaRecoveryFinding{
			Status:          drwaRecoveryStatusHolderMirrorCorrupt,
			TokenID:         tokenID,
			Holder:          holder.Address,
			ExpectedVersion: holder.Version,
			ObservedVersion: stored.Version,
		})
		report.Repairable = false
	case stored.Version != holder.Version:
		report.Findings = append(report.Findings, drwaRecoveryFinding{
			Status:          drwaRecoveryStatusHolderVersionDrift,
			TokenID:         tokenID,
			Holder:          holder.Address,
			ExpectedVersion: holder.Version,
			ObservedVersion: stored.Version,
		})
	case !bytes.Equal(stored.Body, holder.Body):
		report.Findings = append(report.Findings, drwaRecoveryFinding{
			Status:          drwaRecoveryStatusHolderBodyDrift,
			TokenID:         tokenID,
			Holder:          holder.Address,
			ExpectedVersion: holder.Version,
			ObservedVersion: stored.Version,
		})
	}

	return nil
}

// inspectDRWAUnexpectedHolders detects holder mirrors present on-chain but
// absent from the manifest. Only runs when the reader supports enumeration.
func inspectDRWAUnexpectedHolders(reader drwaMigrationStateReader, manifest *drwaRecoveryManifest, report *drwaRecoveryReport) error {
	enumerator, ok := reader.(drwaRecoveryMirrorEnumerator)
	if !ok {
		return nil
	}

	addresses, listErr := enumerator.ListHolderMirrorAddresses(manifest.TokenID)
	if listErr != nil {
		return errors.Join(errDRWARecoveryEnumeratorError, listErr)
	}

	expected := make(map[string]struct{}, len(manifest.Holders))
	for _, holder := range manifest.Holders {
		expected[holder.Address] = struct{}{}
	}

	for _, address := range addresses {
		if _, exists := expected[address]; exists {
			continue
		}

		stored, readErr := reader.GetHolderMirrorStored(manifest.TokenID, address)
		if readErr != nil {
			return readErr
		}

		finding := drwaRecoveryFinding{
			Status:  drwaRecoveryStatusUnexpectedHolderMirror,
			TokenID: manifest.TokenID,
			Holder:  address,
		}
		if stored != nil {
			finding.ObservedVersion = stored.Version
		}

		report.Findings = append(report.Findings, finding)
	}

	return nil
}

// Recovery envelope uses manifest versions. Operators MUST set
// manifest.PolicyVersion and manifest.Holders[i].Version to (current_on_chain_version + 1)
// by calling inspectDRWARecoveryState first to read current versions, then incrementing.
// The applyDRWASyncEnvelope function enforces strict monotonic versioning
// (nextVersion == currentVersion + 1) and will reject mismatched versions.
func buildDRWARecoveryEnvelope(manifest *drwaRecoveryManifest, report *drwaRecoveryReport) (*drwaSyncEnvelope, error) {
	if report == nil {
		return nil, errDRWANilRecoveryReport
	}
	if !report.Repairable {
		return nil, errDRWARecoveryNotRepairable
	}

	if len(report.Findings) == 1 && report.Findings[0].Status == drwaRecoveryStatusInSync {
		payloadHash, err := computeDRWASyncHash(drwaSyncCallerRecoveryAdmin, nil)
		if err != nil {
			return nil, err
		}
		return &drwaSyncEnvelope{
			CallerDomain: drwaSyncCallerRecoveryAdmin,
			PayloadHash:  payloadHash,
			Operations:   nil,
			Noop:         true,
		}, nil
	}
	operations := make([]drwaSyncOperation, 0, 1+len(manifest.Holders)+len(report.Findings))
	repairEnvelope, err := buildDRWAMigrationEnvelope((*drwaMigrationManifest)(manifest))
	if err != nil {
		return nil, err
	}
	operations = append(operations, repairEnvelope.Operations...)

	cleanupOps, err := buildDRWARecoveryCleanupOperations(manifest, report)
	if err != nil {
		return nil, err
	}
	operations = append(operations, cleanupOps...)

	sort.SliceStable(operations, func(i, j int) bool {
		return drwaRecoveryOperationOrder(operations[i]) < drwaRecoveryOperationOrder(operations[j])
	})

	hash, err := computeDRWASyncHash(drwaSyncCallerRecoveryAdmin, operations)
	if err != nil {
		return nil, err
	}

	return &drwaSyncEnvelope{
		CallerDomain:         drwaSyncCallerRecoveryAdmin,
		PayloadHash:          hash,
		Operations:           operations,
		PreRecoveryStateHash: report.StateHash,
	}, nil
}

// buildDRWARecoveryCleanupOperations produces holder_mirror_delete operations
// for unexpected holders found in the recovery report. Returns an error if an
// unexpected holder conflicts with a manifest holder or if a version overflow
// would occur.
func buildDRWARecoveryCleanupOperations(manifest *drwaRecoveryManifest, report *drwaRecoveryReport) ([]drwaSyncOperation, error) {
	manifestHolders := make(map[string]struct{}, len(manifest.Holders))
	for _, holder := range manifest.Holders {
		manifestHolders[holder.Address] = struct{}{}
	}

	var ops []drwaSyncOperation
	for _, finding := range report.Findings {
		if finding.Status != drwaRecoveryStatusUnexpectedHolderMirror {
			continue
		}
		if _, conflict := manifestHolders[finding.Holder]; conflict {
			return nil, errDRWARecoveryUnexpectedHolderConflict
		}
		// Check for overflow before incrementing
		if finding.ObservedVersion == math.MaxUint64 {
			return nil, fmt.Errorf("recovery version overflow: holder %s at max version", finding.Holder)
		}
		nextVersion := finding.ObservedVersion + 1
		ops = append(ops, drwaSyncOperation{
			OperationType: drwaSyncOpHolderMirrorDelete,
			TokenID:       finding.TokenID,
			Holder:        finding.Holder,
			Version:       nextVersion,
		})
	}
	return ops, nil
}

func sanitizeDRWARecoveryManifest(manifest *drwaRecoveryManifest) {
	if manifest == nil {
		return
	}

	manifest.TokenID = strings.TrimSpace(manifest.TokenID)
	for idx := range manifest.Holders {
		manifest.Holders[idx].Address = strings.TrimSpace(manifest.Holders[idx].Address)
	}
}

func marshalDRWARecoveryEvidence(report *drwaRecoveryReport) ([]byte, error) {
	if report == nil {
		return nil, errDRWANilRecoveryReport
	}

	return json.MarshalIndent(report, "", "  ")
}

func persistDRWARecoveryEvidence(sink drwaRecoveryEvidenceSink, report *drwaRecoveryReport) error {
	if sink == nil {
		return errDRWANilRecoveryEvidenceSink
	}

	payload, err := marshalDRWARecoveryEvidence(report)
	if err != nil {
		return err
	}

	return sink.PersistRecoveryEvidence(report.TokenID, payload)
}

func drwaRecoveryOperationOrder(operation drwaSyncOperation) string {
	switch operation.OperationType {
	case drwaSyncOpTokenPolicy:
		return "0|"
	case drwaSyncOpHolderMirror:
		return "1|" + operation.Holder
	case drwaSyncOpHolderMirrorDelete:
		return "2|" + operation.Holder
	default:
		return "9|" + operation.Holder
	}
}

// computeDRWARecoveryStateHash produces a keccak256 digest of the current
// on-chain state for the token and all holders referenced in the manifest.
// This hash is embedded in the recovery envelope (C-2) so that apply can
// detect state mutations between inspection and execution.
func computeDRWARecoveryStateHash(reader drwaMigrationStateReader, manifest *drwaRecoveryManifest) ([]byte, error) {
	// F-023: Reuse Keccak hasher from pool.
	hasher := drwaKeccakPool.Get().(interface{ Compute(string) []byte })
	defer drwaKeccakPool.Put(hasher)
	var buf bytes.Buffer

	// Include token policy state.
	tokenPolicy, err := reader.GetTokenPolicyStored(manifest.TokenID)
	if err != nil {
		return nil, err
	}
	if tokenPolicy != nil {
		versionBytes := make([]byte, 8)
		binary.BigEndian.PutUint64(versionBytes, tokenPolicy.Version)
		buf.Write(versionBytes)
		buf.Write(tokenPolicy.Body)
	} else {
		buf.Write([]byte{0}) // sentinel for missing policy
	}

	// Include holder mirror state in deterministic order (manifest order is
	// validated/sorted by the caller).
	sortedHolders := make([]drwaMigrationHolder, len(manifest.Holders))
	copy(sortedHolders, manifest.Holders)
	sort.SliceStable(sortedHolders, func(i, j int) bool {
		return sortedHolders[i].Address < sortedHolders[j].Address
	})

	for _, holder := range sortedHolders {
		stored, readErr := reader.GetHolderMirrorStored(manifest.TokenID, holder.Address)
		if readErr != nil {
			return nil, readErr
		}
		buf.WriteString(holder.Address)
		if stored != nil {
			versionBytes := make([]byte, 8)
			binary.BigEndian.PutUint64(versionBytes, stored.Version)
			buf.Write(versionBytes)
			buf.Write(stored.Body)
		} else {
			buf.Write([]byte{0}) // sentinel for missing holder
		}
	}

	return hasher.Compute(buf.String()), nil
}
