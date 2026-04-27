package hooks

import (
	"encoding/hex"
	"errors"
	"fmt"
	"math"
	"sort"
	"strings"
)

var (
	errDRWANilMigrationManifest       = errors.New("nil DRWA migration manifest")
	errDRWAEmptyMigrationTokenID      = errors.New("empty DRWA migration token id")
	errDRWAEmptyMigrationPolicyBody   = errors.New("empty DRWA migration policy body")
	errDRWAEmptyMigrationHolder       = errors.New("empty DRWA migration holder")
	errDRWADuplicateMigrationHolder   = errors.New("duplicate DRWA migration holder")
	errDRWAEmptyMigrationHolderBody   = errors.New("empty DRWA migration holder body")
	errDRWAInvalidMigrationVersion    = errors.New("invalid DRWA migration version")
	errDRWAMigrationTooManyOperations = errors.New("DRWA migration exceeds sync operation limit")
	errDRWAInvalidAuthorizedCaller    = errors.New("invalid DRWA authorized caller")
	errDRWANilMigrationCallerSink     = errors.New("nil DRWA migration caller sink")
)

type drwaMigrationHolder struct {
	Address string `json:"address"`
	Version uint64 `json:"version"`
	Body    []byte `json:"body"`
}

type drwaMigrationManifest struct {
	TokenID           string                `json:"token_id"`
	PolicyVersion     uint64                `json:"policy_version"`
	PolicyBody        []byte                `json:"policy_body"`
	Holders           []drwaMigrationHolder `json:"holders"`
	AuthorizedCallers map[string]string     `json:"authorized_callers,omitempty"`
}

type drwaMigrationSnapshot struct {
	TokenID              string
	TokenPolicy          *drwaSyncStoredValue
	Holders              map[string]*drwaSyncStoredValue
	RequestedHolderState map[string]drwaMigrationHolder
}

type drwaMigrationStateReader interface {
	drwaSyncStateAdapter
	GetTokenPolicyStored(tokenID string) (*drwaSyncStoredValue, error)
	GetHolderMirrorStored(tokenID, holder string) (*drwaSyncStoredValue, error)
}

type drwaMigrationAuthorizedCallerSink interface {
	PutAuthorizedCallerAddress(domain string, address []byte) error
}

func validateDRWAMigrationManifest(manifest *drwaMigrationManifest) error {
	if manifest == nil {
		return errDRWANilMigrationManifest
	}
	if strings.TrimSpace(manifest.TokenID) == "" {
		return errDRWAEmptyMigrationTokenID
	}
	if manifest.PolicyVersion == 0 {
		return errDRWAInvalidMigrationVersion
	}
	if len(manifest.PolicyBody) == 0 {
		return errDRWAEmptyMigrationPolicyBody
	}

	seen := make(map[string]struct{}, len(manifest.Holders))
	for _, holder := range manifest.Holders {
		addr := strings.TrimSpace(holder.Address)
		if addr == "" {
			return errDRWAEmptyMigrationHolder
		}
		if holder.Version == 0 {
			return errDRWAInvalidMigrationVersion
		}
		if len(holder.Body) == 0 {
			return errDRWAEmptyMigrationHolderBody
		}
		if _, exists := seen[addr]; exists {
			return fmt.Errorf("%w: %s", errDRWADuplicateMigrationHolder, addr)
		}
		seen[addr] = struct{}{}
	}

	if 1+len(manifest.Holders) > drwaSyncMaxOperations {
		return errDRWAMigrationTooManyOperations
	}

	if len(manifest.AuthorizedCallers) > 0 {
		requiredDomains := []string{
			drwaSyncCallerPolicyRegistry,
			drwaSyncCallerAssetManager,
			drwaSyncCallerIdentityRegistry,
			drwaSyncCallerAttestation,
			drwaSyncCallerRecoveryAdmin,
		}
		for _, domain := range requiredDomains {
			address, normalizeErr := normalizeDRWAAuthorizedCallerAddress(manifest.AuthorizedCallers[domain])
			if normalizeErr != nil || len(address) == 0 {
				return fmt.Errorf("%w: %s", errDRWAInvalidAuthorizedCaller, domain)
			}
		}
	}

	return nil
}

func buildDRWAMigrationEnvelope(manifest *drwaMigrationManifest) (*drwaSyncEnvelope, error) {
	err := validateDRWAMigrationManifest(manifest)
	if err != nil {
		return nil, err
	}

	sortedHolders := append([]drwaMigrationHolder(nil), manifest.Holders...)
	sort.Slice(sortedHolders, func(i, j int) bool {
		return sortedHolders[i].Address < sortedHolders[j].Address
	})

	operations := make([]drwaSyncOperation, 0, 1+len(sortedHolders))
	operations = append(operations, drwaSyncOperation{
		OperationType: drwaSyncOpTokenPolicy,
		TokenID:       manifest.TokenID,
		Version:       manifest.PolicyVersion,
		Body:          manifest.PolicyBody,
	})

	for _, holder := range sortedHolders {
		operations = append(operations, drwaSyncOperation{
			OperationType: drwaSyncOpHolderMirror,
			TokenID:       manifest.TokenID,
			Holder:        holder.Address,
			Version:       holder.Version,
			Body:          holder.Body,
		})
	}

	hash, err := computeDRWASyncHash(drwaSyncCallerRecoveryAdmin, operations)
	if err != nil {
		return nil, err
	}

	return &drwaSyncEnvelope{
		CallerDomain: drwaSyncCallerRecoveryAdmin,
		PayloadHash:  hash,
		Operations:   operations,
	}, nil
}

func captureDRWAMigrationSnapshot(adapter drwaMigrationStateReader, manifest *drwaMigrationManifest) (*drwaMigrationSnapshot, error) {
	err := validateDRWAMigrationManifest(manifest)
	if err != nil {
		return nil, err
	}

	tokenPolicy, err := adapter.GetTokenPolicyStored(manifest.TokenID)
	if err != nil {
		return nil, err
	}

	holders := make(map[string]*drwaSyncStoredValue, len(manifest.Holders))
	for _, holder := range manifest.Holders {
		stored, readErr := adapter.GetHolderMirrorStored(manifest.TokenID, holder.Address)
		if readErr != nil {
			return nil, readErr
		}
		holders[holder.Address] = stored
	}

	return &drwaMigrationSnapshot{
		TokenID:     manifest.TokenID,
		TokenPolicy: tokenPolicy,
		Holders:     holders,
		RequestedHolderState: func() map[string]drwaMigrationHolder {
			requested := make(map[string]drwaMigrationHolder, len(manifest.Holders))
			for _, holder := range manifest.Holders {
				requested[holder.Address] = holder
			}
			return requested
		}(),
	}, nil
}

// This function is only valid if the migration was previously applied via
// applyDRWASyncEnvelope. Calling it on a snapshot taken after adapter rollback
// will produce version-mismatched delete operations.
func buildDRWARollbackEnvelope(snapshot *drwaMigrationSnapshot) (*drwaSyncEnvelope, error) {
	if snapshot == nil {
		return nil, errors.New("nil DRWA migration snapshot")
	}

	operations := make([]drwaSyncOperation, 0, 1+len(snapshot.Holders))
	if snapshot.TokenPolicy != nil {
		// SM-2: Use stored.Version + 1 (post-migration version + 1) for rollback.
		// After migration, the on-chain version is the migration manifest version.
		// The rollback envelope must use a version that passes validateDRWASyncVersion
		// (nextVersion == currentVersion + 1). Since captureDRWAMigrationSnapshot
		// records the PRE-migration version, and migration writes manifest version,
		// the rollback must advance past the migration version. We use
		// stored.Version + 1 which, when applied after migration (on-chain == manifest
		// version), will pass validation only if manifest version == stored.Version + 1
		// (the expected case: manifest.PolicyVersion is pre + 1).
		if snapshot.TokenPolicy.Version == math.MaxUint64 {
			return nil, errors.New("rollback token policy version overflow")
		}
		operations = append(operations, drwaSyncOperation{
			OperationType: drwaSyncOpTokenPolicy,
			TokenID:       snapshot.TokenID,
			Version:       snapshot.TokenPolicy.Version + 1,
			Body:          snapshot.TokenPolicy.Body,
		})
	}

	holderAddresses := make([]string, 0, len(snapshot.Holders))
	for holder := range snapshot.Holders {
		holderAddresses = append(holderAddresses, holder)
	}
	sort.Strings(holderAddresses)

	for _, holder := range holderAddresses {
		stored := snapshot.Holders[holder]
		if stored == nil {
			requested, ok := snapshot.RequestedHolderState[holder]
			if !ok {
				continue
			}
			if requested.Version == math.MaxUint64 {
				return nil, errors.New("rollback delete version overflow")
			}
			operations = append(operations, drwaSyncOperation{
				OperationType: drwaSyncOpHolderMirrorDelete,
				TokenID:       snapshot.TokenID,
				Holder:        holder,
				Version:       requested.Version + 1,
			})
			continue
		}
		// SM-2: Same rationale as token policy — use stored.Version + 1
		// so the rollback version advances past the migration-applied version.
		if stored.Version == math.MaxUint64 {
			return nil, errors.New("rollback holder mirror version overflow")
		}
		operations = append(operations, drwaSyncOperation{
			OperationType: drwaSyncOpHolderMirror,
			TokenID:       snapshot.TokenID,
			Holder:        holder,
			Version:       stored.Version + 1,
			Body:          stored.Body,
		})
	}

	hash, err := computeDRWASyncHash(drwaSyncCallerRecoveryAdmin, operations)
	if err != nil {
		return nil, err
	}

	return &drwaSyncEnvelope{
		CallerDomain: drwaSyncCallerRecoveryAdmin,
		PayloadHash:  hash,
		Operations:   operations,
	}, nil
}

func persistDRWAMigrationAuthorizedCallers(
	sink drwaMigrationAuthorizedCallerSink,
	manifest *drwaMigrationManifest,
) error {
	if sink == nil {
		return errDRWANilMigrationCallerSink
	}

	err := validateDRWAMigrationManifest(manifest)
	if err != nil {
		return err
	}

	if len(manifest.AuthorizedCallers) == 0 {
		return nil
	}

	requiredDomains := []string{
		drwaSyncCallerAssetManager,
		drwaSyncCallerAttestation,
		drwaSyncCallerIdentityRegistry,
		drwaSyncCallerPolicyRegistry,
		drwaSyncCallerRecoveryAdmin,
	}
	for _, domain := range requiredDomains {
		address, normalizeErr := normalizeDRWAAuthorizedCallerAddress(manifest.AuthorizedCallers[domain])
		if normalizeErr != nil {
			return fmt.Errorf("%w: %s", errDRWAInvalidAuthorizedCaller, domain)
		}
		err = sink.PutAuthorizedCallerAddress(domain, address)
		if err != nil {
			return err
		}
	}

	return nil
}

// normalizeDRWAAuthorizedCallerAddress accepts two unambiguous formats:
//   - 64-character hex string (optionally 0x-prefixed): decoded to 32 bytes
//   - bech32 "erd1..." address: decoded via standard bech32 to 32 bytes
//
// SM-1: Raw 32-byte binary addresses are explicitly REJECTED. A 32-byte string
// is ambiguous — it could be binary or a short hex fragment. Requiring explicit
// hex (64 chars) or bech32 (erd1...) eliminates format confusion across the
// protocol boundary.
func normalizeDRWAAuthorizedCallerAddress(value string) ([]byte, error) {
	address := strings.TrimSpace(value)
	if address == "" {
		return nil, errDRWAInvalidAuthorizedCaller
	}

	// SM-1: Reject raw 32-byte binary. Any 32-byte string that contains
	// non-hex characters is raw binary — reject it outright. A 32-byte all-hex
	// string decodes to only 16 bytes, so it naturally falls through to
	// rejection below.
	if len(address) == 32 {
		return nil, fmt.Errorf("%w: raw 32-byte binary addresses are not accepted; use 64-char hex or bech32 (erd1...)", errDRWAInvalidAuthorizedCaller)
	}

	// Bech32 path: "erd1..." addresses.
	if strings.HasPrefix(address, "erd1") {
		decoded, bechErr := decodeBech32Address(address)
		if bechErr == nil && len(decoded) == 32 {
			if isAllZeroAddress(decoded) {
				return nil, errDRWAInvalidAuthorizedCaller
			}
			return decoded, nil
		}
		return nil, fmt.Errorf("%w: invalid bech32 address", errDRWAInvalidAuthorizedCaller)
	}

	// Hex path: 64-char hex (optionally 0x-prefixed).
	trimmedHex := strings.TrimPrefix(address, "0x")
	trimmedHex = strings.TrimPrefix(trimmedHex, "0X")
	decoded, err := hex.DecodeString(trimmedHex)
	if err == nil && len(decoded) == 32 {
		if isAllZeroAddress(decoded) {
			return nil, errDRWAInvalidAuthorizedCaller
		}
		return decoded, nil
	}

	return nil, errDRWAInvalidAuthorizedCaller
}

func NormalizeDRWAAuthorizedCallerAddress(value string) ([]byte, error) {
	return normalizeDRWAAuthorizedCallerAddress(value)
}

// decodeBech32Address decodes a bech32-encoded MultiversX address (erd1...) to
// its raw 32-byte public key. This is a simplified decoder that validates the
// "erd" human-readable part and extracts the 32-byte data payload.
func decodeBech32Address(address string) ([]byte, error) {
	hrp, data, err := bech32Decode(address)
	if err != nil {
		return nil, err
	}
	if hrp != "erd" {
		return nil, fmt.Errorf("invalid bech32 HRP: expected erd, got %s", hrp)
	}
	converted, err := bech32ConvertBits(data, 5, 8, false)
	if err != nil {
		return nil, err
	}
	if len(converted) != 32 {
		return nil, fmt.Errorf("invalid bech32 payload length: %d", len(converted))
	}
	return converted, nil
}

// bech32Decode is a minimal bech32 decoder sufficient for erd1... addresses.
func bech32Decode(bech string) (string, []byte, error) {
	if len(bech) < 8 || len(bech) > 90 {
		return "", nil, fmt.Errorf("invalid bech32 length: %d", len(bech))
	}
	pos := strings.LastIndex(bech, "1")
	if pos < 1 || pos+7 > len(bech) {
		return "", nil, fmt.Errorf("invalid bech32 separator position")
	}
	hrp := strings.ToLower(bech[:pos])
	dataPart := bech[pos+1:]

	const charset = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"
	values := make([]byte, len(dataPart))
	for i, c := range dataPart {
		idx := strings.IndexRune(charset, c)
		if idx < 0 {
			return "", nil, fmt.Errorf("invalid bech32 character: %c", c)
		}
		values[i] = byte(idx)
	}

	// Verify 6-byte checksum before stripping (H-1 FIX).
	// Without this, a typo in an authorized caller address would silently
	// register the wrong address, potentially locking out the legitimate caller
	// or granting access to an unintended one.
	if len(values) < 6 {
		return "", nil, fmt.Errorf("bech32 data too short for checksum")
	}
	if !bech32VerifyChecksum(hrp, values) {
		return "", nil, fmt.Errorf("invalid bech32 checksum")
	}
	return hrp, values[:len(values)-6], nil
}

// bech32VerifyChecksum validates the bech32 polymod checksum.
func bech32VerifyChecksum(hrp string, data []byte) bool {
	values := bech32HrpExpand(hrp)
	values = append(values, data...)
	return bech32Polymod(values) == 1
}

// bech32HrpExpand expands the human-readable part for checksum computation.
func bech32HrpExpand(hrp string) []byte {
	ret := make([]byte, 0, len(hrp)*2+1)
	for _, c := range hrp {
		ret = append(ret, byte(c>>5))
	}
	ret = append(ret, 0)
	for _, c := range hrp {
		ret = append(ret, byte(c&31))
	}
	return ret
}

// bech32Polymod computes the bech32 polynomial modular checksum.
func bech32Polymod(values []byte) uint32 {
	chk := uint32(1)
	generator := [5]uint32{0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3}
	for _, v := range values {
		top := chk >> 25
		chk = (chk&0x1ffffff)<<5 ^ uint32(v)
		for i := 0; i < 5; i++ {
			if (top>>uint(i))&1 == 1 {
				chk ^= generator[i]
			}
		}
	}
	return chk
}

// bech32ConvertBits converts between bit groups (5-bit bech32 to 8-bit bytes).
func bech32ConvertBits(data []byte, fromBits, toBits uint, pad bool) ([]byte, error) {
	acc := uint32(0)
	bits := uint(0)
	maxv := uint32((1 << toBits) - 1)
	var result []byte

	for _, value := range data {
		if uint32(value)>>fromBits != 0 {
			return nil, fmt.Errorf("invalid data range")
		}
		acc = (acc << fromBits) | uint32(value)
		bits += fromBits
		for bits >= toBits {
			bits -= toBits
			result = append(result, byte((acc>>bits)&maxv))
		}
	}

	if pad {
		if bits > 0 {
			result = append(result, byte((acc<<(toBits-bits))&maxv))
		}
	} else if bits >= fromBits || ((acc<<(toBits-bits))&maxv) != 0 {
		return nil, fmt.Errorf("invalid padding")
	}

	return result, nil
}

func isAllZeroAddress(addr []byte) bool {
	for _, b := range addr {
		if b != 0 {
			return false
		}
	}
	return true
}
