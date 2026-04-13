package hooks

import (
	"testing"

	builtInFunctions "github.com/multiversx/mx-chain-vm-common-go/builtInFunctions"
)

// TestInitPrefixValidation_DidNotPanic verifies that the init() function in
// drwa_sync_types.go executed without panicking, which means all prefix
// constants between this module and mx-chain-vm-common-go are aligned.
// If the binary loaded and this test runs, init() succeeded.
func TestInitPrefixValidation_DidNotPanic(t *testing.T) {
	// Cross-check a representative pair to confirm the constants are in sync.
	if drwaSyncTokenPolicyPrefix != builtInFunctions.DRWATokenPolicyPrefix {
		t.Fatalf("token policy prefix mismatch: local=%q vm-common=%q",
			drwaSyncTokenPolicyPrefix, builtInFunctions.DRWATokenPolicyPrefix)
	}
	if drwaSyncHolderMirrorPrefix != builtInFunctions.DRWAHolderMirrorPrefix {
		t.Fatalf("holder mirror prefix mismatch: local=%q vm-common=%q",
			drwaSyncHolderMirrorPrefix, builtInFunctions.DRWAHolderMirrorPrefix)
	}
	if drwaSyncHolderProfilePrefix != builtInFunctions.DRWAHolderProfilePrefix {
		t.Fatalf("holder profile prefix mismatch: local=%q vm-common=%q",
			drwaSyncHolderProfilePrefix, builtInFunctions.DRWAHolderProfilePrefix)
	}
	if drwaSyncHolderAuditorAuthPrefix != builtInFunctions.DRWAHolderAuditorAuthPrefix {
		t.Fatalf("holder auditor auth prefix mismatch: local=%q vm-common=%q",
			drwaSyncHolderAuditorAuthPrefix, builtInFunctions.DRWAHolderAuditorAuthPrefix)
	}
	if drwaSyncAssetRecordPrefix != builtInFunctions.DRWAAssetRecordPrefix {
		t.Fatalf("asset record prefix mismatch: local=%q vm-common=%q",
			drwaSyncAssetRecordPrefix, builtInFunctions.DRWAAssetRecordPrefix)
	}
}

func TestSyncLimits_ExpectedValues(t *testing.T) {
	if drwaSyncMaxOperations != 256 {
		t.Fatalf("expected drwaSyncMaxOperations=256, got %d", drwaSyncMaxOperations)
	}
	expectedPayloadBytes := 1 << 20 // 1 MB
	if drwaSyncMaxPayloadBytes != expectedPayloadBytes {
		t.Fatalf("expected drwaSyncMaxPayloadBytes=%d (1 MB), got %d",
			expectedPayloadBytes, drwaSyncMaxPayloadBytes)
	}
}

func TestOperationTypeConstants_NonEmpty(t *testing.T) {
	opTypes := []drwaSyncOperationType{
		drwaSyncOpTokenPolicy,
		drwaSyncOpAssetRecord,
		drwaSyncOpHolderMirror,
		drwaSyncOpHolderProfile,
		drwaSyncOpHolderAuditorAuth,
		drwaSyncOpHolderMirrorDelete,
	}
	for _, op := range opTypes {
		if op == "" {
			t.Error("found empty operation type constant")
		}
	}
}

func TestOperationTypeConstants_NoDuplicates(t *testing.T) {
	opTypes := []drwaSyncOperationType{
		drwaSyncOpTokenPolicy,
		drwaSyncOpAssetRecord,
		drwaSyncOpHolderMirror,
		drwaSyncOpHolderProfile,
		drwaSyncOpHolderAuditorAuth,
		drwaSyncOpHolderMirrorDelete,
	}
	seen := make(map[drwaSyncOperationType]bool)
	for _, op := range opTypes {
		if seen[op] {
			t.Errorf("duplicate operation type constant: %q", op)
		}
		seen[op] = true
	}
}

func TestCallerDomainConstants_NonEmpty(t *testing.T) {
	callers := []string{
		drwaSyncCallerPolicyRegistry,
		drwaSyncCallerAssetManager,
		drwaSyncCallerIdentityRegistry,
		drwaSyncCallerAttestation,
		drwaSyncCallerRecoveryAdmin,
	}
	for _, c := range callers {
		if c == "" {
			t.Error("found empty caller domain constant")
		}
	}
}

func TestCallerDomainConstants_NoDuplicates(t *testing.T) {
	callers := []string{
		drwaSyncCallerPolicyRegistry,
		drwaSyncCallerAssetManager,
		drwaSyncCallerIdentityRegistry,
		drwaSyncCallerAttestation,
		drwaSyncCallerRecoveryAdmin,
	}
	seen := make(map[string]bool)
	for _, c := range callers {
		if seen[c] {
			t.Errorf("duplicate caller domain constant: %q", c)
		}
		seen[c] = true
	}
}

func TestRejectReasonConstants_NonEmpty(t *testing.T) {
	reasons := []string{
		drwaSyncRejectUnauthorizedCaller,
		drwaSyncRejectPayloadTooLarge,
		drwaSyncRejectHashMismatch,
		drwaSyncRejectReplayStale,
		drwaSyncRejectReplayDuplicate,
		drwaSyncRejectVersionOverflow,
		drwaSyncRejectVersionGap,
		drwaSyncRejectBatchAtomicity,
	}
	for _, r := range reasons {
		if r == "" {
			t.Error("found empty reject reason constant")
		}
	}
}

func TestRejectReasonConstants_NoDuplicates(t *testing.T) {
	reasons := []string{
		drwaSyncRejectUnauthorizedCaller,
		drwaSyncRejectPayloadTooLarge,
		drwaSyncRejectHashMismatch,
		drwaSyncRejectReplayStale,
		drwaSyncRejectReplayDuplicate,
		drwaSyncRejectVersionOverflow,
		drwaSyncRejectVersionGap,
		drwaSyncRejectBatchAtomicity,
	}
	seen := make(map[string]bool)
	for _, r := range reasons {
		if seen[r] {
			t.Errorf("duplicate reject reason constant: %q", r)
		}
		seen[r] = true
	}
}
