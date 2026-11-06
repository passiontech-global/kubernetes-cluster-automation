// Package testhelp holds the leaf-level k8s test fakes: machinery
// that depends only on client-go/apimachinery (the httptest-backed
// probe seams and the real-scheme dynamic fake), with NO internal/*
// imports above the platform layer. It exists inside platform
// because internal/testutil is off-limits to platform tests —
// testutil imports internal/shared for the manager/contract helpers,
// and platform is the leaf. Domain test files may import testhelp
// directly, but the same symbols are re-exported through
// internal/testutil so existing tests keep a single import.
//
// Like internal/health/probetest this is non-_test scaffolding: the
// files must be importable from sibling packages' _test.go files, so
// the leaf-layer depguard rules apply here — k8s libs only.
package testhelp
