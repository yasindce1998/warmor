package integrity

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/yasindce1998/warmor/internal/streaming"
)

func writeFile(t *testing.T, path string, data []byte, perm os.FileMode) {
	t.Helper()
	if err := os.WriteFile(path, data, perm); err != nil {
		t.Fatal(err)
	}
}

func mkdirAll(t *testing.T, path string) {
	t.Helper()
	if err := os.MkdirAll(path, 0755); err != nil {
		t.Fatal(err)
	}
}

func TestHashFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "test-binary")
	content := []byte("#!/bin/sh\necho hello world\n")
	writeFile(t, path, content, 0755)

	hash, err := HashFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if hash.SHA256 == "" {
		t.Error("expected non-empty SHA256")
	}
	if hash.FastHash == 0 {
		t.Error("expected non-zero fast hash")
	}
	if hash.Size != int64(len(content)) {
		t.Errorf("size mismatch: got %d want %d", hash.Size, len(content))
	}
}

func TestHashFileConsistency(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "binary")
	writeFile(t, path, []byte("consistent content"), 0755)

	h1, _ := HashFile(path)
	h2, _ := HashFile(path)

	if h1.SHA256 != h2.SHA256 {
		t.Error("SHA256 not consistent")
	}
	if h1.FastHash != h2.FastHash {
		t.Error("FastHash not consistent")
	}
}

func TestFastHashBytes(t *testing.T) {
	data := []byte("hello world")
	h1 := FastHashBytes(data)
	h2 := FastHashBytes(data)
	if h1 != h2 {
		t.Error("FastHashBytes not consistent")
	}
	if h1 == 0 {
		t.Error("expected non-zero hash")
	}
}

func TestFastHashPath(t *testing.T) {
	h1 := FastHashPath("/usr/bin/nginx")
	h2 := FastHashPath("/usr/bin/nginx")
	h3 := FastHashPath("/usr/bin/curl")

	if h1 != h2 {
		t.Error("same path should produce same hash")
	}
	if h1 == h3 {
		t.Error("different paths should produce different hashes")
	}
}

func TestScanRootFS(t *testing.T) {
	root := t.TempDir()
	binDir := filepath.Join(root, "usr", "bin")
	mkdirAll(t, binDir)
	writeFile(t, filepath.Join(binDir, "nginx"), []byte("fake-nginx"), 0755)
	writeFile(t, filepath.Join(binDir, "curl"), []byte("fake-curl"), 0755)
	writeFile(t, filepath.Join(binDir, "readme.txt"), []byte("not executable"), 0644)

	db, err := ScanRootFS(root)
	if err != nil {
		t.Fatal(err)
	}
	if len(db.Binaries) != 2 {
		t.Fatalf("expected 2 binaries, got %d", len(db.Binaries))
	}
	if _, ok := db.Binaries["/usr/bin/nginx"]; !ok {
		t.Error("expected /usr/bin/nginx in database")
	}
	if _, ok := db.Binaries["/usr/bin/curl"]; !ok {
		t.Error("expected /usr/bin/curl in database")
	}
}

func TestDatabaseSaveAndLoad(t *testing.T) {
	root := t.TempDir()
	binDir := filepath.Join(root, "usr", "bin")
	mkdirAll(t, binDir)
	writeFile(t, filepath.Join(binDir, "app"), []byte("application"), 0755)

	db, _ := ScanRootFS(root)

	dbPath := filepath.Join(t.TempDir(), "integrity.json")
	if err := db.Save(dbPath); err != nil {
		t.Fatal(err)
	}

	loaded, err := LoadDatabase(dbPath)
	if err != nil {
		t.Fatal(err)
	}
	if len(loaded.Binaries) != len(db.Binaries) {
		t.Fatalf("loaded %d binaries, expected %d", len(loaded.Binaries), len(db.Binaries))
	}
	for path, orig := range db.Binaries {
		l, ok := loaded.Binaries[path]
		if !ok {
			t.Errorf("missing %s in loaded db", path)
			continue
		}
		if l.SHA256 != orig.SHA256 {
			t.Errorf("SHA256 mismatch for %s", path)
		}
	}
}

func TestDatabaseVerify(t *testing.T) {
	dir := t.TempDir()
	binPath := filepath.Join(dir, "app")
	writeFile(t, binPath, []byte("original"), 0755)

	db, _ := ScanPaths([]string{binPath})

	ok, err := db.Verify(binPath)
	if err != nil {
		t.Fatal(err)
	}
	if !ok {
		t.Error("expected verify to pass for unchanged file")
	}

	writeFile(t, binPath, []byte("tampered"), 0755)
	ok, err = db.Verify(binPath)
	if err != nil {
		t.Fatal(err)
	}
	if ok {
		t.Error("expected verify to fail for tampered file")
	}
}

func TestDatabaseVerifyUnknownPath(t *testing.T) {
	db := &Database{Binaries: make(map[string]*BinaryHash)}
	ok, err := db.Verify("/nonexistent")
	if err != nil {
		t.Fatal(err)
	}
	if ok {
		t.Error("expected false for unknown path")
	}
}

func TestCheckerPass(t *testing.T) {
	dir := t.TempDir()
	binPath := filepath.Join(dir, "good")
	writeFile(t, binPath, []byte("trusted binary"), 0755)

	db, _ := ScanPaths([]string{binPath})
	checker := NewChecker(db)

	result, err := checker.Check(binPath)
	if err != nil {
		t.Fatal(err)
	}
	if result != CheckPass {
		t.Errorf("expected PASS, got %s", result)
	}
}

func TestCheckerFail(t *testing.T) {
	dir := t.TempDir()
	binPath := filepath.Join(dir, "binary")
	writeFile(t, binPath, []byte("original"), 0755)

	db, _ := ScanPaths([]string{binPath})
	writeFile(t, binPath, []byte("tampered!"), 0755)

	checker := NewChecker(db)
	result, err := checker.Check(binPath)
	if err != nil {
		t.Fatal(err)
	}
	if result != CheckFail {
		t.Errorf("expected FAIL, got %s", result)
	}
}

func TestCheckerUnknownDeny(t *testing.T) {
	db := &Database{Binaries: make(map[string]*BinaryHash)}
	checker := NewChecker(db)

	result, _ := checker.Check("/some/unknown/binary")
	if result != CheckUnknown {
		t.Errorf("expected UNKNOWN, got %s", result)
	}
}

func TestCheckerUnknownAllow(t *testing.T) {
	db := &Database{Binaries: make(map[string]*BinaryHash)}
	checker := NewChecker(db, WithAllowUnknown(true))

	result, _ := checker.Check("/some/unknown/binary")
	if result != CheckPass {
		t.Errorf("expected PASS with allow-unknown, got %s", result)
	}
}

func TestCheckerCaching(t *testing.T) {
	dir := t.TempDir()
	binPath := filepath.Join(dir, "cached")
	writeFile(t, binPath, []byte("binary"), 0755)

	db, _ := ScanPaths([]string{binPath})
	checker := NewChecker(db)

	r1, _ := checker.Check(binPath)
	writeFile(t, binPath, []byte("changed"), 0755)
	r2, _ := checker.Check(binPath)

	if r1 != r2 {
		t.Error("cached result should be the same")
	}

	checker.ClearCache()
	r3, _ := checker.Check(binPath)
	if r3 != CheckFail {
		t.Errorf("after cache clear, expected FAIL, got %s", r3)
	}
}

func TestCheckerCheckEvent(t *testing.T) {
	dir := t.TempDir()
	binPath := filepath.Join(dir, "app")
	writeFile(t, binPath, []byte("original"), 0755)
	db, _ := ScanPaths([]string{binPath})

	writeFile(t, binPath, []byte("tampered"), 0755)
	checker := NewChecker(db)

	event := &streaming.SecurityEvent{
		EventType: "exec",
		Filename:  binPath,
		PID:       1234,
		Comm:      "app",
		CgroupID:  999,
	}

	result := checker.CheckEvent(event)
	if result == nil {
		t.Fatal("expected denial for tampered binary")
	}
	if result.Action != 1 { // ActionDeny
		t.Errorf("expected ActionDeny, got %d", result.Action)
	}

	violations := checker.Violations()
	if len(violations) != 1 {
		t.Fatalf("expected 1 violation, got %d", len(violations))
	}
	if violations[0].Path != binPath {
		t.Errorf("violation path mismatch")
	}
}

func TestCheckerCheckEventNonExec(t *testing.T) {
	db := &Database{Binaries: make(map[string]*BinaryHash)}
	checker := NewChecker(db)

	event := &streaming.SecurityEvent{
		EventType: "file",
		Filename:  "/etc/passwd",
	}
	result := checker.CheckEvent(event)
	if result != nil {
		t.Error("non-exec events should not be checked")
	}
}

func TestEnricher(t *testing.T) {
	dir := t.TempDir()
	binPath := filepath.Join(dir, "verified")
	writeFile(t, binPath, []byte("content"), 0755)
	db, _ := ScanPaths([]string{binPath})

	enricher := NewEnricher(NewChecker(db))
	event := &streaming.SecurityEvent{
		EventType: "exec",
		Filename:  binPath,
	}

	enricher.Enrich(context.Background(), event)
	if event.Labels["integrity"] != "PASS" {
		t.Errorf("expected PASS label, got %s", event.Labels["integrity"])
	}
}

func TestLookupFastHash(t *testing.T) {
	db := &Database{
		Binaries: map[string]*BinaryHash{
			"/usr/bin/nginx": {Path: "/usr/bin/nginx", SHA256: "abc123", FastHash: 42},
		},
	}

	hash := FastHashPath("/usr/bin/nginx")
	entry := db.LookupFastHash(hash)
	if entry == nil {
		t.Fatal("expected to find entry by fast hash")
	}
	if entry.SHA256 != "abc123" {
		t.Errorf("unexpected SHA256: %s", entry.SHA256)
	}
}
