package sbompolicy

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const spdxFixture = `{
  "spdxVersion": "SPDX-2.3",
  "name": "nginx-alpine",
  "packages": [
    {
      "name": "nginx",
      "versionInfo": "1.25.3-r1",
      "downloadLocation": "https://nginx.org",
      "primaryPackagePurpose": "APPLICATION",
      "checksums": [{"algorithm": "SHA256", "checksumValue": "abc123"}]
    },
    {
      "name": "musl",
      "versionInfo": "1.2.4-r2",
      "downloadLocation": "https://musl.libc.org",
      "primaryPackagePurpose": "LIBRARY"
    },
    {
      "name": "alpine-baselayout",
      "versionInfo": "3.4.3-r1",
      "downloadLocation": "https://alpinelinux.org",
      "primaryPackagePurpose": "OPERATING-SYSTEM"
    }
  ]
}`

const cyclonedxFixture = `{
  "bomFormat": "CycloneDX",
  "specVersion": "1.5",
  "metadata": {
    "component": {
      "type": "container",
      "name": "nginx",
      "version": "1.25-alpine"
    }
  },
  "components": [
    {
      "type": "library",
      "name": "musl",
      "version": "1.2.4-r2",
      "purl": "pkg:apk/alpine/musl@1.2.4-r2",
      "hashes": [{"alg": "SHA-256", "content": "def456"}]
    },
    {
      "type": "application",
      "name": "nginx",
      "version": "1.25.3-r1",
      "purl": "pkg:apk/alpine/nginx@1.25.3-r1"
    },
    {
      "type": "framework",
      "name": "should-be-skipped",
      "version": "1.0"
    }
  ]
}`

func TestParseSPDX(t *testing.T) {
	sbom, err := Parse([]byte(spdxFixture), "spdx")
	if err != nil {
		t.Fatalf("Parse SPDX: %v", err)
	}
	if sbom.Format != "spdx" {
		t.Errorf("format = %q, want spdx", sbom.Format)
	}
	if sbom.Name != "nginx-alpine" {
		t.Errorf("name = %q, want nginx-alpine", sbom.Name)
	}
	if len(sbom.Packages) != 3 {
		t.Fatalf("packages = %d, want 3", len(sbom.Packages))
	}
	if sbom.Packages[0].Name != "nginx" {
		t.Errorf("packages[0].name = %q, want nginx", sbom.Packages[0].Name)
	}
	if sbom.Packages[0].Type != "application" {
		t.Errorf("packages[0].type = %q, want application", sbom.Packages[0].Type)
	}
	if sbom.Packages[0].Hashes["SHA256"] != "abc123" {
		t.Errorf("packages[0] hash missing or wrong")
	}
}

func TestParseCycloneDX(t *testing.T) {
	sbom, err := Parse([]byte(cyclonedxFixture), "cyclonedx")
	if err != nil {
		t.Fatalf("Parse CycloneDX: %v", err)
	}
	if sbom.Format != "cyclonedx" {
		t.Errorf("format = %q, want cyclonedx", sbom.Format)
	}
	if sbom.Name != "nginx:1.25-alpine" {
		t.Errorf("name = %q, want nginx:1.25-alpine", sbom.Name)
	}
	if len(sbom.Packages) != 2 {
		t.Fatalf("packages = %d, want 2 (framework component filtered)", len(sbom.Packages))
	}
	if sbom.Packages[0].Purl != "pkg:apk/alpine/musl@1.2.4-r2" {
		t.Errorf("packages[0].purl = %q", sbom.Packages[0].Purl)
	}
}

func TestAutoDetectSPDX(t *testing.T) {
	sbom, err := Parse([]byte(spdxFixture), "auto")
	if err != nil {
		t.Fatalf("auto-detect SPDX: %v", err)
	}
	if sbom.Format != "spdx" {
		t.Errorf("format = %q, want spdx", sbom.Format)
	}
}

func TestAutoDetectCycloneDX(t *testing.T) {
	sbom, err := Parse([]byte(cyclonedxFixture), "auto")
	if err != nil {
		t.Fatalf("auto-detect CycloneDX: %v", err)
	}
	if sbom.Format != "cyclonedx" {
		t.Errorf("format = %q, want cyclonedx", sbom.Format)
	}
}

func TestAutoDetectInvalid(t *testing.T) {
	_, err := Parse([]byte(`{"foo": "bar"}`), "auto")
	if err == nil {
		t.Fatal("expected error for unrecognized format")
	}
	if !strings.Contains(err.Error(), "cannot auto-detect") {
		t.Errorf("error = %q, want auto-detect failure message", err.Error())
	}
}

func TestResolveAPK(t *testing.T) {
	rootfs := t.TempDir()
	apkDB := filepath.Join(rootfs, "lib", "apk", "db")
	os.MkdirAll(apkDB, 0755)

	content := `P:nginx
V:1.25.3-r1
F:usr/sbin
R:nginx
F:usr/share/nginx
R:index.html

P:musl
V:1.2.4-r2
F:lib
R:ld-musl-x86_64.so.1
R:libc.musl-x86_64.so.1
F:usr/lib
R:libm.so

`
	os.WriteFile(filepath.Join(apkDB, "installed"), []byte(content), 0644)

	packages := []Package{
		{Name: "nginx", Version: "1.25.3-r1"},
		{Name: "musl", Version: "1.2.4-r2"},
	}

	resolved, err := Resolve(packages, ResolveOptions{RootFS: rootfs, Level: "binary"})
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}

	if len(resolved) != 1 {
		t.Fatalf("binary level: got %d files, want 1 (nginx)", len(resolved))
	}
	if resolved[0].Path != "/usr/sbin/nginx" {
		t.Errorf("path = %q, want /usr/sbin/nginx", resolved[0].Path)
	}

	resolved, err = Resolve(packages, ResolveOptions{RootFS: rootfs, Level: "library"})
	if err != nil {
		t.Fatalf("Resolve library: %v", err)
	}
	if len(resolved) != 4 {
		t.Errorf("library level: got %d files, want 4 (nginx + 3 libs)", len(resolved))
	}

	resolved, err = Resolve(packages, ResolveOptions{RootFS: rootfs, Level: "all"})
	if err != nil {
		t.Fatalf("Resolve all: %v", err)
	}
	if len(resolved) != 5 {
		t.Errorf("all level: got %d files, want 5", len(resolved))
	}
}

func TestResolveDEB(t *testing.T) {
	rootfs := t.TempDir()
	infoDir := filepath.Join(rootfs, "var", "lib", "dpkg", "info")
	os.MkdirAll(infoDir, 0755)

	os.WriteFile(filepath.Join(infoDir, "nginx.list"), []byte("/usr/sbin/nginx\n/usr/share/nginx/index.html\n"), 0644)
	os.WriteFile(filepath.Join(infoDir, "libc6:amd64.list"), []byte("/lib/x86_64-linux-gnu/libc.so.6\n/usr/lib/x86_64-linux-gnu/libc.so\n"), 0644)

	packages := []Package{
		{Name: "nginx", Version: "1.25"},
		{Name: "libc6", Version: "2.36"},
	}

	resolved, err := Resolve(packages, ResolveOptions{RootFS: rootfs, Level: "binary"})
	if err != nil {
		t.Fatalf("Resolve DEB: %v", err)
	}
	if len(resolved) != 1 {
		t.Fatalf("binary level: got %d, want 1", len(resolved))
	}
	if resolved[0].Path != "/usr/sbin/nginx" {
		t.Errorf("path = %q, want /usr/sbin/nginx", resolved[0].Path)
	}
}

func TestGenerate(t *testing.T) {
	files := []ResolvedFile{
		{Path: "/usr/sbin/nginx", PackageName: "nginx", FileType: "binary"},
		{Path: "/usr/bin/envsubst", PackageName: "gettext", FileType: "binary"},
	}

	yamlBytes, err := Generate(files, GenerateOptions{
		PolicyName:          "test-policy",
		SBOMName:            "nginx:alpine",
		IncludeInterpreters: false,
	})
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}

	yaml := string(yamlBytes)
	if !strings.Contains(yaml, "name: test-policy") {
		t.Error("missing policy name")
	}
	if !strings.Contains(yaml, "default_action: deny") {
		t.Error("missing default_action")
	}
	if !strings.Contains(yaml, "/usr/sbin/nginx") {
		t.Error("missing nginx binary")
	}
	if !strings.Contains(yaml, "/usr/bin/envsubst") {
		t.Error("missing envsubst binary")
	}
	if !strings.Contains(yaml, "allow-sbom-binaries") {
		t.Error("missing rule name")
	}
	if !strings.Contains(yaml, "any_of: $sbom-binaries") {
		t.Error("missing variable reference")
	}
}

func TestGenerateWithInterpreters(t *testing.T) {
	files := []ResolvedFile{
		{Path: "/usr/sbin/nginx", PackageName: "nginx", FileType: "binary"},
	}

	yamlBytes, err := Generate(files, GenerateOptions{
		IncludeInterpreters: true,
		SBOMName:            "test",
	})
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}

	yaml := string(yamlBytes)
	if !strings.Contains(yaml, "/usr/bin/python3") {
		t.Error("missing interpreter python3")
	}
	if !strings.Contains(yaml, "/bin/sh") {
		t.Error("missing interpreter sh")
	}
}

func TestGenerateWithLibraries(t *testing.T) {
	files := []ResolvedFile{
		{Path: "/usr/sbin/nginx", PackageName: "nginx", FileType: "binary"},
		{Path: "/usr/lib/libpcre2.so.0", PackageName: "pcre2", FileType: "library"},
		{Path: "/usr/lib/libz.so.1", PackageName: "zlib", FileType: "library"},
	}

	yamlBytes, err := Generate(files, GenerateOptions{
		PolicyName:          "lib-test",
		IncludeInterpreters: false,
		SBOMName:            "test",
	})
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}

	yaml := string(yamlBytes)
	if !strings.Contains(yaml, "allow-sbom-libraries") {
		t.Error("missing library rule")
	}
	if !strings.Contains(yaml, "sbom-libraries") {
		t.Error("missing library variable")
	}
	if !strings.Contains(yaml, "/usr/lib/libpcre2.so.0") {
		t.Error("missing pcre2 library")
	}
}

func TestSanitizeName(t *testing.T) {
	cases := []struct {
		input, want string
	}{
		{"nginx:1.25-alpine", "nginx-1-25-alpine"},
		{"My App v2.0", "my-app-v2-0"},
		{"UPPER--CASE", "upper-case"},
		{"--trim--", "trim"},
	}
	for _, tc := range cases {
		got := sanitizeName(tc.input)
		if got != tc.want {
			t.Errorf("sanitizeName(%q) = %q, want %q", tc.input, got, tc.want)
		}
	}
}
