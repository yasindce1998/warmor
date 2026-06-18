package sbompolicy

import (
	"encoding/json"
	"fmt"
	"os"
)

type SBOM struct {
	Format   string
	Name     string
	Packages []Package
}

type Package struct {
	Name    string
	Version string
	Type    string
	Purl    string
	Hashes  map[string]string
}

type ResolveOptions struct {
	RootFS string
	Level  string // "binary", "library", "all"
}

type ResolvedFile struct {
	Path        string
	PackageName string
	FileType    string // "binary", "library", "config", "other"
}

func ParseFile(path string, format string) (*SBOM, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading SBOM file: %w", err)
	}
	return Parse(data, format)
}

func Parse(data []byte, format string) (*SBOM, error) {
	if format == "" || format == "auto" {
		detected, err := detectFormat(data)
		if err != nil {
			return nil, err
		}
		format = detected
	}

	switch format {
	case "spdx":
		return parseSPDX(data)
	case "cyclonedx":
		return parseCycloneDX(data)
	default:
		return nil, fmt.Errorf("unsupported SBOM format: %q (supported: spdx, cyclonedx)", format)
	}
}

func detectFormat(data []byte) (string, error) {
	var probe map[string]json.RawMessage
	if err := json.Unmarshal(data, &probe); err != nil {
		return "", fmt.Errorf("invalid JSON: %w", err)
	}

	if _, ok := probe["spdxVersion"]; ok {
		return "spdx", nil
	}
	if _, ok := probe["bomFormat"]; ok {
		return "cyclonedx", nil
	}

	return "", fmt.Errorf("cannot auto-detect SBOM format: no 'spdxVersion' or 'bomFormat' key found")
}
