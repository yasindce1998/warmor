package sbompolicy

import "encoding/json"

type spdxDocument struct {
	SPDXVersion string        `json:"spdxVersion"`
	Name        string        `json:"name"`
	Packages    []spdxPackage `json:"packages"`
}

type spdxPackage struct {
	Name             string         `json:"name"`
	VersionInfo      string         `json:"versionInfo"`
	DownloadLocation string         `json:"downloadLocation"`
	Checksums        []spdxChecksum `json:"checksums"`
	PrimaryPurpose   string         `json:"primaryPackagePurpose"`
}

type spdxChecksum struct {
	Algorithm string `json:"algorithm"`
	Value     string `json:"checksumValue"`
}

func parseSPDX(data []byte) (*SBOM, error) {
	var doc spdxDocument
	if err := json.Unmarshal(data, &doc); err != nil {
		return nil, err
	}

	sbom := &SBOM{
		Format: "spdx",
		Name:   doc.Name,
	}

	for _, sp := range doc.Packages {
		pkg := Package{
			Name:    sp.Name,
			Version: sp.VersionInfo,
			Type:    mapSPDXPurpose(sp.PrimaryPurpose),
		}
		if len(sp.Checksums) > 0 {
			pkg.Hashes = make(map[string]string, len(sp.Checksums))
			for _, cs := range sp.Checksums {
				pkg.Hashes[cs.Algorithm] = cs.Value
			}
		}
		sbom.Packages = append(sbom.Packages, pkg)
	}

	return sbom, nil
}

func mapSPDXPurpose(purpose string) string {
	switch purpose {
	case "APPLICATION":
		return "application"
	case "LIBRARY":
		return "library"
	case "OPERATING-SYSTEM":
		return "os"
	default:
		return "library"
	}
}
