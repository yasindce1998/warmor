package sbompolicy

import "encoding/json"

type cdxBOM struct {
	BOMFormat   string         `json:"bomFormat"`
	SpecVersion string         `json:"specVersion"`
	Metadata    *cdxMetadata   `json:"metadata"`
	Components  []cdxComponent `json:"components"`
}

type cdxMetadata struct {
	Component *cdxComponent `json:"component"`
}

type cdxComponent struct {
	Type    string    `json:"type"`
	Name    string    `json:"name"`
	Version string    `json:"version"`
	Purl    string    `json:"purl"`
	Hashes  []cdxHash `json:"hashes"`
}

type cdxHash struct {
	Alg     string `json:"alg"`
	Content string `json:"content"`
}

func parseCycloneDX(data []byte) (*SBOM, error) {
	var bom cdxBOM
	if err := json.Unmarshal(data, &bom); err != nil {
		return nil, err
	}

	name := ""
	if bom.Metadata != nil && bom.Metadata.Component != nil {
		name = bom.Metadata.Component.Name
		if bom.Metadata.Component.Version != "" {
			name += ":" + bom.Metadata.Component.Version
		}
	}

	sbom := &SBOM{
		Format: "cyclonedx",
		Name:   name,
	}

	for _, comp := range bom.Components {
		if comp.Type != "library" && comp.Type != "application" && comp.Type != "operating-system" {
			continue
		}

		pkg := Package{
			Name:    comp.Name,
			Version: comp.Version,
			Type:    comp.Type,
			Purl:    comp.Purl,
		}
		if len(comp.Hashes) > 0 {
			pkg.Hashes = make(map[string]string, len(comp.Hashes))
			for _, h := range comp.Hashes {
				pkg.Hashes[h.Alg] = h.Content
			}
		}
		sbom.Packages = append(sbom.Packages, pkg)
	}

	return sbom, nil
}
