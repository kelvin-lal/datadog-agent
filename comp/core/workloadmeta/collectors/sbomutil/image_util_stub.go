// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2023-present Datadog, Inc.

//go:build !trivy

package sbomutil

import (
	workloadmeta "github.com/DataDog/datadog-agent/comp/core/workloadmeta/def"
)

// UpdateSBOMRepoMetadata does nothing
func UpdateSBOMRepoMetadata(sbom *workloadmeta.SBOM, _, _ []string) *workloadmeta.SBOM {
	return sbom
}

// CompressSBOM converts a workloadmeta.SBOM into a workloadmeta.CompressedSBOM.
func CompressSBOM(sbom *workloadmeta.SBOM) (*workloadmeta.CompressedSBOM, error) {
	if sbom == nil {
		return nil, nil
	}

	return &workloadmeta.CompressedSBOM{
		Bom:                nil,
		GenerationTime:     sbom.GenerationTime,
		GenerationDuration: sbom.GenerationDuration,
		Status:             sbom.Status,
		Error:              sbom.Error,
	}, nil
}

// UncompressSBOM converts a workloadmeta.CompressedSBOM into a workloadmeta.SBOM.
func UncompressSBOM(csbom *workloadmeta.CompressedSBOM) (*workloadmeta.SBOM, error) {
	if csbom == nil {
		return nil, nil
	}

	return &workloadmeta.SBOM{
		CycloneDXBOM:       nil,
		GenerationTime:     csbom.GenerationTime,
		GenerationDuration: csbom.GenerationDuration,
		Status:             csbom.Status,
		Error:              csbom.Error,
	}, nil
}
