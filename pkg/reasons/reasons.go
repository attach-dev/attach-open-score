package reasons

const (
	KnownMaliciousPackage      = "KNOWN_MALICIOUS_PACKAGE"
	KnownVulnerabilityCritical = "KNOWN_VULNERABILITY_CRITICAL"
	KnownVulnerabilityHigh     = "KNOWN_VULNERABILITY_HIGH"
	KnownVulnerabilityModerate = "KNOWN_VULNERABILITY_MODERATE"
	NoKnownVulnerabilities     = "NO_KNOWN_VULNERABILITIES"

	PackageTooNew              = "PACKAGE_TOO_NEW"
	VersionTooNew              = "VERSION_TOO_NEW"
	PackageUnpublishedOrYanked = "PACKAGE_UNPUBLISHED_OR_YANKED"
	DeprecatedPackage          = "DEPRECATED_PACKAGE"

	InstallScriptPresent     = "INSTALL_SCRIPT_PRESENT"
	SuspiciousInstallScript  = "SUSPICIOUS_INSTALL_SCRIPT"
	SuspiciousBinaryArtifact = "SUSPICIOUS_BINARY_ARTIFACT"
	ArtifactDigestMismatch   = "ARTIFACT_DIGEST_MISMATCH"

	PossibleTyposquat       = "POSSIBLE_TYPOSQUAT"
	DependencyConfusionRisk = "DEPENDENCY_CONFUSION_RISK"
	UnresolvedPackage       = "UNRESOLVED_PACKAGE"
	UnsupportedEcosystem    = "UNSUPPORTED_ECOSYSTEM"

	LowRepositoryHealth        = "LOW_REPOSITORY_HEALTH"
	RepositoryMappingUncertain = "REPOSITORY_MAPPING_UNCERTAIN"
	MaintainerActivityLow      = "MAINTAINER_ACTIVITY_LOW"

	SourceUnavailable     = "SOURCE_UNAVAILABLE"
	SourceTermsBlocked    = "SOURCE_TERMS_BLOCKED"
	SourceStale           = "SOURCE_STALE"
	InsufficientData      = "INSUFFICIENT_DATA"
	ConflictingSourceData = "CONFLICTING_SOURCE_DATA"
)

var Known = map[string]struct{}{
	KnownMaliciousPackage:      {},
	KnownVulnerabilityCritical: {},
	KnownVulnerabilityHigh:     {},
	KnownVulnerabilityModerate: {},
	NoKnownVulnerabilities:     {},
	PackageTooNew:              {},
	VersionTooNew:              {},
	PackageUnpublishedOrYanked: {},
	DeprecatedPackage:          {},
	InstallScriptPresent:       {},
	SuspiciousInstallScript:    {},
	SuspiciousBinaryArtifact:   {},
	ArtifactDigestMismatch:     {},
	PossibleTyposquat:          {},
	DependencyConfusionRisk:    {},
	UnresolvedPackage:          {},
	UnsupportedEcosystem:       {},
	LowRepositoryHealth:        {},
	RepositoryMappingUncertain: {},
	MaintainerActivityLow:      {},
	SourceUnavailable:          {},
	SourceTermsBlocked:         {},
	SourceStale:                {},
	InsufficientData:           {},
	ConflictingSourceData:      {},
}

func IsKnown(code string) bool {
	_, ok := Known[code]
	return ok
}
