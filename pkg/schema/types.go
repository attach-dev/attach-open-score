package schema

import "time"

const VersionV0 = "attach-open-score/v0"

type Decision string

const (
	DecisionAllow   Decision = "ALLOW"
	DecisionAsk     Decision = "ASK"
	DecisionDeny    Decision = "DENY"
	DecisionUnknown Decision = "UNKNOWN"
)

type DecisionEffect string

const (
	DecisionEffectAllow   DecisionEffect = "ALLOW"
	DecisionEffectAsk     DecisionEffect = "ASK"
	DecisionEffectDeny    DecisionEffect = "DENY"
	DecisionEffectUnknown DecisionEffect = "UNKNOWN"
	DecisionEffectNone    DecisionEffect = "NONE"
)

type Confidence string

const (
	ConfidenceLow    Confidence = "LOW"
	ConfidenceMedium Confidence = "MEDIUM"
	ConfidenceHigh   Confidence = "HIGH"
)

type PackageIdentity struct {
	Ecosystem     string `json:"ecosystem"`
	Name          string `json:"name"`
	Version       string `json:"version,omitempty"`
	PURL          string `json:"purl"`
	RequestedSpec string `json:"requested_spec,omitempty"`
	Resolved      bool   `json:"resolved"`
	RepositoryURL string `json:"repository_url,omitempty"`
}

type Reason struct {
	Code           string         `json:"code"`
	Severity       string         `json:"severity"`
	DecisionEffect DecisionEffect `json:"decision_effect"`
	Message        string         `json:"message"`
	SourceRefIDs   []string       `json:"source_ref_ids,omitempty"`
	Details        map[string]any `json:"details,omitempty"`
}

type SourceRef struct {
	ID                  string `json:"id"`
	Source              string `json:"source"`
	SourceID            string `json:"source_id,omitempty"`
	URL                 string `json:"url"`
	RetrievedAt         string `json:"retrieved_at"`
	TTLSeconds          int    `json:"ttl_seconds"`
	LicenseOrTermsURL   string `json:"license_or_terms_url"`
	Attribution         string `json:"attribution"`
	AttributionRequired bool   `json:"attribution_required"`
	Redistribution      string `json:"redistribution"`
	PublicDisplay       string `json:"public_display"`
}

type Request struct {
	Package  PackageIdentity `json:"package"`
	Evidence []Evidence      `json:"evidence,omitempty"`
	Mode     string          `json:"mode,omitempty"`
}

type Evidence struct {
	Reason     Reason      `json:"reason"`
	SourceRef  *SourceRef  `json:"source_ref,omitempty"`
	SourceRefs []SourceRef `json:"source_refs,omitempty"`
}

type Verdict struct {
	SchemaVersion string          `json:"schema_version"`
	PolicyProfile string          `json:"policy_profile,omitempty"`
	EngineVersion string          `json:"engine_version,omitempty"`
	Package       PackageIdentity `json:"package"`
	Decision      Decision        `json:"decision"`
	Score         *int            `json:"score"`
	Confidence    Confidence      `json:"confidence"`
	Reasons       []Reason        `json:"reasons"`
	SourceRefs    []SourceRef     `json:"source_refs"`
	EvaluatedAt   string          `json:"evaluated_at"`
	TTLSeconds    int             `json:"ttl_seconds"`
	Limitations   []string        `json:"limitations"`
	Debug         map[string]any  `json:"debug,omitempty"`
}

func (v Verdict) EvaluatedTime() (time.Time, error) {
	return time.Parse(time.RFC3339, v.EvaluatedAt)
}
