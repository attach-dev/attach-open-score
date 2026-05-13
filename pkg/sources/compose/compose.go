package compose

import (
	"fmt"
	"reflect"

	"github.com/attach-dev/attach-open-score/pkg/schema"
)

// EvidenceSet labels evidence produced by one source adapter family.
type EvidenceSet struct {
	Name     string
	Evidence []schema.Evidence
}

// Request combines already-normalized adapter evidence into one offline scorer
// request without changing reason codes, severities, or decision effects.
func Request(pkg schema.PackageIdentity, sets ...EvidenceSet) (schema.Request, error) {
	evidence, err := Evidence(sets...)
	if err != nil {
		return schema.Request{}, err
	}
	return schema.Request{Package: pkg, Evidence: evidence}, nil
}

// Evidence combines already-normalized adapter evidence, de-duplicating repeated
// source_ref entries and source_ref_ids while rejecting conflicting source_ref
// records that share an ID.
func Evidence(sets ...EvidenceSet) ([]schema.Evidence, error) {
	out := []schema.Evidence{}
	seenRefs := map[string]schema.SourceRef{}
	labels := []string{}

	for setIndex, set := range sets {
		label := set.Name
		if label == "" {
			label = fmt.Sprintf("set[%d]", setIndex)
		}
		for evidenceIndex, item := range set.Evidence {
			normalized, err := normalizeEvidence(item, seenRefs)
			if err != nil {
				return nil, fmt.Errorf("%s evidence[%d]: %w", label, evidenceIndex, err)
			}
			out = append(out, normalized)
			labels = append(labels, fmt.Sprintf("%s evidence[%d]", label, evidenceIndex))
		}
	}

	for i, item := range out {
		for _, sourceRefID := range item.Reason.SourceRefIDs {
			if _, ok := seenRefs[sourceRefID]; !ok {
				return nil, fmt.Errorf("%s reason %q references missing source_ref_id %q", labels[i], item.Reason.Code, sourceRefID)
			}
		}
	}

	return out, nil
}

func normalizeEvidence(item schema.Evidence, seenRefs map[string]schema.SourceRef) (schema.Evidence, error) {
	normalized := item

	localRefs := map[string]schema.SourceRef{}
	if normalized.SourceRef != nil {
		sourceRef := *normalized.SourceRef
		if err := rememberSourceRef(localRefs, seenRefs, sourceRef); err != nil {
			return schema.Evidence{}, err
		}
		normalized.SourceRef = &sourceRef
	}

	sourceRefs := make([]schema.SourceRef, 0, len(normalized.SourceRefs))
	for _, sourceRef := range normalized.SourceRefs {
		if existing, ok := localRefs[sourceRef.ID]; ok {
			if !reflect.DeepEqual(existing, sourceRef) {
				return schema.Evidence{}, fmt.Errorf("conflicting source_ref %q", sourceRef.ID)
			}
			continue
		}
		if err := rememberSourceRef(localRefs, seenRefs, sourceRef); err != nil {
			return schema.Evidence{}, err
		}
		sourceRefs = append(sourceRefs, sourceRef)
	}
	normalized.SourceRefs = sourceRefs
	normalized.Reason.SourceRefIDs = dedupeStrings(normalized.Reason.SourceRefIDs)

	return normalized, nil
}

func rememberSourceRef(localRefs, seenRefs map[string]schema.SourceRef, sourceRef schema.SourceRef) error {
	if sourceRef.ID == "" {
		return fmt.Errorf("source_ref id is required")
	}
	if existing, ok := seenRefs[sourceRef.ID]; ok && !reflect.DeepEqual(existing, sourceRef) {
		return fmt.Errorf("conflicting source_ref %q", sourceRef.ID)
	}
	localRefs[sourceRef.ID] = sourceRef
	seenRefs[sourceRef.ID] = sourceRef
	return nil
}

func dedupeStrings(values []string) []string {
	if len(values) == 0 {
		return values
	}

	out := make([]string, 0, len(values))
	seen := map[string]struct{}{}
	for _, value := range values {
		if _, ok := seen[value]; ok {
			continue
		}
		seen[value] = struct{}{}
		out = append(out, value)
	}
	return out
}
