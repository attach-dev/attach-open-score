package sources

import "github.com/attach-dev/attach-open-score/pkg/schema"

type Ref = schema.SourceRef

const (
	RedistributionAllowed    = "allowed"
	RedistributionRestricted = "restricted"
	RedistributionUnknown    = "unknown"

	PublicDisplayAllowed    = "allowed"
	PublicDisplayRestricted = "restricted"
	PublicDisplayUnknown    = "unknown"
)
