package ghsa

import (
	"strconv"
	"strings"
)

func compareVersion(left, right string) (int, bool) {
	left = strings.TrimSpace(left)
	right = strings.TrimSpace(right)
	if left == "" || right == "" {
		return 0, false
	}
	if left == right {
		return 0, true
	}
	return compareNumericVersion(left, right)
}

func compareNumericVersion(left, right string) (int, bool) {
	leftParts, ok := numericVersionParts(left)
	if !ok {
		return 0, false
	}
	rightParts, ok := numericVersionParts(right)
	if !ok {
		return 0, false
	}

	maxLen := len(leftParts)
	if len(rightParts) > maxLen {
		maxLen = len(rightParts)
	}
	for i := 0; i < maxLen; i++ {
		var leftPart int64
		if i < len(leftParts) {
			leftPart = leftParts[i]
		}
		var rightPart int64
		if i < len(rightParts) {
			rightPart = rightParts[i]
		}
		switch {
		case leftPart < rightPart:
			return -1, true
		case leftPart > rightPart:
			return 1, true
		}
	}
	return 0, true
}

func numericVersionParts(value string) ([]int64, bool) {
	value = strings.TrimSpace(value)
	if value == "" {
		return nil, false
	}
	if value[0] == 'v' || value[0] == 'V' {
		value = value[1:]
	}
	if value == "" {
		return nil, false
	}

	rawParts := strings.Split(value, ".")
	if len(rawParts) == 0 {
		return nil, false
	}

	parts := make([]int64, 0, len(rawParts))
	for _, rawPart := range rawParts {
		if rawPart == "" {
			return nil, false
		}
		for _, r := range rawPart {
			if r < '0' || r > '9' {
				return nil, false
			}
		}
		part, err := strconv.ParseInt(rawPart, 10, 64)
		if err != nil {
			return nil, false
		}
		parts = append(parts, part)
	}
	if len(parts) == 0 {
		return nil, false
	}
	return parts, true
}
