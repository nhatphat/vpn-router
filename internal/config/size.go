package config

import (
	"fmt"
	"strconv"
	"strings"

	"gopkg.in/yaml.v3"
)

// Size is a byte count that reads as "512KB" or "1MB" as well as a bare
// number. Buffer sizes are one of the few settings where the value matters and
// the units are easy to get wrong by three orders of magnitude.
type Size int

func (s Size) Bytes() int { return int(s) }

func (s Size) String() string {
	switch {
	case s >= 1<<20 && s%(1<<20) == 0:
		return fmt.Sprintf("%dMB", s/(1<<20))
	case s >= 1<<10 && s%(1<<10) == 0:
		return fmt.Sprintf("%dKB", s/(1<<10))
	default:
		return strconv.Itoa(int(s))
	}
}

func (s *Size) UnmarshalYAML(n *yaml.Node) error {
	var raw string
	if err := n.Decode(&raw); err != nil {
		var n64 int
		if err2 := n.Decode(&n64); err2 != nil {
			return err
		}
		*s = Size(n64)
		return nil
	}

	text := strings.TrimSpace(strings.ToUpper(raw))
	multiplier := 1

	switch {
	case strings.HasSuffix(text, "MB"):
		multiplier, text = 1<<20, strings.TrimSuffix(text, "MB")
	case strings.HasSuffix(text, "KB"):
		multiplier, text = 1<<10, strings.TrimSuffix(text, "KB")
	case strings.HasSuffix(text, "B"):
		text = strings.TrimSuffix(text, "B")
	}

	value, err := strconv.Atoi(strings.TrimSpace(text))
	if err != nil {
		return fmt.Errorf("invalid size %q: want a number of bytes, or a value like 512KB", raw)
	}
	*s = Size(value * multiplier)
	return nil
}
