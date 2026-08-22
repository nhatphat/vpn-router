package config

import _ "embed"

// ExampleYAML is the annotated default configuration, embedded so that
// "vpnctl install" can write one without needing the source tree, and so the
// documented defaults cannot drift from the compiled ones — a test parses this
// file and compares it against Defaults().
//
//go:embed example.yaml
var ExampleYAML string
