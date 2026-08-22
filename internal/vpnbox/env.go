package vpnbox

import (
	"bufio"
	"fmt"
	"os"
	"strings"
)

// LoadEnvFile reads a KEY=VALUE file of the kind compose used to consume.
//
// Values are never logged anywhere in this package: the file holds the TOTP
// secret that generates the VPN's one-time codes.
func LoadEnvFile(path string) (map[string]string, error) {
	out := make(map[string]string)
	if path == "" {
		return out, nil
	}

	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	line := 0
	for scanner.Scan() {
		line++
		text := strings.TrimSpace(scanner.Text())
		if text == "" || strings.HasPrefix(text, "#") {
			continue
		}
		text = strings.TrimPrefix(text, "export ")

		key, value, found := strings.Cut(text, "=")
		if !found {
			return nil, fmt.Errorf("%s:%d: expected KEY=VALUE", path, line)
		}

		key = strings.TrimSpace(key)
		value = strings.TrimSpace(value)
		// Strip one layer of matching quotes, the way a shell would.
		if len(value) >= 2 {
			if (value[0] == '"' && value[len(value)-1] == '"') ||
				(value[0] == '\'' && value[len(value)-1] == '\'') {
				value = value[1 : len(value)-1]
			}
		}
		out[key] = value
	}
	return out, scanner.Err()
}
