package supervisor

import (
	"os"
	"path/filepath"
	"strings"
)

// pausedFile records that the stack was deliberately switched off.
const pausedFile = "paused"

func readPaused(stateDir string) (bool, error) {
	data, err := os.ReadFile(filepath.Join(stateDir, pausedFile))
	if err != nil {
		return false, err
	}
	return strings.TrimSpace(string(data)) == "1", nil
}

// writePaused records the state so a reboot does not undo it. Someone who
// turned the stack off does not expect it back on because their laptop slept.
func writePaused(stateDir string, paused bool) error {
	path := filepath.Join(stateDir, pausedFile)
	if !paused {
		err := os.Remove(path)
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}

	if err := os.MkdirAll(stateDir, 0o755); err != nil {
		return err
	}
	return os.WriteFile(path, []byte("1\n"), 0o644)
}
