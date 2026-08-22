package container

import (
	"crypto/sha256"
	"encoding/hex"
	"time"
)

// fixedModTime makes the tar archive deterministic; see BuildContext.
var fixedModTime = time.Unix(0, 0).UTC()

// ContextHash identifies the embedded build context.
func ContextHash() (string, error) {
	tarball, err := BuildContext()
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(tarball)
	return hex.EncodeToString(sum[:]), nil
}
