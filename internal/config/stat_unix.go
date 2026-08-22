package config

import (
	"io/fs"
	"os"
	"syscall"
)

type ownerInfo struct {
	uid  uint32
	mode fs.FileMode
}

func ownerAndMode(info fs.FileInfo) (ownerInfo, bool) {
	st, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return ownerInfo{}, false
	}
	return ownerInfo{uid: st.Uid, mode: info.Mode().Perm()}, true
}

// OwnerGID is the group of the config file, which is the group of the user
// whose menu bar needs to reach the daemon's socket. Returns -1 when unknown.
func (c *Config) OwnerGID() int {
	info, err := os.Stat(c.Path)
	if err != nil {
		return -1
	}
	st, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return -1
	}
	return int(st.Gid)
}
