/*
   Copyright The containerd Authors.

   Licensed under the Apache License, Version 2.0 (the "License");
   you may not use this file except in compliance with the License.
   You may obtain a copy of the License at

       http://www.apache.org/licenses/LICENSE-2.0

   Unless required by applicable law or agreed to in writing, software
   distributed under the License is distributed on an "AS IS" BASIS,
   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
   See the License for the specific language governing permissions and
   limitations under the License.
*/

// Copyright 2018 CNI authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software

// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package netns

import (
	"crypto/rand"
	"fmt"
	"os"
	"path"

	"github.com/containerd/containerd/mount"
	cnins "github.com/containernetworking/plugins/pkg/ns"
	"github.com/moby/sys/symlink"
	"golang.org/x/sys/unix"
)

// Some of the following functions are migrated from
// https://github.com/containernetworking/plugins/blob/master/pkg/testutils/netns_linux.go

// newNS creates a new persistent (bind-mounted) network namespace from
// /proc/<pid>/ns/net and returns the path to the network namespace.
func newNS(baseDir string, pid uint32) (nsPath string, err error) {
	b := make([]byte, 16)

	_, err = rand.Read(b)
	if err != nil {
		return "", fmt.Errorf("failed to generate random netns name: %w", err)
	}

	// Create the directory for mounting network namespaces
	// This needs to be a shared mountpoint in case it is mounted in to
	// other namespaces (containers)
	if err := os.MkdirAll(baseDir, 0755); err != nil {
		return "", err
	}

	// create an empty file at the mount point and fail if it already exists
	nsName := fmt.Sprintf("cni-%x-%x-%x-%x-%x", b[0:4], b[4:6], b[6:8], b[8:10], b[10:])
	nsPath = path.Join(baseDir, nsName)
	mountPointFd, err := os.OpenFile(nsPath, os.O_RDWR|os.O_CREATE|os.O_EXCL, 0666)
	if err != nil {
		return "", err
	}
	mountPointFd.Close()

	defer func() {
		// Ensure the mount point is cleaned up on errors
		if err != nil {
			os.RemoveAll(nsPath) // nolint: errcheck
		}
	}()

	procNsPath := getNetNSPathFromPID(pid)

	// bind mount the netns onto the mount point. This causes the namespace
	// to persist, even when there are no threads in the ns.
	if err = unix.Mount(procNsPath, nsPath, "none", unix.MS_BIND, ""); err != nil {
		return "", fmt.Errorf("failed to bind mount ns src: %v at %s: %w", procNsPath, nsPath, err)
	}

	return nsPath, nil
}

// unmountNS unmounts the NS held by the netns object. unmountNS is idempotent.
func unmountNS(path string) error {
	if _, err := os.Stat(path); err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return fmt.Errorf("failed to stat netns: %w", err)
	}
	path, err := symlink.FollowSymlinkInScope(path, "/")
	if err != nil {
		return fmt.Errorf("failed to follow symlink: %w", err)
	}
	if err := mount.Unmount(path, unix.MNT_DETACH); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("failed to umount netns: %w", err)
	}
	if err := os.RemoveAll(path); err != nil {
		return fmt.Errorf("failed to remove netns: %w", err)
	}
	return nil
}

func getNetNSPathFromPID(pid uint32) string {
	return fmt.Sprintf("/proc/%d/ns/net", pid)
}

// NetNS holds network namespace.
type NetNS struct {
	path string
}

// NewNetNS creates a new persistent (bind-mounted) network namespace from
// /proc/pid/ns/net.
func NewNetNS(baseDir string, pid uint32) (*NetNS, error) {
	path, err := newNS(baseDir, pid)
	if err != nil {
		return nil, fmt.Errorf("failed to setup netns: %w", err)
	}
	return &NetNS{path: path}, nil
}

// LoadNetNS loads existing network namespace.
func LoadNetNS(path string) *NetNS {
	return &NetNS{path: path}
}

// Remove removes network namespace. Remove is idempotent, meaning it might
// be invoked multiple times and provides consistent result.
func (n *NetNS) Remove() error {
	return unmountNS(n.path)
}

// Closed checks whether the network namespace has been closed.
func (n *NetNS) Closed() (bool, error) {
	ns, err := cnins.GetNS(n.path)
	if err != nil {
		if _, ok := err.(cnins.NSPathNotExistErr); ok {
			// The network namespace has already been removed.
			return true, nil
		}
		if _, ok := err.(cnins.NSPathNotNSErr); ok {
			// The network namespace is not mounted, remove it.
			if err := os.RemoveAll(n.path); err != nil {
				return false, fmt.Errorf("remove netns: %w", err)
			}
			return true, nil
		}
		return false, fmt.Errorf("get netns fd: %w", err)
	}
	if err := ns.Close(); err != nil {
		return false, fmt.Errorf("close netns fd: %w", err)
	}
	return false, nil
}

// GetPath returns network namespace path for sandbox container
func (n *NetNS) GetPath() string {
	return n.path
}

// Do runs a function in the network namespace.
func (n *NetNS) Do(f func(cnins.NetNS) error) error {
	ns, err := cnins.GetNS(n.path)
	if err != nil {
		return fmt.Errorf("get netns fd: %w", err)
	}
	defer ns.Close() // nolint: errcheck
	return ns.Do(f)
}
