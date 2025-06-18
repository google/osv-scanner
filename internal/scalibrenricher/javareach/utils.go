// Copyright 2025 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//	http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package javareach

import (
	"os"
	"syscall"
)

// mkdirAll simulates the same logic as os.MkdirAll but uses os.Root as input.
// Code logic copied from https://cs.opensource.google/go/go/+/refs/tags/go1.24.4:src/os/path.go;l=19
func mkdirAll(jarRoot *os.Root, path string, perm os.FileMode) error {
	// Fast path: if we can tell whether path is a directory or file, stop with success or error.
	dir, err := jarRoot.Stat(path)
	if err == nil {
		if dir.IsDir() {
			return nil
		}

		return &os.PathError{Op: "mkdir", Path: path, Err: syscall.ENOTDIR}
	}

	// Slow path: make sure parent exists and then call Mkdir for path.

	// Extract the parent folder from path by first removing any trailing
	// path separator and then scanning backward until finding a path
	// separator or reaching the beginning of the string.
	i := len(path) - 1

	for i >= 0 && os.IsPathSeparator(path[i]) {
		i--
	}
	for i >= 0 && !os.IsPathSeparator(path[i]) {
		i--
	}
	if i < 0 {
		i = 0
	}

	// recurse to ensure parent directory exists.
	if parent := path[:i]; len(parent) > 0 {
		err = mkdirAll(jarRoot, parent, perm)
		if err != nil {
			return err
		}
	}

	// Parent now exists; invoke Mkdir and use its result.
	err = jarRoot.Mkdir(path, perm)
	if err != nil {
		// Handle arguments like "foo/." by
		// double-checking that directory doesn't exist.
		dir, err1 := jarRoot.Lstat(path)
		if err1 == nil && dir.IsDir() {
			return nil
		}

		return err
	}

	return nil
}
