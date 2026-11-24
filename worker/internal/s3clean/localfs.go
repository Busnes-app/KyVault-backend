package s3clean

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// LocalFS erases under one local storage root, e.g. the Rust server's ATTACHMENTS_FOLDER.
// os.Root confines every removal to Root, symlinks included. A missing Root is an error,
// so an unmounted volume never reports a successful deletion.
type LocalFS struct {
	Root string
}

func (l *LocalFS) DeleteObject(_ context.Context, key string) error {
	return l.remove(key)
}

func (l *LocalFS) DeletePrefix(_ context.Context, prefix string) error {
	if !strings.HasSuffix(prefix, "/") {
		return fmt.Errorf("s3clean: refusing unsafe prefix %q", prefix)
	}
	return l.remove(prefix)
}

func (l *LocalFS) remove(key string) error {
	if err := CheckKey(key); err != nil {
		return err
	}
	root, err := os.OpenRoot(l.Root)
	if err != nil {
		return fmt.Errorf("s3clean: storage root: %w", err)
	}
	defer root.Close()
	return root.RemoveAll(filepath.FromSlash(strings.TrimSuffix(key, "/")))
}

// ForRoot returns the eraser for a storage root as the Rust server names it: a local
// directory, or s3://bucket/prefix erased with s3's endpoint and credentials. An empty
// root is nil: that kind of object is not configured, and cleanup of it fails.
func ForRoot(root string, s3 Client) (Eraser, error) {
	if root == "" {
		return nil, nil
	}
	rest, isS3 := strings.CutPrefix(root, "s3://")
	if !isS3 {
		return &LocalFS{Root: root}, nil
	}
	if strings.ContainsAny(rest, "?#") {
		return nil, fmt.Errorf("s3clean: %q: options in s3:// roots are not supported; set S3_* instead", root)
	}
	bucket, prefix, _ := strings.Cut(rest, "/")
	if bucket == "" {
		return nil, fmt.Errorf("s3clean: %q has no bucket", root)
	}
	s3.Bucket, s3.Root = bucket, strings.Trim(prefix, "/")
	return &s3, nil
}
