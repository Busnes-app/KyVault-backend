package s3clean

import (
	"context"
	"errors"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
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
// directory, or s3://bucket/prefix[?options] erased with s3's endpoint and credentials,
// overridden by the root's own endpoint, region and enable_virtual_host_style options
// (the backend's OpenDAL format). An empty root is nil: that kind of object is not
// configured, and cleanup of it fails.
func ForRoot(root string, s3 Client) (Eraser, error) {
	if root == "" {
		return nil, nil
	}
	rest, isS3 := strings.CutPrefix(root, "s3://")
	if !isS3 {
		return &LocalFS{Root: root}, nil
	}
	rest, query, _ := strings.Cut(rest, "?")
	if strings.Contains(rest, "#") || strings.Contains(query, "#") {
		return nil, fmt.Errorf("s3clean: %q: fragments are not supported", root)
	}
	bucket, prefix, _ := strings.Cut(rest, "/")
	if bucket == "" {
		return nil, fmt.Errorf("s3clean: %q has no bucket", root)
	}
	if err := applyOptions(&s3, query); err != nil {
		return nil, fmt.Errorf("s3clean: %q: %w", root, err)
	}
	s3.Bucket, s3.Root = bucket, strings.Trim(prefix, "/")
	return &s3, nil
}

// applyOptions reads the options the backend honours. Anything else is refused, so the
// worker never erases somewhere other than where the backend writes.
func applyOptions(c *Client, query string) error {
	if query == "" {
		return nil
	}
	opts, err := url.ParseQuery(query)
	if err != nil {
		return err
	}
	vhost := ""
	for k, v := range opts {
		if len(v) != 1 {
			return fmt.Errorf("option %q given %d times", k, len(v))
		}
		switch k {
		case "endpoint":
			u, err := url.Parse(v[0])
			if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" {
				return fmt.Errorf("endpoint %q must be an http(s) URL without credentials, query or fragment", v[0])
			}
			c.Endpoint = strings.TrimRight(v[0], "/")
		case "region":
			c.Region = v[0]
		case "enable_virtual_host_style", "aws_virtual_hosted_style_request", "virtual_hosted_style_request":
			if vhost != "" && vhost != v[0] {
				return errors.New("conflicting virtual host style options")
			}
			vhost = v[0]
		case "default_storage_class":
			// Applies to writes only.
		default:
			return fmt.Errorf("option %q is not supported by the worker (credentials come from AWS_ACCESS_KEY_ID and AWS_SECRET_ACCESS_KEY)", k)
		}
	}
	if vhost != "" {
		on, err := strconv.ParseBool(vhost)
		if err != nil {
			return fmt.Errorf("enable_virtual_host_style: not a boolean: %q", vhost)
		}
		c.ForcePathStyle = !on
	}
	return nil
}
