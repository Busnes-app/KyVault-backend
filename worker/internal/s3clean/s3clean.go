// Package s3clean erases tenant objects from one storage root: an S3 bucket prefix or a
// local directory, the same roots the Rust server's ATTACHMENTS_FOLDER and SENDS_FOLDER
// name. Keys are relative to the root and always start with cells/<cell>/tenants/<tenant_id>/.
package s3clean

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/md5"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"path"
	"sort"
	"strings"
	"time"

	"github.com/Busnes-app/kyvault-worker/internal/config"
)

// Eraser deletes from one storage root. A missing object is already deleted; any other
// failure is an error so the caller keeps the work pending and retries.
type Eraser interface {
	// DeleteObject removes key and anything beneath key/, every version included.
	DeleteObject(ctx context.Context, key string) error
	// DeletePrefix removes everything under prefix (which ends in "/"): objects, every
	// version and delete marker, and unfinished multipart uploads.
	DeletePrefix(ctx context.Context, prefix string) error
}

// CheckKey refuses anything but a clean path strictly inside cells/<cell>/tenants/<tenant_id>/.
func CheckKey(key string) error {
	k := strings.TrimSuffix(key, "/")
	if k == "" || k != path.Clean(k) || strings.Contains(k, "..") || strings.ContainsRune(k, '\\') {
		return fmt.Errorf("s3clean: refusing unsafe key %q", key)
	}
	parts := strings.Split(k, "/")
	if len(parts) < 4 || parts[0] != "cells" || !config.IsValidCellSlug(parts[1]) || parts[2] != "tenants" || parts[3] == "" || parts[3] == "." {
		return fmt.Errorf("s3clean: refusing unsafe key %q", key)
	}
	return nil
}

// Client is a SigV4 S3 eraser for AWS S3, MinIO, RustFS and other providers that
// implement ListObjectVersions. A provider that does not is refused, never treated as empty.
type Client struct {
	Endpoint        string
	Bucket          string
	Region          string
	AccessKeyID     string
	SecretAccessKey string
	ForcePathStyle  bool
	// Root is the key prefix of the storage root (s3://bucket/<Root>), without slashes at the ends.
	Root       string
	HTTPClient *http.Client
	Now        func() time.Time
}

func (c *Client) DeleteObject(ctx context.Context, key string) error {
	if err := CheckKey(key); err != nil {
		return err
	}
	full := c.fullKey(strings.TrimSuffix(key, "/"))
	return c.purge(ctx, full, func(k string) bool { return k == full || strings.HasPrefix(k, full+"/") }, false)
}

func (c *Client) DeletePrefix(ctx context.Context, prefix string) error {
	if err := CheckKey(prefix); err != nil || !strings.HasSuffix(prefix, "/") {
		return fmt.Errorf("s3clean: refusing unsafe prefix %q", prefix)
	}
	return c.purge(ctx, c.fullKey(prefix), func(string) bool { return true }, true)
}

func (c *Client) fullKey(key string) string {
	if c.Root == "" {
		return key
	}
	return c.Root + "/" + key
}

func (c *Client) purge(ctx context.Context, prefix string, match func(string) bool, uploads bool) error {
	if uploads {
		if err := c.abortUploads(ctx, prefix); err != nil {
			return err
		}
	}
	keyMarker, versionMarker := "", ""
	for {
		page, err := c.listVersions(ctx, prefix, keyMarker, versionMarker)
		if err != nil {
			return err
		}
		var objs []deleteObject
		for _, v := range page.entries() {
			if match(v.Key) {
				objs = append(objs, v)
			}
		}
		if len(objs) > 0 {
			if err := c.deleteBatch(ctx, objs); err != nil {
				return err
			}
		}
		if !page.IsTruncated {
			break
		}
		if page.NextKeyMarker == "" {
			return errors.New("s3clean: truncated version listing without a marker")
		}
		keyMarker, versionMarker = page.NextKeyMarker, page.NextVersionIDMarker
	}

	// A fresh listing must be empty: catches late writers and providers that answer a
	// delete without deleting.
	page, err := c.listVersions(ctx, prefix, "", "")
	if err != nil {
		return err
	}
	for _, v := range page.entries() {
		if match(v.Key) {
			return fmt.Errorf("s3clean: %q still holds %q after purge", prefix, v.Key)
		}
	}
	if uploads {
		left, err := c.listUploads(ctx, prefix, "", "")
		if err != nil {
			return err
		}
		if len(left.Uploads) > 0 {
			return fmt.Errorf("s3clean: %q still has %d multipart uploads after purge", prefix, len(left.Uploads))
		}
	}
	return nil
}

type listVersionsResult struct {
	XMLName             xml.Name       `xml:"ListVersionsResult"`
	IsTruncated         bool           `xml:"IsTruncated"`
	NextKeyMarker       string         `xml:"NextKeyMarker"`
	NextVersionIDMarker string         `xml:"NextVersionIdMarker"`
	Versions            []deleteObject `xml:"Version"`
	DeleteMarkers       []deleteObject `xml:"DeleteMarker"`
}

func (r listVersionsResult) entries() []deleteObject {
	return append(append([]deleteObject{}, r.Versions...), r.DeleteMarkers...)
}

type listUploadsResult struct {
	XMLName            xml.Name `xml:"ListMultipartUploadsResult"`
	IsTruncated        bool     `xml:"IsTruncated"`
	NextKeyMarker      string   `xml:"NextKeyMarker"`
	NextUploadIDMarker string   `xml:"NextUploadIdMarker"`
	Uploads            []struct {
		Key      string `xml:"Key"`
		UploadID string `xml:"UploadId"`
	} `xml:"Upload"`
}

type deleteRequest struct {
	XMLName xml.Name       `xml:"Delete"`
	Quiet   bool           `xml:"Quiet"`
	Objects []deleteObject `xml:"Object"`
}

type deleteObject struct {
	Key       string `xml:"Key"`
	VersionID string `xml:"VersionId,omitempty"`
}

type deleteResult struct {
	Errors []struct {
		Key     string `xml:"Key"`
		Code    string `xml:"Code"`
		Message string `xml:"Message"`
	} `xml:"Error"`
}

func (c *Client) listVersions(ctx context.Context, prefix, keyMarker, versionMarker string) (listVersionsResult, error) {
	q := url.Values{"versions": {""}, "prefix": {prefix}, "max-keys": {"1000"}}
	if keyMarker != "" {
		q.Set("key-marker", keyMarker)
		if versionMarker != "" {
			q.Set("version-id-marker", versionMarker)
		}
	}
	var out listVersionsResult
	err := c.call(ctx, http.MethodGet, "", q, nil, &out)
	return out, err
}

func (c *Client) listUploads(ctx context.Context, prefix, keyMarker, uploadMarker string) (listUploadsResult, error) {
	q := url.Values{"uploads": {""}, "prefix": {prefix}}
	if keyMarker != "" {
		q.Set("key-marker", keyMarker)
		if uploadMarker != "" {
			q.Set("upload-id-marker", uploadMarker)
		}
	}
	var out listUploadsResult
	err := c.call(ctx, http.MethodGet, "", q, nil, &out)
	return out, err
}

func (c *Client) abortUploads(ctx context.Context, prefix string) error {
	keyMarker, uploadMarker := "", ""
	for {
		page, err := c.listUploads(ctx, prefix, keyMarker, uploadMarker)
		if err != nil {
			return err
		}
		for _, up := range page.Uploads {
			err := c.call(ctx, http.MethodDelete, up.Key, url.Values{"uploadId": {up.UploadID}}, nil, nil)
			var se *statusError
			if err != nil && !(errors.As(err, &se) && se.code == http.StatusNotFound) {
				return err
			}
		}
		if !page.IsTruncated {
			return nil
		}
		if page.NextKeyMarker == "" {
			return errors.New("s3clean: truncated upload listing without a marker")
		}
		keyMarker, uploadMarker = page.NextKeyMarker, page.NextUploadIDMarker
	}
}

func (c *Client) deleteBatch(ctx context.Context, objs []deleteObject) error {
	payload, err := xml.Marshal(deleteRequest{Quiet: true, Objects: objs})
	if err != nil {
		return err
	}
	payload = append([]byte(xml.Header), payload...)
	var res deleteResult
	if err := c.call(ctx, http.MethodPost, "", url.Values{"delete": {""}}, payload, &res); err != nil {
		return err
	}
	for _, e := range res.Errors {
		if e.Code != "NoSuchKey" && e.Code != "NoSuchVersion" {
			return fmt.Errorf("s3clean: delete %q: %s: %s", e.Key, e.Code, e.Message)
		}
	}
	return nil
}

type statusError struct {
	code int
	body string
}

func (e *statusError) Error() string { return fmt.Sprintf("s3clean: status %d: %s", e.code, e.body) }

// call sends a signed request for key ("" for the bucket) and decodes an XML answer
// into out when out is non-nil.
func (c *Client) call(ctx context.Context, method, key string, q url.Values, payload []byte, out any) error {
	u, err := c.objectURL(key)
	if err != nil {
		return err
	}
	u.RawQuery = q.Encode()
	req, err := http.NewRequestWithContext(ctx, method, u.String(), bytes.NewReader(payload))
	if err != nil {
		return err
	}
	if payload != nil {
		sum := md5.Sum(payload)
		req.Header.Set("Content-Type", "application/xml")
		req.Header.Set("Content-MD5", base64.StdEncoding.EncodeToString(sum[:]))
	}
	c.signV4(req, payload)

	hc := http.Client{Timeout: 30 * time.Second}
	if c.HTTPClient != nil {
		hc = *c.HTTPClient
	}
	hc.CheckRedirect = func(*http.Request, []*http.Request) error { return errors.New("redirects are refused") }
	resp, err := hc.Do(req)
	if err != nil {
		return fmt.Errorf("s3clean: %s: %w", method, err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 8<<20))
	if err != nil {
		return err
	}
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		snippet := string(body)
		if len(snippet) > 512 {
			snippet = snippet[:512]
		}
		return &statusError{code: resp.StatusCode, body: strings.TrimSpace(snippet)}
	}
	if out == nil {
		return nil
	}
	if err := xml.Unmarshal(body, out); err != nil {
		return fmt.Errorf("s3clean: unexpected answer (provider may lack this S3 API): %w", err)
	}
	return nil
}

func (c *Client) objectURL(key string) (*url.URL, error) {
	if c.Bucket == "" {
		return nil, errors.New("s3clean: bucket is required")
	}
	raw := c.Endpoint
	if raw == "" {
		raw = fmt.Sprintf("https://s3.%s.amazonaws.com", c.region())
	}
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" {
		return nil, fmt.Errorf("s3clean: invalid endpoint %q", raw)
	}
	p := "/"
	if c.ForcePathStyle {
		p = "/" + c.Bucket + "/"
	} else {
		u.Host = c.Bucket + "." + u.Host
	}
	if key == "" {
		u.Path = strings.TrimSuffix(p, "/")
		if u.Path == "" {
			u.Path = "/"
		}
		return u, nil
	}
	segs := strings.Split(key, "/")
	for i, s := range segs {
		segs[i] = awsURLEncode(s)
	}
	u.Path = p + key
	u.RawPath = p + strings.Join(segs, "/")
	return u, nil
}

func (c *Client) region() string {
	if c.Region == "" {
		return "us-east-1"
	}
	return c.Region
}

func (c *Client) signV4(req *http.Request, payload []byte) {
	now := time.Now().UTC()
	if c.Now != nil {
		now = c.Now().UTC()
	}
	amzDate := now.Format("20060102T150405Z")
	dateStamp := now.Format("20060102")
	payloadHashBytes := sha256.Sum256(payload)
	payloadHash := hex.EncodeToString(payloadHashBytes[:])

	req.Header.Set("X-Amz-Date", amzDate)
	req.Header.Set("X-Amz-Content-Sha256", payloadHash)

	canonicalHeaders, signedHeaders := buildCanonicalHeaders(req)
	canonicalURI := req.URL.EscapedPath()
	if canonicalURI == "" {
		canonicalURI = "/"
	}
	canonicalRequest := strings.Join([]string{
		req.Method, canonicalURI, buildCanonicalQuery(req.URL.Query()), canonicalHeaders, signedHeaders, payloadHash,
	}, "\n")
	crHash := sha256.Sum256([]byte(canonicalRequest))
	scope := fmt.Sprintf("%s/%s/s3/aws4_request", dateStamp, c.region())
	stringToSign := strings.Join([]string{"AWS4-HMAC-SHA256", amzDate, scope, hex.EncodeToString(crHash[:])}, "\n")
	sig := hex.EncodeToString(hmacSHA256(deriveSigningKey(c.SecretAccessKey, dateStamp, c.region(), "s3"), stringToSign))
	req.Header.Set("Authorization", fmt.Sprintf("AWS4-HMAC-SHA256 Credential=%s/%s, SignedHeaders=%s, Signature=%s",
		c.AccessKeyID, scope, signedHeaders, sig))
}

func buildCanonicalHeaders(req *http.Request) (string, string) {
	headers := map[string]string{
		"host":                 req.URL.Host,
		"x-amz-content-sha256": req.Header.Get("X-Amz-Content-Sha256"),
		"x-amz-date":           req.Header.Get("X-Amz-Date"),
	}
	if v := req.Header.Get("Content-MD5"); v != "" {
		headers["content-md5"] = v
	}
	keys := make([]string, 0, len(headers))
	for k := range headers {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	var b strings.Builder
	for _, k := range keys {
		b.WriteString(k + ":" + strings.TrimSpace(headers[k]) + "\n")
	}
	return b.String(), strings.Join(keys, ";")
}

func buildCanonicalQuery(values url.Values) string {
	keys := make([]string, 0, len(values))
	for k := range values {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	var parts []string
	for _, k := range keys {
		vals := append([]string(nil), values[k]...)
		sort.Strings(vals)
		for _, v := range vals {
			parts = append(parts, awsURLEncode(k)+"="+awsURLEncode(v))
		}
	}
	return strings.Join(parts, "&")
}

func awsURLEncode(s string) string {
	esc := url.QueryEscape(s)
	esc = strings.ReplaceAll(esc, "+", "%20")
	esc = strings.ReplaceAll(esc, "*", "%2A")
	return strings.ReplaceAll(esc, "%7E", "~")
}

func deriveSigningKey(secret, dateStamp, region, service string) []byte {
	k := hmacSHA256([]byte("AWS4"+secret), dateStamp)
	k = hmacSHA256(k, region)
	k = hmacSHA256(k, service)
	return hmacSHA256(k, "aws4_request")
}

func hmacSHA256(key []byte, data string) []byte {
	mac := hmac.New(sha256.New, key)
	mac.Write([]byte(data))
	return mac.Sum(nil)
}
