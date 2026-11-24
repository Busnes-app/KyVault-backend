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
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

// Eraser removes all tenant-prefixed objects from S3 and/or local disk.
type Eraser interface {
	DeletePrefix(ctx context.Context, prefix string) (int, error)
}

// Client is a minimal, zero-dependency AWS SigV4 S3 prefix eraser supporting
// AWS S3, MinIO, Cloudflare R2, and RustFS (path-style and virtual-host-style).
type Client struct {
	Endpoint        string
	Bucket          string
	Region          string
	AccessKeyID     string
	SecretAccessKey string
	ForcePathStyle  bool
	KeyPrefix       string
	HTTPClient      *http.Client
	Now             func() time.Time
}

func (c *Client) httpClient() *http.Client {
	if c.HTTPClient != nil {
		return c.HTTPClient
	}
	return &http.Client{Timeout: 30 * time.Second}
}

func (c *Client) now() time.Time {
	if c.Now != nil {
		return c.Now().UTC()
	}
	return time.Now().UTC()
}

type listBucketResult struct {
	IsTruncated           bool   `xml:"IsTruncated"`
	NextContinuationToken string `xml:"NextContinuationToken"`
	Contents              []struct {
		Key string `xml:"Key"`
	} `xml:"Contents"`
}

type deleteRequest struct {
	XMLName xml.Name       `xml:"Delete"`
	Quiet   bool           `xml:"Quiet"`
	Objects []deleteObject `xml:"Object"`
}

type deleteObject struct {
	Key string `xml:"Key"`
}

type deleteResult struct {
	Errors []struct {
		Key     string `xml:"Key"`
		Code    string `xml:"Code"`
		Message string `xml:"Message"`
	} `xml:"Error"`
}

// DeletePrefix deletes every object under prefix (automatically prepending c.KeyPrefix if configured).
// Refuses empty prefixes so a caller can never accidentally wipe an entire bucket.
func (c *Client) DeletePrefix(ctx context.Context, prefix string) (int, error) {
	cleanPrefix := strings.TrimLeft(strings.TrimSpace(prefix), "/")
	if cleanPrefix == "" || !strings.HasPrefix(cleanPrefix, "tenants/") || cleanPrefix == "tenants/" {
		return 0, fmt.Errorf("s3clean: refusing unsafe delete prefix %q", prefix)
	}
	fullPrefix := cleanPrefix
	if c.KeyPrefix != "" {
		fullPrefix = strings.Trim(c.KeyPrefix, "/") + "/" + cleanPrefix
	}

	totalDeleted := 0
	continuationToken := ""

	for {
		keys, nextToken, truncated, err := c.listPage(ctx, fullPrefix, continuationToken)
		if err != nil {
			return totalDeleted, err
		}
		if len(keys) > 0 {
			if err := c.deleteBatch(ctx, keys); err != nil {
				return totalDeleted, err
			}
			totalDeleted += len(keys)
		}
		if !truncated || nextToken == "" {
			break
		}
		continuationToken = nextToken
	}

	return totalDeleted, nil
}

func (c *Client) bucketEndpoint() (*url.URL, error) {
	if c.Bucket == "" {
		return nil, errors.New("s3clean: bucket is required")
	}
	raw := c.Endpoint
	if raw == "" {
		raw = fmt.Sprintf("https://s3.%s.amazonaws.com", c.Region)
	}
	u, err := url.Parse(raw)
	if err != nil {
		return nil, fmt.Errorf("s3clean: invalid endpoint: %w", err)
	}
	if c.ForcePathStyle {
		u.Path = "/" + c.Bucket
	} else {
		u.Host = c.Bucket + "." + u.Host
		u.Path = "/"
	}
	return u, nil
}

func (c *Client) listPage(ctx context.Context, prefix, continuationToken string) ([]string, string, bool, error) {
	u, err := c.bucketEndpoint()
	if err != nil {
		return nil, "", false, err
	}
	q := url.Values{}
	q.Set("list-type", "2")
	q.Set("prefix", prefix)
	q.Set("max-keys", "1000")
	if continuationToken != "" {
		q.Set("continuation-token", continuationToken)
	}
	u.RawQuery = q.Encode()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
	if err != nil {
		return nil, "", false, err
	}
	c.signV4(req, nil)

	resp, err := c.httpClient().Do(req)
	if err != nil {
		return nil, "", false, fmt.Errorf("s3clean: list objects: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(io.LimitReader(resp.Body, 10<<20))
	if err != nil {
		return nil, "", false, err
	}
	if resp.StatusCode == http.StatusNotFound {
		return nil, "", false, nil
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, "", false, fmt.Errorf("s3clean: list objects status %d: %s", resp.StatusCode, strings.TrimSpace(string(body)))
	}

	var parsed listBucketResult
	if err := xml.Unmarshal(body, &parsed); err != nil {
		return nil, "", false, fmt.Errorf("s3clean: parse list response: %w", err)
	}
	keys := make([]string, 0, len(parsed.Contents))
	for _, item := range parsed.Contents {
		if item.Key != "" {
			keys = append(keys, item.Key)
		}
	}
	return keys, parsed.NextContinuationToken, parsed.IsTruncated, nil
}

func (c *Client) deleteBatch(ctx context.Context, keys []string) error {
	u, err := c.bucketEndpoint()
	if err != nil {
		return err
	}
	q := url.Values{}
	q.Set("delete", "")
	u.RawQuery = q.Encode()

	objs := make([]deleteObject, len(keys))
	for i, k := range keys {
		objs[i] = deleteObject{Key: k}
	}
	payload, err := xml.Marshal(deleteRequest{Quiet: true, Objects: objs})
	if err != nil {
		return err
	}
	payload = append([]byte(xml.Header), payload...)

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, u.String(), bytes.NewReader(payload))
	if err != nil {
		return err
	}
	sumMD5 := md5.Sum(payload)
	req.Header.Set("Content-Type", "application/xml")
	req.Header.Set("Content-MD5", base64.StdEncoding.EncodeToString(sumMD5[:]))
	c.signV4(req, payload)

	resp, err := c.httpClient().Do(req)
	if err != nil {
		return fmt.Errorf("s3clean: delete objects: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
	if err != nil {
		return err
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("s3clean: delete objects status %d: %s", resp.StatusCode, strings.TrimSpace(string(body)))
	}
	if len(body) > 0 {
		var parsed deleteResult
		if err := xml.Unmarshal(body, &parsed); err == nil && len(parsed.Errors) > 0 {
			// Missing objects (NoSuchKey) are already deleted; any other error must fail so purge retries.
			for _, delErr := range parsed.Errors {
				if delErr.Code != "NoSuchKey" {
					return fmt.Errorf("s3clean: failed deleting key %q (%s): %s", delErr.Key, delErr.Code, delErr.Message)
				}
			}
		}
	}
	return nil
}

func (c *Client) signV4(req *http.Request, payload []byte) {
	now := c.now()
	amzDate := now.Format("20060102T150405Z")
	dateStamp := now.Format("20060102")
	region := c.Region
	if region == "" {
		region = "us-east-1"
	}

	payloadHashBytes := sha256.Sum256(payload)
	payloadHash := hex.EncodeToString(payloadHashBytes[:])

	req.Header.Set("Host", req.URL.Host)
	req.Header.Set("X-Amz-Date", amzDate)
	req.Header.Set("X-Amz-Content-Sha256", payloadHash)

	canonicalHeaders, signedHeaders := buildCanonicalHeaders(req)
	canonicalQuery := buildCanonicalQuery(req.URL.Query())
	canonicalURI := req.URL.EscapedPath()
	if canonicalURI == "" {
		canonicalURI = "/"
	}

	canonicalRequest := strings.Join([]string{
		req.Method,
		canonicalURI,
		canonicalQuery,
		canonicalHeaders,
		signedHeaders,
		payloadHash,
	}, "\n")

	crHash := sha256.Sum256([]byte(canonicalRequest))
	credentialScope := fmt.Sprintf("%s/%s/s3/aws4_request", dateStamp, region)
	stringToSign := strings.Join([]string{
		"AWS4-HMAC-SHA256",
		amzDate,
		credentialScope,
		hex.EncodeToString(crHash[:]),
	}, "\n")

	signingKey := deriveSigningKey(c.SecretAccessKey, dateStamp, region, "s3")
	sig := hex.EncodeToString(hmacSHA256(signingKey, stringToSign))

	authHeader := fmt.Sprintf(
		"AWS4-HMAC-SHA256 Credential=%s/%s, SignedHeaders=%s, Signature=%s",
		c.AccessKeyID, credentialScope, signedHeaders, sig,
	)
	req.Header.Set("Authorization", authHeader)
}

func buildCanonicalHeaders(req *http.Request) (string, string) {
	headers := map[string]string{
		"host":                 req.URL.Host,
		"x-amz-content-sha256": req.Header.Get("X-Amz-Content-Sha256"),
		"x-amz-date":           req.Header.Get("X-Amz-Date"),
	}
	if md5v := req.Header.Get("Content-MD5"); md5v != "" {
		headers["content-md5"] = md5v
	}
	keys := make([]string, 0, len(headers))
	for k := range headers {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	var canon strings.Builder
	for _, k := range keys {
		canon.WriteString(k)
		canon.WriteByte(':')
		canon.WriteString(strings.TrimSpace(headers[k]))
		canon.WriteByte('\n')
	}
	return canon.String(), strings.Join(keys, ";")
}

func buildCanonicalQuery(values url.Values) string {
	if len(values) == 0 {
		return ""
	}
	keys := make([]string, 0, len(values))
	for k := range values {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	parts := make([]string, 0, len(keys))
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
	esc = strings.ReplaceAll(esc, "%7E", "~")
	return esc
}

func deriveSigningKey(secret, dateStamp, region, service string) []byte {
	kDate := hmacSHA256([]byte("AWS4"+secret), dateStamp)
	kRegion := hmacSHA256(kDate, region)
	kService := hmacSHA256(kRegion, service)
	return hmacSHA256(kService, "aws4_request")
}

func hmacSHA256(key []byte, data string) []byte {
	mac := hmac.New(sha256.New, key)
	mac.Write([]byte(data))
	return mac.Sum(nil)
}

// LocalFSEraser removes tenant directories under DATA_FOLDER/tenants/<tenant_id>
// when running without S3 (or in hybrid deployments).
type LocalFSEraser struct {
	DataFolder string
}

func (l *LocalFSEraser) DeletePrefix(_ context.Context, prefix string) (int, error) {
	if l.DataFolder == "" {
		return 0, nil
	}
	clean := filepath.Clean(strings.TrimLeft(prefix, "/"))
	if !strings.HasPrefix(clean, "tenants"+string(os.PathSeparator)) || clean == "tenants" || strings.Contains(clean, "..") {
		return 0, fmt.Errorf("s3clean: refusing unsafe local fs prefix %q", prefix)
	}
	baseAbs, err := filepath.Abs(l.DataFolder)
	if err != nil {
		return 0, err
	}
	targetAbs, err := filepath.Abs(filepath.Join(baseAbs, clean))
	if err != nil {
		return 0, err
	}
	if !strings.HasPrefix(targetAbs, baseAbs+string(os.PathSeparator)) {
		return 0, fmt.Errorf("s3clean: path traversal rejected for %q", prefix)
	}
	if _, err := os.Stat(targetAbs); errors.Is(err, os.ErrNotExist) {
		return 0, nil
	}
	if err := os.RemoveAll(targetAbs); err != nil {
		return 0, err
	}
	return 1, nil
}

// MultiEraser fans out prefix erasure to all configured storage backends.
type MultiEraser struct {
	Erasers []Eraser
}

func (m *MultiEraser) DeletePrefix(ctx context.Context, prefix string) (int, error) {
	total := 0
	for _, e := range m.Erasers {
		if e == nil {
			continue
		}
		n, err := e.DeletePrefix(ctx, prefix)
		total += n
		if err != nil {
			return total, err
		}
	}
	return total, nil
}
