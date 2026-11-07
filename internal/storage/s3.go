// Package storage talks to Cloudflare R2 through its S3 API.
package storage

import (
	"context"
	"errors"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/feature/s3/manager"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/aws-sdk-go-v2/service/s3/types"
	"github.com/aws/smithy-go"
)

// Metadata keys cfr2 stores on every object it uploads.
const (
	MetaSHA256      = "sha256"       // sha256 of the stored bytes
	MetaPlainSHA256 = "plain-sha256" // sha256 of the plaintext before encryption
	MetaScheme      = "cfr2-enc"     // age | gpg | none
	MetaSize        = "plain-size"   // plaintext size in bytes
)

// TrashPrefix is where `cfr2 rm` moves objects. A lifecycle rule deletes them.
const TrashPrefix = ".trash/"

// ErrNotFound is returned when a key does not exist.
var ErrNotFound = errors.New("object not found")

// Object is one listed key.
type Object struct {
	Key          string    `json:"key"`
	Size         int64     `json:"size"`
	LastModified time.Time `json:"modified"`
	ETag         string    `json:"etag"`
}

// Info is a HEAD result.
type Info struct {
	Object
	Meta map[string]string `json:"meta"`
}

// Bucket is one bucket from ListBuckets.
type Bucket struct {
	Name      string    `json:"name"`
	CreatedAt time.Time `json:"created"`
}

// Client is an R2 client bound to one bucket.
type Client struct {
	s3     *s3.Client
	up     *manager.Uploader
	Bucket string
}

// New builds a client for endpoint/bucket with a static key pair.
func New(endpoint, bucket, keyID, secret string) *Client {
	c := s3.New(s3.Options{
		Region:       "auto",
		BaseEndpoint: aws.String(endpoint),
		Credentials:  credentials.NewStaticCredentialsProvider(keyID, secret, ""),
		UsePathStyle: true,
		// R2 does not need the newer default checksum trailers; keep requests plain.
		RequestChecksumCalculation: aws.RequestChecksumCalculationWhenRequired,
		ResponseChecksumValidation: aws.ResponseChecksumValidationWhenRequired,
	})
	up := manager.NewUploader(c, func(u *manager.Uploader) {
		u.PartSize = 16 << 20
		u.Concurrency = 4
	})
	return &Client{s3: c, up: up, Bucket: bucket}
}

// ListPage is one page of a listing.
type ListPage struct {
	Objects  []Object `json:"objects"`
	Prefixes []string `json:"prefixes"`
}

// List lists keys under prefix. With delim "/" it returns one "folder"
// level: objects directly under prefix plus sub-prefixes.
func (c *Client) List(ctx context.Context, prefix, delim string, limit int) (ListPage, error) {
	var page ListPage
	in := &s3.ListObjectsV2Input{Bucket: aws.String(c.Bucket), Prefix: aws.String(prefix)}
	if delim != "" {
		in.Delimiter = aws.String(delim)
	}
	p := s3.NewListObjectsV2Paginator(c.s3, in)
	for p.HasMorePages() {
		out, err := p.NextPage(ctx)
		if err != nil {
			return page, wrap("list", err)
		}
		for _, o := range out.Contents {
			page.Objects = append(page.Objects, Object{
				Key: aws.ToString(o.Key), Size: aws.ToInt64(o.Size),
				LastModified: aws.ToTime(o.LastModified), ETag: strings.Trim(aws.ToString(o.ETag), `"`),
			})
		}
		for _, cp := range out.CommonPrefixes {
			page.Prefixes = append(page.Prefixes, aws.ToString(cp.Prefix))
		}
		if limit > 0 && len(page.Objects) >= limit {
			page.Objects = page.Objects[:limit]
			break
		}
	}
	return page, nil
}

// Head returns size, time and user metadata of key.
func (c *Client) Head(ctx context.Context, key string) (Info, error) {
	out, err := c.s3.HeadObject(ctx, &s3.HeadObjectInput{Bucket: aws.String(c.Bucket), Key: aws.String(key)})
	if err != nil {
		return Info{}, wrap("head "+key, err)
	}
	return Info{Object: Object{
		Key: key, Size: aws.ToInt64(out.ContentLength), LastModified: aws.ToTime(out.LastModified),
		ETag: strings.Trim(aws.ToString(out.ETag), `"`),
	}, Meta: out.Metadata}, nil
}

// Get streams key. The caller closes the body.
func (c *Client) Get(ctx context.Context, key string) (io.ReadCloser, Info, error) {
	out, err := c.s3.GetObject(ctx, &s3.GetObjectInput{Bucket: aws.String(c.Bucket), Key: aws.String(key)})
	if err != nil {
		return nil, Info{}, wrap("get "+key, err)
	}
	return out.Body, Info{Object: Object{
		Key: key, Size: aws.ToInt64(out.ContentLength), LastModified: aws.ToTime(out.LastModified),
		ETag: strings.Trim(aws.ToString(out.ETag), `"`),
	}, Meta: out.Metadata}, nil
}

// Put uploads body as key with user metadata (multipart for big bodies).
func (c *Client) Put(ctx context.Context, key string, body io.Reader, meta map[string]string) error {
	_, err := c.up.Upload(ctx, &s3.PutObjectInput{
		Bucket: aws.String(c.Bucket), Key: aws.String(key), Body: body, Metadata: meta,
	})
	return wrap("put "+key, err)
}

// Copy copies src to dst inside the bucket, keeping metadata.
func (c *Client) Copy(ctx context.Context, src, dst string) error {
	_, err := c.s3.CopyObject(ctx, &s3.CopyObjectInput{
		Bucket: aws.String(c.Bucket), Key: aws.String(dst),
		CopySource: aws.String(c.Bucket + "/" + escapeKey(src)),
	})
	return wrap("copy "+src, err)
}

// Delete removes key for good.
func (c *Client) Delete(ctx context.Context, key string) error {
	_, err := c.s3.DeleteObject(ctx, &s3.DeleteObjectInput{Bucket: aws.String(c.Bucket), Key: aws.String(key)})
	return wrap("delete "+key, err)
}

// Presign returns a GET URL for key that expires after ttl.
func (c *Client) Presign(ctx context.Context, key string, ttl time.Duration) (string, error) {
	ps := s3.NewPresignClient(c.s3)
	r, err := ps.PresignGetObject(ctx, &s3.GetObjectInput{Bucket: aws.String(c.Bucket), Key: aws.String(key)},
		s3.WithPresignExpires(ttl))
	if err != nil {
		return "", wrap("presign "+key, err)
	}
	return r.URL, nil
}

// ListBuckets lists the buckets the key can see (needs account-level rights).
func (c *Client) ListBuckets(ctx context.Context) ([]Bucket, error) {
	out, err := c.s3.ListBuckets(ctx, &s3.ListBucketsInput{})
	if err != nil {
		return nil, wrap("list buckets", err)
	}
	var bs []Bucket
	for _, b := range out.Buckets {
		bs = append(bs, Bucket{Name: aws.ToString(b.Name), CreatedAt: aws.ToTime(b.CreationDate)})
	}
	return bs, nil
}

// CreateBucket creates name.
func (c *Client) CreateBucket(ctx context.Context, name string) error {
	_, err := c.s3.CreateBucket(ctx, &s3.CreateBucketInput{Bucket: aws.String(name)})
	return wrap("create bucket "+name, err)
}

// DeleteBucket removes an empty bucket.
func (c *Client) DeleteBucket(ctx context.Context, name string) error {
	_, err := c.s3.DeleteBucket(ctx, &s3.DeleteBucketInput{Bucket: aws.String(name)})
	return wrap("delete bucket "+name, err)
}

// TrashRule reports the expiry days of the .trash/ lifecycle rule (0 = none).
func (c *Client) TrashRule(ctx context.Context) (int, error) {
	out, err := c.s3.GetBucketLifecycleConfiguration(ctx, &s3.GetBucketLifecycleConfigurationInput{Bucket: aws.String(c.Bucket)})
	if err != nil {
		var ae smithy.APIError
		if errors.As(err, &ae) && strings.Contains(ae.ErrorCode(), "NoSuchLifecycle") {
			return 0, nil
		}
		return 0, wrap("get lifecycle", err)
	}
	for _, r := range out.Rules {
		if r.Filter != nil && aws.ToString(r.Filter.Prefix) == TrashPrefix && r.Expiration != nil && r.Status == types.ExpirationStatusEnabled {
			return int(aws.ToInt32(r.Expiration.Days)), nil
		}
	}
	return 0, nil
}

// SetTrashRule makes R2 delete objects under .trash/ after days, keeping
// any other lifecycle rules the bucket has.
func (c *Client) SetTrashRule(ctx context.Context, days int) error {
	var rules []types.LifecycleRule
	out, err := c.s3.GetBucketLifecycleConfiguration(ctx, &s3.GetBucketLifecycleConfigurationInput{Bucket: aws.String(c.Bucket)})
	if err == nil {
		for _, r := range out.Rules {
			if r.Filter != nil && aws.ToString(r.Filter.Prefix) == TrashPrefix {
				continue
			}
			rules = append(rules, r)
		}
	}
	rules = append(rules, types.LifecycleRule{
		ID:         aws.String("cfr2-trash"),
		Status:     types.ExpirationStatusEnabled,
		Filter:     &types.LifecycleRuleFilter{Prefix: aws.String(TrashPrefix)},
		Expiration: &types.LifecycleExpiration{Days: aws.Int32(int32(days))},
	})
	_, err = c.s3.PutBucketLifecycleConfiguration(ctx, &s3.PutBucketLifecycleConfigurationInput{
		Bucket: aws.String(c.Bucket), LifecycleConfiguration: &types.BucketLifecycleConfiguration{Rules: rules},
	})
	return wrap("set lifecycle", err)
}

func escapeKey(k string) string {
	parts := strings.Split(k, "/")
	for i, p := range parts {
		parts[i] = urlPathEscape(p)
	}
	return strings.Join(parts, "/")
}

func urlPathEscape(s string) string {
	const hex = "0123456789ABCDEF"
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		ch := s[i]
		if ch >= 'a' && ch <= 'z' || ch >= 'A' && ch <= 'Z' || ch >= '0' && ch <= '9' || strings.IndexByte("-_.~", ch) >= 0 {
			b.WriteByte(ch)
		} else {
			b.WriteByte('%')
			b.WriteByte(hex[ch>>4])
			b.WriteByte(hex[ch&15])
		}
	}
	return b.String()
}

func wrap(op string, err error) error {
	if err == nil {
		return nil
	}
	var nsk *types.NoSuchKey
	var nf *types.NotFound
	if errors.As(err, &nsk) || errors.As(err, &nf) {
		return fmt.Errorf("%s: %w", op, ErrNotFound)
	}
	var ae smithy.APIError
	if errors.As(err, &ae) {
		if ae.ErrorCode() == "NotFound" || ae.ErrorCode() == "NoSuchKey" {
			return fmt.Errorf("%s: %w", op, ErrNotFound)
		}
		return fmt.Errorf("%s: %s: %s", op, ae.ErrorCode(), ae.ErrorMessage())
	}
	return fmt.Errorf("%s: %w", op, err)
}
