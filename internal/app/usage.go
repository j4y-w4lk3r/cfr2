package app

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"time"
)

// R2 Standard prices (USD) and the monthly free tier.
const (
	pricePerGBMonth = 0.015
	pricePerMClassA = 4.50
	pricePerMClassB = 0.36
	freeGB          = 10
	freeClassA      = 1_000_000
	freeClassB      = 10_000_000
)

var classA = map[string]bool{
	"ListBuckets": true, "PutBucket": true, "ListObjects": true, "PutObject": true, "CopyObject": true,
	"CompleteMultipartUpload": true, "CreateMultipartUpload": true, "UploadPart": true, "UploadPartCopy": true,
	"ListMultipartUploads": true, "ListParts": true, "PutBucketEncryption": true, "PutBucketCors": true,
	"PutBucketLifecycleConfiguration": true, "PutBucketStorageClass": true, "LifecycleStorageTierTransition": true,
}

var freeOps = map[string]bool{"DeleteObject": true, "DeleteBucket": true, "AbortMultipartUpload": true}

// BucketUsage is one bucket in the usage report.
type BucketUsage struct {
	Bucket  string `json:"bucket"`
	Bytes   int64  `json:"bytes"`
	Objects int64  `json:"objects"`
}

// UsageReport is what `cfr2 usage --json` prints and caches.
type UsageReport struct {
	At          time.Time     `json:"at"`
	Days        int           `json:"days"`
	Buckets     []BucketUsage `json:"buckets"`
	ClassA      int64         `json:"class_a"`
	ClassB      int64         `json:"class_b"`
	MonthlyUSD  float64       `json:"monthly_usd_estimate"`
	TotalBytes  int64         `json:"total_bytes"`
	PriceSource string        `json:"price_source"`
}

// Usage reports storage per bucket, operations and a monthly cost estimate.
func (a *App) Usage(ctx context.Context, args []string) error {
	fs := newFlags("usage", a.Err)
	asJSON := fs.Bool("json", false, "JSON output")
	short := fs.Bool("short", false, "one line, for a status bar")
	cached := fs.Bool("cached", false, "use the cached report when it is under 24h old")
	days := fs.Int("days", 30, "look back this many days for operations")
	if err := fs.Parse(args); err != nil {
		return err
	}
	var rep *UsageReport
	if *cached {
		rep = readUsageCache()
	}
	if rep == nil {
		var err error
		if rep, err = a.fetchUsage(ctx, *days); err != nil {
			return err
		}
		writeUsageCache(rep)
	}
	switch {
	case *short:
		fmt.Fprintf(a.Out, "R2 %s ~$%.2f/mo\n", HumanSize(rep.TotalBytes), rep.MonthlyUSD)
	case *asJSON:
		return a.printJSON(rep)
	default:
		for _, b := range rep.Buckets {
			fmt.Fprintf(a.Out, "%-24s %9s  %d objects\n", b.Bucket, HumanSize(b.Bytes), b.Objects)
		}
		fmt.Fprintf(a.Out, "operations (last %d days): class A %d (free %d), class B %d (free %d)\n", rep.Days, rep.ClassA, freeClassA, rep.ClassB, freeClassB)
		fmt.Fprintf(a.Out, "estimate: about $%.2f per month (%s)\n", rep.MonthlyUSD, rep.PriceSource)
	}
	return nil
}

func (a *App) fetchUsage(ctx context.Context, days int) (*UsageReport, error) {
	if a.Cfg.Usage.Token == "" {
		return nil, errors.New("set [usage] token = \"keyhole:NAME\" (a Cloudflare API token with Account Analytics Read)")
	}
	if a.Cfg.AccountID == "" {
		return nil, errors.New("usage needs account_id in the config")
	}
	tok, err := a.Sec.Token(ctx, a.Cfg.Usage.Token)
	if err != nil {
		return nil, err
	}
	end := time.Now().UTC()
	start := end.Add(-time.Duration(days) * 24 * time.Hour)
	q := `query($a:String!,$s:Time!,$e:Time!){viewer{accounts(filter:{accountTag:$a}){
 st:r2StorageAdaptiveGroups(limit:1000,filter:{datetime_geq:$s,datetime_leq:$e},orderBy:[datetime_DESC]){max{payloadSize metadataSize objectCount} dimensions{bucketName datetime}}
 op:r2OperationsAdaptiveGroups(limit:1000,filter:{datetime_geq:$s,datetime_leq:$e}){sum{requests} dimensions{actionType}}}}}`
	body, _ := json.Marshal(map[string]any{"query": q, "variables": map[string]string{
		"a": a.Cfg.AccountID, "s": start.Format(time.RFC3339), "e": end.Format(time.RFC3339)}})
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, "https://api.cloudflare.com/client/v4/graphql", bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+tok)
	req.Header.Set("Content-Type", "application/json")
	resp, err := (&http.Client{Timeout: 30 * time.Second}).Do(req)
	if err != nil {
		return nil, fmt.Errorf("usage: %w", err)
	}
	defer resp.Body.Close()
	var out struct {
		Data struct {
			Viewer struct {
				Accounts []struct {
					St []struct {
						Max struct {
							PayloadSize, MetadataSize, ObjectCount int64
						} `json:"max"`
						Dimensions struct {
							BucketName string `json:"bucketName"`
						} `json:"dimensions"`
					} `json:"st"`
					Op []struct {
						Sum struct {
							Requests int64 `json:"requests"`
						} `json:"sum"`
						Dimensions struct {
							ActionType string `json:"actionType"`
						} `json:"dimensions"`
					} `json:"op"`
				} `json:"accounts"`
			} `json:"viewer"`
		} `json:"data"`
		Errors []struct {
			Message string `json:"message"`
		} `json:"errors"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return nil, fmt.Errorf("usage: HTTP %d: %w", resp.StatusCode, err)
	}
	if len(out.Errors) > 0 {
		return nil, fmt.Errorf("usage: %s", out.Errors[0].Message)
	}
	rep := &UsageReport{At: time.Now(), Days: days, PriceSource: "R2 Standard list prices, free tier subtracted"}
	if len(out.Data.Viewer.Accounts) == 0 {
		return rep, nil
	}
	acc := out.Data.Viewer.Accounts[0]
	latest := map[string]BucketUsage{} // newest sample per bucket (rows are newest first)
	for _, s := range acc.St {
		n := s.Dimensions.BucketName
		if _, ok := latest[n]; ok {
			continue
		}
		latest[n] = BucketUsage{Bucket: n, Bytes: s.Max.PayloadSize + s.Max.MetadataSize, Objects: s.Max.ObjectCount}
	}
	for _, b := range latest {
		rep.Buckets = append(rep.Buckets, b)
		rep.TotalBytes += b.Bytes
	}
	sort.Slice(rep.Buckets, func(i, j int) bool { return rep.Buckets[i].Bytes > rep.Buckets[j].Bytes })
	for _, o := range acc.Op {
		t := o.Dimensions.ActionType
		switch {
		case freeOps[t]:
		case classA[t]:
			rep.ClassA += o.Sum.Requests
		default:
			rep.ClassB += o.Sum.Requests
		}
	}
	gb := float64(rep.TotalBytes) / 1e9
	cost := max(0, gb-freeGB) * pricePerGBMonth
	scale := 30.0 / float64(days) // operations per month
	cost += max(0, float64(rep.ClassA)*scale-freeClassA) / 1e6 * pricePerMClassA
	cost += max(0, float64(rep.ClassB)*scale-freeClassB) / 1e6 * pricePerMClassB
	rep.MonthlyUSD = cost
	return rep, nil
}

func usageCachePath() string {
	dir, err := os.UserCacheDir()
	if err != nil {
		return ""
	}
	return filepath.Join(dir, "cfr2", "usage.json")
}

func readUsageCache() *UsageReport {
	p := usageCachePath()
	b, err := os.ReadFile(p)
	if err != nil {
		return nil
	}
	var r UsageReport
	if json.Unmarshal(b, &r) != nil || time.Since(r.At) > 24*time.Hour {
		return nil
	}
	return &r
}

func writeUsageCache(r *UsageReport) {
	p := usageCachePath()
	if p == "" {
		return
	}
	os.MkdirAll(filepath.Dir(p), 0o700)
	if b, err := json.Marshal(r); err == nil {
		os.WriteFile(p, b, 0o600)
	}
}
