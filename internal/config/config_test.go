package config

import (
	"strings"
	"testing"
)

const good = `
account_id = "acc123"
default_bucket = "b1"
[buckets.b1]
credentials = "keyhole:r2-b1"
[buckets.b2]
credentials = "env:B2X"
share = false
encrypt = "gpg"
`

func TestParseGood(t *testing.T) {
	c, err := Parse(good)
	if err != nil {
		t.Fatal(err)
	}
	if got := c.S3Endpoint(); got != "https://acc123.r2.cloudflarestorage.com" {
		t.Fatalf("endpoint %q", got)
	}
	b2, _ := c.Bucket("b2")
	if b2.ShareAllowed() || c.EncryptionFor(b2) != "gpg" {
		t.Fatal("b2 should refuse share links and use gpg")
	}
	b1, _ := c.Bucket("")
	if b1.Name != "b1" || !b1.ShareAllowed() || c.EncryptionFor(b1) != "age" {
		t.Fatal("default bucket b1 should allow share and default to age")
	}
}

func TestLiteralKeyRefused(t *testing.T) {
	_, err := Parse(`account_id = "a"
[buckets.x]
credentials = "AKIAPLAINTEXTKEY"`)
	if err == nil || !strings.Contains(err.Error(), "never a literal") {
		t.Fatalf("want literal refused, got %v", err)
	}
}

func TestLiteralUsageTokenRefused(t *testing.T) {
	_, err := Parse(`account_id = "a"
[usage]
token = "plain-token"
[buckets.x]
credentials = "keyhole:x"`)
	if err == nil {
		t.Fatal("literal usage token must be refused")
	}
}

func TestSyncNeedsKnownBucket(t *testing.T) {
	_, err := Parse(good + `
[[sync]]
local = "~/n"
remote = "nope:n/"`)
	if err == nil {
		t.Fatal("sync to an unknown bucket must be refused")
	}
}

func TestJurisdictionEndpoint(t *testing.T) {
	c, err := Parse(`account_id = "acc"
jurisdiction = "eu"
[buckets.x]
credentials = "keyhole:x"`)
	if err != nil {
		t.Fatal(err)
	}
	if c.S3Endpoint() != "https://acc.eu.r2.cloudflarestorage.com" {
		t.Fatal(c.S3Endpoint())
	}
}
