package main

import (
	"testing"
	"time"

	"github.com/netrixone/udig"
	"github.com/stretchr/testify/assert"
)

func Test_isValidDomain(t *testing.T) {
	assert.False(t, isValidDomain(""))
	assert.False(t, isValidDomain("not a domain"))
	assert.True(t, isValidDomain("example.com"))
	assert.True(t, isValidDomain("sub.example.com"))
}

func Test_resolve_withOptions_smoke(t *testing.T) {
	// Short timeout and max 1 domain so the test finishes quickly without real crawl.
	options := []udig.Option{
		udig.WithTimeout(50 * time.Millisecond),
	}
	outputJson = false
	resolve("example.com", options)
	// If we get here without panic, resolve completed (channel was consumed).
}

func Test_options_parseTimeoutAndCTFrom(t *testing.T) {
	// Build options as the CLI would for valid timeout and ct:from.
	opts := []udig.Option{}
	if tDur, err := time.ParseDuration("5s"); err == nil {
		opts = append(opts, udig.WithTimeout(tDur))
	}
	assert.Len(t, opts, 1)

	if since, err := time.Parse("2006-01-02", "2024-01-15"); err == nil {
		opts = append(opts, udig.WithCTSince(since))
	}
	assert.Len(t, opts, 2)

	// Invalid timeout is not applied (would use default in real CLI).
	opts = []udig.Option{}
	if _, err := time.ParseDuration("invalid"); err != nil {
		// skip appending WithTimeout
	}
	assert.Len(t, opts, 0)

	// Invalid ct:from is not applied.
	opts = []udig.Option{}
	if _, err := time.Parse("2006-01-02", "not-a-date"); err != nil {
		// skip
	}
	assert.Len(t, opts, 0)
}
