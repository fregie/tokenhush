package rules

// Active selection and rollback for the rule client. Active is read-only: it
// re-verifies the cached bytes and never mutates state, so a read (including
// `rules sync --check`) can never write to disk. Rollback changes the active
// serial to the next lower verified, unrevoked pack, or to the built-in
// defaults when none remains.

import (
	"fmt"
)

// Active returns the currently selected remote rule set, re-verifying the
// cached bytes. Any problem falls back to the built-in defaults with a warning;
// the underlying I/O error is not fatal because the system stays functional.
func (c *Client) Active() (ActiveRules, error) {
	if err := c.validate(); err != nil {
		return ActiveRules{}, err
	}
	return c.activeState()
}

// activeState is the read-only core of Active.
func (c *Client) activeState() (ActiveRules, error) {
	serial, ok, err := c.Cache.Active()
	if err != nil {
		return c.builtinWarn(fmt.Sprintf("read active pointer: %v", err)), nil
	}
	if !ok {
		return ActiveRules{}, nil
	}
	if rev, rerr := c.Cache.Revoked(); rerr == nil && rev.Revokes(serial) {
		return c.builtinWarn(fmt.Sprintf("cached serial %d is revoked", serial)), nil
	}
	rawManifest, rawBundle, err := c.Cache.Load(serial)
	if err != nil {
		return c.builtinWarn(fmt.Sprintf("cached serial %d unreadable: %v", serial, err)), nil
	}
	m, err := c.Verifier.VerifyManifest(rawManifest)
	if err != nil {
		return c.builtinWarn(fmt.Sprintf("cached serial %d manifest invalid: %v", serial, err)), nil
	}
	p, err := c.Verifier.VerifyPack(rawBundle)
	if err != nil {
		return c.builtinWarn(fmt.Sprintf("cached serial %d pack invalid: %v", serial, err)), nil
	}
	if p.Serial != m.Serial || !hashMatches(m.BundleSHA256, rawBundle) {
		return c.builtinWarn(fmt.Sprintf("cached serial %d fails integrity checks", serial)), nil
	}
	if _, err := Compile(p.Content(), DefaultOptions()); err != nil {
		return c.builtinWarn(fmt.Sprintf("cached serial %d does not compile: %v", serial, err)), nil
	}
	cfg := p.Content()
	return ActiveRules{Config: cfg, Serial: serial}, nil
}

// builtinWarn records a fallback to the compiled-in defaults.
func (c *Client) builtinWarn(msg string) ActiveRules {
	w := "rules: " + msg + "; using built-in defaults"
	c.warn(w)
	return ActiveRules{Warnings: []string{w}}
}

// Rollback selects the highest cached serial below the active one that is not
// revoked and still verifies, or clears the selection to the built-in defaults
// when none remains. It reports ErrNothingToRollback when no remote pack is
// active.
func (c *Client) Rollback() (ActiveRules, error) {
	if err := c.validate(); err != nil {
		return ActiveRules{}, err
	}
	active, ok, err := c.Cache.Active()
	if err != nil {
		return ActiveRules{}, err
	}
	if !ok {
		return ActiveRules{}, ErrNothingToRollback
	}
	serials, err := c.Cache.Serials()
	if err != nil {
		return ActiveRules{}, err
	}
	rev, _ := c.Cache.Revoked()
	var prev uint64
	for _, s := range serials {
		if s < active && s > prev && !rev.Revokes(s) {
			prev = s
		}
	}
	if prev == 0 {
		if err := c.Cache.SetActive(0); err != nil {
			return ActiveRules{}, err
		}
		w := "rules: no earlier cached rule pack; using built-in defaults"
		c.warn(w)
		return ActiveRules{Warnings: []string{w}}, nil
	}
	if err := c.Cache.SetActive(prev); err != nil {
		return ActiveRules{}, err
	}
	res, err := c.activeState()
	if err != nil {
		return res, err
	}
	w := fmt.Sprintf("rules: rolled back to cached serial %d", prev)
	c.warn(w)
	res.Warnings = append([]string{w}, res.Warnings...)
	return res, nil
}
