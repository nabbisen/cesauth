/**
 * RFC 178 §4 / §4b, RFC 179 §4/§5/§6 — stylesheet-presence.spec.ts
 *
 * RFC 179 imported nine lines of CSS (`.sr-only`, `crates/frontend/static/
 * base.css`) that already existed at the mockup pin R2a used, and wired
 * them into `leptos_shell.rs`'s `<head>`. Importing was the easy half.
 *
 * The hard half: RFC 178's own `ruleCount > 0` assertion is satisfied by
 * `.sr-only` alone, so landing the import bare would flip this gate from
 * "loudly exempt" to "quietly passing" while leaving 95 of 96 distinct CSR
 * class names with no rule at all and nothing reporting it (RFC 179 §5).
 * That is strictly worse than before. So this is now a **census**, not a
 * count — every scanned name is either declared styled and verified to
 * have a matching rule, or it falls into the single, dated, reported
 * not-yet-styled remainder. `unclassified` must be 0.
 *
 * ## Why declare the styled set, not the exempt one (RFC 179 §6.1)
 *
 * An earlier design named the 95 unstyled class names individually, one
 * exemption entry each, to delete as the stylesheet grows. That inverts on
 * every future import: 83 hand-maintained deletions is a list nobody keeps
 * honest. Declaring the **complement** instead means one line of
 * maintenance per import (add the newly-styled names to
 * `DECLARED_STYLED`) rather than N deletions, with the same staleness
 * guarantee pointed the other way: a class that gains a rule without
 * being added to `DECLARED_STYLED` fails, naming itself, so the
 * stylesheet cannot grow past what has been reviewed.
 *
 * ## The denominator (RFC 179 §4.2/§6, §10.1's own corrections)
 *
 * 84 distinct names come from a literal `class="..."` grep over `pages/`
 * and `components/`. Nine more `class=` sites compute their value in
 * Rust, which that grep cannot see at all — RFC 179's own first pass
 * missed them too (§10.1), which is why they are resolved here by hand,
 * cited to the exact source line, rather than trusted as a flat grep
 * output. Seven of the nine resolve to concrete literals (contributing 12
 * new names: `84 + 12 = 96`); two compute a class name from a
 * caller-supplied prop and are not statically enumerable — declared out
 * by name rather than guessed (a component's own doc comment listing
 * "intended" values is not a constraint). Verified 2026-11-07 that
 * neither has an actual call site in `pages/`/`components/` today
 * (`grep -rn "<Badge\|<MetricChip" crates/frontend/src --include='*.rs'`
 * — zero results), so declaring them out is not currently hiding a real
 * rendered class, only a theoretical one; re-verify this if either
 * component gains a caller.
 *
 * `LC_ALL=C` matters for any shell reproduction of this census (RFC 179
 * §10.1's third correction: `comm` on locale-sorted input silently
 * produced a wrong-but-summing-correctly partition). This file does its
 * own set operations in JS, which has no locale-sort failure mode, but
 * the lesson generalises: a census number is only as good as its
 * matcher's vocabulary, stated beside the number.
 *
 * ## RFC 180 (R2b) update
 *
 * R2b's ten imported `components/{shells,nav,domain}` files add 37 new
 * literal names, plus two more computed sites a literal grep cannot see
 * (`operator_shell.rs`'s `Environment::class()`, a 3-arm match resolving
 * to `env-badge`/`production`/`local`; and `is_active()`'s 2-arm
 * if/else, resolving to `sidebar-link` -- `active` itself was already
 * resolved via `density_toggle.rs`), both added to
 * `RESOLVED_COMPUTED_NAMES` above. One more site is caller-supplied and
 * not statically enumerable (`tenant_admin_shell.rs`'s `<span
 * class=cls>`, `cls` being half of the `tenant_badge` prop), added to
 * `DECLARED_OUT_SITES`. No `DECLARED_STYLED` growth -- R2b touches no
 * CSS (RFC 179 owns that) -- so the new names fall under
 * `not-yet-styled`: 96 -> 136 = 1 declared-and-matching (`sr-only`,
 * unchanged) + 135 not-yet-styled + 0 unclassified.
 */
import * as fs from 'fs';
import * as path from 'path';
import { test, expect } from '@playwright/test';
import { PUBLIC_ROUTES, gotoMounted } from './support';

const REPO_ROOT = path.resolve(__dirname, '../..');
const SCAN_DIRS = [
  path.join(REPO_ROOT, 'crates/frontend/src/pages'),
  path.join(REPO_ROOT, 'crates/frontend/src/components'),
];

function listRustFiles(dir: string): string[] {
  const out: string[] = [];
  for (const entry of fs.readdirSync(dir, { withFileTypes: true })) {
    const full = path.join(dir, entry.name);
    if (entry.isDirectory()) out.push(...listRustFiles(full));
    else if (entry.name.endsWith('.rs')) out.push(full);
  }
  return out;
}

/** Literal `class="..."` sites — the part a plain grep already sees. */
function literalClassNames(files: string[]): Set<string> {
  const names = new Set<string>();
  for (const file of files) {
    const text = fs.readFileSync(file, 'utf8');
    for (const m of text.matchAll(/class="([^"]*)"/g)) {
      for (const token of m[1].split(/\s+/)) if (token) names.add(token);
    }
  }
  return names;
}

/**
 * RFC 179 §4.2/§6: the nine `class=` sites a literal grep cannot see
 * (`grep -rn 'class=[^"]' crates/frontend/src/pages crates/frontend/src/
 * components`), hand-resolved and cited. Seven resolve to concrete
 * literals; the other two (badge.rs, metric_strip.rs's tone suffix) are
 * `DECLARED_OUT_SITES` below, not here.
 */
const RESOLVED_COMPUTED_NAMES: ReadonlyArray<{ names: string[]; site: string }> = [
  {
    names: ['alert-info', 'alert-success', 'alert-warning', 'alert-danger'],
    site: 'components/primitives/alert.rs: fn class(self), 4-arm match ("alert" itself is already literal elsewhere)',
  },
  {
    names: ['col-secondary'],
    site: 'components/primitives/entity_list.rs:70, inline if/else (the else branch is "")',
  },
  {
    names: ['step', 'step-done', 'step-current'],
    site: 'components/primitives/stepper.rs: 3-arm match on StepState',
  },
  {
    names: ['crumb-current'],
    site: 'components/primitives/scope_breadcrumb.rs:36, inline if/else ("crumb" itself is already literal elsewhere)',
  },
  {
    names: ['density-btn', 'active'],
    site: 'components/primitives/density_toggle.rs:17,25, two inline if/else closures',
  },
  {
    names: ['metric-chip', 'metric-chip-link'],
    site: 'components/primitives/metric_strip.rs: the tone=None literal fallback, and the literal "metric-chip-link" suffix in the Some(href) branch',
  },
  {
    names: ['env-badge', 'production', 'local'],
    site: 'components/shells/operator_shell.rs: fn class(self) on Environment, 3-arm match (RFC 180 R2b)',
  },
  {
    names: ['sidebar-link'],
    site: 'components/shells/operator_shell.rs: is_active() closure, and components/shells/tenant_admin_shell.rs:57, same inline if/else pair ("active" itself already resolved above via density_toggle.rs) (RFC 180 R2b)',
  },
];

/**
 * RFC 179 §4.2/§6: `format!()` over a caller-supplied prop — the suffix
 * is not statically enumerable, and a doc comment listing intended
 * values is not a constraint. Verified 2026-11-07: zero call sites for
 * either component in pages/ or components/ today.
 */
const DECLARED_OUT_SITES: readonly string[] = [
  'components/primitives/badge.rs: format!("badge {}", class) -- class is a caller-supplied prop; no <Badge usage exists in scope',
  'components/primitives/metric_strip.rs: format!("metric-chip metric-chip-{t}") -- t is a caller-supplied prop; no <MetricChip usage exists in scope (its literal fallback and literal suffix are resolved above, not here)',
  'components/shells/tenant_admin_shell.rs:76: <span class=cls>{lbl}</span> -- cls is the first element of the caller-supplied tenant_badge: Option<(String, String)> prop; not statically enumerable (RFC 180 R2b)',
];

/**
 * RFC 179 §6.1: the styled set, declared -- not the exempt one. After
 * RFC 179 §4's import this is one entry. Growing this list (as future
 * imports land real CSS) is the gate's only required maintenance.
 */
const DECLARED_STYLED = new Set<string>(['sr-only']); // RFC 179 §4

const CENSUS_ROUTE = PUBLIC_ROUTES[0];

test('RFC 179 census: every CSR class name is declared styled, or reported not-yet-styled', async ({ page }) => {
  const files = SCAN_DIRS.flatMap(listRustFiles);
  const allNames = literalClassNames(files);
  for (const { names } of RESOLVED_COMPUTED_NAMES) {
    for (const n of names) allNames.add(n);
  }

  await gotoMounted(page, CENSUS_ROUTE);
  const styledSelectors: string[] = await page.evaluate(() => {
    const out = new Set<string>();
    for (const sheet of Array.from(document.styleSheets)) {
      let rules: CSSRuleList;
      try {
        rules = sheet.cssRules;
      } catch {
        continue; // cross-origin stylesheet; this app loads none
      }
      for (const rule of Array.from(rules)) {
        if (!(rule instanceof CSSStyleRule)) continue;
        for (const m of rule.selectorText.matchAll(/\.([A-Za-z0-9_-]+)/g)) out.add(m[1]);
      }
    }
    return Array.from(out);
  });
  const styledSet = new Set(styledSelectors);

  let declaredMatching = 0;
  let notYetStyled = 0;
  const unclassified: string[] = [];
  const staleDeclaredMissing: string[] = []; // declared styled, but no rule -- a regression
  const staleUndeclaredStyled: string[] = []; // not declared, but has a rule -- unreviewed growth

  for (const name of allNames) {
    const isDeclared = DECLARED_STYLED.has(name);
    const hasRule = styledSet.has(name);
    if (isDeclared && hasRule) declaredMatching++;
    else if (isDeclared && !hasRule) staleDeclaredMissing.push(name);
    else if (!isDeclared && !hasRule) notYetStyled++;
    else staleUndeclaredStyled.push(name);
  }

  const total = allNames.size;
  console.log(
    `ℹ️  RFC 179 census: ${total} = ${declaredMatching} declared-and-matching + `
      + `${notYetStyled} not-yet-styled (one dated exemption, RFC 179 §8's `
      + `deferred import) + ${unclassified.length} unclassified`
      + (staleDeclaredMissing.length || staleUndeclaredStyled.length
        ? ` -- PLUS ${staleDeclaredMissing.length} declared-but-missing and `
          + `${staleUndeclaredStyled.length} undeclared-but-styled (stale; see below)`
        : ''),
  );
  console.log(
    `ℹ️  declared out (not statically enumerable, RFC 179 §6/§4.2): `
      + `${DECLARED_OUT_SITES.length} site(s) -- ${DECLARED_OUT_SITES.join('; ')}`,
  );

  // Named staleness failures first, so a reader sees which class is the
  // problem rather than a bare arithmetic mismatch -- the arithmetic
  // check below only ever fires for a bug in this census itself, since
  // every name provably falls into exactly one of the five buckets.
  expect(
    staleDeclaredMissing,
    `DECLARED_STYLED name(s) with no matching rule in the loaded stylesheet -- `
      + `a regression in the imported CSS, not a census bug: `
      + `${staleDeclaredMissing.join(', ')}`,
  ).toHaveLength(0);

  expect(
    staleUndeclaredStyled,
    `class name(s) NOT in DECLARED_STYLED that now have a matching rule -- `
      + `the stylesheet grew past what this census reviewed. Add each to `
      + `DECLARED_STYLED with its own citation (which import, which RFC) `
      + `rather than leaving the growth unreviewed: ${staleUndeclaredStyled.join(', ')}`,
  ).toHaveLength(0);

  expect(
    total,
    `census arithmetic does not reconcile: ${total} scanned != `
      + `${declaredMatching} + ${notYetStyled} + ${staleDeclaredMissing.length} + `
      + `${staleUndeclaredStyled.length} + ${unclassified.length} -- this is a `
      + 'bug in the census itself, not a finding about the stylesheet',
  ).toBe(
    declaredMatching + notYetStyled + staleDeclaredMissing.length
      + staleUndeclaredStyled.length + unclassified.length,
  );
});

for (const route of PUBLIC_ROUTES) {
  test(`the mounted app has at least one author stylesheet rule: ${route}`, async ({ page }) => {
    await gotoMounted(page, route);

    const ruleCount = await page.evaluate(() => {
      let count = 0;
      for (const sheet of Array.from(document.styleSheets)) {
        try {
          count += sheet.cssRules.length;
        } catch {
          // A cross-origin stylesheet throws on .cssRules; this app loads
          // none, but failing closed (not counting it) is the safe default.
        }
      }
      return count;
    });

    expect(
      ruleCount,
      `${route}: the mounted app has no author CSS rules at all — it renders `
        + 'at browser defaults, and any sr-only-style class does nothing '
        + '(RFC 178/179)',
    ).toBeGreaterThan(0);
  });
}
