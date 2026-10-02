# Publishing

Two paths. The second is the one to use once it is set up.

---

## The rename from Proofwire

Up to 0.5.0 the project was **Proofwire**: npm packages `proofwire` and
`@proof_wire/*`, the `pw` command, and the GitHub organisation `proofwire`.
It was renamed **Deedwrit** because another developer tools company was
already using the name. Those releases stay on npm as they are; the next
release is the first under the new names, and the old packages get a
deprecation notice pointing here (see "After the rename" below).

For a few days in between, `main` used the name **Vouchwell**. Nothing was
published under it; files, settings and evidence it wrote are read like the
Proofwire ones.

## What is already done

- The repository is public, with GitHub's private vulnerability reporting on,
  so the link in [`SECURITY.md`](../SECURITY.md) works.
- 0.2.0, 0.3.0 and 0.5.0 were published under the old names, from tagged
  commits, each with a GitHub release carrying its `CHANGELOG.md` section.
- The website is live: at <https://proofwire.github.io/proofwire/> until the
  organisation is renamed, then at <https://deedwrit.github.io/deedwrit/>. It is static files in `site/`, deployed by
  `.github/workflows/pages.yml`; the site's own tests gate the deploy and
  `site/test/` is not published.
- CI runs the full suite on Linux, macOS and Windows, on Node 22 LTS and 24,
  plus a compatibility job that exercises the core on Node 20.11 — the oldest
  version it claims to support.
- Every package carries its own README, LICENSE and repository metadata, so
  each npm page links back to its own subtree rather than the repo root.
- Scoped packages are marked `publishConfig.access=public`, which they need
  in order to publish at all under a free org.
- `npm run release:dry` passes except for authentication.

## What is not, and cannot be from here

Publishing needs npm credentials. Nothing in this repository asks for them and
nothing stores them — that is deliberate. Both paths below put the credential
somewhere you control.

---

## Path 1 — from your machine

How 0.2.0, 0.3.0 and 0.4.0 were released. First, **bump**: write what the
release changes under `## Unreleased` in `CHANGELOG.md`, then

```bash
npm run bump -- 0.4.1           # every package, every internal pin, the Python
                                # SDK, the lockfile, and the CHANGELOG heading
git commit -am "Release 0.4.1" && git push
```

Then publish and tag:

```bash
npm login                       # opens a browser
npm run release:dry             # the preflight, publishing nothing
npm run release                 # asks for a 2FA code per package
git tag -a v0.4.1 -m "Deedwrit 0.4.1" && git push origin v0.4.1
```

The preflight refuses to publish a version that is already on npm, a
package pinning another at an older version, a version with no CHANGELOG
section, or a Python SDK at a different number. Forgetting to bump used to
look like a successful release that skipped every package.

Tag *after* publishing. The tag push runs `.github/workflows/release.yml`,
which, with no `NPM_TOKEN` secret, re-runs the suite on three operating
systems, confirms every package at the tagged version is genuinely on npm, and
creates the GitHub release from that version's `CHANGELOG.md` section. Push
the tag first and it fails, saying what isn't published yet.

### First time only: create the scope

The four `@deedwrit/*` packages need an npm org to live in. It is free for
public packages:

**https://www.npmjs.com/org/create** → name it `deedwrit`.

Without it those four fail to publish, and it is not optional for the CLI
either: the unscoped `deedwrit` package depends on `@deedwrit/core` and
`@deedwrit/proxy`, so a CLI published without them installs nowhere.

### What the script does

Preflight, then publish in dependency order:

```
core  →  proxy  →  dashboard  →  server  →  cli
```

Order matters. Publishing the CLI before the proxy leaves a package on the
registry whose dependency does not exist yet: briefly uninstallable, and not
fixable by unpublishing.

Preflight refuses to continue on a failing test run, a dirty working tree,
mismatched versions, or missing auth. A version already on the registry is
skipped, so a re-run after a partial failure resumes rather than erroring.

> **npm is effectively write-once.** `npm unpublish` works for 72 hours, and
> the name is held forever either way. Run the dry run first.

---

## Path 2 — from CI, every time after that

Better for a security product, for three reasons: the artifact is built from a
tagged commit anyone can inspect, npm records **provenance attestations**
linking each tarball to the workflow run that produced it, and no long-lived
credential sits on a laptop.

### Setup, once

1. On npm: **Access Tokens → Generate New Token → Granular Access Token**.
   Scope it to the `deedwrit` packages and the `@deedwrit` org, with
   *Read and write*. Set an expiry.
2. On GitHub: **Settings → Secrets and variables → Actions → New repository
   secret**, named `NPM_TOKEN`.

### Releasing

```bash
npm run bump -- 0.4.1
git commit -am "Release 0.4.1"
git tag -a v0.4.1 -m "Deedwrit 0.4.1"
git push && git push --tags
```

(Not `npm version --workspaces`: it leaves the internal `@deedwrit/*` pins at
the old version, so the new CLI would install the old core.)

The tag triggers `.github/workflows/release.yml`, which re-runs the full suite
on three operating systems, checks the tag matches the manifests, publishes
with provenance, and creates the GitHub release from that version's
`CHANGELOG.md` section.

Try it first with **Actions → Release → Run workflow → dry run: true**.

---

## After the first publish

```bash
npx deedwrit@latest --version
npm view deedwrit
```

Then the things that are not automatable and are worth doing deliberately:

- [ ] Check the site noticed. The Pages workflow reruns when Release finishes
      and writes the version into `site/release.json`, which reveals the install
      line on the page. It does so only if `npm view deedwrit repository.url`
      points at this repository: the CLI's name is unscoped, so without that
      check anyone who registered it first would be advertised here. Done for 0.2.0.
- [ ] Enable **2FA on the npm account**. A compromised publish account on a
      package that claims to make things tamper-evident is the worst available
      outcome.
- [ ] Turn on **branch protection** for `main`, requiring CI to pass.
- [ ] Add the repository to **GitHub's secret scanning and Dependabot alerts**
      (Settings → Code security).
- [ ] Commission the cryptographic review in
      [`AUDIT-BRIEF.md`](AUDIT-BRIEF.md) — the one remaining blocker for a
      hosted service, and the thing to do before charging anyone.

## The website's address

The repository is `github.com/deedwrit/deedwrit` and the site is at
<https://deedwrit.github.io/deedwrit/>. Every path on the site is relative, so
it works under any prefix or at a root; moving it changes where it is served
from, not the site.

The bare hostname, <https://deedwrit.github.io/>, is served by a separate
one-file repository, `deedwrit/deedwrit.github.io`, that does nothing but
redirect to `/deedwrit/`. GitHub serves a hostname's root only from a repository
of exactly that name, and keeping the site's source in one place is worth more
than one fewer path segment. If you would rather the site *be* at the root,
rename this repository to `deedwrit.github.io` (that name then appears in every
source link) and delete the redirect repository.

The repository was transferred from a personal account, which left three things
worth knowing:

- GitHub redirects the old repository and `git` URLs. It does not redirect the
  old `github.io` address, which now returns 404.
- `repository` in each `package.json` already names this repository, so the
  first publish carries the right value. The site's npm check compares it with
  `GITHUB_REPOSITORY`; a package published under the old owner's URL would,
  correctly, not be advertised.
- Pages, private vulnerability reporting, the homepage and the topics all
  survived the transfer; that was checked, not assumed.

A custom domain later is Settings → Pages → Custom domain; nothing in the site
needs to change.

## After the rename

Once, in this order. Each is an account action, so none can be done from CI.

0. **Claim the name.** Check <https://github.com/deedwrit> is free (GitHub
   could not be searched when the name was chosen), register `deedwrit.com`,
   and have a trademark search run before announcing it.
1. **GitHub.** Rename the organisation `proofwire` to `deedwrit`
   (Settings → Rename organization), then the repository `proofwire` to
   `deedwrit`, and `proofwire.github.io` to `deedwrit.github.io`. GitHub
   redirects the old repository URLs, so existing clones and links keep
   working; the website moves to <https://deedwrit.github.io/deedwrit/>.
2. **npm.** Create the org `deedwrit` (https://www.npmjs.com/org/create), so
   the `@deedwrit/*` packages have somewhere to publish.
3. **Release.** Bump to the next version and publish as in Path 1 or 2. It is
   the first release of `deedwrit` and `@deedwrit/*`.
4. **Point the old packages at the new ones**, so anyone installing them is
   told where the project went. The old versions stay installable:

   ```bash
   npm deprecate proofwire "Renamed to deedwrit: npm i -g deedwrit"
   for p in core proxy dashboard server; do
     npm deprecate "@proof_wire/$p" "Renamed to @deedwrit/$p"
   done
   ```
5. **PyPI.** Publish `deedwrit` (below). The old name was never published
   there, so there is nothing to deprecate.

Existing users need to change nothing to keep working: the CLI still finds a
`.proofwire/` log and `proofwire.*.json` files, `~/.proofwire` credentials and
`PROOFWIRE_*` settings; the hub keeps using a `proofwire.db` and still answers
at `/.well-known/proofwire`; and bundles labelled `proofwire.bundle` verify.
The same holds for anything written under the interim name, Vouchwell.

## The Python SDK (PyPI)

The Python package lives in `sdk/python`. It's published as **`deedwrit`**
and imported as `deedwrit`, the same name as on npm.

**Once:** create an account at <https://pypi.org>, turn on two-factor
authentication, and create an API token scoped to all projects. After the first
upload, replace it with one scoped to `deedwrit` only.

**Each release**, from the repository root, with the version in
`sdk/python/pyproject.toml` and `sdk/python/src/deedwrit/__init__.py`
matching the npm release:

```bash
cd sdk/python
python -m pip install --upgrade build twine
python -m build                      # sdist and wheel into dist/
python -m twine check dist/*
python -m twine upload dist/*        # asks for the token; username __token__
```

Check it installs cleanly:

```bash
python -m venv /tmp/pwcheck && /tmp/pwcheck/bin/pip install deedwrit
/tmp/pwcheck/bin/python -c "import deedwrit; print(deedwrit.__version__)"
```

## Versioning

All five packages release at the same version; preflight enforces it. The wire
format is versioned separately (`"v": 1` in every receipt) and will be
migrated rather than broken.
