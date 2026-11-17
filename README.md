# Hyalos marketplace

Skills for [Hyalos](https://github.com/hyaloslabs/hyalos), built reproducibly and signed keylessly by this repository's release pipeline. Hyalos installs a skill from here only if its Sigstore bundle shows that `release.yml`, run for this repository's `main`, signed it (ADR-0007, ADR-0093 and ADR-0094 in the Hyalos repository).

## Layout

| Path | What |
| --- | --- |
| `skills/<name>/` | One Agent Skill: a `SKILL.md` naming it, its scripts, and `capabilities.json` if it asks for any |
| `versions.json` | Each skill's version. A changed skill needs a new one; CI refuses a change without it |
| `tools/pack.py` | Writes a skill's archive in the format Hyalos reads (ADR-0090), byte for byte |
| `tools/build.py` | Builds every skill. It reads only the repository, so two builds of one commit agree |
| `tools/index.py` | Writes `index.json` for a release |
| `tools/check_workflows.py` | Fails if a workflow could sign other than as the release pipeline, or reach the settings token |
| `tools/snapshot.py`, `trust/sigstore-tuf-root.json`, `tools/requirements-snapshot.txt` | Fetches Sigstore's trusted root through TUF, from the TUF root pinned here, with a hash-pinned client, and wraps it as the snapshot Hyalos imports |
| `tools/check_settings.py`, `settings/expected.json` | The repository's protection settings, and what they must be |
| `tests/reference/` | A fixed skill whose digest Hyalos pins too, so the two archive writers cannot drift |

## A release

Every push to `main` runs `release.yml`:

1. Every skill is built on two runner images (Ubuntu 24.04 and 22.04).
2. The two builds must be the same bytes, or nothing is signed.
3. Each archive is signed keylessly with cosign, which logs it in Rekor, and its bundle is checked for the pinned identity and refused for another.
4. `index.json`, the archives and their bundles are published as release `r<run>`, marked latest. Nothing is published when nothing changed.

It also runs every day on a schedule, which runs `main`'s own file and so signs as the same identity. Each run fetches Sigstore's trusted root through TUF and signs it as `trusted-root.json`, the snapshot Hyalos verifies releases against (ADR-0007, ADR-0097). A release carries it, and a new release is published when the index changed, the trusted root changed, or the last one is 7 days old, so what the latest release carries is never older than that. A run that fails publishes nothing and opens an issue labelled `release-failed`; the last release stays current.

There is no signing key. What decides what is signed is what reaches `main`, so `main` accepts only pull requests a code owner approved, and never a force push or a deletion.

The identity Hyalos pins is this file at `main` in this repository. Renaming `release.yml`, moving the repository or releasing from another branch makes every release unverifiable until a Hyalos release pins the new identity.

## The settings that protect it

Those settings live in GitHub, not in this repository: the `main` ruleset, the Actions settings, who holds admin, and the `settings-check` environment. `settings.yml` compares them with `settings/expected.json` every day. On a difference it opens one issue labelled `settings-drift`, and closes it when they match again. `release.yml` signs nothing unless that check last passed within 8 days and no such issue is open, so a check that stopped running blocks the next release rather than going unnoticed.

The check reads through a GitHub App of its own, read-only on Actions, Administration, Metadata and the organization's members. It also checks that App's own grant, so a wider App, or one installed elsewhere, is drift too. Making the App, storing its key, the first run, rotating the key, and changing a setting on purpose are in the maintainer runbook, [`docs/operations/marketplace.md`](https://github.com/hyaloslabs/hyalos/blob/main/docs/operations/marketplace.md) in the Hyalos repository. The App can be made from `https://hyaloslabs.github.io/hyalos/setup/settings-check/`.

## Installing from it

The repository is private, so its release assets need a GitHub login to download, and Hyalos fetches without one. Download a release into a directory and install from there:

```
gh release download --repo hyaloslabs/marketplace --pattern '*' --dir marketplace
hyalos plugin install --index ./marketplace hello
```

The directory is an offline bundle (ADR-0090): the same check runs with no network.

## Adding a skill

Add `skills/<name>/` and its version in `versions.json`, and open a pull request. CI checks it builds, that nothing changed without a new version, and the workflow rules. Merging it releases it.
