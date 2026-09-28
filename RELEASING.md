# Maintainer-controlled release candidates

`.github/workflows/release.yml` is a manually dispatched, tag-only candidate
workflow. It builds a wheel, runs strict tests/advisory checks, smoke-tests the
installed artifact, creates SHA-256 checksums/environment evidence, and requests
GitHub OIDC-backed build-provenance attestations for those exact artifacts.

## Maintainer setup and operation

1. Enable and configure the `release` GitHub environment with required reviewers
   and appropriate tag restrictions. Merely naming an environment in YAML does
   **not** configure its protection rules.
2. Protect release tags and the default branch. Require the quality matrix for the
   commit being released. Review code and dependency updates before tagging.
3. Set the package version and create a matching `vVERSION` tag through the
   maintainer's normal reviewed process. Dispatch **Attested release candidate**
   on that existing tag. The workflow rejects a tag/version mismatch.
4. Approve the environment job if all release criteria are met. Download the
   `attested-release-candidate` artifact and retain its checksum/environment files.
5. Verify the wheel's attestation:

   ```console
   gh attestation verify websentinel-VERSION-py3-none-any.whl --repo aaryx/websentinel --signer-workflow aaryx/websentinel/.github/workflows/release.yml
   ```

6. Publish the exact verified artifact through the maintainer-controlled release
   process. Rebuilding produces a different artifact and requires new verification.

The workflow has no `contents: write` or package-publishing permission. It produces
an attested candidate, not an automatically published GitHub/PyPI release. OIDC
attestations are signed provenance statements, not a GPG signature on the Git tag.
GitHub attestation availability depends on repository visibility and plan.

## Local artifact checks

```console
python -m pip wheel . --no-deps --wheel-dir dist
python scripts/release_manifest.py dist
```

Install the wheel in a clean environment, then run `scripts/release_smoke.py` using
that environment's interpreter. The smoke test invokes the installed CLI from a
temporary working directory and checks loopback HTTP, completion state, and secret
redaction.

All third-party action references are pinned to full commits. Dependabot is
configured to propose updates. The recorded environment is provenance evidence,
not a reproducible dependency lock; a maintainer should separately approve a
locked release environment where reproducible dependency resolution is required.

## Execution status

Local wheel/manifest/smoke checks can run without repository changes. Remote
attestation, environment protections, signing identity, publication, and Linux/
macOS matrix results are **not established by this file**. No workflow has been
dispatched or release published as part of this local implementation pass.
