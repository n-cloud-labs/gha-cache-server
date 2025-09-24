# Release process

This project publishes Debian, RPM and Arch Linux packages, a multi-architecture
container image, and a Helm chart whenever a semantic version tag is pushed to
GitHub. The automation lives in `.github/workflows/release.yml` and turns a tag
such as `v1.2.3` into a full set of signed release artifacts.

## Prerequisites

Before cutting a release make sure the following requirements are satisfied:

- The `Cargo.toml` version, changelog entries and chart metadata reflect the
  version you plan to ship.
- Maintainers have push permissions on the repository so they can create and
  push tags.
- Signing keys are configured when your policies require signed packages,
  container images or charts:
  - `DEB_SIGNING_KEY` and `DEB_SIGNING_KEY_ID` (plus optional
    `DEB_SIGNING_PASSPHRASE`) for `dpkg-sig`.
  - `RPM_SIGNING_KEY`, `RPM_SIGNING_KEY_ID` and the optional
    `RPM_SIGNING_PASSPHRASE` for `rpm --addsign`.
  - `COSIGN_KEY` and `COSIGN_PASSWORD` for `cosign` when signing the container
    image and Helm chart archives.
  - Provide ASCII-armored private keys. They may be passphrase-protected, but a
    passphrase-less key simplifies the non-interactive signing steps.
- Optionally configure repository variables to tune publishing targets:
  - `RELEASE_IMAGE_NAME` overrides the default container image reference
    (`ghcr.io/<owner>/<repo>`).
  - `HELM_REPOSITORY_URL` sets the public URL for the Helm repository if it is
    not hosted at `https://<owner>.github.io/<repo>`.

## Generating signing keys

Create dedicated signing material for the packaging and container workflows.
Export the private keys in ASCII-armored form so they can be stored as GitHub
secrets, and keep the public certificates in a safe place so downstream users
can verify signatures.

### Debian (`dpkg-sig`)

1. Generate a signing-only OpenPGP key with a descriptive identity:
   ```bash
   gpg --quick-generate-key "gha-cache-server Debian Signing <release@example.com>" rsa4096 sign 1y
   ```
2. Retrieve the key ID from `gpg --list-secret-keys` and export the armored
   private key and optional revocation certificate:
   ```bash
   gpg --armor --export-secret-keys KEYID > deb-signing-key.asc
   gpg --armor --output deb-signing-key.rev --gen-revoke KEYID
   ```
3. Store the contents of `deb-signing-key.asc` inside the `DEB_SIGNING_KEY`
   secret (and the passphrase in `DEB_SIGNING_PASSPHRASE` when set). Keep the
   revocation certificate offline so the key can be revoked if compromised.

### RPM (`rpm --addsign`)

1. Create a dedicated OpenPGP key, optionally reusing the same identity as for
   Debian packages:
   ```bash
   gpg --quick-generate-key "gha-cache-server RPM Signing <release@example.com>" rsa4096 sign 1y
   ```
2. Export the key in ASCII-armored form and record the key ID:
   ```bash
   gpg --armor --export-secret-keys KEYID > rpm-signing-key.asc
   gpg --armor --export KEYID > rpm-signing-key.pub
   ```
3. Configure the `RPM_SIGNING_KEY`, `RPM_SIGNING_KEY_ID`, and optional
   `RPM_SIGNING_PASSPHRASE` secrets with the exported private key, its ID, and
   passphrase. Publish the public key (`rpm-signing-key.pub`) so consumers can
   import it into their RPM keyring.

### Cosign (container image and Helm chart)

1. Install Cosign locally and generate a new key pair:
   ```bash
   cosign generate-key-pair
   ```
   The command produces `cosign.key` (private key) and `cosign.pub` (public
   certificate). Provide the `COSIGN_PASSWORD` when prompted to encrypt the
   private key, or press Enter to keep it unencrypted.
2. Upload the private key to the `COSIGN_KEY` secret and, if applicable, the
   password to the `COSIGN_PASSWORD` secret. Publish the public certificate so
   users can verify the container image and chart signatures with
   `cosign verify`.

## Cutting a release

1. Merge all code destined for the release into the default branch.
2. Create a signed tag following the `vMAJOR.MINOR.PATCH` convention, for
   example:
   ```bash
   git tag -s v1.2.3 -m "gha-cache-server 1.2.3"
   git push origin v1.2.3
   ```
3. Pushing the tag triggers the **Release** workflow. The pipeline performs the
   following steps:
   - **prepare** derives version metadata, normalises the Arch `pkgver`, and
     determines the Helm repository URL and container image name.
   - **build** runs a matrix covering `debian`, `rpm`, `arch`, `docker`, and
     `helm` targets:
     - Debian packages are produced with `dpkg-buildpackage`. If the Debian
       signing secrets are present each `.deb` is signed via `dpkg-sig`.
     - RPM packages are built inside a Fedora container using `rpmbuild` and
       optionally signed with `rpm --addsign`.
     - Arch packages are created in an Arch Linux container with `makepkg`.
     - A multi-architecture container image (`linux/amd64` and `linux/arm64`)
       is built with BuildKit (`docker/setup-qemu-action` and
       `docker/build-push-action`) and pushed to GitHub Container Registry.
       When cosign credentials are available the first published tag is signed.
     - The Helm chart under `deploy/charts/gha-cache-server` is packaged with
       `helm package`, published to the `gh-pages` branch via
       `peaceiris/actions-gh-pages`, and optionally signed with `cosign`.
   - **release** collects all uploaded artifacts (`.deb`, `.rpm`, `.pkg.tar.zst`,
     `.tgz`, and accompanying signatures) and creates the GitHub Release with
     generated release notes.
4. Verify the workflow status in the GitHub Actions tab. All matrix legs must
   finish successfully for the release job to run.
5. Validate the published assets:
   - Confirm the container tags on `ghcr.io` include the new version and desired
     semver aliases.
   - Check the GitHub Release page for the expected binaries and signatures.
   - Ensure the Helm repository (for example the `gh-pages` branch) contains the
     new chart archive and an updated `index.yaml`.

## Troubleshooting and tips

- The Debian packaging step edits `debian/changelog` on the fly so that the
  generated `.deb` file matches the pushed tag. These modifications are
  ephemeral and do not persist in the repository.
- Both RPM and Arch builds execute inside containers. The workflow remaps file
  ownership afterwards to avoid permission issues while uploading artifacts.
- When introducing pre-release tags (`-rc`, `-beta`, etc.) the workflow marks
  the GitHub Release as a pre-release automatically.
- If you rotate signing keys remember to update the corresponding secrets
  before creating the next tag. Missing secrets simply skip the signing steps;
  the build will still complete but the resulting artifacts will be unsigned.
