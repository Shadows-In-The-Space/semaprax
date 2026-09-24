# Changelog summary

Status: public release summary; v0.6.0 is not published.
Audience: users and contributors who need the recent changes.

This is a quick orientation, not a feature-support claim. For exact changes, read
the [full changelog](https://github.com/wavect/semaprax/blob/main/CHANGELOG.md).
For implementation status and required evidence, use the
[completion matrix](COMPLETION-MATRIX.md).

## v0.6.0 work in progress

`v0.6.0` is the current prerelease tag, but it is not published.

- Local package-registry work now covers signed metadata, lock-bound artifact
  reads, held generations, and a resolver-cache bridge. It is not a hosted
  package service.
- Private native owned-byte and Core Wasm work gained bounded fixtures and
  observed JavaScript-arena settlement evidence. Public parity and complete
  cleanup/fuel evidence remain open.
- The release verifier checks Wavect GmbH's approved GitHub repository and
  owner identities in the signing certificate. The v0.6.0 tag's hosted gate
  has not passed, so there are no v0.6.0 release archives or signed-release
  evidence. See [release status](RELEASE-0.6.0-STATUS.md).

## Latest available prerelease: v0.5.0

v0.5.0 added source-Agent accounting and bounded live-operation envelopes,
broader owned-data and closure support, and reliability repairs across the
supported host paths. It remains the latest downloadable prerelease. Its
[release page](https://github.com/wavect/semaprax/releases/tag/v0.5.0) lists
the available archives.

## Earlier milestones

- v0.4.1 introduced separate public-generic prerequisites and gates. The
  public generic surface remains unsupported and unpublished.
- v0.4.0 is the last accepted
  [hosted-green baseline](RELEASE-0.4.0-STATUS.md). It expanded internal owned
  data, agent workflows, Project profiles, and standard-library packages.
- v0.3.5 and v0.2.0 remain historical prereleases.

The [changelog archive](CHANGELOG-ARCHIVE.md) preserves older detailed notes.
