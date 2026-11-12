# Security policy

## Reporting a vulnerability

If you find a security problem in the scan, please report it privately
through GitHub: open the repository's **Security** tab and choose
**Report a vulnerability**. Please do not open a public issue for it.

Useful things to include: the script version (from `scan-manifest.json` or
the top of the script), what you ran, what happened, and what you expected.
Never include scan results, tenant identifiers, tokens or other data from a
real tenant.

Troglodyte Security will acknowledge the report, investigate, and publish a
fixed version with its new SHA-256 hash on trogsec.com.

## What counts as a vulnerability

Anything that breaks one of the scan's promises, for example:

- requesting or using a Microsoft Graph permission that is not read-only;
- making a change to the tenant;
- sending data anywhere other than Microsoft sign-in, Microsoft Graph or the
  PowerShell Gallery;
- writing a token or credential to disk or to the output folder;
- running code that is not the pinned Maester, Microsoft.Graph.Authentication
  or Pester version.

## Supported versions

Only the latest released version, the one whose hash is published on
trogsec.com, is supported.
