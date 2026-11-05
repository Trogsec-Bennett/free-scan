# Contributing

Issues and pull requests are welcome. The scan runs in other people's
tenants, so a few rules are fixed:

- **Read-only, always.** Never add a Microsoft Graph permission that is not
  read-only, and never weaken the check that stops the scan when one appears.
- **Pinned versions.** Maester, Microsoft.Graph.Authentication and Pester are
  installed at exact versions. Changing a pin is its own pull request, with
  the reason and the new version's release notes linked.
- **No new network calls.** Only Microsoft sign-in, Microsoft Graph and the
  PowerShell Gallery. No telemetry, no uploads.
- **No new dependencies** without discussing it in an issue first.
- **Identity scope.** Adding Exchange, Teams, SharePoint or Intune checks
  changes what the scan asks for, so open an issue before writing code.

## Making a change

1. Run the tests on PowerShell 7.4 or later with Pester 5.7.1:

   ```powershell
   Install-Module Pester -RequiredVersion 5.7.1 -Scope CurrentUser -SkipPublisherCheck
   Invoke-Pester ./tests
   ```

2. Add or change tests for any behaviour you change. Tests mock Maester and
   Microsoft Graph; they must never need a real tenant.
3. Keep files UTF-8 without BOM, with LF line endings (`.editorconfig` and
   `.gitattributes` set this up).
4. Never commit scan output, tenant identifiers, tokens or anything from a
   real tenant, including in tests, issues or screenshots.

Pull requests are merged with merge commits. By contributing you agree that
your contribution is licensed under the [MIT licence](LICENSE).
