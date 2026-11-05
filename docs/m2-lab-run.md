# M2 lab run sheet

For TrogSec's Red Herring lab tenant only. Never run the comparison script
against a client tenant, and never paste a client's scan output into any AI
tool.

The goal is to confirm four things before v0.1.0:

1. The scan runs end to end on Windows with PowerShell 7.4 or later.
2. The pinned Microsoft.Graph.Authentication 2.41.2 installs and loads next to
   Maester 2.3.0.
3. The 13 scopes are enough: no identity test changes result when Maester's
   full default list of 25 read-only scopes is granted instead.
4. A Global Reader can run the scan once admin consent exists.

## Before you start

- A Windows machine with PowerShell 7.4 or later (`pwsh -v`).
- A clone of this repository on the `main` branch.
- A Red Herring account that can grant admin consent (Global Administrator)
  for the first run, and a Global Reader account for step 4.

## Steps

Run each command from the repository folder in a new `pwsh` window.

**1. Normal scan, 13 scopes.** Sign in as the Global Administrator and grant
consent when asked.

```powershell
pwsh -File .\src\Invoke-TrogsecFreeScan.ps1 -TenantId redherringfishing.com -OutputPath C:\LabRuns\scan-13
```

Note from the console whether Graph 2.41.2 installed and loaded without
errors. If it fails, copy the error text; it holds no tenant data.

**2. Comparison run, 25 scopes.** Same account, new `pwsh` window. It asks for
consent again, for the 12 extra scopes.

```powershell
pwsh -File .\tools\Invoke-LabFullScopeRun.ps1 -TenantId redherringfishing.com -OutputPath C:\LabRuns\full-25
```

**3. Compare.**

```powershell
pwsh -File .\tools\Compare-ScanResult.ps1 `
    -Reference (Get-ChildItem C:\LabRuns\scan-13 -Directory)[0].FullName `
    -Difference (Get-ChildItem C:\LabRuns\full-25 -Directory)[0].FullName `
    -AsJson > C:\LabRuns\comparison.json
```

The output lists only result counts, test IDs, test titles and results.

**4. Remove the extra consent.** In the Entra admin center, open Enterprise
applications, Microsoft Graph Command Line Tools, Permissions, and remove the
12 scopes the scan does not request (the 25 in
`tools/Invoke-LabFullScopeRun.ps1` minus the 13 in the README). Remove any
write scope consented to this app in the past too, because the scan stops if
the sign-in carries one.

**5. Global Reader run.** Sign in as the Global Reader.

```powershell
pwsh -File .\src\Invoke-TrogsecFreeScan.ps1 -TenantId redherringfishing.com -OutputPath C:\LabRuns\global-reader
```

Note the result counts the console prints at the end, and compare them with
step 1's.

## What to send back

- `C:\LabRuns\comparison.json`
- Whether Graph 2.41.2 loaded cleanly, and any error text.
- The step 5 result counts, and whether the run finished.

Lab output is fine to share in full if it helps, since Red Herring is
TrogSec's own lab tenant. Do not send output from trogsec.com or any client
tenant.

## What the results decide

- **No differences in step 3:** the 13 scopes stand.
- **Some tests change from Skipped or Error to a result:** each one is a
  decision for Bennett: add the scope it needs, or accept the skip and list it
  in the client instructions.
- **Graph 2.41.2 fails to load:** change the pin to the version Maester's own
  CI uses and run step 1 again.
- **Step 5 fails or differs from step 1:** client instructions name the role
  the scan needs.
