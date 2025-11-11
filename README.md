# SQLInjectionCheck

Automated static analysis for T-SQL to detect likely SQL injection and related risks.
Parses T-SQL from jobs, procedures, triggers, plan cache and other sources with Microsoft ScriptDom, runs checks and exports results to Excel and trace files.

---

## Quick summary

* **Purpose:** Find likely SQL injection and risky dynamic SQL patterns in captured T‑SQL.
* **Primary language:** PowerShell.
* **Main engine:** `Invoke-TSqlChecks.ps1` (ScriptDom‑based analyzer).

## Features

* Collects T‑SQL from multiple sources (Agent jobs, stored procedures, triggers, plan cache, etc.) and analyzes statements.
* Uses `Microsoft.SqlServer.TransactSql.ScriptDom` for parsing.
* Produces Excel reports and per‑statement trace files for triage and reporting.
* Includes helper and test scripts for validation and automation.

## Repository layout

* `Invoke-TSqlChecks.ps1` — main analyzer.
* `Import-ScriptDom.ps1` — helper to load or copy the ScriptDom DLL.
* `Import-RequiredModules.ps1` — helper to install/validate PowerShell modules.
* `Test-Invoke-TSqlChecks.ps1`, `Test-TSqlInjection.ps1` — example/test runners.
* `Microsoft.SqlServer.TransactSql.ScriptDom.dll` — parser assembly (included for convenience).
* Bundled helper artifacts (e.g., ImportExcel, dbatools) where present.

## Requirements

* Windows or any host with PowerShell support.
* PowerShell 5.1 or later recommended.
* `Microsoft.SqlServer.TransactSql.ScriptDom` assembly available (repository contains DLL for convenience).
* `ImportExcel` PowerShell module (or the included ImportExcel bundle) for Excel output.
* Optional: `dbatools` for inventory and collection helpers.

## Installation

```powershell
git clone https://github.com/mcflyamorim/SQLInjectionCheck.git
cd SQLInjectionCheck
.\Import-RequiredModules.ps1
.\Import-ScriptDom.ps1
```

Verify the ScriptDom assembly loads:

```powershell
[Reflection.Assembly]::LoadFrom((Resolve-Path .\Microsoft.SqlServer.TransactSql.ScriptDom.dll)).FullName
```

## Configuration

`Invoke-TSqlChecks.ps1` accepts parameters to control collection sources, output folder and analyzer behavior. See the script header comments and `Test-Invoke-TSqlChecks.ps1` for examples.

Common knobs:

* SQL instance connection string or server and credential parameters.
* Which sources to scan (Jobs, Procedures, Triggers, PlanCache).
* Output folder for Excel and trace files.
* Allow/ignore lists for known-safe patterns.

## Usage examples

Quick test run:

```powershell
.\Test-Invoke-TSqlChecks.ps1 -SqlInstance "MYSERVER\INSTANCE" -OutputFolder "C:\temp\sqlcheck"
```

Run the analyzer directly:

```powershell
.\Invoke-TSqlChecks.ps1 -SqlInstance "MYSERVER\INSTANCE" -CollectFrom Jobs,Procedures -OutputFolder "C:\temp\sqlcheck"
```

Use `Test-TSqlInjection.ps1` to validate detection against known patterns.

## Output

* Excel workbook with summary and per-check details (requires ImportExcel).
* Per-statement trace files grouped under the output folder for manual review.
* Logs and exit codes suitable for automation.

## Recommendations & caveats

* Run only in authorized, controlled environments. The tool reads object definitions and metadata. Do not run against production without approvals and backups.
* The analyzer is static and heuristic-based. Treat findings as indicators that require manual review.
* Keep ScriptDom and PowerShell modules up to date. Parser behavior can change across SQL Server versions.

## Extending the tool

* Add new checks in `Invoke-TSqlChecks.ps1` to detect additional risky patterns.
* Add collectors to capture T‑SQL from custom sources.
* Integrate results with CI pipelines or ticketing systems to automate triage.

## Contributing

1. Fork the repository.
2. Implement a focused change and add tests or examples.
3. Submit a pull request with clear description and rationale.

## License

Choose a license and add `LICENSE` file. MIT is a good default if you want permissive terms.

## Contact / Attribution

Maintainer: `mcflyamorim` (GitHub). Repository: `https://github.com/mcflyamorim/SQLInjectionCheck`.

---
