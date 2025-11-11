<#
.SYNOPSIS
    Automated static analysis for T-SQL to detect likely SQL injection and related risks.

.DESCRIPTION
    Connects to a SQL Server instance and collects T-SQL from Agent jobs, instance triggers,
    stored procedures, triggers, plan cache and optionally system objects or a custom query.
    Each captured T-SQL text is parsed with ScriptDom and analyzed by Invoke-TSqlChecks.
    Produces an Excel report and per-statement trace files under the script Output folder.

.NOTES
    - Designed as a diagnostic tool for DBAs and security engineers.
    - Intended for use in controlled environments with proper authorization.
    - The script may execute metadata queries against all accessible databases and read object definitions.
    - Do not run against production systems without prior authorization and adequate backups.

.PARAMETER SQLInstance
    The SQL Server instance name to connect to.
    Example: "SERVERNAME\SQLINSTANCE" or "myserver.domain.local".

.PARAMETER Database
    The database context used for some queries (default: master). Many metadata queries enumerate each accessible DB.

.PARAMETER UserName
    Optional. SQL or Windows username when using explicit credentials.

.PARAMETER Password
    Optional. Plain-text password used to build a PSCredential when UserName specified.
    Security note: Passing plaintext password on the command line is insecure. Prefer using Get-Credential
    or a secure vault and supply a PSCredential object to the script.

.PARAMETER QueryTextColumnName
    Name of the column that contains SQL text when using a custom query. Default: 'sql_text'.

.PARAMETER CustomQuery
    Optional. A custom query that returns columns mapped into the expected schema (DbName, SchemaName, ObjId, ObjName, ObjType, cTSql, CreateDate).
    When provided the script will execute it and append returned rows to the analysis set.

.PARAMETER KillExcel
    Switch. If provided, the script will kill running Excel processes prior to writing the output.

.PARAMETER IncludeSystemObjects
    Switch. If provided, system stored procedures (from sys.system_objects) will be included in the scan.

.PARAMETER CreateTranscriptLog
    Switch. If provided, the script starts a transcript file in the script Log folder.

.PARAMETER ExportTrace
    Switch (default: $true). When enabled the script writes a TraceDetails_{RowID}.txt file for each scanned statement.

.INPUTS
    None via pipeline. The script reads from SQL Server metadata and DMVs.

.OUTPUTS
    - Excel workbook file: Output\SQLInjectionCheck_<Instance>_yyyyMMdd_hhmm.xlsx
    - Trace text files: Output\TraceDetails\<FilePrefix>\TraceDetails_<RowID>.txt
    - Returns a PSCustomObject with Value property describing result status.

.REQUIREMENTS
    - PowerShell 5.1 or later (works on PowerShell Core but some dependencies may be Windows-only).
    - Modules:
        * dbatools (Connect-DbaInstance, Get-DbaDatabase, Get-DbaAgentJob, Get-DbaInstanceTrigger, Invoke-DbaQuery)
        * ImportExcel (Export-Excel, Close-ExcelPackage)
    - Script dependencies (must be located in the same folder or an importable path):
        * Import-RequiredModules.ps1
        * Import-ScriptDom.ps1
        * Invoke-TSqlChecks.ps1
    - .NET ScriptDom assemblies (Microsoft.SqlServer.TransactSql.ScriptDom) available via Import-ScriptDom.ps1.

.PERMISSIONS
    - The account used must have sufficient permissions to read metadata and object definitions across the target databases:
        * VIEW DEFINITION on objects to read stored procedure/trigger text, or membership in a role that provides those rights.
        * Permission to query sys.dm_exec_cached_plans if plan cache scanning is enabled.
        * If connecting with lower-privilege account the returned dataset may be limited.
    - The script does not require sysadmin by design but some objects or jobs may be unreadable without higher privileges.

.SECURITY CONSIDERATIONS
    - Do NOT hardcode plaintext passwords inside scripts. Prefer passing a PSCredential or using a secret vault.
    - Running Export-Excel will load the ImportExcel module which may spawn Excel COM objects when on Windows.
    - Handle the resulting trace files securely as they contain full SQL text and potential sensitive data.
    - Ensure authorized scope and obtain permission before scanning customer environments.

.EXAMPLES
    # Run against local default instance using integrated auth and produce output
    .\Test-TSqlInjection.ps1 -SQLInstance "MYSERVER\SQL2022" -Database "msdb" -CreateTranscriptLog

    # Run using explicit credentials (not recommended to pass password in clear text)
    .\Test-TSqlInjection.ps1 -SQLInstance "myserver" -Database "master" -UserName "svc_account" -Password "P@ssw0rd" -KillExcel

    # Include system objects and export full traces
    .\Test-TSqlInjection.ps1 -SQLInstance "MYSERVER" -IncludeSystemObjects -ExportTrace

    # Execute a custom query that returns expected columns and analyze the results
    $custom = "SELECT DB_NAME() AS DbName, OBJECT_SCHEMA_NAME(object_id) AS SchemaName, CONVERT(sysname, '') AS TabName, object_id AS ObjID, name AS ObjName, 'User - StoredProcedure' AS ObjType, LEN(OBJECT_DEFINITION(object_id)) AS cLength, OBJECT_DEFINITION(object_id) AS cTSql, create_date AS CreateDate FROM sys.objects WHERE type = 'P'"
    .\Test-TSqlInjection.ps1 -SQLInstance "MYSERVER" -CustomQuery $custom

.OUTPUT FILE LAYOUT
    Output\
      SQLInjectionCheck_<Instance>_YYYYMMDD_HHMM.xlsx
      TraceDetails\
        SQLInjectionCheck_<Instance>_YYYYMMDD_HHMM\
          TraceDetails_1.txt
          TraceDetails_2.txt
          ...

.LOGGING
    - If -CreateTranscriptLog is supplied, transcript is written into <ScriptPath>\Log\LogOutput_<timestamp>.txt
    - Per-statement trace details are written under Output\TraceDetails\<FilePrefix>\*.txt when -ExportTrace is enabled.

.TROUBLESHOOTING
    - ScriptDom assembly not found:
        * Ensure Import-ScriptDom.ps1 is present and loads the correct Microsoft.SqlServer.TransactSql.ScriptDom assembly.
    - ImportExcel missing:
        * Install-Module -Name ImportExcel -Scope CurrentUser
    - dbatools missing or cmdlets not found:
        * Install-Module -Name dbatools -Scope CurrentUser
    - Permission errors reading object definitions:
        * Verify VIEW DEFINITION permission or run with an account that can enumerate object definitions.

.CHANGELOG
    - v1.0  : Initial stable script. Collects jobs, instance triggers, stored procs, triggers, plan cache, optional system objects and custom query. Exports Excel + trace details.

.AUTHOR
    Fabiano Amorim (mcfly)
    Email: <your-email@example.com>
    Twitter/Handle: @mcflyamorim
    Company: Pythian

.LICENSE
    MIT (or specify your preferred license). Use responsibly and only against systems you own or are authorized to test.

.LINKS
    - dbatools: https://dbatools.io
    - ImportExcel: https://github.com/dfinke/ImportExcel
    - Microsoft ScriptDom: https://learn.microsoft.com/sql/relational-databases/scripts/sql-server-scriptdom
    - Script for static analysis: include your repo link here if available

#>
# -----------------------------
# PARAMETER DEFINITIONS
# -----------------------------
param
(
    [String]$SQLInstance = "AMORIM-7VQGKX3\SQL2022",    # Default SQL instance name
    [String]$Database = "master",                        # Default database context
    [String]$UserName,                                   # Optional SQL login user
    [String]$Password,                                   # Optional SQL login password
    [String] $QueryTextColumnName = 'sql_text',          # Default SQL text column name for custom queries
    [String] $CustomQuery = "",                          # Optional custom query
    [Switch] $KillExcel,                                 # Kill Excel processes before export
    [switch] $IncludeSystemObjects = $false,             # Include system stored procedures
    [switch] $CreateTranscriptLog,                       # Create transcript log
    [switch] $ExportTrace = $true                        # Export per-object trace detail files
)
Clear-Host  # Clear console for clean output
Write-Msg -Message "Starting Test-TSqlInjection script" -Level Starting

# -----------------------------
# IMPORT REQUIRED MODULES / FUNCTIONS
# -----------------------------
Write-Msg -Message "Importing required modules and functions" -Level Starting

# Identify current script directory so relative imports work even if run from another path
$ScriptPath = Split-Path $($MyInvocation.MyCommand.Definition)

# Import prerequisite script that loads dbatools, ImportExcel, and logging helpers
. (Join-Path $ScriptPath 'Import-RequiredModules.ps1')

Write-Msg -Message "Finished to import required modules and functions" -Level Finished

# -----------------------------
# MAIN EXECUTION BODY
# -----------------------------
$CheckResult = @()
try {
    # --- Validate mandatory parameter ---
    if (-Not $SQLInstance){
        Write-Msg "SQLInstance is a mandatory parameter" -Level Error
		$CheckResult = [PSCustomObject]@{ Value  = "SQLInstance is a mandatory parameter" }
        return $CheckResult
    }

	# --- Prepare timestamped output filenames ---
	$CurrentDate = Get-Date
	$FileOutputPath = Join-Path $ScriptPath "\Output\"

	# Sanitize SQL instance name for filesystem-safe filename
	$SQLInstanceTmp = $SQLInstance.Replace('\','').Replace('/','').Replace(':','').Replace('*','').Replace('?','').Replace('"','').Replace('<','').Replace('>','').Replace('|','')
	$FilePrefix = $SQLInstanceTmp + "_" + $CurrentDate.ToString("yyyyMMdd") + "_" + $CurrentDate.ToString("hhmm") + ".xlsx"
	$FileOutput = $FileOutputPath + "SQLInjectionCheck_" + $FilePrefix

    # -----------------------------
    # OPTIONAL: START TRANSCRIPT LOG
    # -----------------------------
    if ($CreateTranscriptLog){
        $TranscriptTimestamp = Get-Date -format "yyyyMMdd_HH_mm_ss_fff"
        Write-Msg -Message "Creating TranscriptLog on $ScriptPath\Log\LogOutput_$TranscriptTimestamp.txt" -VerboseMsg

        # Stop any previous transcript if running, ignore failures
        try {Stop-Transcript -ErrorAction SilentlyContinue | Out-Null} catch{}

        # Start new transcript safely
        try {
            Start-Transcript -Path "$ScriptPath\Log\LogOutput_$TranscriptTimestamp.txt" -Force -ErrorAction | Out-Null
        } catch {
            Start-Transcript "$ScriptPath\Log\LogOutput_$TranscriptTimestamp.txt" | Out-Null
        }
    }
    
    # -----------------------------
    # DISPLAY INPUT PARAMETERS
    # -----------------------------
    Write-Msg -Message "------------------------------------------------------------------------"
    Write-Msg -Message "Input parameters:"
    Write-Msg -Message "SQLInstance: $SQLInstance"
    Write-Msg -Message "Database: $Database"
	Write-Msg -Message "FileOutput: $FileOutput"
    Write-Msg -Message "QueryTextColumnName: $QueryTextColumnName"
    Write-Msg -Message "KillExcel: $KillExcel"
    Write-Msg -Message "IncludeSystemObjects: $IncludeSystemObjects"
    Write-Msg -Message "CreateTranscriptLog: $CreateTranscriptLog"
    Write-Msg -Message "ExportTrace: $ExportTrace"
    Write-Msg -Message "------------------------------------------------------------------------"

    # -----------------------------
    # Validate ImportExcel module
    # -----------------------------
    if (-not (Get-Module -Name ImportExcel)) {
        Write-Msg "ImportExcel is not installed, please install it before continue" -Level Error
        return
    }
    else {
        Write-Msg "ImportExcel is installed and loaded. Continuing..."
    }

    # -----------------------------
    # Load ScriptDom Assembly
    # -----------------------------
    try {
        Write-Msg -Message "Loading ScriptDom assembly" -Level Starting
        $ScriptPath = Split-Path $($MyInvocation.MyCommand.Definition)
        . (Join-Path $ScriptPath 'Import-ScriptDom.ps1')  # loads Microsoft.SqlServer.TransactSql.ScriptDom
        Write-Msg -Message "Finished to load ScriptDom assembly" -Level Finished
    }
    catch {
        Write-Msg -Message "Error trying to load ScriptDom assembly, import it manually and try again." -Level Error
        Write-Msg -Message "ErrorMessage: $($_.Exception.Message)" -Level Error
        try {Stop-Transcript -ErrorAction SilentlyContinue | Out-Null} catch{}
        return
    }

    # Verify ScriptDom successfully loaded by checking loaded assemblies in the current AppDomain
    $LoadedAssembly = [System.AppDomain]::CurrentDomain.GetAssemblies() |
        Where-Object {$_.FullName -like '*ScriptDom*'} |
        Sort-Object -Property ImageRuntimeVersion -Descending |
        Select-Object -First 1

    if (-Not($LoadedAssembly)) {
        Write-Msg -Message "ScriptDom assembly is not loaded, import it and try again." -Level Error
        try {Stop-Transcript -ErrorAction SilentlyContinue | Out-Null} catch{}
        return
    }

    # -----------------------------
    # LOAD TSQL CHECKS MODULE
    # -----------------------------
    # This module defines Invoke-TSqlChecks and helper parsing functions.
    $ScriptPath = Split-Path $($MyInvocation.MyCommand.Definition)
    . (Join-Path $ScriptPath 'Invoke-TSqlChecks.ps1')

    # -----------------------------
    # CREDENTIAL HANDLING
    # -----------------------------
    $SqlCredential = $null
    if ($UserName -and $Password) {
        # Convert plaintext password to SecureString and build PSCredential
        $SecurePassword = ConvertTo-SecureString -String $Password -AsPlainText -Force
        $SqlCredential = New-Object -TypeName System.Management.Automation.PSCredential -ArgumentList $UserName, $SecurePassword
    }

    # -----------------------------
    # CONNECT TO SQL INSTANCE
    # -----------------------------
    Write-Msg -Message "Connecting to SQL Server instance $SQLInstance and database $Database" -Level Starting
    if ($SqlCredential) {
        # Explicit credential connection
        Write-Msg -Message "Using credentials to connect to SQL Server instance" -Level Output
        $DbaInstance = Connect-DbaInstance -SqlInstance $SQLInstance -Database $Database -ClientName "Test-TSqlInjection" -ErrorAction Stop -SqlCredential $SqlCredential
    }
    else {
        # Integrated authentication connection
        Write-Msg -Message "Using default credentials to connect to SQL Server instance" -Level Output
        $DbaInstance = Connect-DbaInstance -SqlInstance $SQLInstance -Database $Database -ClientName "Test-TSqlInjection" -ErrorAction Stop
    }
    
    # -----------------------------
    # CONFIGURE CONNECTION CONTEXT
    # -----------------------------
    # Shorten lock timeout to prevent script hang on locked objects
    $DbaInstance.ConnectionContext.LockTimeout = 5

    Write-Msg -Message "Setting isolation level to read uncommitted" -Level Starting
    # Reduce locking overhead when scanning metadata
    $DbaInstance.ConnectionContext.ExecuteNonQuery("SET TRANSACTION ISOLATION LEVEL READ UNCOMMITTED;") | Out-Null
    Write-Msg -Message "Connected to SQL Server instance $SQLInstance" -Level Finished

    # -----------------------------
    # READ SQL AGENT JOB STEPS (Transact-SQL STEPS)
    # -----------------------------
    # Use dbatools Get-DbaAgentJob to enumerate Agent jobs.
    # Expand JobSteps to access each step command and metadata.
    Write-Msg -Message "Reading SQL Server Agent jobs" -Level Starting
    $Jobs = Get-DbaAgentJob -SqlInstance $DbaInstance `
            | Select-Object -ExpandProperty JobSteps `
            | Select-Object Parent, ID, Name, SubSystem, @{Name="cTSql";Expression={ $_.Command}}, LastRunDate

    # Filter only Transact-SQL job steps (ignore CmdExec, PowerShell, etc.)
    $Jobs = $Jobs | Where-Object { $_.SubSystem -eq 'TransactSql' }
    $JobsCount = $Jobs.Count
    Write-Msg -Message "Found $JobsCount SQL Server Agent jobs" -Level Finished

    # -----------------------------
    # READ INSTANCE TRIGGERS
    # -----------------------------
    # Instance triggers live in msdb/sys.server_triggers context and can contain T-SQL.
    # Filter out encrypted triggers because their text cannot be analyzed.
    Write-Msg -Message "Reading Instance triggers" -Level Starting
    $InstanceTriggers = Get-DbaInstanceTrigger -SqlInstance $DbaInstance `
                        | Where-Object { $_.IsEncrypted -eq $false } `
                        | Select-Object Database, ObjectId, Schema, Name, @{Name="cTSql";Expression={ $_.TextHeader + $_.TextBody}}, CreateDate
    $InstanceTriggersCount = $InstanceTriggers.Count
    Write-Msg -Message "Found $InstanceTriggersCount instance triggers" -Level Finished

    # -----------------------------
    # INITIALIZE AGGREGATE RESULT COLLECTION
    # -----------------------------
    # $QueryResults will contain a normalized set of rows with fields:
    # DbName, SchemaName, ParentName, ObjID, ObjName, ObjType, cLength, cTSql, CreateDate
    $QueryResults = @()

    # Map job step records into the normalized shape and append to $QueryResults
    $QueryResults += $Jobs | Select-Object `
                            @{Name='DbName';Expression={ "" }}, `
                            @{Name='SchemaName';Expression={ "" }}, `
                            @{Name='ParentName';Expression={ $_.Parent.Name }}, `
                            @{Name='ObjID';Expression={ $_.ID }}, `
                            @{Name='ObjName';Expression={ $_.Name }}, `
                            @{Name='ObjType';Expression={ "Job - " + $_.SubSystem }}, `
                            @{Name='cLength';Expression={ $_.cTSql.ToString().Length }}, `
                            @{Name='cTSql';Expression={ $_.cTSql }}, `
                            @{Name='CreateDate';Expression={ $_.LastRunDate }}

    # Map instance triggers into normalized shape and append
    $QueryResults += $InstanceTriggers | Select-Object `
                                @{Name='DbName';Expression={ $_.Database }}, `
                                @{Name='SchemaName';Expression={ "" }}, `
                                @{Name='ParentName';Expression={ "" }}, `
                                @{Name='ObjID';Expression={ $_.ObjectId }}, `
                                @{Name='ObjName';Expression={ $_.Name }}, `
                                @{Name='ObjType';Expression={ "InstanceTrigger" }}, `
                                @{Name='cLength';Expression={ $_.cTSql.ToString().Length }}, `
                                @{Name='cTSql';Expression={ $_.cTSql }}, `
                                @{Name='CreateDate';Expression={ $_.CreateDate }}

    # -----------------------------
    # DEFINE QUERY TO COLLECT STORED PROCEDURES AND TRIGGERS FROM EACH DATABASE
    # -----------------------------
    # This T-SQL returns user stored procedures and triggers with their definition using OBJECT_DEFINITION.
    # Note: OBJECT_DEFINITION may return NULL for encrypted objects.
    $QuerySpAndTriggers = @"
        SELECT DB_NAME() AS DbName,
            OBJECT_SCHEMA_NAME(object_id) AS SchemaName,
            CONVERT(sysname, '') AS TabName,
            object_id AS ObjID,
            name AS ObjName,
            'User - StoredProcedure' AS ObjType,
            LEN(OBJECT_DEFINITION(object_id)) AS cLength,
            OBJECT_DEFINITION(object_id) AS cTSql,
            create_date AS CreateDate
        FROM sys.objects
        WHERE OBJECT_DEFINITION(OBJECT_ID(name)) IS NOT NULL
            AND type = 'P'
        UNION ALL
        SELECT DB_NAME() AS DbName,
            OBJECT_SCHEMA_NAME(parent_id) AS SchemaName,
            OBJECT_NAME(parent_id) AS TabName,
            object_id AS ObjID,
            name AS ObjName,
            'User - Trigger' AS ObjType,
            LEN(OBJECT_DEFINITION(object_id)) AS cLength,
            OBJECT_DEFINITION(object_id) AS cTSql,
            create_date AS CreateDate
        FROM sys.triggers
        WHERE OBJECT_DEFINITION(object_id) IS NOT NULL
"@

    # -----------------------------
    # ENUMERATE ACCESSIBLE DATABASES
    # -----------------------------
    # Use dbatools Get-DbaDatabase -OnlyAccessible to avoid permission errors on inaccessible DBs.
    Write-Msg -Message "Reading databases" -Level Starting
    $Databases = Get-DbaDatabase -SqlInstance $DbaInstance -OnlyAccessible | Select-Object Name
    $DatabasesCount = $Databases.Count
    Write-Msg -Message "Found $DatabasesCount databases" -Level Finished

    # -----------------------------
    # EXECUTE $QuerySpAndTriggers ON EACH DATABASE
    # -----------------------------
    # Loop over accessible databases and collect stored procedure and trigger definitions.
    $QueryResultsDb = @()
    foreach ($Database_Row in $Databases) {
        Write-Msg -Message "Starting to execute query to read SPs and triggers from DB $($Database_Row.Name)" -Level Starting

        # Invoke-DbaQuery runs the T-SQL in the context of the target DB and returns PSObjects.
        $QueryResultsDb = Invoke-DbaQuery -SqlInstance $DbaInstance -Database $($Database_Row.Name) -Query $QuerySpAndTriggers -As PSObject -ErrorAction Stop

        # Append the returned rows to the aggregate results collection.
        $QueryResults += $QueryResultsDb
        Write-Msg -Message "Finished to execute query, RowCount = $($QueryResultsDb.Count)" -Level Finished
    }

    # -----------------------------
    # OPTIONAL: READ SYSTEM STORED PROCEDURES
    # -----------------------------
    # When IncludeSystemObjects is true, also collect procedures from sys.system_objects.
    if ($IncludeSystemObjects -eq $true) {
        $QuerySystemObjects = @"
            SELECT DB_NAME() AS DbName,
                OBJECT_SCHEMA_NAME(object_id) AS SchemaName,
                CONVERT(sysname, '') AS TabName,
                object_id AS ObjID,
                name AS ObjName,
                'System - StoredProcedure' AS ObjType,
                LEN(OBJECT_DEFINITION(object_id)) AS cLength,
                OBJECT_DEFINITION(object_id) AS cTSql,
                create_date AS CreateDate
            FROM sys.system_objects
            WHERE OBJECT_DEFINITION(OBJECT_ID(name)) IS NOT NULL
                AND type = 'P';
"@
        Write-Msg -Message "Starting to execute query to read system objects" -Level Starting

        # Run the query in the chosen $Database context (defaults to param)
        $QueryResultsDb = Invoke-DbaQuery -SqlInstance $DbaInstance -Database $Database -Query $QuerySystemObjects -As PSObject -ErrorAction Stop
        $QueryResults += $QueryResultsDb
        Write-Msg -Message "Finished to execute query, RowCount = $($QueryResultsDb.Count)" -Level Finished
    }

    # -----------------------------
    # READ PLAN CACHE (DMV) STATEMENTS
    # -----------------------------
    # Query sys.dm_exec_cached_plans and cross apply to the sql text. This returns ad-hoc queries and batch text that may not exist as objects.
    $QueryPlanCache = @"
        SELECT DISTINCT 
            DB_NAME(dbid) AS DbName,
            NULL AS SchemaName,
            NULL AS TabName,
            objectid AS ObjID,
            OBJECT_NAME(objectid, dbid) AS ObjName,
            'PlanCache - ' + cacheobjtype + ' - ' + objtype  AS ObjType,
            LEN(dm_exec_sql_text.text) AS cLength,
            dm_exec_sql_text.text AS cTSql,
            NULL AS CreateDate
        FROM sys.dm_exec_cached_plans AS cp 
        CROSS APPLY sys.dm_exec_sql_text(cp.plan_handle)
"@

    Write-Msg -Message "Starting to execute query to read plan cache" -Level Starting
    $QueryResultsDb = Invoke-DbaQuery -SqlInstance $DbaInstance -Database $Database -Query $QueryPlanCache -As PSObject -ErrorAction Stop
    $QueryResults += $QueryResultsDb
    Write-Msg -Message "Finished to execute query, RowCount = $($QueryResultsDb.Count)" -Level Finished

    # -----------------------------
    # EXECUTE A USER-SUPPLIED CUSTOM QUERY (OPTIONAL)
    # -----------------------------
    # The custom query must return expected columns to be normalized and analyzed.
    if ($CustomQuery) {
        Write-Msg -Message "Starting to execute custom query" -Level Starting
        $QueryResultsDb = Invoke-DbaQuery -SqlInstance $DbaInstance -Database $Database -Query $CustomQuery -As PSObject -ErrorAction Stop

        # Map/normalize the custom query's columns into the expected shape
        $QueryResultsDb = $QueryResultsDb | Select-Object `
                                @{Name='DbName';Expression={ $_.DbName }}, `
                                @{Name='SchemaName';Expression={ $_.SchemaName }}, `
                                @{Name='ParentName';Expression={ "" }}, `
                                @{Name='ObjID';Expression={ $_.ObjId }}, `
                                @{Name='ObjName';Expression={ $_.ObjName }}, `
                                @{Name='ObjType';Expression={ $_.ObjType }}, `
                                @{Name='cLength';Expression={ $_.cTSql.ToString().Length }}, `
                                @{Name='cTSql';Expression={ $_.cTSql }}, `
                                @{Name='CreateDate';Expression={ $_.CreateDate }}

        $QueryResults += $QueryResultsDb
        Write-Msg -Message "Finished to execute custom query, RowCount = $($QueryResultsDb.Count)" -Level Finished
    }

    # -----------------------------
    # ADD ROWID FOR EASY TRACEABILITY
    # -----------------------------
    # Add a RowID property as the first column for easier reference in trace files and Excel.
    $i = 0
    for ($index = 0; $index -lt $QueryResults.Count; $index++) {
        $i++
        $Row = $QueryResults[$index]

        # Create an ordered hashtable so RowID is the first property in the PSCustomObject.
        $ordered = [ordered]@{ RowID = $i }
        foreach ($prop in $Row.PSObject.Properties) {
            if ($prop.Name -ne 'RowID') {
                $ordered[$prop.Name] = $prop.Value
            }
        }

        $QueryResults[$index] = [PSCustomObject]$ordered
    }
    $QueryResultsCount = $QueryResults.Count
    Write-Msg -Message "Found $QueryResultsCount objects to check" -Level Finished

    # -----------------------------
    # PREPARE OUTPUT TRACE FOLDER
    # -----------------------------
    # Create Output\TraceDetails\<FilePrefix> folder. Remove pre-existing to ensure fresh export.
    $TraceDetailsOutputFolder = Join-Path $ScriptPath 'Output'
    $TraceDetailsOutputFolder = Join-Path $TraceDetailsOutputFolder 'TraceDetails'

    # Derive a folder name from the FileOutput filename (without extension)
    $FileOutputBase = [System.IO.Path]::GetFileNameWithoutExtension($FileOutput)
    $TraceDetailsOutputFolder = Join-Path $TraceDetailsOutputFolder $FileOutputBase

    # Remove existing folder if present to avoid mixing results
    if (Test-Path $TraceDetailsOutputFolder) {
        Write-Msg -Message "Removing existing TraceDetails folder $TraceDetailsOutputFolder" -Level Output
        Remove-Item $TraceDetailsOutputFolder -Recurse -Force
        Write-Msg -Message "Finished to remove existing TraceDetails folder" -Level Output
    }

    # Create TraceDetails folder tree
    if (-not (Test-Path $TraceDetailsOutputFolder)) {
        Write-Msg -Message "Creating TraceDetails folder at $TraceDetailsOutputFolder" -Level Output
        New-Item -Path $TraceDetailsOutputFolder -ItemType Directory -Force | Out-Null 
        Write-Msg -Message "Finished to create TraceDetails folder" -Level Output
    }

    # -----------------------------
    # RUN STATIC ANALYSIS (Invoke-TSqlChecks) FOR EACH CAPTURED STATEMENT
    # -----------------------------
    $i = 0
    $startTime = Get-Date
    Write-Msg -Message "Starting to run Invoke-TSqlChecks" -Level Starting

    foreach ($Row in $QueryResults) {
        $i++

        # -----------------------------
        # TIME & RATE CALCULATIONS FOR UX
        # -----------------------------
        # Compute elapsed time and rows processed per second.
        $Elapsed = (Get-Date) - $StartTime
        $RowsPerSecond = if ($Elapsed.TotalSeconds -gt 0) { [Math]::Round($i / $Elapsed.TotalSeconds, 2) } else { 0 }

        # Estimate remaining time using simple linear extrapolation.
        $EstimatedTotalSeconds = if ($i -gt 0) { ($Elapsed.TotalSeconds / $i) * $QueryResultsCount } else { 0 }
        $EstimatedRemaining = [TimeSpan]::FromSeconds($EstimatedTotalSeconds - $Elapsed.TotalSeconds)

        # Update console progress bar for user feedback.
        Write-Progress -Activity "Checking query text" `
                       -Status ("Row {0}/{1} | {2} rows/s | Elapsed: {3} | ETA: {4}" -f `
                                    $i, $QueryResultsCount, $RowsPerSecond, `
                                    $Elapsed.ToString("hh\:mm\:ss"), `
                                    $EstimatedRemaining.ToString("hh\:mm\:ss")) `
                       -PercentComplete ([int](($i / $QueryResultsCount) * 100))

        # -----------------------------
        # INVOKE THE T-SQL CHECKS
        # -----------------------------
        # Call Invoke-TSqlChecks which parses T-SQL using ScriptDom and returns findings.
        # -ReportBuyfferSizeVuln and -CheckForPasswords are example flags that your module supports.
        $TSqlChecks = Invoke-TSqlChecks -InputText $($Row.cTSql) -ReportBuyfferSizeVuln -CheckForPasswords -ErrorAction Stop

        # Extract the human-readable message output and attach to the $Row object.
        $TSqlCheckResult = $TSqlChecks | Select-Object -Property Message | Format-List | Out-String
        $Row | Add-Member -MemberType NoteProperty -Name "TSqlCheckResult" -Value $TSqlCheckResult

        # Extract the detailed trace (parse tree, warnings, etc.) to include in per-object trace files.
        $TSqlCheckResultTrace = $TSqlChecks | Select-Object -Property Trace | Format-List | Out-String

        # -----------------------------
        # TRIM OUTPUT WHITESPACE
        # -----------------------------
        # Remove extra newlines and whitespace for tidy output files.
        $TSqlCheckResult = $TSqlCheckResult.TrimEnd([Environment]::NewLine.ToCharArray())
        $TSqlCheckResult = $TSqlCheckResult.Trim()
        $TSqlCheckResult = $TSqlCheckResult.TrimStart()

        $TSqlCheckResultTrace = $TSqlCheckResultTrace.TrimEnd([Environment]::NewLine.ToCharArray())
        $TSqlCheckResultTrace = $TSqlCheckResultTrace.Trim()
        $TSqlCheckResultTrace = $TSqlCheckResultTrace.TrimStart()        

        # -----------------------------
        # OPTIONAL: EXPORT PER-STATEMENT TRACE FILE
        # -----------------------------
        if ($ExportTrace) {
            # Build filename using RowID for deterministic mapping
            $TraceFileName = "TraceDetails_{0}.txt" -f $Row.RowID
            $TraceFilePath = Join-Path $TraceDetailsOutputFolder $TraceFileName

            # Compose an ordered list of lines containing metadata, the statement and analysis traces
            $Content = @()
            $Content += ('-' * 80)            
            $Content += "RowID        : $($Row.RowID)"
            $Content += "SQL Instance : $SQLInstance"
            $Content += "Database     : $($Row.DbName)"
            $Content += "Object Name  : $($Row.ObjName)"
            $Content += "Object ID    : $($Row.ObjID)"
            $Content += "Object Type  : $($Row.ObjType)"
            $Content += "Create Date  : $($Row.CreateDate)"
            $Content += "Export Time  : $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss.fff')"
            $Content += ('-' * 80)
            $Content += "Statement:"
            $Content += ($Row.cTSql -as [string])
            $Content += ('-' * 80)
            $Content += ($TSqlCheckResult | Out-String) # Append Message section
            $Content += ('-' * 80)
            $Content += ($TSqlCheckResultTrace | Out-String) # Append Trace section

            # Write the content as UTF8 text. Use -Force to overwrite if file exists.
            $Content | Out-File -FilePath $TraceFilePath -Encoding UTF8 -Force
        }
    }

    Write-Msg -Message "Finished to run Invoke-TSqlChecks" -Level Finished

    # -----------------------------
    # OPTIONAL: KILL EXCEL PROCESSES BEFORE EXPORT
    # -----------------------------
    # If requested, terminate any existing Excel COM processes to avoid file locks during Export-Excel.
    if ($KillExcel) {
        if (Get-Process -Name "excel" -ErrorAction Ignore) {
            Write-Msg -Message "Killing Excel processes" -Level Starting
            Get-Process -Name "excel" -ErrorAction Ignore | Stop-Process
            # Wait until all Excel processes have stopped
            while (Get-Process -Name "excel" -ErrorAction Ignore) { }
            Write-Msg -Message "Finished to kill Excel processes" -Level Finished
        }
    }

    # -----------------------------
    # REMOVE PRE-EXISTING EXCEL FILE IF PRESENT
    # -----------------------------
    if (Test-Path $FileOutput) {
        Write-Msg -Message "Removing existing Excel file $FileOutput" -Level Output
        Remove-Item $FileOutput -Force
        Write-Msg -Message "Finished to remove existing Excel file" -Level Output
    }

    # -----------------------------
    # EXPORT AGGREGATED RESULTS TO EXCEL USING ImportExcel
    # -----------------------------
    $QueryWorksheetName = "SQLInjectionCheck"
    Write-Msg -Message "Starting to export data to Excel($QueryWorksheetName)" -Level Starting

    # Use Export-Excel with -PassThru to receive an ExcelPackage object for post-formatting.
    $ExcelFile = $null
    $ExcelFile = $QueryResults | Select-Object * -ExcludeProperty RowError, RowState, Table, ItemArray, HasErrors `
                                | Export-Excel -Path $FileOutput `
                                               -FreezeTopRow `
                                               -WorksheetName $QueryWorksheetName `
                                               -TableStyle Medium2 `
                                               -StartRow 1 `
                                               -PassThru

    # -----------------------------
    # APPLY WORKSHEET FORMATTING
    # -----------------------------
    # Access worksheet object to set fonts, column widths, date formats and zoom scale.
    $WorkSheet = $ExcelFile.Workbook.Worksheets[$QueryWorksheetName]

    # Adjust view and font for legibility in fixed-width font (good for T-SQL).
    $WorkSheet.View.ZoomScale = 90
    # AutoFitColumns with max rows to avoid performance issues. The numeric argument is the max rows to sample.
    $WorkSheet.Cells.AutoFitColumns(100)
    $WorkSheet.Cells.Style.Font.Name = 'Lucida Console'
    $WorkSheet.Cells.Style.Font.Size = 9

    # -----------------------------
    # ADJUST COLUMN WIDTHS AND FORMATS
    # -----------------------------
    # Heuristic adjustments: increase each column width by 15% after AutoFit.
    # Apply a date-time format to the CreateDate column and widen it further.
    for ($i = 1; $i -le 13; $i++) {
        $Curr = $WorkSheet.Column($i).Width
        $WorkSheet.Column($i).Width = $Curr * 1.15

        # Prevent excessively large columns
        if ($Curr -gt 50) {
            $WorkSheet.Column($i).Width = 50
        }

        # Column index 10 is expected to be CreateDate. Format as precise timestamp and make wider.
        if ($i -eq 10) {
            $Range = $WorkSheet.Cells[$WorkSheet.Dimension.Start.Row, $i, $WorkSheet.Dimension.End.Row, $i]
            $Range.Style.Numberformat.Format = 'yyyy-mm-dd hh:mm:ss.000'
            $WorkSheet.Column($i).Width = $Curr * 2.0
        }

        # Column index 11 reserved for long text fields like TSqlCheckResult; make it wide for readability.
        if ($i -eq 11) {
            $WorkSheet.Column($i).Width = 100
        }
    }

    # -----------------------------
    # CLOSE EXCEL PACKAGE AND FINALIZE
    # -----------------------------
    Close-ExcelPackage $ExcelFile
    Write-Msg -Message "Finished to export data to Excel($QueryWorksheetName)" -Level Finished

} # End of try block
catch {
    # -----------------------------
    # GLOBAL ERROR HANDLER
    # -----------------------------
    # Log and rethrow or exit gracefully with an error message.
    Write-Msg -Message "Error trying to run Script, check the following message for more info." -Level Error
    Write-Msg -Message "ErrorMessage: $($_.Exception.Message)" -Level Error
}

# -----------------------------
# FINAL STATUS MESSAGE AND RETURN OBJECT
# -----------------------------
Write-Msg -Message "Script executed successfully" -Level Finished

$CheckResult = [PSCustomObject]@{
    Value  = "Script executed successfully and file created at $FileOutput"
}

# Return status object to caller or pipeline
$CheckResult