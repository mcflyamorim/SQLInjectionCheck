Clear-Host
[string] $InputText = @'
CREATE PROCEDURE sp_test1 @schema sysname, @table sysname
AS
    DECLARE @sql nvarchar(258)
    SET @sql = 'select * from '+ @schema + '.' + QUOTENAME(@table)
    PRINT @sql
    EXECUTE sp_executeSQL @sql
'@

$ScriptPath = Split-Path -parent $($MyInvocation.MyCommand.Definition)
# Loading the script files\
. (Join-Path $ScriptPath 'Import-RequiredModules.ps1')
. (Join-Path $ScriptPath 'Import-ScriptDom.ps1')
. (Join-Path $ScriptPath 'Invoke-TSqlChecks.ps1')

Invoke-TSqlChecks -InputText $InputText -ShowVerboseMessages -ReportBuyfferSizeVuln -CheckForPasswords | Select-Object Message | Format-List