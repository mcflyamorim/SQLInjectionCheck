Clear-Host
[string] $InputText = @'
CREATE PROCEDURE dbo.test_sp_dbmmonitorupdate (@database_name		sysname = null)
AS
BEGIN
  DECLARE @command	CHAR(256)
  SET @command = N'EXEC msdb.sys.sp_dbmmonitorresults ''' + REPLACE(@database_name, N'''',N'''''') + N''',0,0'
  PRINT @command
  EXEC (@command)
END
GO
'@
$ScriptPath = Split-Path -parent $($MyInvocation.MyCommand.Definition)
. (Join-Path $ScriptPath 'Import-RequiredModules.ps1')
. (Join-Path $ScriptPath 'Import-ScriptDom.ps1')
. (Join-Path $ScriptPath 'Invoke-TSqlChecks.ps1')

#Invoke-TSqlChecks -InputText $InputText -ShowVerboseMessages -ReportBuyfferSizeVuln -CheckForPasswords | Select-Object Message | Format-List
Invoke-TSqlChecks -InputText $InputText -ShowVerboseMessages -ReportBuyfferSizeVuln | Select-Object Message | Format-List