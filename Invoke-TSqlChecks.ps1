<#
    .SYNOPSIS
        This script contains functions to check for SQL Injection vulnerabilities in T-SQL code.
    .DESCRIPTION
        The script uses the Microsoft.SqlServer.TransactSql.ScriptDom library to parse T-SQL code and identify potential SQL Injection vulnerabilities.
        It includes functions to load the ScriptDom library, parse T-SQL code, and check for specific patterns that may indicate vulnerabilities.
    .LINK
        https://github.com/mcflyamorim
    .EXAMPLE
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
#>

# Import-ScriptDom -ScriptPath $ScriptPath

class SqlInjectionVisitor : Microsoft.SqlServer.TransactSql.ScriptDom.TSqlFragmentVisitor {
    # Declare a local variable to store the results of the visitor
    $VisitorResults = @{}
    [void] AddVisitorResult([int] $StartOffset, [Microsoft.SqlServer.TransactSql.ScriptDom.TSqlFragment] $Fragment) {
        if (-not $this.VisitorResults.ContainsKey($StartOffset)) {
            $this.VisitorResults[$StartOffset] = $Fragment
        }
    }

    [System.Collections.Hashtable] GetVisitorResults() {
        return $this.VisitorResults
    }

    [void] ExplicitVisit([Microsoft.SqlServer.TransactSql.ScriptDom.TSqlFragment] $Fragment) {
        #Write-Msg -Message "Visiting ProcedureParameter $($Fragment.VariableName.Value) at line $($Fragment.StartLine)..." -VerboseMsg
        $this.AddVisitorResult($Fragment.StartOffset, $Fragment)
        $Fragment.AcceptChildren($this)
    }

    [void] ExplicitVisit([Microsoft.SqlServer.TransactSql.ScriptDom.ProcedureParameter] $Fragment) {
        #Write-Msg -Message "Visiting ProcedureParameter $($Fragment.VariableName.Value) at line $($Fragment.StartLine)..." -VerboseMsg
        $this.AddVisitorResult($Fragment.StartOffset, $Fragment)
        $Fragment.AcceptChildren($this)
    }

    [void] ExplicitVisit([Microsoft.SqlServer.TransactSql.ScriptDom.DeclareVariableStatement] $Fragment) {
        #Write-Msg -Message "Visiting DeclareVariableStatement at line $($Fragment.StartLine)..." -VerboseMsg
        $this.AddVisitorResult($Fragment.StartOffset, $Fragment)
        $Fragment.AcceptChildren($this)
    }

    [void] ExplicitVisit([Microsoft.SqlServer.TransactSql.ScriptDom.SelectSetVariable] $Fragment) {
        #Write-Msg -Message "Visiting SelectSetVariable $($Fragment.Variable.Name) at line $($Fragment.StartLine)..." -VerboseMsg
        $this.AddVisitorResult($Fragment.StartOffset, $Fragment)
        $Fragment.AcceptChildren($this)
    }

    [void] ExplicitVisit([Microsoft.SqlServer.TransactSql.ScriptDom.SetVariableStatement] $Fragment) {
        #Write-Msg -Message "Visiting SetVariableStatement $($Fragment.Variable.Name) at line $($Fragment.StartLine)..." -VerboseMsg
        $this.AddVisitorResult($Fragment.StartOffset, $Fragment)
        $Fragment.AcceptChildren($this)
    }

    [void] ExplicitVisit([Microsoft.SqlServer.TransactSql.ScriptDom.AssignmentSetClause] $Fragment) {
        #Write-Msg -Message "Visiting AssignmentSetClause $($Fragment.Variable.Name) at line $($Fragment.StartLine)..." -VerboseMsg
        $this.AddVisitorResult($Fragment.StartOffset, $Fragment)
        $Fragment.AcceptChildren($this)
    }

    [void] ExplicitVisit([Microsoft.SqlServer.TransactSql.ScriptDom.ExecuteInsertSource] $Fragment) {
        #Write-Msg -Message "Visiting ExecuteInsertSource at line $($Fragment.StartLine)..." -VerboseMsg
        $this.AddVisitorResult($Fragment.StartOffset, $Fragment)
        $Fragment.AcceptChildren($this)
    }

    [void] ExplicitVisit([Microsoft.SqlServer.TransactSql.ScriptDom.ExecuteStatement] $Fragment) {
        #Write-Msg -Message "Visiting ExecuteStatement at line $($Fragment.StartLine)..." -VerboseMsg
        $this.AddVisitorResult($Fragment.StartOffset, $Fragment)
        $Fragment.AcceptChildren($this)
    }

    [void] ExplicitVisit([Microsoft.SqlServer.TransactSql.ScriptDom.DeclareCursorStatement] $Fragment) {
        #Write-Msg -Message "Visiting DeclareCursorStatement at line $($Fragment.StartLine)..." -VerboseMsg
        $this.AddVisitorResult($Fragment.StartOffset, $Fragment)
        $Fragment.AcceptChildren($this)
    }

    [void] ExplicitVisit([Microsoft.SqlServer.TransactSql.ScriptDom.OpenCursorStatement] $Fragment) {
        #Write-Msg -Message "Visiting OpenCursorStatement at line $($Fragment.StartLine)..." -VerboseMsg
        $this.AddVisitorResult($Fragment.StartOffset, $Fragment)
        $Fragment.AcceptChildren($this)
    }

    [void] ExplicitVisit([Microsoft.SqlServer.TransactSql.ScriptDom.FetchCursorStatement] $Fragment) {
        #Write-Msg -Message "Visiting FetchCursorStatement at line $($Fragment.StartLine)..." -VerboseMsg
        $this.AddVisitorResult($Fragment.StartOffset, $Fragment)
        $Fragment.AcceptChildren($this)
    }

    [void] ExplicitVisit([Microsoft.SqlServer.TransactSql.ScriptDom.DeallocateCursorStatement] $Fragment) {
        #Write-Msg -Message "Visiting DeallocateCursorStatement at line $($Fragment.StartLine)..." -VerboseMsg
        $this.AddVisitorResult($Fragment.StartOffset, $Fragment)
        $Fragment.AcceptChildren($this)
    }

    #Adding visitors for DML or DDL events to capture scenarios vulnerable to trigger hijacking.
    #Starting with the DML events
    [void] ExplicitVisit([Microsoft.SqlServer.TransactSql.ScriptDom.InsertStatement] $Fragment) {
        $this.AddVisitorResult($Fragment.StartOffset, $Fragment); 
        $Fragment.AcceptChildren($this); 
        # If property $Fragment.InsertSpecification.Target.SchemaObject.BaseIdentifier.Value exists, read it
        $BaseIdentifier = ""
        if ($Fragment.InsertSpecification.Target -is [Microsoft.SqlServer.TransactSql.ScriptDom.VariableTableReference]){
            $BaseIdentifier = $Fragment.InsertSpecification.Target.Variable.Name
        }
        elseif ($null -ne $Fragment.InsertSpecification.Target.SchemaObject -and $null -ne $Fragment.InsertSpecification.Target.SchemaObject.BaseIdentifier) {
            $BaseIdentifier = $Fragment.InsertSpecification.Target.SchemaObject.BaseIdentifier.Value
        }
        # if $BaseIdentifier starts with #, it's a temporary object, so ignore it
        if ($BaseIdentifier[0] -ne "#" -and $BaseIdentifier[0] -ne "@") {
            $Global:DMLEvents += [PsCustomObject]@{Message = ""; Line = $Fragment.StartLine; Type = $Fragment.GetType().Name; Fragment = $Fragment}
        }
    }
    [void] ExplicitVisit([Microsoft.SqlServer.TransactSql.ScriptDom.DeleteStatement] $Fragment) {
        $this.AddVisitorResult($Fragment.StartOffset, $Fragment); 
        $Fragment.AcceptChildren($this); 
        # If property $Fragment.DeleteSpecification.Target.SchemaObject.BaseIdentifier.Value exists, read it
        $BaseIdentifier = ""
        if ($Fragment.DeleteSpecification.Target -is [Microsoft.SqlServer.TransactSql.ScriptDom.VariableTableReference]){
            $BaseIdentifier = $Fragment.DeleteSpecification.Target.Variable.Name
        }
        elseif ($null -ne $Fragment.DeleteSpecification.Target.SchemaObject -and $null -ne $Fragment.DeleteSpecification.Target.SchemaObject.BaseIdentifier) {
            $BaseIdentifier = $Fragment.DeleteSpecification.Target.SchemaObject.BaseIdentifier.Value
        }
        # if $BaseIdentifier starts with #, it's a temporary object, so ignore it
        if ($BaseIdentifier[0] -ne "#" -and $BaseIdentifier[0] -ne "@") {
            $Global:DMLEvents += [PsCustomObject]@{Message = ""; Line = $Fragment.StartLine; Type = $Fragment.GetType().Name; Fragment = $Fragment}
        }
    }
    [void] ExplicitVisit([Microsoft.SqlServer.TransactSql.ScriptDom.UpdateStatement] $Fragment) {
        $this.AddVisitorResult($Fragment.StartOffset, $Fragment); 
        $Fragment.AcceptChildren($this); 
        # If property $Fragment.UpdateSpecification.Target.SchemaObject.BaseIdentifier.Value exists, read it
        $BaseIdentifier = ""
        if ($Fragment.UpdateSpecification.Target -is [Microsoft.SqlServer.TransactSql.ScriptDom.VariableTableReference]){
            $BaseIdentifier = $Fragment.UpdateSpecification.Target.Variable.Name
        }
        elseif ($null -ne $Fragment.UpdateSpecification.Target.SchemaObject -and $null -ne $Fragment.UpdateSpecification.Target.SchemaObject.BaseIdentifier) {
            $BaseIdentifier = $Fragment.UpdateSpecification.Target.SchemaObject.BaseIdentifier.Value
        }
        # if $BaseIdentifier starts with #, it's a temporary object, so ignore it
        if ($BaseIdentifier[0] -ne "#" -and $BaseIdentifier[0] -ne "@") {
            $Global:DMLEvents += [PsCustomObject]@{Message = ""; Line = $Fragment.StartLine; Type = $Fragment.GetType().Name; Fragment = $Fragment}
        }
    }
    [void] ExplicitVisit([Microsoft.SqlServer.TransactSql.ScriptDom.MergeStatement] $Fragment) {
        $this.AddVisitorResult($Fragment.StartOffset, $Fragment); 
        $Fragment.AcceptChildren($this); 
        # If property $Fragment.MergeSpecification.Target.SchemaObject.BaseIdentifier.Value exists, read it
        $BaseIdentifier = ""
        if ($Fragment.MergeSpecification.Target -is [Microsoft.SqlServer.TransactSql.ScriptDom.VariableTableReference]){
            $BaseIdentifier = $Fragment.MergeSpecification.Target.Variable.Name
        }
        elseif ($null -ne $Fragment.MergeSpecification.Target.SchemaObject -and $null -ne $Fragment.MergeSpecification.Target.SchemaObject.BaseIdentifier) {
            $BaseIdentifier = $Fragment.MergeSpecification.Target.SchemaObject.BaseIdentifier.Value
        }
        # if $BaseIdentifier starts with #, it's a temporary object, so ignore it
        if ($BaseIdentifier[0] -ne "#" -and $BaseIdentifier[0] -ne "@") {
            $Global:DMLEvents += [PsCustomObject]@{Message = ""; Line = $Fragment.StartLine; Type = $Fragment.GetType().Name; Fragment = $Fragment}
        }
    }

    #DDL events
    # AlterAssemblyStatement and CreateAssemblyStatement
    [void] ExplicitVisit([Microsoft.SqlServer.TransactSql.ScriptDom.AlterAssemblyStatement] $Fragment) {$this.AddVisitorResult($Fragment.StartOffset, $Fragment); $Fragment.AcceptChildren($this); $Global:DDLEvents += [PsCustomObject]@{Message = ""; Line = $Fragment.StartLine; Type = $Fragment.GetType().Name; Fragment = $Fragment}}
    [void] ExplicitVisit([Microsoft.SqlServer.TransactSql.ScriptDom.CreateAssemblyStatement] $Fragment) {$this.AddVisitorResult($Fragment.StartOffset, $Fragment); $Fragment.AcceptChildren($this); $Global:DDLEvents += [PsCustomObject]@{Message = ""; Line = $Fragment.StartLine; Type = $Fragment.GetType().Name; Fragment = $Fragment}}
    
    # DropAggregateStatement, DropAssemblyStatement, DropDefaultStatement, DropFunctionStatement, DropProcedureStatement, DropRuleStatement, DropSynonymStatement, DropTableStatement, DropTriggerStatement, DropViewStatement
    [void] ExplicitVisit([Microsoft.SqlServer.TransactSql.ScriptDom.DropAggregateStatement] $Fragment) {$this.AddVisitorResult($Fragment.StartOffset, $Fragment); $Fragment.AcceptChildren($this); $Global:DDLEvents += [PsCustomObject]@{Message = ""; Line = $Fragment.StartLine; Type = $Fragment.GetType().Name; Fragment = $Fragment}}
    [void] ExplicitVisit([Microsoft.SqlServer.TransactSql.ScriptDom.DropAssemblyStatement] $Fragment) {$this.AddVisitorResult($Fragment.StartOffset, $Fragment); $Fragment.AcceptChildren($this); $Global:DDLEvents += [PsCustomObject]@{Message = ""; Line = $Fragment.StartLine; Type = $Fragment.GetType().Name; Fragment = $Fragment}}
    [void] ExplicitVisit([Microsoft.SqlServer.TransactSql.ScriptDom.DropDefaultStatement] $Fragment) {$this.AddVisitorResult($Fragment.StartOffset, $Fragment); $Fragment.AcceptChildren($this); $Global:DDLEvents += [PsCustomObject]@{Message = ""; Line = $Fragment.StartLine; Type = $Fragment.GetType().Name; Fragment = $Fragment}}
    [void] ExplicitVisit([Microsoft.SqlServer.TransactSql.ScriptDom.DropFunctionStatement] $Fragment) {$this.AddVisitorResult($Fragment.StartOffset, $Fragment); $Fragment.AcceptChildren($this); $Global:DDLEvents += [PsCustomObject]@{Message = ""; Line = $Fragment.StartLine; Type = $Fragment.GetType().Name; Fragment = $Fragment}}
    [void] ExplicitVisit([Microsoft.SqlServer.TransactSql.ScriptDom.DropProcedureStatement] $Fragment) {
        $this.AddVisitorResult($Fragment.StartOffset, $Fragment); 
        $Fragment.AcceptChildren($this); 
        # If property $Fragment.SchemaObjectName.BaseIdentifier.Value exists, read it
        $BaseIdentifier = ""
        if ($null -ne $Fragment.SchemaObjectName -and $null -ne $Fragment.SchemaObjectName.BaseIdentifier) {
            $BaseIdentifier = $Fragment.SchemaObjectName.BaseIdentifier.Value
        }
        # if $BaseIdentifier starts with #, it's a temporary object, so ignore it
        if ($BaseIdentifier[0] -ne "#") {
            $Global:DDLEvents += [PsCustomObject]@{Message = ""; Line = $Fragment.StartLine; Type = $Fragment.GetType().Name; Fragment = $Fragment}
        }
    }
    [void] ExplicitVisit([Microsoft.SqlServer.TransactSql.ScriptDom.DropRuleStatement] $Fragment) {$this.AddVisitorResult($Fragment.StartOffset, $Fragment); $Fragment.AcceptChildren($this); $Global:DDLEvents += [PsCustomObject]@{Message = ""; Line = $Fragment.StartLine; Type = $Fragment.GetType().Name; Fragment = $Fragment}}
    [void] ExplicitVisit([Microsoft.SqlServer.TransactSql.ScriptDom.DropSynonymStatement] $Fragment) {$this.AddVisitorResult($Fragment.StartOffset, $Fragment); $Fragment.AcceptChildren($this); $Global:DDLEvents += [PsCustomObject]@{Message = ""; Line = $Fragment.StartLine; Type = $Fragment.GetType().Name; Fragment = $Fragment}}
    [void] ExplicitVisit([Microsoft.SqlServer.TransactSql.ScriptDom.DropTableStatement] $Fragment) {
        $this.AddVisitorResult($Fragment.StartOffset, $Fragment); 
        $Fragment.AcceptChildren($this); 
        # If property $Fragment.SchemaObjectName.BaseIdentifier.Value exists, read it
        $BaseIdentifier = ""
        # loop for each object in $Fragment.Objects, if property BaseIdentifier.Value exists, read it
        foreach ($Object in $Fragment.Objects) {
            if ($null -ne $Object -and $null -ne $Object.BaseIdentifier) {
                $BaseIdentifier = $Object.BaseIdentifier.Value
                # if $BaseIdentifier starts with #, it's a temporary object, so ignore it
                if ($BaseIdentifier[0] -ne "#") {
                    $Global:DDLEvents += [PsCustomObject]@{Message = ""; Line = $Fragment.StartLine; Type = $Fragment.GetType().Name; Fragment = $Fragment}
                }
            }
        }
    }
    
    [void] ExplicitVisit([Microsoft.SqlServer.TransactSql.ScriptDom.DropTriggerStatement] $Fragment) {$this.AddVisitorResult($Fragment.StartOffset, $Fragment); $Fragment.AcceptChildren($this); $Global:DDLEvents += [PsCustomObject]@{Message = ""; Line = $Fragment.StartLine; Type = $Fragment.GetType().Name; Fragment = $Fragment}}
    [void] ExplicitVisit([Microsoft.SqlServer.TransactSql.ScriptDom.DropViewStatement] $Fragment) {
        $this.AddVisitorResult($Fragment.StartOffset, $Fragment); 
        $Fragment.AcceptChildren($this); 
        # If property $Fragment.SchemaObjectName.BaseIdentifier.Value exists, read it
        $BaseIdentifier = ""
        if ($null -ne $Fragment.SchemaObjectName -and $null -ne $Fragment.SchemaObjectName.BaseIdentifier) {
            $BaseIdentifier = $Fragment.SchemaObjectName.BaseIdentifier.Value
        }
        # if $BaseIdentifier starts with #, it's a temporary object, so ignore it
        if ($BaseIdentifier[0] -ne "#") {
            $Global:DDLEvents += [PsCustomObject]@{Message = ""; Line = $Fragment.StartLine; Type = $Fragment.GetType().Name; Fragment = $Fragment}
        }
    }
    

    # DropApplicationRoleStatement, DropAsymmetricKeyStatement, DropBrokerPriorityStatement, DropCertificateStatement, DropContractStatement, DropCredentialStatement, DropCryptographicProviderStatement, 
    # DropDatabaseAuditSpecificationStatement, DropEndpointStatement, DropEventSessionStatement, DropFullTextCatalogStatement, DropFullTextStopListStatement, DropLoginStatement, DropMessageTypeStatement, 
    # DropPartitionFunctionStatement, DropPartitionSchemeStatement, DropRemoteServiceBindingStatement, DropResourcePoolStatement, DropRoleStatement, DropRouteStatement, DropServerAuditSpecificationStatement, 
    # DropServerAuditStatement, DropServiceStatement, DropSymmetricKeyStatement, DropUserStatement, DropWorkloadGroupStatement
    [void] ExplicitVisit([Microsoft.SqlServer.TransactSql.ScriptDom.DropApplicationRoleStatement] $Fragment) {$this.AddVisitorResult($Fragment.StartOffset, $Fragment); $Fragment.AcceptChildren($this); $Global:DDLEvents += [PsCustomObject]@{Message = ""; Line = $Fragment.StartLine; Type = $Fragment.GetType().Name; Fragment = $Fragment}}
    [void] ExplicitVisit([Microsoft.SqlServer.TransactSql.ScriptDom.DropAsymmetricKeyStatement] $Fragment) {$this.AddVisitorResult($Fragment.StartOffset, $Fragment); $Fragment.AcceptChildren($this); $Global:DDLEvents += [PsCustomObject]@{Message = ""; Line = $Fragment.StartLine; Type = $Fragment.GetType().Name; Fragment = $Fragment}}
    [void] ExplicitVisit([Microsoft.SqlServer.TransactSql.ScriptDom.DropBrokerPriorityStatement] $Fragment) {$this.AddVisitorResult($Fragment.StartOffset, $Fragment); $Fragment.AcceptChildren($this); $Global:DDLEvents += [PsCustomObject]@{Message = ""; Line = $Fragment.StartLine; Type = $Fragment.GetType().Name; Fragment = $Fragment}}
    [void] ExplicitVisit([Microsoft.SqlServer.TransactSql.ScriptDom.DropCertificateStatement] $Fragment) {$this.AddVisitorResult($Fragment.StartOffset, $Fragment); $Fragment.AcceptChildren($this); $Global:DDLEvents += [PsCustomObject]@{Message = ""; Line = $Fragment.StartLine; Type = $Fragment.GetType().Name; Fragment = $Fragment}}
    [void] ExplicitVisit([Microsoft.SqlServer.TransactSql.ScriptDom.DropContractStatement] $Fragment) {$this.AddVisitorResult($Fragment.StartOffset, $Fragment); $Fragment.AcceptChildren($this); $Global:DDLEvents += [PsCustomObject]@{Message = ""; Line = $Fragment.StartLine; Type = $Fragment.GetType().Name; Fragment = $Fragment}}
    [void] ExplicitVisit([Microsoft.SqlServer.TransactSql.ScriptDom.DropCredentialStatement] $Fragment) {$this.AddVisitorResult($Fragment.StartOffset, $Fragment); $Fragment.AcceptChildren($this); $Global:DDLEvents += [PsCustomObject]@{Message = ""; Line = $Fragment.StartLine; Type = $Fragment.GetType().Name; Fragment = $Fragment}}
    [void] ExplicitVisit([Microsoft.SqlServer.TransactSql.ScriptDom.DropCryptographicProviderStatement] $Fragment) {$this.AddVisitorResult($Fragment.StartOffset, $Fragment); $Fragment.AcceptChildren($this); $Global:DDLEvents += [PsCustomObject]@{Message = ""; Line = $Fragment.StartLine; Type = $Fragment.GetType().Name; Fragment = $Fragment}}
    [void] ExplicitVisit([Microsoft.SqlServer.TransactSql.ScriptDom.DropDatabaseAuditSpecificationStatement] $Fragment) {$this.AddVisitorResult($Fragment.StartOffset, $Fragment); $Fragment.AcceptChildren($this); $Global:DDLEvents += [PsCustomObject]@{Message = ""; Line = $Fragment.StartLine; Type = $Fragment.GetType().Name; Fragment = $Fragment}}
    [void] ExplicitVisit([Microsoft.SqlServer.TransactSql.ScriptDom.DropEndpointStatement] $Fragment) {$this.AddVisitorResult($Fragment.StartOffset, $Fragment); $Fragment.AcceptChildren($this); $Global:DDLEvents += [PsCustomObject]@{Message = ""; Line = $Fragment.StartLine; Type = $Fragment.GetType().Name; Fragment = $Fragment}}
    [void] ExplicitVisit([Microsoft.SqlServer.TransactSql.ScriptDom.DropEventSessionStatement] $Fragment) {$this.AddVisitorResult($Fragment.StartOffset, $Fragment); $Fragment.AcceptChildren($this); $Global:DDLEvents += [PsCustomObject]@{Message = ""; Line = $Fragment.StartLine; Type = $Fragment.GetType().Name; Fragment = $Fragment}}
    [void] ExplicitVisit([Microsoft.SqlServer.TransactSql.ScriptDom.DropFullTextCatalogStatement] $Fragment) {$this.AddVisitorResult($Fragment.StartOffset, $Fragment); $Fragment.AcceptChildren($this); $Global:DDLEvents += [PsCustomObject]@{Message = ""; Line = $Fragment.StartLine; Type = $Fragment.GetType().Name; Fragment = $Fragment}}
    [void] ExplicitVisit([Microsoft.SqlServer.TransactSql.ScriptDom.DropFullTextStopListStatement] $Fragment) {$this.AddVisitorResult($Fragment.StartOffset, $Fragment); $Fragment.AcceptChildren($this); $Global:DDLEvents += [PsCustomObject]@{Message = ""; Line = $Fragment.StartLine; Type = $Fragment.GetType().Name; Fragment = $Fragment}}
    [void] ExplicitVisit([Microsoft.SqlServer.TransactSql.ScriptDom.DropLoginStatement] $Fragment) {$this.AddVisitorResult($Fragment.StartOffset, $Fragment); $Fragment.AcceptChildren($this); $Global:DDLEvents += [PsCustomObject]@{Message = ""; Line = $Fragment.StartLine; Type = $Fragment.GetType().Name; Fragment = $Fragment}}
    [void] ExplicitVisit([Microsoft.SqlServer.TransactSql.ScriptDom.DropMessageTypeStatement] $Fragment) {$this.AddVisitorResult($Fragment.StartOffset, $Fragment); $Fragment.AcceptChildren($this); $Global:DDLEvents += [PsCustomObject]@{Message = ""; Line = $Fragment.StartLine; Type = $Fragment.GetType().Name; Fragment = $Fragment}}
    [void] ExplicitVisit([Microsoft.SqlServer.TransactSql.ScriptDom.DropPartitionFunctionStatement] $Fragment) {$this.AddVisitorResult($Fragment.StartOffset, $Fragment); $Fragment.AcceptChildren($this); $Global:DDLEvents += [PsCustomObject]@{Message = ""; Line = $Fragment.StartLine; Type = $Fragment.GetType().Name; Fragment = $Fragment}}
    [void] ExplicitVisit([Microsoft.SqlServer.TransactSql.ScriptDom.DropPartitionSchemeStatement] $Fragment) {$this.AddVisitorResult($Fragment.StartOffset, $Fragment); $Fragment.AcceptChildren($this); $Global:DDLEvents += [PsCustomObject]@{Message = ""; Line = $Fragment.StartLine; Type = $Fragment.GetType().Name; Fragment = $Fragment}}
    [void] ExplicitVisit([Microsoft.SqlServer.TransactSql.ScriptDom.DropRemoteServiceBindingStatement] $Fragment) {$this.AddVisitorResult($Fragment.StartOffset, $Fragment); $Fragment.AcceptChildren($this); $Global:DDLEvents += [PsCustomObject]@{Message = ""; Line = $Fragment.StartLine; Type = $Fragment.GetType().Name; Fragment = $Fragment}}
    [void] ExplicitVisit([Microsoft.SqlServer.TransactSql.ScriptDom.DropResourcePoolStatement] $Fragment) {$this.AddVisitorResult($Fragment.StartOffset, $Fragment); $Fragment.AcceptChildren($this); $Global:DDLEvents += [PsCustomObject]@{Message = ""; Line = $Fragment.StartLine; Type = $Fragment.GetType().Name; Fragment = $Fragment}}
    [void] ExplicitVisit([Microsoft.SqlServer.TransactSql.ScriptDom.DropRoleStatement] $Fragment) {$this.AddVisitorResult($Fragment.StartOffset, $Fragment); $Fragment.AcceptChildren($this); $Global:DDLEvents += [PsCustomObject]@{Message = ""; Line = $Fragment.StartLine; Type = $Fragment.GetType().Name; Fragment = $Fragment}}
    [void] ExplicitVisit([Microsoft.SqlServer.TransactSql.ScriptDom.DropRouteStatement] $Fragment) {$this.AddVisitorResult($Fragment.StartOffset, $Fragment); $Fragment.AcceptChildren($this); $Global:DDLEvents += [PsCustomObject]@{Message = ""; Line = $Fragment.StartLine; Type = $Fragment.GetType().Name; Fragment = $Fragment}}
    [void] ExplicitVisit([Microsoft.SqlServer.TransactSql.ScriptDom.DropServerAuditSpecificationStatement] $Fragment) {$this.AddVisitorResult($Fragment.StartOffset, $Fragment); $Fragment.AcceptChildren($this); $Global:DDLEvents += [PsCustomObject]@{Message = ""; Line = $Fragment.StartLine; Type = $Fragment.GetType().Name; Fragment = $Fragment}}
    [void] ExplicitVisit([Microsoft.SqlServer.TransactSql.ScriptDom.DropServerAuditStatement] $Fragment) {$this.AddVisitorResult($Fragment.StartOffset, $Fragment); $Fragment.AcceptChildren($this); $Global:DDLEvents += [PsCustomObject]@{Message = ""; Line = $Fragment.StartLine; Type = $Fragment.GetType().Name; Fragment = $Fragment}}
    [void] ExplicitVisit([Microsoft.SqlServer.TransactSql.ScriptDom.DropServiceStatement] $Fragment) {$this.AddVisitorResult($Fragment.StartOffset, $Fragment); $Fragment.AcceptChildren($this); $Global:DDLEvents += [PsCustomObject]@{Message = ""; Line = $Fragment.StartLine; Type = $Fragment.GetType().Name; Fragment = $Fragment}}
    [void] ExplicitVisit([Microsoft.SqlServer.TransactSql.ScriptDom.DropSymmetricKeyStatement] $Fragment) {$this.AddVisitorResult($Fragment.StartOffset, $Fragment); $Fragment.AcceptChildren($this); $Global:DDLEvents += [PsCustomObject]@{Message = ""; Line = $Fragment.StartLine; Type = $Fragment.GetType().Name; Fragment = $Fragment}}
    [void] ExplicitVisit([Microsoft.SqlServer.TransactSql.ScriptDom.DropUserStatement] $Fragment) {$this.AddVisitorResult($Fragment.StartOffset, $Fragment); $Fragment.AcceptChildren($this); $Global:DDLEvents += [PsCustomObject]@{Message = ""; Line = $Fragment.StartLine; Type = $Fragment.GetType().Name; Fragment = $Fragment}}
    [void] ExplicitVisit([Microsoft.SqlServer.TransactSql.ScriptDom.DropWorkloadGroupStatement] $Fragment) {$this.AddVisitorResult($Fragment.StartOffset, $Fragment); $Fragment.AcceptChildren($this); $Global:DDLEvents += [PsCustomObject]@{Message = ""; Line = $Fragment.StartLine; Type = $Fragment.GetType().Name; Fragment = $Fragment}}
        
    # AlterAuthorizationStatement
    [void] ExplicitVisit([Microsoft.SqlServer.TransactSql.ScriptDom.AlterAuthorizationStatement] $Fragment) {$this.AddVisitorResult($Fragment.StartOffset, $Fragment); $Fragment.AcceptChildren($this); $Global:DDLEvents += [PsCustomObject]@{Message = ""; Line = $Fragment.StartLine; Type = $Fragment.GetType().Name; Fragment = $Fragment}}

    # AlterBrokerPriorityStatement, CreateBrokerPriorityStatement
    [void] ExplicitVisit([Microsoft.SqlServer.TransactSql.ScriptDom.AlterBrokerPriorityStatement] $Fragment) {$this.AddVisitorResult($Fragment.StartOffset, $Fragment); $Fragment.AcceptChildren($this); $Global:DDLEvents += [PsCustomObject]@{Message = ""; Line = $Fragment.StartLine; Type = $Fragment.GetType().Name; Fragment = $Fragment}}
    [void] ExplicitVisit([Microsoft.SqlServer.TransactSql.ScriptDom.CreateBrokerPriorityStatement] $Fragment) {$this.AddVisitorResult($Fragment.StartOffset, $Fragment); $Fragment.AcceptChildren($this); $Global:DDLEvents += [PsCustomObject]@{Message = ""; Line = $Fragment.StartLine; Type = $Fragment.GetType().Name; Fragment = $Fragment}}

    # AlterCertificateStatement, BackupCertificateStatement, CreateCertificateStatement
    [void] ExplicitVisit([Microsoft.SqlServer.TransactSql.ScriptDom.AlterCertificateStatement] $Fragment) {$this.AddVisitorResult($Fragment.StartOffset, $Fragment); $Fragment.AcceptChildren($this); $Global:DDLEvents += [PsCustomObject]@{Message = ""; Line = $Fragment.StartLine; Type = $Fragment.GetType().Name; Fragment = $Fragment}}
    [void] ExplicitVisit([Microsoft.SqlServer.TransactSql.ScriptDom.BackupCertificateStatement] $Fragment) {$this.AddVisitorResult($Fragment.StartOffset, $Fragment); $Fragment.AcceptChildren($this); $Global:DDLEvents += [PsCustomObject]@{Message = ""; Line = $Fragment.StartLine; Type = $Fragment.GetType().Name; Fragment = $Fragment}}
    [void] ExplicitVisit([Microsoft.SqlServer.TransactSql.ScriptDom.CreateCertificateStatement] $Fragment) {$this.AddVisitorResult($Fragment.StartOffset, $Fragment); $Fragment.AcceptChildren($this); $Global:DDLEvents += [PsCustomObject]@{Message = ""; Line = $Fragment.StartLine; Type = $Fragment.GetType().Name; Fragment = $Fragment}}
    
    # CreateContractStatement
    [void] ExplicitVisit([Microsoft.SqlServer.TransactSql.ScriptDom.CreateContractStatement] $Fragment) {$this.AddVisitorResult($Fragment.StartOffset, $Fragment); $Fragment.AcceptChildren($this); $Global:DDLEvents += [PsCustomObject]@{Message = ""; Line = $Fragment.StartLine; Type = $Fragment.GetType().Name; Fragment = $Fragment}}
    
    # AlterCredentialStatement, CreateCredentialStatement
    [void] ExplicitVisit([Microsoft.SqlServer.TransactSql.ScriptDom.AlterCredentialStatement] $Fragment) {$this.AddVisitorResult($Fragment.StartOffset, $Fragment); $Fragment.AcceptChildren($this); $Global:DDLEvents += [PsCustomObject]@{Message = ""; Line = $Fragment.StartLine; Type = $Fragment.GetType().Name; Fragment = $Fragment}}
    [void] ExplicitVisit([Microsoft.SqlServer.TransactSql.ScriptDom.CreateCredentialStatement] $Fragment) {$this.AddVisitorResult($Fragment.StartOffset, $Fragment); $Fragment.AcceptChildren($this); $Global:DDLEvents += [PsCustomObject]@{Message = ""; Line = $Fragment.StartLine; Type = $Fragment.GetType().Name; Fragment = $Fragment}}

    # DenyStatement, GrantStatement, RevokeStatement
    [void] ExplicitVisit([Microsoft.SqlServer.TransactSql.ScriptDom.DenyStatement] $Fragment) {$this.AddVisitorResult($Fragment.StartOffset, $Fragment); $Fragment.AcceptChildren($this); $Global:DDLEvents += [PsCustomObject]@{Message = ""; Line = $Fragment.StartLine; Type = $Fragment.GetType().Name; Fragment = $Fragment}}
    [void] ExplicitVisit([Microsoft.SqlServer.TransactSql.ScriptDom.GrantStatement] $Fragment) {$this.AddVisitorResult($Fragment.StartOffset, $Fragment); $Fragment.AcceptChildren($this); $Global:DDLEvents += [PsCustomObject]@{Message = ""; Line = $Fragment.StartLine; Type = $Fragment.GetType().Name; Fragment = $Fragment}}
    [void] ExplicitVisit([Microsoft.SqlServer.TransactSql.ScriptDom.RevokeStatement] $Fragment) {$this.AddVisitorResult($Fragment.StartOffset, $Fragment); $Fragment.AcceptChildren($this); $Global:DDLEvents += [PsCustomObject]@{Message = ""; Line = $Fragment.StartLine; Type = $Fragment.GetType().Name; Fragment = $Fragment}}

    # AlterDatabaseAuditSpecificationStatement, AlterServerAuditSpecificationStatement, CreateDatabaseAuditSpecificationStatement, CreateServerAuditSpecificationStatement
    [void] ExplicitVisit([Microsoft.SqlServer.TransactSql.ScriptDom.AlterDatabaseAuditSpecificationStatement] $Fragment) {$this.AddVisitorResult($Fragment.StartOffset, $Fragment); $Fragment.AcceptChildren($this); $Global:DDLEvents += [PsCustomObject]@{Message = ""; Line = $Fragment.StartLine; Type = $Fragment.GetType().Name; Fragment = $Fragment}}
    [void] ExplicitVisit([Microsoft.SqlServer.TransactSql.ScriptDom.AlterServerAuditSpecificationStatement] $Fragment) {$this.AddVisitorResult($Fragment.StartOffset, $Fragment); $Fragment.AcceptChildren($this); $Global:DDLEvents += [PsCustomObject]@{Message = ""; Line = $Fragment.StartLine; Type = $Fragment.GetType().Name; Fragment = $Fragment}}
    [void] ExplicitVisit([Microsoft.SqlServer.TransactSql.ScriptDom.CreateDatabaseAuditSpecificationStatement] $Fragment) {$this.AddVisitorResult($Fragment.StartOffset, $Fragment); $Fragment.AcceptChildren($this); $Global:DDLEvents += [PsCustomObject]@{Message = ""; Line = $Fragment.StartLine; Type = $Fragment.GetType().Name; Fragment = $Fragment}}
    [void] ExplicitVisit([Microsoft.SqlServer.TransactSql.ScriptDom.CreateServerAuditSpecificationStatement] $Fragment) {$this.AddVisitorResult($Fragment.StartOffset, $Fragment); $Fragment.AcceptChildren($this); $Global:DDLEvents += [PsCustomObject]@{Message = ""; Line = $Fragment.StartLine; Type = $Fragment.GetType().Name; Fragment = $Fragment}}
    
    # AlterDatabaseEncryptionKeyStatement, CreateDatabaseEncryptionKeyStatement
    [void] ExplicitVisit([Microsoft.SqlServer.TransactSql.ScriptDom.AlterDatabaseEncryptionKeyStatement] $Fragment) {$this.AddVisitorResult($Fragment.StartOffset, $Fragment); $Fragment.AcceptChildren($this); $Global:DDLEvents += [PsCustomObject]@{Message = ""; Line = $Fragment.StartLine; Type = $Fragment.GetType().Name; Fragment = $Fragment}}
    [void] ExplicitVisit([Microsoft.SqlServer.TransactSql.ScriptDom.CreateDatabaseEncryptionKeyStatement] $Fragment) {$this.AddVisitorResult($Fragment.StartOffset, $Fragment); $Fragment.AcceptChildren($this); $Global:DDLEvents += [PsCustomObject]@{Message = ""; Line = $Fragment.StartLine; Type = $Fragment.GetType().Name; Fragment = $Fragment}}

    # CreateDefaultStatement
    [void] ExplicitVisit([Microsoft.SqlServer.TransactSql.ScriptDom.CreateDefaultStatement] $Fragment) {$this.AddVisitorResult($Fragment.StartOffset, $Fragment); $Fragment.AcceptChildren($this); $Global:DDLEvents += [PsCustomObject]@{Message = ""; Line = $Fragment.StartLine; Type = $Fragment.GetType().Name; Fragment = $Fragment}}

    # CreateEventNotificationStatement
    [void] ExplicitVisit([Microsoft.SqlServer.TransactSql.ScriptDom.CreateEventNotificationStatement] $Fragment) {$this.AddVisitorResult($Fragment.StartOffset, $Fragment); $Fragment.AcceptChildren($this); $Global:DDLEvents += [PsCustomObject]@{Message = ""; Line = $Fragment.StartLine; Type = $Fragment.GetType().Name; Fragment = $Fragment}}

    # AlterFullTextCatalogStatement, CreateFullTextCatalogStatement
    [void] ExplicitVisit([Microsoft.SqlServer.TransactSql.ScriptDom.AlterFullTextCatalogStatement] $Fragment) {$this.AddVisitorResult($Fragment.StartOffset, $Fragment); $Fragment.AcceptChildren($this); $Global:DDLEvents += [PsCustomObject]@{Message = ""; Line = $Fragment.StartLine; Type = $Fragment.GetType().Name; Fragment = $Fragment}}
    [void] ExplicitVisit([Microsoft.SqlServer.TransactSql.ScriptDom.CreateFullTextCatalogStatement] $Fragment) {$this.AddVisitorResult($Fragment.StartOffset, $Fragment); $Fragment.AcceptChildren($this); $Global:DDLEvents += [PsCustomObject]@{Message = ""; Line = $Fragment.StartLine; Type = $Fragment.GetType().Name; Fragment = $Fragment}}

    # CreateFullTextIndexStatement
    [void] ExplicitVisit([Microsoft.SqlServer.TransactSql.ScriptDom.CreateFullTextIndexStatement] $Fragment) {$this.AddVisitorResult($Fragment.StartOffset, $Fragment); $Fragment.AcceptChildren($this); $Global:DDLEvents += [PsCustomObject]@{Message = ""; Line = $Fragment.StartLine; Type = $Fragment.GetType().Name; Fragment = $Fragment}}

    # CreateFullTextStopListStatement
    [void] ExplicitVisit([Microsoft.SqlServer.TransactSql.ScriptDom.CreateFullTextStopListStatement] $Fragment) {$this.AddVisitorResult($Fragment.StartOffset, $Fragment); $Fragment.AcceptChildren($this); $Global:DDLEvents += [PsCustomObject]@{Message = ""; Line = $Fragment.StartLine; Type = $Fragment.GetType().Name; Fragment = $Fragment}}

    # AlterFullTextStopListStatement
    [void] ExplicitVisit([Microsoft.SqlServer.TransactSql.ScriptDom.AlterFullTextStopListStatement] $Fragment) {$this.AddVisitorResult($Fragment.StartOffset, $Fragment); $Fragment.AcceptChildren($this); $Global:DDLEvents += [PsCustomObject]@{Message = ""; Line = $Fragment.StartLine; Type = $Fragment.GetType().Name; Fragment = $Fragment}}

    # # CreateFunctionStatement
    # [void] ExplicitVisit([Microsoft.SqlServer.TransactSql.ScriptDom.CreateFunctionStatement] $Fragment) {$this.AddVisitorResult($Fragment.StartOffset, $Fragment); $Fragment.AcceptChildren($this); $Global:DDLEvents += [PsCustomObject]@{Message = ""; Line = $Fragment.StartLine; Type = $Fragment.GetType().Name; Fragment = $Fragment}}

    # AlterFunctionStatement
    [void] ExplicitVisit([Microsoft.SqlServer.TransactSql.ScriptDom.AlterFunctionStatement] $Fragment) {$this.AddVisitorResult($Fragment.StartOffset, $Fragment); $Fragment.AcceptChildren($this); $Global:DDLEvents += [PsCustomObject]@{Message = ""; Line = $Fragment.StartLine; Type = $Fragment.GetType().Name; Fragment = $Fragment}}

    # AlterIndexStatement, CreateIndexStatement, CreateXmlIndexStatement
    [void] ExplicitVisit([Microsoft.SqlServer.TransactSql.ScriptDom.AlterIndexStatement] $Fragment) {$this.AddVisitorResult($Fragment.StartOffset, $Fragment); $Fragment.AcceptChildren($this); $Global:DDLEvents += [PsCustomObject]@{Message = ""; Line = $Fragment.StartLine; Type = $Fragment.GetType().Name; Fragment = $Fragment}}
    [void] ExplicitVisit([Microsoft.SqlServer.TransactSql.ScriptDom.CreateIndexStatement] $Fragment) {$this.AddVisitorResult($Fragment.StartOffset, $Fragment); $Fragment.AcceptChildren($this); $Global:DDLEvents += [PsCustomObject]@{Message = ""; Line = $Fragment.StartLine; Type = $Fragment.GetType().Name; Fragment = $Fragment}}
    [void] ExplicitVisit([Microsoft.SqlServer.TransactSql.ScriptDom.CreateXmlIndexStatement] $Fragment) {$this.AddVisitorResult($Fragment.StartOffset, $Fragment); $Fragment.AcceptChildren($this); $Global:DDLEvents += [PsCustomObject]@{Message = ""; Line = $Fragment.StartLine; Type = $Fragment.GetType().Name; Fragment = $Fragment}}
    
    # AlterMasterKeyStatement, CreateMasterKeyStatement
    [void] ExplicitVisit([Microsoft.SqlServer.TransactSql.ScriptDom.AlterMasterKeyStatement] $Fragment) {$this.AddVisitorResult($Fragment.StartOffset, $Fragment); $Fragment.AcceptChildren($this); $Global:DDLEvents += [PsCustomObject]@{Message = ""; Line = $Fragment.StartLine; Type = $Fragment.GetType().Name; Fragment = $Fragment}}
    [void] ExplicitVisit([Microsoft.SqlServer.TransactSql.ScriptDom.CreateMasterKeyStatement] $Fragment) {$this.AddVisitorResult($Fragment.StartOffset, $Fragment); $Fragment.AcceptChildren($this); $Global:DDLEvents += [PsCustomObject]@{Message = ""; Line = $Fragment.StartLine; Type = $Fragment.GetType().Name; Fragment = $Fragment}}
    
    # AlterMessageTypeStatement, CreateMessageTypeStatement
    [void] ExplicitVisit([Microsoft.SqlServer.TransactSql.ScriptDom.AlterMessageTypeStatement] $Fragment) {$this.AddVisitorResult($Fragment.StartOffset, $Fragment); $Fragment.AcceptChildren($this); $Global:DDLEvents += [PsCustomObject]@{Message = ""; Line = $Fragment.StartLine; Type = $Fragment.GetType().Name; Fragment = $Fragment}}
    [void] ExplicitVisit([Microsoft.SqlServer.TransactSql.ScriptDom.CreateMessageTypeStatement] $Fragment) {$this.AddVisitorResult($Fragment.StartOffset, $Fragment); $Fragment.AcceptChildren($this); $Global:DDLEvents += [PsCustomObject]@{Message = ""; Line = $Fragment.StartLine; Type = $Fragment.GetType().Name; Fragment = $Fragment}}

    # CreatePartitionFunctionStatement
    [void] ExplicitVisit([Microsoft.SqlServer.TransactSql.ScriptDom.CreatePartitionFunctionStatement] $Fragment) {$this.AddVisitorResult($Fragment.StartOffset, $Fragment); $Fragment.AcceptChildren($this); $Global:DDLEvents += [PsCustomObject]@{Message = ""; Line = $Fragment.StartLine; Type = $Fragment.GetType().Name; Fragment = $Fragment}}

    # AlterPartitionFunctionStatement
    [void] ExplicitVisit([Microsoft.SqlServer.TransactSql.ScriptDom.AlterPartitionFunctionStatement] $Fragment) {$this.AddVisitorResult($Fragment.StartOffset, $Fragment); $Fragment.AcceptChildren($this); $Global:DDLEvents += [PsCustomObject]@{Message = ""; Line = $Fragment.StartLine; Type = $Fragment.GetType().Name; Fragment = $Fragment}}

    # CreatePartitionSchemeStatement
    [void] ExplicitVisit([Microsoft.SqlServer.TransactSql.ScriptDom.CreatePartitionSchemeStatement] $Fragment) {$this.AddVisitorResult($Fragment.StartOffset, $Fragment); $Fragment.AcceptChildren($this); $Global:DDLEvents += [PsCustomObject]@{Message = ""; Line = $Fragment.StartLine; Type = $Fragment.GetType().Name; Fragment = $Fragment}}

    # AlterPartitionSchemeStatement
    [void] ExplicitVisit([Microsoft.SqlServer.TransactSql.ScriptDom.AlterPartitionSchemeStatement] $Fragment) {$this.AddVisitorResult($Fragment.StartOffset, $Fragment); $Fragment.AcceptChildren($this); $Global:DDLEvents += [PsCustomObject]@{Message = ""; Line = $Fragment.StartLine; Type = $Fragment.GetType().Name; Fragment = $Fragment}}

    # CreateProcedureStatement
    # [void] ExplicitVisit([Microsoft.SqlServer.TransactSql.ScriptDom.CreateProcedureStatement] $Fragment) {
    #     $this.AddVisitorResult($Fragment.StartOffset, $Fragment); 
    #     $Fragment.AcceptChildren($this); 
    #     # If property $Fragment.SchemaObjectName.BaseIdentifier.Value exists, read it
    #     $BaseIdentifier = ""
    #     if ($null -ne $Fragment.SchemaObjectName -and $null -ne $Fragment.SchemaObjectName.BaseIdentifier) {
    #         $BaseIdentifier = $Fragment.SchemaObjectName.BaseIdentifier.Value
    #     }
    #     # if $BaseIdentifier starts with #, it's a temporary object, so ignore it
    #     if ($BaseIdentifier[0] -ne "#") {
    #         $Global:DDLEvents += [PsCustomObject]@{Message = ""; Line = $Fragment.StartLine; Type = $Fragment.GetType().Name; Fragment = $Fragment}
    #     }
    # }

    # AlterProcedureStatement
    [void] ExplicitVisit([Microsoft.SqlServer.TransactSql.ScriptDom.AlterProcedureStatement] $Fragment) {$this.AddVisitorResult($Fragment.StartOffset, $Fragment); $Fragment.AcceptChildren($this); $Global:DDLEvents += [PsCustomObject]@{Message = ""; Line = $Fragment.StartLine; Type = $Fragment.GetType().Name; Fragment = $Fragment}}

    # CreateQueueStatement
    [void] ExplicitVisit([Microsoft.SqlServer.TransactSql.ScriptDom.CreateQueueStatement] $Fragment) {$this.AddVisitorResult($Fragment.StartOffset, $Fragment); $Fragment.AcceptChildren($this); $Global:DDLEvents += [PsCustomObject]@{Message = ""; Line = $Fragment.StartLine; Type = $Fragment.GetType().Name; Fragment = $Fragment}}

    # AlterQueueStatement
    [void] ExplicitVisit([Microsoft.SqlServer.TransactSql.ScriptDom.AlterQueueStatement] $Fragment) {$this.AddVisitorResult($Fragment.StartOffset, $Fragment); $Fragment.AcceptChildren($this); $Global:DDLEvents += [PsCustomObject]@{Message = ""; Line = $Fragment.StartLine; Type = $Fragment.GetType().Name; Fragment = $Fragment}}

    # CreateSpatialIndexStatement
    [void] ExplicitVisit([Microsoft.SqlServer.TransactSql.ScriptDom.CreateSpatialIndexStatement] $Fragment) {$this.AddVisitorResult($Fragment.StartOffset, $Fragment); $Fragment.AcceptChildren($this); $Global:DDLEvents += [PsCustomObject]@{Message = ""; Line = $Fragment.StartLine; Type = $Fragment.GetType().Name; Fragment = $Fragment}}

    # Rename - sp_rename
    # Todo

    # AlterRoleStatement, CreateRoleStatement
    [void] ExplicitVisit([Microsoft.SqlServer.TransactSql.ScriptDom.AlterRoleStatement] $Fragment) {$this.AddVisitorResult($Fragment.StartOffset, $Fragment); $Fragment.AcceptChildren($this); $Global:DDLEvents += [PsCustomObject]@{Message = ""; Line = $Fragment.StartLine; Type = $Fragment.GetType().Name; Fragment = $Fragment}}
    [void] ExplicitVisit([Microsoft.SqlServer.TransactSql.ScriptDom.CreateRoleStatement] $Fragment) {$this.AddVisitorResult($Fragment.StartOffset, $Fragment); $Fragment.AcceptChildren($this); $Global:DDLEvents += [PsCustomObject]@{Message = ""; Line = $Fragment.StartLine; Type = $Fragment.GetType().Name; Fragment = $Fragment}}

    # AlterRouteStatement, CreateRouteStatement
    [void] ExplicitVisit([Microsoft.SqlServer.TransactSql.ScriptDom.AlterRouteStatement] $Fragment) {$this.AddVisitorResult($Fragment.StartOffset, $Fragment); $Fragment.AcceptChildren($this); $Global:DDLEvents += [PsCustomObject]@{Message = ""; Line = $Fragment.StartLine; Type = $Fragment.GetType().Name; Fragment = $Fragment}}
    [void] ExplicitVisit([Microsoft.SqlServer.TransactSql.ScriptDom.CreateRouteStatement] $Fragment) {$this.AddVisitorResult($Fragment.StartOffset, $Fragment); $Fragment.AcceptChildren($this); $Global:DDLEvents += [PsCustomObject]@{Message = ""; Line = $Fragment.StartLine; Type = $Fragment.GetType().Name; Fragment = $Fragment}}

    # CreateRuleStatement
    [void] ExplicitVisit([Microsoft.SqlServer.TransactSql.ScriptDom.CreateRuleStatement] $Fragment) {$this.AddVisitorResult($Fragment.StartOffset, $Fragment); $Fragment.AcceptChildren($this); $Global:DDLEvents += [PsCustomObject]@{Message = ""; Line = $Fragment.StartLine; Type = $Fragment.GetType().Name; Fragment = $Fragment}}

    # CreateSchemaStatement
    [void] ExplicitVisit([Microsoft.SqlServer.TransactSql.ScriptDom.CreateSchemaStatement] $Fragment) {$this.AddVisitorResult($Fragment.StartOffset, $Fragment); $Fragment.AcceptChildren($this); $Global:DDLEvents += [PsCustomObject]@{Message = ""; Line = $Fragment.StartLine; Type = $Fragment.GetType().Name; Fragment = $Fragment}}

    # AlterSchemaStatement
    [void] ExplicitVisit([Microsoft.SqlServer.TransactSql.ScriptDom.AlterSchemaStatement] $Fragment) {$this.AddVisitorResult($Fragment.StartOffset, $Fragment); $Fragment.AcceptChildren($this); $Global:DDLEvents += [PsCustomObject]@{Message = ""; Line = $Fragment.StartLine; Type = $Fragment.GetType().Name; Fragment = $Fragment}}

    # CreateSequenceStatement
    [void] ExplicitVisit([Microsoft.SqlServer.TransactSql.ScriptDom.CreateSequenceStatement] $Fragment) {$this.AddVisitorResult($Fragment.StartOffset, $Fragment); $Fragment.AcceptChildren($this); $Global:DDLEvents += [PsCustomObject]@{Message = ""; Line = $Fragment.StartLine; Type = $Fragment.GetType().Name; Fragment = $Fragment}}

    # AlterSequenceStatement
    [void] ExplicitVisit([Microsoft.SqlServer.TransactSql.ScriptDom.AlterSequenceStatement] $Fragment) {$this.AddVisitorResult($Fragment.StartOffset, $Fragment); $Fragment.AcceptChildren($this); $Global:DDLEvents += [PsCustomObject]@{Message = ""; Line = $Fragment.StartLine; Type = $Fragment.GetType().Name; Fragment = $Fragment}}

    # DropSequenceStatement
    [void] ExplicitVisit([Microsoft.SqlServer.TransactSql.ScriptDom.DropSequenceStatement] $Fragment) {$this.AddVisitorResult($Fragment.StartOffset, $Fragment); $Fragment.AcceptChildren($this); $Global:DDLEvents += [PsCustomObject]@{Message = ""; Line = $Fragment.StartLine; Type = $Fragment.GetType().Name; Fragment = $Fragment}}

    # CreateStatisticsStatement
    [void] ExplicitVisit([Microsoft.SqlServer.TransactSql.ScriptDom.CreateStatisticsStatement] $Fragment) {$this.AddVisitorResult($Fragment.StartOffset, $Fragment); $Fragment.AcceptChildren($this); $Global:DDLEvents += [PsCustomObject]@{Message = ""; Line = $Fragment.StartLine; Type = $Fragment.GetType().Name; Fragment = $Fragment}}

    # DropStatisticsStatement
    [void] ExplicitVisit([Microsoft.SqlServer.TransactSql.ScriptDom.DropStatisticsStatement] $Fragment) {$this.AddVisitorResult($Fragment.StartOffset, $Fragment); $Fragment.AcceptChildren($this); $Global:DDLEvents += [PsCustomObject]@{Message = ""; Line = $Fragment.StartLine; Type = $Fragment.GetType().Name; Fragment = $Fragment}}

    # UpdateStatisticsStatement
    [void] ExplicitVisit([Microsoft.SqlServer.TransactSql.ScriptDom.UpdateStatisticsStatement] $Fragment) {$this.AddVisitorResult($Fragment.StartOffset, $Fragment); $Fragment.AcceptChildren($this); $Global:DDLEvents += [PsCustomObject]@{Message = ""; Line = $Fragment.StartLine; Type = $Fragment.GetType().Name; Fragment = $Fragment}}

    # CreateSymmetricKeyStatement
    [void] ExplicitVisit([Microsoft.SqlServer.TransactSql.ScriptDom.CreateSymmetricKeyStatement] $Fragment) {$this.AddVisitorResult($Fragment.StartOffset, $Fragment); $Fragment.AcceptChildren($this); $Global:DDLEvents += [PsCustomObject]@{Message = ""; Line = $Fragment.StartLine; Type = $Fragment.GetType().Name; Fragment = $Fragment}}

    # CreateSynonymStatement
    [void] ExplicitVisit([Microsoft.SqlServer.TransactSql.ScriptDom.CreateSynonymStatement] $Fragment) {$this.AddVisitorResult($Fragment.StartOffset, $Fragment); $Fragment.AcceptChildren($this); $Global:DDLEvents += [PsCustomObject]@{Message = ""; Line = $Fragment.StartLine; Type = $Fragment.GetType().Name; Fragment = $Fragment}}

    # CreateTableStatement
    [void] ExplicitVisit([Microsoft.SqlServer.TransactSql.ScriptDom.CreateTableStatement] $Fragment) {
        $this.AddVisitorResult($Fragment.StartOffset, $Fragment); 
        $Fragment.AcceptChildren($this); 
        # If property $Fragment.SchemaObjectName.BaseIdentifier.Value exists, read it
        $BaseIdentifier = ""
        if ($null -ne $Fragment.SchemaObjectName -and $null -ne $Fragment.SchemaObjectName.BaseIdentifier) {
            $BaseIdentifier = $Fragment.SchemaObjectName.BaseIdentifier.Value
        }
        # if $BaseIdentifier starts with #, it's a temporary object, so ignore it
        if ($BaseIdentifier[0] -ne "#" -and $BaseIdentifier[0] -ne "@") {
            $Global:DDLEvents += [PsCustomObject]@{Message = ""; Line = $Fragment.StartLine; Type = $Fragment.GetType().Name; Fragment = $Fragment}
        }
    }

    # AlterTableStatement
    [void] ExplicitVisit([Microsoft.SqlServer.TransactSql.ScriptDom.AlterTableStatement] $Fragment) {
        $this.AddVisitorResult($Fragment.StartOffset, $Fragment); 
        $Fragment.AcceptChildren($this); 
        # If property $Fragment.SchemaObjectName.BaseIdentifier.Value exists, read it
        $BaseIdentifier = ""
        if ($null -ne $Fragment.SchemaObjectName -and $null -ne $Fragment.SchemaObjectName.BaseIdentifier) {
            $BaseIdentifier = $Fragment.SchemaObjectName.BaseIdentifier.Value
        }
        # if $BaseIdentifier starts with #, it's a temporary object, so ignore it
        if ($BaseIdentifier[0] -ne "#") {
            $Global:DDLEvents += [PsCustomObject]@{Message = ""; Line = $Fragment.StartLine; Type = $Fragment.GetType().Name; Fragment = $Fragment}
        }
    }

    # # CreateTriggerStatement
    # [void] ExplicitVisit([Microsoft.SqlServer.TransactSql.ScriptDom.CreateTriggerStatement] $Fragment) {$this.AddVisitorResult($Fragment.StartOffset, $Fragment); $Fragment.AcceptChildren($this); $Global:DDLEvents += [PsCustomObject]@{Message = ""; Line = $Fragment.StartLine; Type = $Fragment.GetType().Name; Fragment = $Fragment}}

    # AlterTriggerStatement
    [void] ExplicitVisit([Microsoft.SqlServer.TransactSql.ScriptDom.AlterTriggerStatement] $Fragment) {$this.AddVisitorResult($Fragment.StartOffset, $Fragment); $Fragment.AcceptChildren($this); $Global:DDLEvents += [PsCustomObject]@{Message = ""; Line = $Fragment.StartLine; Type = $Fragment.GetType().Name; Fragment = $Fragment}}

    # CreateTypeStatement
    [void] ExplicitVisit([Microsoft.SqlServer.TransactSql.ScriptDom.CreateTypeStatement] $Fragment) {$this.AddVisitorResult($Fragment.StartOffset, $Fragment); $Fragment.AcceptChildren($this); $Global:DDLEvents += [PsCustomObject]@{Message = ""; Line = $Fragment.StartLine; Type = $Fragment.GetType().Name; Fragment = $Fragment}}

    # CreateUserStatement
    [void] ExplicitVisit([Microsoft.SqlServer.TransactSql.ScriptDom.CreateUserStatement] $Fragment) {$this.AddVisitorResult($Fragment.StartOffset, $Fragment); $Fragment.AcceptChildren($this); $Global:DDLEvents += [PsCustomObject]@{Message = ""; Line = $Fragment.StartLine; Type = $Fragment.GetType().Name; Fragment = $Fragment}}

    # AlterUserStatement
    [void] ExplicitVisit([Microsoft.SqlServer.TransactSql.ScriptDom.AlterUserStatement] $Fragment) {$this.AddVisitorResult($Fragment.StartOffset, $Fragment); $Fragment.AcceptChildren($this); $Global:DDLEvents += [PsCustomObject]@{Message = ""; Line = $Fragment.StartLine; Type = $Fragment.GetType().Name; Fragment = $Fragment}}

    # # CreateViewStatement
    # [void] ExplicitVisit([Microsoft.SqlServer.TransactSql.ScriptDom.CreateViewStatement] $Fragment) {$this.AddVisitorResult($Fragment.StartOffset, $Fragment); $Fragment.AcceptChildren($this)}

    # AlterViewStatement
    [void] ExplicitVisit([Microsoft.SqlServer.TransactSql.ScriptDom.AlterViewStatement] $Fragment) {$this.AddVisitorResult($Fragment.StartOffset, $Fragment); $Fragment.AcceptChildren($this); $Global:DDLEvents += [PsCustomObject]@{Message = ""; Line = $Fragment.StartLine; Type = $Fragment.GetType().Name; Fragment = $Fragment}}

    # CreateXmlSchemaCollectionStatement
    [void] ExplicitVisit([Microsoft.SqlServer.TransactSql.ScriptDom.CreateXmlSchemaCollectionStatement] $Fragment) {$this.AddVisitorResult($Fragment.StartOffset, $Fragment); $Fragment.AcceptChildren($this); $Global:DDLEvents += [PsCustomObject]@{Message = ""; Line = $Fragment.StartLine; Type = $Fragment.GetType().Name; Fragment = $Fragment}}

    # AlterXmlSchemaCollectionStatement
    [void] ExplicitVisit([Microsoft.SqlServer.TransactSql.ScriptDom.AlterXmlSchemaCollectionStatement] $Fragment) {$this.AddVisitorResult($Fragment.StartOffset, $Fragment); $Fragment.AcceptChildren($this); $Global:DDLEvents += [PsCustomObject]@{Message = ""; Line = $Fragment.StartLine; Type = $Fragment.GetType().Name; Fragment = $Fragment}}

}

function Add-TSqlCheckResult([string]$Message) {
    # Add the result to the Global variable
    $Global:TSqlCheckResults += [PsCustomObject]@{
        Message = $Message
        Trace = $script:TraceBuffer -join "`n"
    }
}

function Add-ExecVulnerability([Microsoft.SqlServer.TransactSql.ScriptDom.TSqlFragment] $Fragment, [string] $Msg, [string] $VulnerabilityType = "SQL Injection", [bool]$ReportTriggerVuln = $false) {
    # Generate the query text for the scalar expression
    $QueryText = ""
    $QueryText = Get-FragmentText($Fragment)
    $StartLine = $Fragment.StartLine

    # Find position of | on $Msg
    $Pos = $Msg.IndexOf('|')
    if ($Pos -gt 0) {
        $Msg = $Msg.Substring($Pos + 2)
    }

    # if $VulnerabilityType is empty, set it to "SQL Injection"
    if ([string]::IsNullOrEmpty($VulnerabilityType)) {
        $VulnerabilityType = "SQL Injection"
    }

    if ($VulnerabilityType -eq "Trigger permission hijacking") {
        if ($QueryText.Length -gt 50) {
            $QueryTextLimitedTo50char = $QueryText.Substring(0, 50) + "..."
        }
        else {
            $QueryTextLimitedTo50char = $QueryText
        }
        # Remove line breaks from the string literal
        $QueryTextLimitedTo50char = $QueryTextLimitedTo50char -replace "`r`n", " "
        $QueryText = $QueryTextLimitedTo50char    
    }

    $Msg = "Warning - Potential $VulnerabilityType at line $StartLine, Fragment: $QueryText, Comment: " + $Msg
    
    if (($ReportTriggerVuln) -or ($VulnerabilityType -ne "Trigger permission hijacking")) {
        Add-TSqlCheckResult -Message $Msg
        # If vulnerability was already added on $Global:TSqlCheckResults, return
        $AlreadyAdded = $null
        $AlreadyAdded = $Global:TSqlCheckResults | Where-Object { $_.Message -eq $Msg}
        if ($null -ne $AlreadyAdded) {
            return
        }
    }
}

function New-ScriptDomParser {
    # List of parser types to check
    $ParserTypes = @(
        "Microsoft.SqlServer.TransactSql.ScriptDom.TSql80Parser",
        "Microsoft.SqlServer.TransactSql.ScriptDom.TSql90Parser",
        "Microsoft.SqlServer.TransactSql.ScriptDom.TSql100Parser",
        "Microsoft.SqlServer.TransactSql.ScriptDom.TSql110Parser",
        "Microsoft.SqlServer.TransactSql.ScriptDom.TSql120Parser",
        "Microsoft.SqlServer.TransactSql.ScriptDom.TSql130Parser",
        "Microsoft.SqlServer.TransactSql.ScriptDom.TSql140Parser",
        "Microsoft.SqlServer.TransactSql.ScriptDom.TSql150Parser",
        "Microsoft.SqlServer.TransactSql.ScriptDom.TSql160Parser",
        "Microsoft.SqlServer.TransactSql.ScriptDom.TSql170Parser",
        "Microsoft.SqlServer.TransactSql.ScriptDom.TSql180Parser"
    )

    $AvailableParsers = @()

    $i = 0
    foreach ($ParserType in $ParserTypes) {
        $i++
        try {
            # Attempt to instantiate the parser
            $Parser = [Activator]::CreateInstance([type]$ParserType, $true, [Microsoft.SqlServer.TransactSql.ScriptDom.SqlEngineType]::All)
            if ($null -ne $Parser) {
                $AvailableParsers += [PsCustomObject]@{
                    i = $i
                    ParserType = $ParserType
                }
            }
        } catch {
            # Log the error for unavailable parsers
        }
    }
    # Get the most recent parser available - use Max for better performance
    $MostRecentParserAvailable = if ($AvailableParsers.Count -gt 0) { $AvailableParsers | Where-Object { $_.i -eq ($AvailableParsers.i | Measure-Object -Maximum).Maximum } | Select-Object -First 1 } else { $null }
    if ($null -eq $MostRecentParserAvailable) {
        throw "No parsers available"
        return $null
    }

    # Create a parser object
    $Parser = [Activator]::CreateInstance([type]$MostRecentParserAvailable.ParserType, $true, [Microsoft.SqlServer.TransactSql.ScriptDom.SqlEngineType]::All)

    # Return the parser object
    return $Parser
}

function New-ScriptDomGenerator {
    # List of generators types to check
    $GeneratorTypes = @(
        "Microsoft.SqlServer.TransactSql.ScriptDom.Sql80ScriptGenerator",
        "Microsoft.SqlServer.TransactSql.ScriptDom.Sql90ScriptGenerator",
        "Microsoft.SqlServer.TransactSql.ScriptDom.Sql100ScriptGenerator",
        "Microsoft.SqlServer.TransactSql.ScriptDom.Sql110ScriptGenerator",
        "Microsoft.SqlServer.TransactSql.ScriptDom.Sql120ScriptGenerator",
        "Microsoft.SqlServer.TransactSql.ScriptDom.Sql130ScriptGenerator",
        "Microsoft.SqlServer.TransactSql.ScriptDom.Sql140ScriptGenerator",
        "Microsoft.SqlServer.TransactSql.ScriptDom.Sql150ScriptGenerator",
        "Microsoft.SqlServer.TransactSql.ScriptDom.Sql160ScriptGenerator",
        "Microsoft.SqlServer.TransactSql.ScriptDom.Sql170ScriptGenerator",
        "Microsoft.SqlServer.TransactSql.ScriptDom.Sql180ScriptGenerator"
    )

    $AvailableGenerators = @()

    $i = 0
    foreach ($GeneratorType in $GeneratorTypes) {
        $i++
        try {
            # Attempt to instantiate the parser
            $Generator = [Activator]::CreateInstance([type]$GeneratorType)
            if ($null -ne $Generator) {
                $AvailableGenerators += [PsCustomObject]@{
                    i = $i
                    GeneratorType = $GeneratorType
                }
            }
        } catch {
            # Log the error for unavailable generators
        }
    }
    # Get the most recent generator available - use Max for better performance
    $MostRecentGeneratorAvailable = if ($AvailableGenerators.Count -gt 0) { $AvailableGenerators | Where-Object { $_.i -eq ($AvailableGenerators.i | Measure-Object -Maximum).Maximum } | Select-Object -First 1 } else { $null }

    if ($null -eq $MostRecentGeneratorAvailable) {
        throw "No generators available"
        return $null
    }

    # Create a generator object
    $Generator = [Activator]::CreateInstance([type]$MostRecentGeneratorAvailable.GeneratorType)

    # Return the generator object
    return $Generator
}

function Get-FragmentText($Fragment){
    if ($null -eq $Global:ScriptGenerator){
        # Create a Global ScriptGenerator to be reused later in the script
        $Global:ScriptGenerator = New-ScriptDomGenerator
    }
    
    $text = ''
    $Global:ScriptGenerator.GenerateScript($Fragment, [ref]$text)
    return $text
}

function Find-PotentialPasswordsInTSQL {
    <#
        .SYNOPSIS
            Hunt for clear-text passwords or other secrets in a T-SQL batch.

        .DESCRIPTION
            • Requires Microsoft.SqlServer.TransactSql.ScriptDom on the machine.  
            • Scans two things only: string literals and comments.  
                (No “regex-only fallback” code remains.)  
            • A hit is reported when a fragment matches at least one pattern
              **and** the captured secret is ≥ $MinPasswordLength characters.
    #>
    [CmdletBinding()]
    param (
        [Microsoft.SqlServer.TransactSql.ScriptDom.TSqlFragment] $Fragment,
        [switch] $Mask          # replace the secret with *** in the report
    )

    # ---------- 1.  Read tokens and string literals ---------------------------
    $tokenStream = $Fragment.ScriptTokenStream
    $StringLiterals = Get-VisitStringLiteral -Fragment $Fragment
    $StringLiterals = $StringLiterals.Values | Sort-Object StartOffset

    # ---------- 2.  Build the pattern bank (named group <pw>) ------------------
    $rx = @(
        # Connection strings inside literals ( …;Password=secret; … )
        "(?i)\b(?:Password|Pwd)\s*=\s*(?<pw>[^;''`" ]{4,})",
        # Anything that *looks* like "password = 'secret'" inside a comment
        "(?i)\b(?:password|pwd|pwdhash|passphrase|token|secret|authkey)\b\s*=\s*`"?(?<pw>[^\s*''`" ]{4,})`"?",
        # Words like password:, pwd:, token: inside strings
        '(?i)\b(password|pwd|pwdhash|passphrase|token|secret|authkey)\b'
        # IDENTIFIED BY 'secret'
        "(?i)\bIDENTIFIED\s+BY\s+(`"|\')(?<pw>[^`"`"'']{4,})\1",
        # sp_addlogin … , 'secret'
        "(?i)\bsp_addlogin\b[^\r\n]*'',\s*''(?<pw>[^''\r\n]{4,})''",
        # Command-line password (like in xp_cmdshell)
        "(?i)-P\s+(?<pw>[^\s`"'';]{4,})",
        # Very simple heuristic: a longish alphanum/special string in quotes
        "'(?i)^(?=.*[0-9])(?=.*[@#$%^&+=])(?<pw>[a-z0-9@#$%^&+=]{8,})$'"

    ) | ForEach-Object { [regex]::new($_, 'Compiled') }

    # ---------- 3.  Scan string literals ---------------------------------------
    $hits = [System.Collections.Generic.List[object]]::new()
    foreach ($lit in $StringLiterals) {
        # Skip checking if string literal exceeds maximum length to improve performance
        if ($lit.Value.Length -gt $Global:MaximumStringLength) {
            continue
        }
        foreach ($r in $rx) {
            $m = $r.Match($lit.Value)
            if (-not $m.Success) { continue }

            $secret = $m.Groups['pw'].Value
            if ($secret.Length -lt $MinPasswordLength) { continue }

            if ($Mask) { $secret = '*' * $secret.Length }
            $hits.Add([pscustomobject]@{
                Fragment   = $lit.Value
                Secret     = $secret
                StartLine  = $lit.StartLine
                InFragment = 'StringLiteral'
                Pattern    = $r.ToString()
            })
        }
    }

    # ---------- 4.  Scan comments (cache filtered comments to avoid re-evaluation) ----
    $commentTokens = @($tokenStream | Where-Object { $_.TokenType -match 'Comment' })
    foreach ($tok in $commentTokens) {
        foreach ($r in $rx) {
            foreach ($m in $r.Matches($tok.Text)) {
                $secret = $m.Groups['pw'].Value

                if ($Mask) { $secret = '*' * $secret.Length }
                $hits.Add([pscustomobject]@{
                    Fragment   = $tok.Text
                    Secret     = $secret
                    StartLine  = $lit.StartLine
                    InFragment = 'Comment'
                    Pattern    = $r.ToString()
                })
            }
        }
    }

    return $hits
}
function Get-CleanUpAndParseTSqlText([string]$InputText) {
    function Remove-InternalOpenRowSetTable {
        [CmdletBinding()]
        param(
            [Parameter(Mandatory)]
            [string] $TsqlText,

            [switch] $PreserveLineCount
        )

        # Quick exit if nothing to do
        $reOpenTbl = '(?i)\bOPENROWSET\s*\(\s*TABLE\b'
        if ($TsqlText -notmatch $reOpenTbl) { return $TsqlText }

        $text = $TsqlText

        # ---------------------------------------------------------
        # PASS A: CROSS/OUTER APPLY alias-preserving replacement
        #   ... APPLY OPENROWSET(TABLE ...) [AS] Alias
        # → ... APPLY (VALUES(0)) AS Alias(Col1)
        # ---------------------------------------------------------
        $text = [regex]::Replace(
            $text,
            '(?is)\b(?<kind>CROSS|OUTER)\s+APPLY\s+OPENROWSET\s*\(\s*TABLE\b.*?\)\s+(?:AS\s+)?(?<alias>[A-Za-z_][A-Za-z0-9_]*)',
            { param($m)
                $alias = $m.Groups['alias'].Value
                $kind  = $m.Groups['kind'].Value
                $repl  = "$kind APPLY (VALUES(0)) AS $alias(Col1)"
                if ($PreserveLineCount) {
                    $nl = (($m.Value) -split "`r?`n").Count - 1
                    $repl += ("`n" * [math]::Max(0,$nl))
                }
                $repl
            }
        )

        if ($text -notmatch $reOpenTbl) { return $text }

        # ---------------------------------------------------------
        # PASS B: FROM/JOIN alias-preserving replacement
        #   FROM|JOIN OPENROWSET(TABLE ...) [AS] Alias
        # → FROM|JOIN (VALUES(0)) AS Alias(Col1)
        # ---------------------------------------------------------
        $text = [regex]::Replace(
            $text,
            '(?is)\b(?<kw>FROM|JOIN)\s+OPENROWSET\s*\(\s*TABLE\b.*?\)\s+(?:AS\s+)?(?<alias>[A-Za-z_][A-Za-z0-9_]*)',
            { param($m)
                $alias = $m.Groups['alias'].Value
                $kw    = $m.Groups['kw'].Value
                $repl  = "$kw (VALUES(0)) AS $alias(Col1)"
                if ($PreserveLineCount) {
                    $nl = (($m.Value) -split "`r?`n").Count - 1
                    $repl += ("`n" * [math]::Max(0,$nl))
                }
                $repl
            }
        )

        if ($text -notmatch $reOpenTbl) { return $text }

        # -----------------------------------------
        # PASS 1: scalar subqueries like:
        # (SELECT 1 FROM OPENROWSET(TABLE ...) WHERE ...)
        # -----------------------------------------
        $text = [regex]::Replace(
            $text,
            '(?is)\(\s*SELECT\s+1\s+FROM\s+OPENROWSET\s*\(\s*TABLE\b.*?\)\s*WHERE\b.*?\)',
            { param($m)
                if ($PreserveLineCount) {
                    $nl = (($m.Value) -split "`r?`n").Count - 1
                    return "(SELECT 1 WHERE 1=0)" + ("`n" * [math]::Max(0,$nl))
                } else {
                    return "(SELECT 1 WHERE 1=0)"
                }
            }
        )

        if ($text -notmatch $reOpenTbl) { return $text }

        # -----------------------------------------
        # PASS 2: whole-statement "SELECT * FROM OPENROWSET(TABLE …)"
        # -----------------------------------------
        $text = [regex]::Replace(
            $text,
            '(?is)(^\s*SELECT\s+\*\s+FROM\s+)OPENROWSET\s*\(\s*TABLE\b.*?\)',
            { param($m) $m.Groups[1].Value + "(VALUES(0)) AS Dummy(Col1)" }
        )

        if ($text -notmatch $reOpenTbl) { return $text }

        # -----------------------------------------
        # PASS 3: token-level scanner for any remaining OPENROWSET(TABLE …)
        # (keeps your original logic, used only when alias-aware passes didn’t trigger)
        # -----------------------------------------

        function Get-MatchingParenIndex([string]$s, [int]$start) {
            $s = $s.replace('db_id ()', 'db_id   ').replace('db_id()', 'db_id  ')
            $len = $s.Length
            $depth = 0
            $i = $start
            $inSq = $false
            $inStr = $false
            while ($i -lt $len) {
                $ch = $s[$i]
                if ($inStr) {
                    if ($ch -eq "'") {
                        if ($i+1 -lt $len -and $s[$i+1] -eq "'") { $i += 2; continue }
                        $inStr = $false; $i++; continue
                    }
                    $i++; continue
                }
                if ($inSq) { if ($ch -eq ']') { $inSq = $false }; $i++; continue }

                switch ($ch) {
                    "'" { $inStr = $true; $i++; continue }
                    "[" { $inSq  = $true; $i++; continue }
                    "(" { $depth++; $i++; continue }
                    ")" { $depth--; if ($depth -eq 0) { return $i }; $i++; continue }
                    "/" {
                        if ($i+1 -lt $len -and $s[$i+1] -eq "*") {
                            $i += 2
                            while ($i+1 -lt $len -and -not ($s[$i] -eq "*" -and $s[$i+1] -eq "/")) { $i++ }
                            if ($i+1 -lt $len) { $i += 2 }
                            continue
                        }
                    }
                    "-" {
                        if ($i+1 -lt $len -and $s[$i+1] -eq "-") {
                            while ($i -lt $len -and $s[$i] -notin "`r", "`n") { $i++ }
                            continue
                        }
                    }
                }
                $i++
            }
            return -1
        }

        $sb = [System.Text.StringBuilder]::new()
        $i = 0
        $s = $text
        $len = $s.Length

        while ($i -lt $len) {
            $idx = [cultureinfo]::InvariantCulture.CompareInfo.IndexOf($s, 'OPENROWSET', $i, [System.Globalization.CompareOptions]::IgnoreCase)
            if ($idx -lt 0) { $null = $sb.Append($s.Substring($i)); break }

            if ($idx -gt $i) { $null = $sb.Append($s.Substring($i, $idx - $i)) }

            $j = $idx + 10
            while ($j -lt $len -and [char]::IsWhiteSpace($s[$j])) { $j++ }
            if ($j -ge $len -or $s[$j] -ne '(') {
                $null = $sb.Append($s.Substring($idx, [Math]::Min(11, $len - $idx)))
                $i = $idx + 11
                continue
            }

            $k = $j + 1
            while ($k -lt $len -and [char]::IsWhiteSpace($s[$k])) { $k++ }
            $isTableCall = $false
            if ($k + 4 -le $len) {
                $tok = $s.Substring($k, [Math]::Min(5, $len - $k))
                if ([string]::Compare($tok, 'TABLE', $true) -eq 0) { $isTableCall = $true }
            }

            if (-not $isTableCall) {
                $null = $sb.Append($s.Substring($idx, 10))
                $i = $idx + 10
                continue
            }

            $close = Get-MatchingParenIndex $s $j
            if ($close -lt 0) { $null = $sb.Append($s.Substring($idx)); break }

            $span = $s.Substring($idx, ($close - $idx + 1))
            $replacement = "(VALUES(0)) AS Dummy(Col1)"
            if ($PreserveLineCount) {
                $nl = ($span -split "`r?`n").Count - 1
                $replacement += ("`n" * [math]::Max(0,$nl))
            }
            $null = $sb.Append($replacement)
            $i = $close + 1
        }

        $final = $sb.ToString()
        $final
    }

    function Remove-InternalExecPctPct {
        param(
            [string] $TsqlText,
            [switch] $PreserveLineCount
        )

        if ($TsqlText -notmatch '(?i)\bEXEC\s+%%') {
            # If $TsqlText does not contain any EXEC %% return it as is
            return $TsqlText
        }

        $sb          = [System.Text.StringBuilder]::new()
        $insideExec  = $false
        $parenDepth  = 0

        foreach ($line in $TsqlText -split "`r?`n") {

            if (-not $insideExec) {

                if ($line -match '^[\p{Zs}\t]*EXEC[\p{Zs}\t]+%%') {
                    # ─── EXEC %% statement begins ───
                    $insideExec = $true
                    # Count opening / closing parentheses on the same line
                    $open  = ([regex]::Matches($line, '\(')).Count
                    $close = ([regex]::Matches($line, '\)')).Count
                    $parenDepth = $open - $close

                    if ($PreserveLineCount) {
                        $sb.AppendLine("PRINT '-- EXEC %% skipped --';") > $null
                    }

                    # If the whole call fit on one line (balanced) leave skip mode immediately
                    if ($parenDepth -le 0) { $insideExec = $false }
                }
                else {
                    $sb.AppendLine($line) > $null
                }

            } else {
                # ─── we are inside an EXEC %% (…) block ───
                $open  = ([regex]::Matches($line, '\(')).Count
                $close = ([regex]::Matches($line, '\)')).Count
                $parenDepth += ($open - $close)

                if ($PreserveLineCount) {
                    # keep the line structure intact (blank line)
                    $sb.AppendLine('') > $null
                }

                if ($parenDepth -le 0) {     # balanced → statement finished
                    $insideExec = $false
                }
            }
        }

        return $sb.ToString()
    }
        
    function Remove-ParameterDeclaration {
        param([string] $InputText)

        # Regex to match optional whitespace followed by a parenthesized parameter list at the beginning
        $regex = '^\s*\(\s*(@[\w]+\s+\w+(?:\([^\)]*\))?(?:\s+OUTPUT)?\s*,?\s*)+\)\s*'

        if ($InputText -match $regex) {
            $InputText = $InputText -replace $regex, ''
        }

        return $InputText.TrimStart()
    }    

    # If text is coming from a XML using comment pattern, we need to do some
    # clean up to remove the XML comment tags
    if ($InputText.StartsWith("<?query") -and $InputText.EndsWith("?>")) {
        # Remove the first and the last lines from the text
        $InputText = $InputText.Substring($InputText.IndexOf([Environment]::NewLine) + 1)
        $InputText = $InputText.Substring(0, $InputText.LastIndexOf([Environment]::NewLine))
        $InputText = $InputText.TrimStart()
        $InputText = $InputText.TrimEnd()
    }

    # If text is coming from a parameterized query from QueryStore, we need to do some
    # clean up to remove the parameter values
    # Remove the parameter declaration from the input text
    $InputText = Remove-ParameterDeclaration -InputText $InputText
    $InputText = $InputText.TrimEnd([Environment]::NewLine.ToCharArray())
    $InputText = $InputText.Trim()
    $InputText = $InputText.TrimStart()

    # Adjust the OPENROWSET(TABLE…) from the text
    $InputText = Remove-InternalOpenRowSetTable -TsqlText $InputText -PreserveLineCount

    # Adjust the EXEC %% statement and OPENROWSET(TABLE…) from the text
    $InputText = Remove-InternalExecPctPct -TsqlText $InputText -PreserveLineCount
    
    # Create a TSqlParser
    $Parser = New-ScriptDomParser
    $Errors = New-Object System.Collections.Generic.List[Microsoft.SqlServer.TransactSql.ScriptDom.ParseError]
    $Tree = $Parser.Parse((New-Object System.IO.StringReader($InputText)), [ref]$Errors)

    # If it failed to parse, check if it is a valid TSQL statement
    if ($Errors.Count -gt 0) {
        # If text is coming from query store, check IF EXISTS pattern
        if ($InputText.StartsWith("IF ")) {
            # If error is "Unexpected end of file occurred", try to parse the text again
            # by adding a dummy "END" statement at the end of the text
            # adding a "SELECT 1" statement at the end of the text
            # to avoid parsing errors
            if ($Errors[0].Message -like "*Unexpected end of file occurred*") {
                $InputText = $InputText + [Environment]::NewLine + "SELECT 1;"
                $Parser = New-ScriptDomParser
                $Errors = New-Object System.Collections.Generic.List[Microsoft.SqlServer.TransactSql.ScriptDom.ParseError]
                $Tree = $Parser.Parse((New-Object System.IO.StringReader($InputText)), [ref]$Errors)
            }
        }
    }
    $Result = [PsCustomObject]@{
        InputText = $InputText
        Tree = $Tree
        Errors = $Errors
    }

    return $Result
}

function Test-IsFirstTimeSeen ([Microsoft.SqlServer.TransactSql.ScriptDom.VariableReference] $VarRef){
    # unique key:  VariableName|Line|Column
    $key = "{0}|{1}|{2}" -f $VarRef.Name,
                            $VarRef.StartLine,
                            $VarRef.StartColumn
    if ($Global:VisitedVarRef.ContainsKey($key)) {
        return $false              # we have analysed it already
    }

    $Global:VisitedVarRef[$key] = $true
    return $true                   # first time → go ahead
}

function Remove-VisitedFrag ([Microsoft.SqlServer.TransactSql.ScriptDom.VariableReference] $VarRef){
    # unique key:  VariableName|Line|Column
    $key = "{0}|{1}|{2}" -f $VarRef.Name,
                            $VarRef.StartLine,
                            $VarRef.StartColumn

    $Global:VisitedVarRef.Remove($key) # we have analysed it already
}

function Get-LastVariableAssignment {
    param (
        [string]$VarName,
        [System.Collections.Hashtable]$vResults,
        [Microsoft.SqlServer.TransactSql.ScriptDom.TSqlFragment]$ExecExpression,
        [bool]$SkipLastAssignment = $false
    )
    $LastAssignment = $null

    # Cache vResults.Values to avoid repeated enumeration
    $vResultsValues = @($vResults.Values)

    # Check execute statement with variable assignments via output parameters
    $ExecStatements = @()
    $ExecStatementsTmp = $vResultsValues | Where-Object { $_ -is [Microsoft.SqlServer.TransactSql.ScriptDom.ExecuteStatement] -and $_.FirstTokenIndex -lt $ExecExpression.FirstTokenIndex -and $_.ExecuteSpecification.ExecutableEntity.Parameters.ParameterValue.Name -eq $VarName }
    foreach ($exec in $ExecStatementsTmp) {
        $paramValues = $exec.ExecuteSpecification.ExecutableEntity.Parameters | Where-Object { $_.ParameterValue.Name -eq $VarName }
        foreach ($paramValue in $paramValues) {
            if ($paramValue.IsOutput -eq $true) {
                $ExecStatements += $exec
            }
        }
    }
    $ExecStatements = if ($ExecStatements.Count -gt 0) { $ExecStatements | Sort-Object StartOffset -Descending | Select-Object -First 1 } else { $null }

    # Check variable declare to see if is was assigned with a safe default expression
    $VarDecls = $vResultsValues | Where-Object { $_ -is [Microsoft.SqlServer.TransactSql.ScriptDom.DeclareVariableStatement] }
    $VarDecls = $VarDecls.Declarations | Where-Object { $_.VariableName.Value -eq $VarName -and $_.FirstTokenIndex -lt $ExecExpression.FirstTokenIndex } | Sort-Object StartOffset -Descending | Select-Object -First 1

    # Check all select set variable statements to see if the variable is safe (combine filters for performance)
    $SelectSetVars = $vResultsValues | Where-Object { $_ -is [Microsoft.SqlServer.TransactSql.ScriptDom.SelectSetVariable] -and $_.Variable.Name -eq $VarName -and $_.FirstTokenIndex -lt $ExecExpression.FirstTokenIndex -and -Not($ExecExpression.FirstTokenIndex -gt $_.Expression.FirstTokenIndex -and $ExecExpression.FirstTokenIndex -lt $_.Expression.LastTokenIndex) } | Sort-Object StartOffset -Descending | Select-Object -First 1

    # Check all set variable statements to see if the variable is safe (combine filters for performance)
    $SetVars = $vResultsValues | Where-Object { $_ -is [Microsoft.SqlServer.TransactSql.ScriptDom.SetVariableStatement] -and $_.Variable.Name -eq $VarName -and $_.FirstTokenIndex -lt $ExecExpression.FirstTokenIndex -and -Not($ExecExpression.FirstTokenIndex -gt $_.Expression.FirstTokenIndex -and $ExecExpression.FirstTokenIndex -lt $_.Expression.LastTokenIndex) } | Sort-Object StartOffset -Descending | Select-Object -First 1

    # Check all assignment set clauses to see if the variable is safe (combine filters for performance)
    $AssignmentSetClauses = $vResultsValues | Where-Object { $_ -is [Microsoft.SqlServer.TransactSql.ScriptDom.AssignmentSetClause] -and $_.FirstTokenIndex -lt $ExecExpression.FirstTokenIndex -and $_.Variable.Name -eq $VarName } | Sort-Object StartOffset -Descending | Select-Object -First 1

    # Check all cursor fetch assignments to see if the variable is safe
    $CursorFetchAssignments = $vResultsValues | Where-Object { $_ -is [Microsoft.SqlServer.TransactSql.ScriptDom.FetchCursorStatement] -and $_.FirstTokenIndex -lt $ExecExpression.FirstTokenIndex -and $_.IntoVariables.Name -eq $VarName } | Sort-Object StartOffset -Descending | Select-Object -First 1
    
    # Assignment could be in a DeclareVariableStatement, SetVariableStatement, SelectSetVariable, AssignmentSetClause or FetchCursorStatement
    # Identify what is the last assignment for the variable and check if it is safe
    $LastAssignment = @($VarDecls, $SelectSetVars, $SetVars, $AssignmentSetClauses, $CursorFetchAssignments, $ExecStatements)

    # Removing empty values from $LastAssignment
    $NewLastAssignment = @()
    foreach ($assignment in $LastAssignment) {
        if ($assignment){
            $NewLastAssignment += $assignment
        }
    }

    if ($SkipLastAssignment){
        # Skip the last assignment found
        $NewLastAssignment = $NewLastAssignment | Sort-Object StartOffset -Descending | Select-Object -Skip 1
    }
    $NewLastAssignment = $NewLastAssignment | Sort-Object StartOffset -Descending | Select-Object -First 1

    return $NewLastAssignment
}

function Get-VarDataType ([string] $VarRef, [object] $vResults) {
    $VarDecls = $vResults.Values | Where-Object { $_ -is [Microsoft.SqlServer.TransactSql.ScriptDom.DeclareVariableStatement] }
    $VarDecls = $VarDecls.Declarations | Where-Object { $_.VariableName.Value -eq $VarRef } | Sort-Object StartOffset -Descending | Select-Object -First 1
    if ($null -eq $VarDecls) {
        $VarDecls = $vResults.Values | Where-Object { $_ -is [Microsoft.SqlServer.TransactSql.ScriptDom.ProcedureParameter] }
        $VarDecls = $VarDecls | Where-Object { $_.VariableName.Value -eq $VarRef } | Sort-Object StartOffset -Descending | Select-Object -First 1
    }
    return $VarDecls.DataType
}

function Get-DataTypeCharacterSize([object] $VarDecls) {
    $VarSize = 0
    $StringDataTypes = @("NVARCHAR", "VARCHAR", "CHAR", "NCHAR", "TEXT", "NTEXT", "XML")
    $UserDataTypeName = $VarDecls.DataType.Name.BaseIdentifier.Value.ToUpperInvariant()
    if ($UserDataTypeName -eq "SYSNAME"){
        # sysname is a special case, it is a nvarchar(128)
        $VarSize = 128
    }
    elseif($StringDataTypes -contains $UserDataTypeName) {
        if ($VarDecls.DataType.Parameters.Count -gt 0) {
            $rawSize = $VarDecls.DataType.Parameters[0].Value
            if ($rawSize -eq "MAX") {
                $VarSize = 2147483647
            } elseif ([int]::TryParse($rawSize, [ref]$null)) {
                $VarSize = [int]$rawSize
            } else {
                $VarSize = 1
            }
        }
        else {
            $VarSize = 1
        }
    }    
    elseif ($UserDataTypeName -eq "BIGINT") {
        # BigInt types are 8 bytes
        $MaxValueOfBigInt = [long]::MaxValue # 9223372036854775807
        $VarSize = $MaxValueOfBigInt.ToString().Length
    }
    elseif($UserDataTypeName -eq "INTEGER" -or $UserDataTypeName -eq "INT") {
        $MaxValueOfInt = [int]::MaxValue # 2147483647
        $VarSize = $MaxValueOfInt.ToString().Length
    }
    elseif($UserDataTypeName -eq "SMALLINT") {
        # SmallInt types are 2 bytes
        $MaxValueOfSmallInt = 32767
        $VarSize = $MaxValueOfSmallInt.ToString().Length
    }
    elseif($UserDataTypeName -eq "TINYINT") {
        # TinyInt types are 1 byte
        $MaxValueOfTinyInt = [byte]::MaxValue # 255
        $VarSize = $MaxValueOfTinyInt.ToString().Length
    }
    elseif ($UserDataTypeName -eq "MONEY") {
        $VarSize = "922337203685477.5807".Length
    }
    elseif ($UserDataTypeName -eq "SMALLMONEY") {
        $VarSize = "214748.3647".Length
    }
    elseif($UserDataTypeName -eq "FLOAT") {
        # Float types are 8 bytes
        $MaxValueOfFloat = [double]::MaxValue # 1.79769313486232E+308
        $VarSize = $MaxValueOfFloat.ToString().Length
    }
    elseif ($UserDataTypeName -eq "DATETIME") {
        $VarSize = "9999-12-31 23:59:59.997".Length
    }
    elseif ($UserDataTypeName -eq "SMALLDATETIME") {
        $VarSize = "2079-06-06 23:59:00".Length
    }
    elseif ($UserDataTypeName -eq "DATE") {
        $VarSize = "9999-12-31".Length
    }
    elseif ($UserDataTypeName -eq "TIME") {
        $VarSize = "23:59:59.9999999".Length
    }
    elseif ($UserDataTypeName -eq "UNIQUEIDENTIFIER") {
        $VarSize = 36
    }
    else{
        # Assuming 1 character for all other data types or if the size is not specified
        $VarSize = 1
    }
    return $VarSize
}

# function Get-FindLastAssignmentAndValidadeBufferSize([string] $VarName, [object] $vResults){
#     # Check if the variable is declared
#     $VarDecls = $vResults.Values | Where-Object { $_ -is [Microsoft.SqlServer.TransactSql.ScriptDom.DeclareVariableStatement] }
#     $VarDecls = $VarDecls.Declarations | Where-Object { $_.VariableName.Value -eq $VarName } | Sort-Object StartOffset -Descending | Select-Object -First 1

#     # Check if the variable is declared in a procedure parameter
#     if ($null -eq $VarDecls) {
#         $VarDecls = $vResults.Values | Where-Object { $_ -is [Microsoft.SqlServer.TransactSql.ScriptDom.ProcedureParameter] }
#         $VarDecls = $VarDecls | Where-Object { $_.VariableName.Value -eq $VarName } | Sort-Object StartOffset -Descending | Select-Object -First 1
#     }

#     # Get the last assignment for the variable and check if it is safe
#     $LastAssignment = Get-LastVariableAssignment -VarName $VarName -vResults $vResults

#     # Get the data type of the variable
#     $DataType = Get-VarDataType -VarRef $VarName -vResults $vResults

#     # Get the size of the data type
#     $DataTypeSize = Get-DataTypeCharacterSize -VarDecls $DataType

#     return @($LastAssignment, $DataTypeSize)
# }

function Get-VisitSearchedCaseExpression([Microsoft.SqlServer.TransactSql.ScriptDom.TSqlFragment] $Fragment){
    class VisitFragment : Microsoft.SqlServer.TransactSql.ScriptDom.TSqlFragmentVisitor {
        $AllFragments = @{}
        [System.Collections.Hashtable] GetAllFragments() {
            return $this.AllFragments
        }
        [void] ExplicitVisit([Microsoft.SqlServer.TransactSql.ScriptDom.SearchedWhenClause] $Fragment) {
            # If QuerySpecification is a inner specification, ignore it, as I'm only interested in the outer one
            $ParentAlreadyExists = if ($this.AllFragments.Values | Where-Object { $_.FirstTokenIndex -lt $Fragment.FirstTokenIndex -and $_.LastTokenIndex -gt $Fragment.LastTokenIndex }){$true}else{$false}
            $WhenExpression = $Fragment.WhenExpression

            # Only add the fragment if parent is not already in the hashtable
            if ($ParentAlreadyExists -eq $false) {
                $FragmentID = "$($WhenExpression.GetType().Name)-$($WhenExpression.StartOffset)-$($WhenExpression.FragmentLength)"
                if (-not $this.AllFragments.ContainsKey($FragmentID)) {
                    $this.AllFragments[$FragmentID] = $WhenExpression
                }
            }
            $Fragment.AcceptChildren($this)
        }
    }
    $AllFragments = $null
    $printer = [VisitFragment]::new()
    $Fragment.Accept($printer)
    $AllFragments = $printer.GetAllFragments()
    return $AllFragments
}
function Get-VisitQuerySpecification([Microsoft.SqlServer.TransactSql.ScriptDom.TSqlFragment] $Fragment){
    class VisitFragment : Microsoft.SqlServer.TransactSql.ScriptDom.TSqlFragmentVisitor {
        $AllFragments = @{}
        [System.Collections.Hashtable] GetAllFragments() {
            return $this.AllFragments
        }
        [void] ExplicitVisit([Microsoft.SqlServer.TransactSql.ScriptDom.QuerySpecification] $Fragment) {
            # If QuerySpecification is a inner specification, ignore it, as I'm only interested in the outer one
            $ParentAlreadyExists = if ($this.AllFragments.Values | Where-Object { $_.FirstTokenIndex -lt $Fragment.FirstTokenIndex -and $_.LastTokenIndex -gt $Fragment.LastTokenIndex }){$true}else{$false}

            # Only add the fragment if parent is not already in the hashtable
            if ($ParentAlreadyExists -eq $false) {
                $FragmentID = "$($Fragment.GetType().Name)-$($Fragment.StartOffset)-$($Fragment.FragmentLength)"
                if (-not $this.AllFragments.ContainsKey($FragmentID)) {
                    $this.AllFragments[$FragmentID] = $Fragment
                }
            }
            $Fragment.AcceptChildren($this)
        }
    }
    $AllFragments = $null
    $printer = [VisitFragment]::new()
    $Fragment.Accept($printer)
    $AllFragments = $printer.GetAllFragments()
    return $AllFragments
}

function Get-VisitVariableReference([Microsoft.SqlServer.TransactSql.ScriptDom.TSqlFragment] $Fragment){
    class VisitFragment : Microsoft.SqlServer.TransactSql.ScriptDom.TSqlFragmentVisitor {
        $AllFragments = @{}
        [System.Collections.Hashtable] GetAllFragments() {
            return $this.AllFragments
        }
        [void] ExplicitVisit([Microsoft.SqlServer.TransactSql.ScriptDom.VariableReference] $Fragment) {
            $ParentAlreadyExists = if ($this.AllFragments.Values | Where-Object { $_.FirstTokenIndex -lt $Fragment.FirstTokenIndex -and $_.LastTokenIndex -gt $Fragment.LastTokenIndex }){$true}else{$false}
            # Only add the fragment if parent is not already in the hashtable
            if ($ParentAlreadyExists -eq $false) {
                $FragmentID = "$($Fragment.GetType().Name)-$($Fragment.StartOffset)-$($Fragment.FragmentLength)"
                if (-not $this.AllFragments.ContainsKey($FragmentID)) {
                    $this.AllFragments[$FragmentID] = $Fragment
                }
            }
            $Fragment.AcceptChildren($this)
        }
    }
    $AllFragments = $null
    $printer = [VisitFragment]::new()
    $Fragment.Accept($printer)
    $AllFragments = $printer.GetAllFragments()
    return $AllFragments
}

function Get-VisitColumnReferenceExpression([Microsoft.SqlServer.TransactSql.ScriptDom.TSqlFragment] $Fragment){
    class VisitFragment : Microsoft.SqlServer.TransactSql.ScriptDom.TSqlFragmentVisitor {
        $AllFragments = @{}
        [System.Collections.Hashtable] GetAllFragments() {
            return $this.AllFragments
        }
        [void] ExplicitVisit([Microsoft.SqlServer.TransactSql.ScriptDom.ColumnReferenceExpression] $Fragment) {
            $ParentAlreadyExists = if ($this.AllFragments.Values | Where-Object { $_.FirstTokenIndex -lt $Fragment.FirstTokenIndex -and $_.LastTokenIndex -gt $Fragment.LastTokenIndex }){$true}else{$false}
            # Only add the fragment if parent is not already in the hashtable
            if ($ParentAlreadyExists -eq $false) {
                $FragmentID = "$($Fragment.GetType().Name)-$($Fragment.StartOffset)-$($Fragment.FragmentLength)"
                if (-not $this.AllFragments.ContainsKey($FragmentID)) {
                    $this.AllFragments[$FragmentID] = $Fragment
                }
            }
            $Fragment.AcceptChildren($this)
        }
    }
    $AllFragments = $null
    $printer = [VisitFragment]::new()
    $Fragment.Accept($printer)
    $AllFragments = $printer.GetAllFragments()
    return $AllFragments
}

function Get-VisitStringLiteral([Microsoft.SqlServer.TransactSql.ScriptDom.TSqlFragment] $Fragment){
    class VisitFragment : Microsoft.SqlServer.TransactSql.ScriptDom.TSqlFragmentVisitor {
        $AllFragments = @{}
        [System.Collections.Hashtable] GetAllFragments() {
            return $this.AllFragments
        }
        [void] ExplicitVisit([Microsoft.SqlServer.TransactSql.ScriptDom.StringLiteral] $Fragment) {
            $ParentAlreadyExists = if ($this.AllFragments.Values | Where-Object { $_.FirstTokenIndex -lt $Fragment.FirstTokenIndex -and $_.LastTokenIndex -gt $Fragment.LastTokenIndex }){$true}else{$false}
            # Only add the fragment if parent is not already in the hashtable
            if ($ParentAlreadyExists -eq $false) {
                $FragmentID = "$($Fragment.GetType().Name)-$($Fragment.StartOffset)-$($Fragment.FragmentLength)"
                if (-not $this.AllFragments.ContainsKey($FragmentID)) {
                    $this.AllFragments[$FragmentID] = $Fragment
                }
            }
            $Fragment.AcceptChildren($this)
        }
    }
    $AllFragments = $null
    $printer = [VisitFragment]::new()
    $Fragment.Accept($printer)
    $AllFragments = $printer.GetAllFragments()
    return $AllFragments
}

function Get-VisitFunctionCall([Microsoft.SqlServer.TransactSql.ScriptDom.TSqlFragment] $Fragment){
    class VisitFragment : Microsoft.SqlServer.TransactSql.ScriptDom.TSqlFragmentVisitor {
        $AllFragments = @{}
        [System.Collections.Hashtable] GetAllFragments() {
            return $this.AllFragments
        }
        [void] ExplicitVisit([Microsoft.SqlServer.TransactSql.ScriptDom.FunctionCall] $Fragment) {
            $FunctionName = $Fragment.FunctionName.Value
            $FragmentID = "$($Fragment.GetType().Name)-$($Fragment.StartOffset)-$($Fragment.FragmentLength)"
            if (-not $this.AllFragments.ContainsKey($FragmentID)) {            
                $this.AllFragments[$FragmentID] = [PSCustomObject]@{
                                                FunctionName = $FunctionName
                                                IsSafeFunction = $false
                                                IsReturningStringType = $false
                                                Fragment = $Fragment
                                            }
            }          
            $ListOfValidFunctions = @("QUOTENAME", "datalength", "fn_getvalidname", "fn_quotefourpartname", "fn_replquotename", "fn_replreplacesinglequoteplusprotectstring", "fn_replreplacesinglequote", "fn_replmakestringliteral")
            # Check if the function name is in the list of valid functions
            if ($ListOfValidFunctions -contains $FunctionName) {
                $this.AllFragments[$FragmentID].IsSafeFunction = $true
            }
            elseif ($FunctionName -eq "REPLACE") {
                # If the function name is REPLACE, it is only safe if it is replacing the single quote
                # or the closing square bracket
                # Other type of REPLACE function calls are not safe
                if ($Fragment.Parameters.Count -eq 3) {
                    $secondParam = $Fragment.Parameters[1]
                    $thirdParam = $Fragment.Parameters[2]

                    # Check if the first parameter is a variable reference
                    if (($secondParam.Value -eq "'" -and ($thirdParam.Value -eq "" -or ($thirdParam.Value).Trim() -eq "''")) -or
                        ($secondParam.Value -eq "]" -and ($thirdParam.Value -eq "" -or ($thirdParam.Value).Trim() -eq "]]"))) {
                        # Add the fragment to the hashtable
                        $this.AllFragments[$FragmentID].IsSafeFunction = $true
                    }
                }
            }
            else{
                #Fixed list of string-returning functions
                $StringReturningFunctions = @(
                    "DB_NAME",
                    "OBJECT_NAME",
                    "USER_NAME",
                    "SCHEMA_NAME",
                    "COL_NAME",
                    "TYPE_NAME",
                    "OBJECT_SCHEMA_NAME"
                )
                if ($StringReturningFunctions -contains $FunctionName) {
                    $this.AllFragments[$FragmentID].IsReturningStringType = $true
                }
            }
            $Fragment.AcceptChildren($this)
        }
    }
    $AllFragments = $null
    $printer = [VisitFragment]::new()
    $Fragment.Accept($printer)
    $AllFragments = $printer.GetAllFragments()
    return $AllFragments
}

function Get-CheckExpression([Microsoft.SqlServer.TransactSql.ScriptDom.ScalarExpression] $Expression, [object] $vResults, [string] $VarOnExec, [string] $VarUsedOnSet, [string] $DataTypeVarOnExec, [int] $Depth = 1){
    $CheckExpressionResults = @{}
    $VariableReferences = @{}
    $ColumnReferences = @{}
    $StringLiterals = @{}
    $SystemFunctions = @{}
    $FunctionCalls = @{}
    $SafeFunctionCalls = @{}

    $Ident = "    " * $Depth

    $SearchedCaseExpressionResult = Get-VisitSearchedCaseExpression -Fragment $Expression

    # Reading all relevant fragments from the subqueries in the expression
    $QuerySpecificationResult = Get-VisitQuerySpecification -Fragment $Expression
    foreach ($QuerySpecification in $QuerySpecificationResult.Values) {
        foreach ($QuerySpecificationSelectElement in $QuerySpecification.SelectElements) {
            $Tmp = $null
            $Tmp = Get-VisitVariableReference -Fragment $QuerySpecificationSelectElement
            foreach($Row in $Tmp.Values) {
                $FragmentID = "$($Row.GetType().Name)-$($Row.StartOffset)-$($Row.FragmentLength)"
                if (-not $VariableReferences.ContainsKey($FragmentID)) {
                    $VariableReferences[$FragmentID] = $Row
                }
            }
            $Tmp = $null 
            $Tmp = Get-VisitColumnReferenceExpression -Fragment $QuerySpecificationSelectElement
            foreach($Row in $Tmp.Values) {
                $FragmentID = "$($Row.GetType().Name)-$($Row.StartOffset)-$($Row.FragmentLength)"
                if (-not $ColumnReferences.ContainsKey($FragmentID)) {
                    $ColumnReferences[$FragmentID] = $Row
                }
            }
            $Tmp = $null
            $Tmp = Get-VisitStringLiteral -Fragment $QuerySpecificationSelectElement
            foreach($Row in $Tmp.Values) {
                $FragmentID = "$($Row.GetType().Name)-$($Row.StartOffset)-$($Row.FragmentLength)"
                if (-not $StringLiterals.ContainsKey($FragmentID)) {
                    $StringLiterals[$FragmentID] = $Row
                }
            }
        }
    }

    # Reading all relevant fragments from the expression, ignoring all fragments inside subqueries
    $Tmp = $null
    $Tmp = Get-VisitVariableReference -Fragment $Expression
    foreach($Row in $Tmp.Values) {
        $FragmentID = "$($Row.GetType().Name)-$($Row.StartOffset)-$($Row.FragmentLength)"
        if (-not $VariableReferences.ContainsKey($FragmentID)) {
            $IsInsideQuerySpecification = $false
            $IsInsideQuerySpecification = if ($QuerySpecificationResult.Values | Where-Object { $_.FirstTokenIndex -lt $Row.FirstTokenIndex -and $_.LastTokenIndex -gt $Row.LastTokenIndex }){$true}else{$false}
            $IsInsideCaseWhen = $false
            $IsInsideCaseWhen = if ($SearchedCaseExpressionResult.Values | Where-Object { $_.FirstTokenIndex -le $Row.FirstTokenIndex -and $_.LastTokenIndex -ge $Row.LastTokenIndex }){$true}else{$false}            
            if (($IsInsideQuerySpecification -eq $false) -and ($IsInsideCaseWhen -eq $false)) {
                # If the variable is not inside a query specification and is not part of a  case when expression, add it to the hashtable
                $VariableReferences[$FragmentID] = $Row
            }
        }
    }
    $Tmp = $null 
    $Tmp = Get-VisitColumnReferenceExpression -Fragment $Expression
    foreach($Row in $Tmp.Values) {
        $FragmentID = "$($Row.GetType().Name)-$($Row.StartOffset)-$($Row.FragmentLength)"
        if (-not $ColumnReferences.ContainsKey($FragmentID)) {
            $IsInsideQuerySpecification = $false
            $IsInsideQuerySpecification = if ($QuerySpecificationResult.Values | Where-Object { $_.FirstTokenIndex -lt $Row.FirstTokenIndex -and $_.LastTokenIndex -gt $Row.LastTokenIndex }){$true}else{$false}
            $IsInsideCaseWhen = $false
            $IsInsideCaseWhen = if ($SearchedCaseExpressionResult.Values | Where-Object { $_.FirstTokenIndex -le $Row.FirstTokenIndex -and $_.LastTokenIndex -ge $Row.LastTokenIndex }){$true}else{$false}           
            if (($IsInsideQuerySpecification -eq $false) -and ($IsInsideCaseWhen -eq $false)) {
                # If the column is not inside a query specification and is not part of a  case when expression, add it to the hashtable
                $ColumnReferences[$FragmentID] = $Row
            }
        }
    }
    $Tmp = $null
    $Tmp = Get-VisitStringLiteral -Fragment $Expression
    foreach($Row in $Tmp.Values) {
        $FragmentID = "$($Row.GetType().Name)-$($Row.StartOffset)-$($Row.FragmentLength)"
        if (-not $StringLiterals.ContainsKey($FragmentID)) {
            $IsInsideQuerySpecification = $false
            $IsInsideQuerySpecification = if ($QuerySpecificationResult.Values | Where-Object { $_.FirstTokenIndex -lt $Row.FirstTokenIndex -and $_.LastTokenIndex -gt $Row.LastTokenIndex }){$true}else{$false}
            if ($IsInsideQuerySpecification -eq $false) {
                # If the variable is not inside a query specification, add it to the hashtable
                $StringLiterals[$FragmentID] = $Row
            }
        }
    }

    $FunctionCalls = Get-VisitFunctionCall -Fragment $Expression
    $SafeFunctionCalls = $FunctionCalls.Values | Where-Object { $_.IsSafeFunction -eq $true }
    $UnSafeFunctionCalls = $FunctionCalls.Values | Where-Object { $_.IsReturningStringType -eq $true }

    $Tmp = $null
    $Tmp = $FunctionCalls
    foreach($Row in $Tmp.Values) {
        $FragmentID = "$($Row.GetType().Name)-$($Row.StartOffset)-$($Row.FragmentLength)"
        if (-not $SystemFunctions.ContainsKey($FragmentID)) {
            # if function used is one of known to read data from system tables like DB_NAME, OBJECT_NAME, USER_NAME, SCHEMA_NAME, OBJECT_SCHEMA_NAME, COL_NAME or TYPE_NAME, 
            # then we consider it as a system function and we will check if the variable is used inside those functions, to consider it unsafe as quotename is required 
            # to avoid injection when using those functions
            if ($Row.IsReturningStringType -eq $true) {
                $SystemFunctions[$FragmentID] = $Row
            }
        }
    }    

    # At this point, we should have all the relevant fragments from the expression
    $CombinedFragmentsTmp = $null
    $CombinedFragmentsTmp += $VariableReferences
    $CombinedFragmentsTmp += $ColumnReferences
    $CombinedFragmentsTmp += $StringLiterals
    $CombinedFragmentsTmp += $SystemFunctions
    $CombinedFragments = @{}

    # Adding on final list only the fragments we care, 
    # getting the info about the IsInsideSafeFunction
    # from the function calls
    foreach ($Fragment in $CombinedFragmentsTmp) {
        foreach ($Row in $Fragment.Values) {
            # Ignoring non string variables
            if ($Row -is [Microsoft.SqlServer.TransactSql.ScriptDom.VariableReference]) {
                # I was ignoring non-string types, but there are some cases where a variable  may be converted into a string... for instance DB_NAME(@DBID)...
                # So, I still need to check non-string variables...
                $IsStringType = $true
                # $VariableDataType = Get-VarDataType -VarRef $Row.Name -vResults $vResults
                # $StringDataTypes = @("NVARCHAR", "VARCHAR", "CHAR", "NCHAR", "TEXT", "NTEXT", "XML")
                # if ($StringDataTypes -notcontains $VariableDataType.SqlDataTypeOption -and $VariableDataType -isnot [Microsoft.SqlServer.TransactSql.ScriptDom.UserDataTypeReference]) {
                #     $IsStringType = $false
                # }
                # else {
                #     $IsStringType = $true
                # }

                if ($IsStringType -eq $true) {
                    $FragmentID = "$($Row.GetType().Name)-$($Row.StartOffset)-$($Row.FragmentLength)"
                    if (-not $CombinedFragments.ContainsKey($FragmentID)) {
                        $IsInsideSafeFunction = if ($SafeFunctionCalls.Fragment | Where-Object { $_.FirstTokenIndex -lt $Row.FirstTokenIndex -and $_.LastTokenIndex -gt $Row.LastTokenIndex }){$true}else{$false}
                        $IsInsideFunctionReturningStringType = if ($UnSafeFunctionCalls.Fragment | Where-Object { $_.FirstTokenIndex -lt $Row.FirstTokenIndex -and $_.LastTokenIndex -gt $Row.LastTokenIndex }){$true}else{$false}
                        $IsImplicitConversionIssue = $false
                        
                        # If is inside a safe function, but the variable used on exec is not a unicode type, then we consider it unsafe, because of the potential for implicit conversion to non-unicode and the related injection risk
                        if ($IsInsideSafeFunction -eq $true -and $VarOnExec) {
                            if ($DataTypeVarOnExec -in @("VARCHAR", "CHAR")) {
                                $IsInsideSafeFunction = $false
                                $IsImplicitConversionIssue = $true
                            }
                        }
                        $CombinedFragments[$FragmentID] = [PSCustomObject]@{
                            Fragment = $Row
                            IsInsideSafeFunction = $IsInsideSafeFunction
                            IsInsideFunctionReturningStringType = $IsInsideFunctionReturningStringType
                            IsImplicitConversionIssue = $IsImplicitConversionIssue
                        }
                    }
                }
            }
            $RowFragment = $Row.Fragment
            if ($RowFragment -is [Microsoft.SqlServer.TransactSql.ScriptDom.FunctionCall]) {
                $FragmentID = "$($RowFragment.GetType().Name)-$($RowFragment.StartOffset)-$($RowFragment.FragmentLength)"
                if (-not $CombinedFragments.ContainsKey($FragmentID)) {
                    $IsInsideSafeFunction = if ($SafeFunctionCalls.Fragment | Where-Object { $_.FirstTokenIndex -lt $RowFragment.FirstTokenIndex -and $_.LastTokenIndex -gt $RowFragment.LastTokenIndex }){$true}else{$false}
                    $IsInsideFunctionReturningStringType = if ($UnSafeFunctionCalls.Fragment | Where-Object { $_.FirstTokenIndex -lt $RowFragment.FirstTokenIndex -and $_.LastTokenIndex -gt $RowFragment.LastTokenIndex }){$true}else{$false}
                    $IsImplicitConversionIssue = $false

                    $CombinedFragments[$FragmentID] = [PSCustomObject]@{
                        Fragment = $RowFragment
                        IsInsideSafeFunction = $IsInsideSafeFunction
                        IsInsideFunctionReturningStringType = $IsInsideFunctionReturningStringType
                        IsImplicitConversionIssue = $IsImplicitConversionIssue
                    }
                }
            }
            else{
                # StringLiteral or ColumnReferenceExpression
                $FragmentID = "$($Row.GetType().Name)-$($Row.StartOffset)-$($Row.FragmentLength)"
                if (-not $CombinedFragments.ContainsKey($FragmentID)) {
                    $IsInsideSafeFunction = if ($SafeFunctionCalls.Fragment | Where-Object { $_.FirstTokenIndex -lt $Row.FirstTokenIndex -and $_.LastTokenIndex -gt $Row.LastTokenIndex }){$true}else{$false}
                    $IsInsideFunctionReturningStringType = if ($UnSafeFunctionCalls.Fragment | Where-Object { $_.FirstTokenIndex -lt $Row.FirstTokenIndex -and $_.LastTokenIndex -gt $Row.LastTokenIndex }){$true}else{$false}

                    # If is inside a safe function, but the variable used on exec is not a unicode type, then we consider it unsafe, because of the potential for implicit conversion to non-unicode and the related injection risk
                    if ($IsInsideSafeFunction -eq $true -and $VarOnExec) {
                        if ($DataTypeVarOnExec -in @("VARCHAR", "CHAR")) {
                            $IsInsideSafeFunction = $false
                            $IsImplicitConversionIssue = $true
                        }
                    }
                    $CombinedFragments[$FragmentID] = [PSCustomObject]@{
                        Fragment = $Row
                        IsInsideSafeFunction = $IsInsideSafeFunction
                        IsInsideFunctionReturningStringType = $IsInsideFunctionReturningStringType
                        IsImplicitConversionIssue = $IsImplicitConversionIssue
                    }
                }
            }
        }
    }

    # Get all references that are not safe
    $UnsafeReferences = $CombinedFragments.Values | Where-Object { $_.IsInsideSafeFunction -eq $false -or (($_.IsInsideFunctionReturningStringType -eq $true) -and ($_.IsInsideSafeFunction -eq $false)) }
    $UnsafeReferences = $UnsafeReferences | Where-Object { $_.Fragment -is [Microsoft.SqlServer.TransactSql.ScriptDom.ColumnReferenceExpression] `
                                                            -or $_.Fragment -is [Microsoft.SqlServer.TransactSql.ScriptDom.VariableReference] `
                                                            -or $_.Fragment -is [Microsoft.SqlServer.TransactSql.ScriptDom.StringLiteral] `
                                                            -or $_.Fragment -is [Microsoft.SqlServer.TransactSql.ScriptDom.FunctionCall]}

    $ExpressionTsql = Get-FragmentText($Expression)
    if ($ExpressionTsql.Length -gt 50) {
        $ExpressionTsqlLimitedTo50char = $ExpressionTsql.Substring(0, 50) + "..."
    }
    else {
        $ExpressionTsqlLimitedTo50char = $ExpressionTsql
    }
    # Remove line breaks from the string
    $ExpressionTsqlLimitedTo50char = $ExpressionTsqlLimitedTo50char.Replace("`r`n", " ")

    if ($UnsafeReferences.Count -eq 0) {
        Write-Msg -Message "$($Ident + "| ")No unsafe references found in the expression $($Expression.GetType().Name) at line $($Expression.StartLine): $ExpressionTsqlLimitedTo50char" -VerboseMsg
        return $CheckExpressionResults
    }
    else {
        Write-Msg -Message "$($Ident + "| ")Checking expression $($Expression.GetType().Name) at line $($Expression.StartLine): $ExpressionTsqlLimitedTo50char" -VerboseMsg
        Write-Msg -Message "$($Ident + "| ")Unsafe values referenced in the expression:" -VerboseMsg
    }

    # Sort the unsafe references by start offset
    $UnsafeReferences = $UnsafeReferences | Select-Object -ExpandProperty Fragment | Sort-Object StartOffset
    foreach ($UnsafeReferences_Row in $UnsafeReferences) {
        $Fragment = $UnsafeReferences_Row
        if ($Fragment -is [Microsoft.SqlServer.TransactSql.ScriptDom.StringLiteral]) {
            if ($Fragment.Value.Length -gt 50) {
                $FragmentValueLimitedTo50char = $Fragment.Value.Substring(0, 50) + "..."
            }
            else {
                $FragmentValueLimitedTo50char = $Fragment.Value
            }
            # Remove line breaks from the string literal
            $FragmentValueLimitedTo50char = $FragmentValueLimitedTo50char -replace "`r`n", " "
            $FragmentValue = $FragmentValueLimitedTo50char
        }
        elseif ($Fragment -is [Microsoft.SqlServer.TransactSql.ScriptDom.ColumnReferenceExpression]){
            # If it is refering to a column and we get here, it means it was not inside a safe function
            # set it to unsafe
            foreach($r in $Fragment.MultiPartIdentifier.Identifiers) {
                $ColumnName = $null
                if ($Fragment.MultiPartIdentifier.Identifiers.Count -gt 1) {
                    $ColumnName = ($Fragment.MultiPartIdentifier.Identifiers | ForEach-Object { $_.Value }) -join "."
                } else {
                    $ColumnName = $Fragment.MultiPartIdentifier.Identifiers[0].Value
                }
            }
            $FragmentValue = $ColumnName
        }
        elseif ($Fragment -is [Microsoft.SqlServer.TransactSql.ScriptDom.VariableReference]){
            # If it is refering to a variable and we get here, it means it was not inside a safe function
            # set it to unsafe
            $FragmentValue = $Fragment.Name
        }
        elseif ($Fragment -is [Microsoft.SqlServer.TransactSql.ScriptDom.FunctionCall]){
            $FragmentValue = $Fragment.FunctionName.Value
        }        
        Write-Msg -Message "$($Ident + "    " + "| ")$($Fragment.GetType().Name): {$FragmentValue} (Col:$($Fragment.StartColumn))" -VerboseMsg
    }

    foreach ($UnsafeReferences_Row in $UnsafeReferences) {
        $Fragment = $UnsafeReferences_Row
        $SafeOrUnsafeReason = ""
        $IsSafe = $true
        if ($Fragment -is [Microsoft.SqlServer.TransactSql.ScriptDom.StringLiteral]) {
            if ($Fragment.Value.Length -gt 50) {
                $FragmentValueLimitedTo50char = $Fragment.Value.Substring(0, 50) + "..."
            }
            else {
                $FragmentValueLimitedTo50char = $Fragment.Value
            }
            # Remove line breaks from the string literal
            $FragmentValueLimitedTo50char = $FragmentValueLimitedTo50char -replace "`r`n", " "
            Write-Msg -Message "$($Ident + "| ")Checking $($Fragment.GetType().Name): {$FragmentValueLimitedTo50char}" -VerboseMsg -Level Starting            

            # Check if the string literal was already checked
            $hashValue = ""
            $hashProvider = [System.Security.Cryptography.SHA1CryptoServiceProvider]::new()
            $hashValue = [Convert]::ToBase64String($hashProvider.ComputeHash([System.Text.Encoding]::Unicode.GetBytes($Fragment.Value)))
            if (-Not ($Global:StringsChecked.ContainsKey($hashValue))) {
                if (($Fragment.Value -match "EXEC ") -or ($Fragment.Value -match "EXECUTE ") -or ($Fragment.Value -match "sp_executesql")) {
                    if (($Fragment.Value -match "VARCHAR") -or ($Fragment.Value -match " CHAR")) {
                        $IsSafe = $false
                        $SafeOrUnsafeReason = "Unsafe, suspicious pattern for string literal: {$FragmentValueLimitedTo50char}, contains EXEC or EXECUTE with VARCHAR, check if it is a dynamic SQL execution and if it is not vulnerable to SQL injection via unicode characters."
                        Write-Msg -Message "$($Ident + "    " + "| ")$($SafeOrUnsafeReason)" -VerboseMsg -Level Warning
                        Add-TSqlCheckResult -Message $SafeOrUnsafeReason
                        # Adding string to the list of checked strings
                        $Global:StringsChecked[$hashValue] = [PSCustomObject]@{
                            Fragment = $Fragment
                            IsSafe = $IsSafe
                            SafeOrUnsafeReason = $SafeOrUnsafeReason
                        }
                    }
                }
                # Check if the string literal is a safe expression
                # Look for suspicious patterns
                $suspiciousPatterns = @("］", "ʼ", "xp_cmdshell", "xp_execresultset", "xp_sprintf", "xp_subdirs", "xp_cmdshell_proxy_account", "OPENDATASOURCE", "OPENROWSET", "OPENQUERY")
                foreach ($pattern in $suspiciousPatterns) {
                    # (?i) → ignore case
                    $escaped = '(?i)' + [regex]::Escape($pattern)
                    if ($Fragment.Value -match $escaped) {
                        $IsSafe = $false
                        $SafeOrUnsafeReason = "Unsafe, suspicious pattern for string literal: {$FragmentValueLimitedTo50char}, pattern: $pattern"
                        Write-Msg -Message "$($Ident + "    " + "| ")$($SafeOrUnsafeReason)" -VerboseMsg -Level Warning
                        Add-TSqlCheckResult -Message $SafeOrUnsafeReason                        
                        break
                    }
                }
                if ($IsSafe -eq $true) {
                    $SafeOrUnsafeReason = "Safe, string expression"
                    Write-Msg -Message "$($Ident + "    " + "| ")$($SafeOrUnsafeReason)" -VerboseMsg
                }                
                # Adding string to the list of checked strings
                $Global:StringsChecked[$hashValue] = [PSCustomObject]@{
                    Fragment = $Fragment
                    IsSafe = $IsSafe
                    SafeOrUnsafeReason = $SafeOrUnsafeReason
                }
            }
            else{
                Write-Msg -Message "$($Ident + "    " + "| ")Already checked this string literal, skipping..." -VerboseMsg
                Write-Msg -Message "$($Ident + "| ")Finished to check $($Fragment.GetType().Name): {$FragmentValueLimitedTo50char}" -VerboseMsg  -Level Finished
                continue
            }
            Write-Msg -Message "$($Ident + "| ")Finished to check $($Fragment.GetType().Name): {$FragmentValueLimitedTo50char}" -VerboseMsg  -Level Finished
        }
        elseif ($Fragment -is [Microsoft.SqlServer.TransactSql.ScriptDom.FunctionCall]){
            # If it is refering to a function call and we get here, it means it was not inside a safe function and it is returning a string type, so we consider it unsafe
            Write-Msg -Message "$($Ident + "| ")Checking $($Fragment.GetType().Name): {$FragmentValue}" -VerboseMsg -Level Starting
            $IsSafe = $false
            $FragmentID = "$($Fragment.GetType().Name)-$($Fragment.StartOffset)-$($Fragment.FragmentLength)"
            $tmp = $CombinedFragments[$FragmentID].IsInsideSafeFunction
            $SafeOrUnsafeReason = "Unsafe, function call ($FragmentValue) is not inside a safe function and it returns a string type, check if it is a system function that can be used to read data from the database and if it is not protected by quotename or another safe function."
            Write-Msg -Message "$($Ident + "    " + "| ")$($SafeOrUnsafeReason)" -VerboseMsg -Level Warning
            Write-Msg -Message "$($Ident + "| ")Finished to check $($Fragment.GetType().Name): {$FragmentValue}" -VerboseMsg -Level Finished
            Add-TSqlCheckResult -Message $SafeOrUnsafeReason
        }        
        elseif ($Fragment -is [Microsoft.SqlServer.TransactSql.ScriptDom.ColumnReferenceExpression]){
            # If it is refering to a column and we get here, it means it was not inside a safe function
            # set it to unsafe
            
            # Get the column name
            foreach($r in $Fragment.MultiPartIdentifier.Identifiers) {
                $ColumnName = $null
                if ($Fragment.MultiPartIdentifier.Identifiers.Count -gt 1) {
                    $ColumnName = ($Fragment.MultiPartIdentifier.Identifiers | ForEach-Object { $_.Value }) -join "."
                } else {
                    $ColumnName = $Fragment.MultiPartIdentifier.Identifiers[0].Value
                }
            }
            Write-Msg -Message "$($Ident + "| ")Checking $($Fragment.GetType().Name): {$ColumnName}" -VerboseMsg -Level Starting
            $IsSafe = $false
            $FragmentID = "$($Fragment.GetType().Name)-$($Fragment.StartOffset)-$($Fragment.FragmentLength)"
            if ($CombinedFragments[$FragmentID].IsImplicitConversionIssue -eq $true) {
                $SafeOrUnsafeReason = "Unsafe, column reference ($ColumnName) is not safe because it is being used in dynamic construct using variable ($VarOnExec) that has a non-unicode type ($DataTypeVarOnExec). There is a potential implicit conversion to non-unicode risk."
            }
            else{
                $SafeOrUnsafeReason = "Unsafe, column reference ($ColumnName) is not inside a safe function"
            }
            Write-Msg -Message "$($Ident + "    " + "| ")$($SafeOrUnsafeReason)" -VerboseMsg -Level Warning
            Write-Msg -Message "$($Ident + "| ")Finished to check $($Fragment.GetType().Name): {$ColumnName}" -VerboseMsg -Level Finished
            Add-TSqlCheckResult -Message $SafeOrUnsafeReason
        }
        elseif ($Fragment -is [Microsoft.SqlServer.TransactSql.ScriptDom.VariableReference]){
            Write-Msg -Message "$($Ident + "| ")Checking $($Fragment.GetType().Name): $($Fragment.Name), used on line $($Fragment.StartLine), column position $($Fragment.StartColumn)" -VerboseMsg -Level Starting
            # Find the variable declaration
            $IsStringType = $true
            $IsInputParameter = $false
            $VarName = $Fragment.Name

            # Is it variable on expression the same being assigned?
            if ($VarName -eq $VarOnExec -or $VarName -eq $VarUsedOnSet) {
                # if so, I may also need to check for previous assignments
                $AlsoCheckPreviousAssignments = $true
            }
            else {
                $AlsoCheckPreviousAssignments = $false
            }

            # Check if the variable was already checked
            $VariableCheckStatus = $null
            if ($Global:VariablesChecked.ContainsKey($VarName)) {
                $VariableCheckStatus = $Global:VariablesChecked[$VarName].IsSafe
            }
            if ($null -ne $VariableCheckStatus) {
                # If the variable was already checked, skip it
                Write-Msg -Message "$($Ident + "    " + "| ")Already checked this variable, skipping..." -VerboseMsg
                Write-Msg -Message "$($Ident + "| ")Finished to check $($Fragment.GetType().Name): {$VarName}" -VerboseMsg -Level Finished
                $IsSafe = $VariableCheckStatus
                $SafeOrUnsafeReason = $Global:VariablesChecked[$VarName].SafeOrUnsafeReason
                continue
            }
            else {
                # Checking if reference was used inside a function returning a string datatype
                $FragmentID = "$($Fragment.GetType().Name)-$($Fragment.StartOffset)-$($Fragment.FragmentLength)"
                if ($CombinedFragments[$FragmentID].IsInsideFunctionReturningStringType -eq $true) {
                    $IsSafe = $false
                    $SafeOrUnsafeReason = "Unsafe variable reference ($VarName): Variable was used inside a function that returns a string type"
                    Write-Msg -Message "$($Ident + "    " + "| ")$($SafeOrUnsafeReason)" -VerboseMsg -Level Warning
                    Add-ExecVulnerability -Fragment $Fragment -Msg $SafeOrUnsafeReason
                    # Add the variable to the list of checked variables
                    $Global:VariablesChecked[$VarName] = [PSCustomObject]@{
                        Fragment = $Fragment
                        IsSafe = $IsSafe
                        SafeOrUnsafeReason = $SafeOrUnsafeReason
                    }
                    $UnsafeReported = $true
                    continue
                }
                $VarDecls = $vResults.Values | Where-Object { $_ -is [Microsoft.SqlServer.TransactSql.ScriptDom.DeclareVariableStatement] }
                $VarDecls = $VarDecls.Declarations | Where-Object { $_.VariableName.Value -eq $VarName } | Sort-Object StartOffset -Descending | Select-Object -First 1
                if ($null -eq $VarDecls) {
                    $VarDecls = $vResults.Values | Where-Object { $_ -is [Microsoft.SqlServer.TransactSql.ScriptDom.ProcedureParameter] }
                    $VarDecls = $VarDecls | Where-Object { $_.VariableName.Value -eq $VarName } | Sort-Object StartOffset -Descending | Select-Object -First 1
                }
                if ($null -ne $VarDecls) {
                    # I was ignoring non-string types, but there are some cases where a variable  may be converted into a string... for instance DB_NAME(@DBID)...
                    # So, I still need to check non-string variables...
                    $IsStringType = $true
                    # $StringDataTypes = @("NVARCHAR", "VARCHAR", "CHAR", "NCHAR", "TEXT", "NTEXT", "XML")
                    # if ($StringDataTypes -notcontains $VarDecls.DataType.SqlDataTypeOption -and $VarDecls.DataType -isnot [Microsoft.SqlServer.TransactSql.ScriptDom.UserDataTypeReference]) {
                    #     $IsStringType = $false
                    # }
                }
                if ($IsStringType -eq $true){
                    # Check the last/previous variable assignment in the script
                    $LastAssignment = $null
                    # Only call Get-LastVariableAssignment if it is the first time we're looking at this fragment
                    # This is to avoid infinite loops when the fragment is inside a loop
                    if (Test-IsFirstTimeSeen $Fragment) { 
                        $LastAssignment = Get-LastVariableAssignment -VarName $VarName -vResults $vResults -ExecExpression $Fragment
                        if ($null -ne $LastAssignment) {
                            Write-Msg -Message "$($Ident + "    " + "| " )Found the last assignment for $VarName at line $($LastAssignment.StartLine), assigned with a $($LastAssignment.GetType().Name)" -VerboseMsg
                        }
                    }
                    else{
                        if ($AlsoCheckPreviousAssignments -eq $true) {
                            Write-Msg -Message "$($Ident + "    " + "| " )Already seen this fragment before, but same variable is being assigned, checking previous assignments..." -VerboseMsg
                            $LastAssignment = Get-LastVariableAssignment -VarName $VarName -vResults $vResults -ExecExpression $Fragment -SkipLastAssignment $true
                            if ($null -ne $LastAssignment) {
                                Write-Msg -Message "$($Ident + "    " + "| " )Found the previous assignment for $VarName at line $($LastAssignment.StartLine), assigned with a $($LastAssignment.GetType().Name)" -VerboseMsg
                            }
                        }
                        else{
                            Write-Msg -Message "$($Ident + "    " + "| ")Already checked this variable, skipping..." -VerboseMsg
                        }
                    }
                    # If the last assignment is not found, check if it is a input parameter
                    if ($null -eq $LastAssignment) {
                        $LastAssignment = $vResults.Values | Where-Object { $_ -is [Microsoft.SqlServer.TransactSql.ScriptDom.ProcedureParameter] }
                        $LastAssignment = $LastAssignment | Where-Object { $_.VariableName.Value -eq $VarName }
                        if ($null -ne $LastAssignment) {
                            # For input parameters, only consider unsafe parameter of string types
                            $InputParamType = $LastAssignment.DataType
                            $StringDataTypes = @("NVARCHAR", "VARCHAR", "CHAR", "NCHAR", "TEXT", "NTEXT", "XML")
                            if ($StringDataTypes -contains $InputParamType.SqlDataTypeOption -or $InputParamType -is [Microsoft.SqlServer.TransactSql.ScriptDom.UserDataTypeReference]) {
                                # If last assignment it coming from as the input parameter, set as unsafe
                                $IsSafe = $false
                                if ($CombinedFragments[$FragmentID].IsImplicitConversionIssue -eq $true) {
                                    $SafeOrUnsafeReason = "Unsafe, variable reference ($VarName) is not safe because it is being used in dynamic construct using variable ($VarOnExec) that has a non-unicode type ($DataTypeVarOnExec). There is a potential implicit conversion to non-unicode risk."
                                }
                                else{
                                    $SafeOrUnsafeReason = "Unsafe, variable reference ($VarName) is not safe, it is an input parameter and is not properly quoted"
                                }
                                
                                Write-Msg -Message "$($Ident + "    " + "| ")$($SafeOrUnsafeReason)" -VerboseMsg -Level Warning
                                Add-TSqlCheckResult -Message $SafeOrUnsafeReason
                                $IsInputParameter = $true
                                # Add the variable to the list of checked variables
                                $Global:VariablesChecked[$VarName] = [PSCustomObject]@{
                                    Fragment = $Fragment
                                    IsSafe = $IsSafe
                                    SafeOrUnsafeReason = $SafeOrUnsafeReason
                                }
                            }
                        }
                    }
                    # If the last assignment is found, check if it is a safe expression
                    if ($null -ne $LastAssignment -and $IsInputParameter -eq $false) {
                        if ($LastAssignment -is [Microsoft.SqlServer.TransactSql.ScriptDom.SelectSetVariable] -or $LastAssignment -is [Microsoft.SqlServer.TransactSql.ScriptDom.SetVariableStatement]) {
                            $Expression = $LastAssignment.Expression
                        }
                        elseif ($LastAssignment -is [Microsoft.SqlServer.TransactSql.ScriptDom.AssignmentSetClause]) {
                            $Expression = $LastAssignment.NewValue
                        }
                        elseif ($LastAssignment -is [Microsoft.SqlServer.TransactSql.ScriptDom.FetchCursorStatement]) {
                            $UnsafeReported = $false
                            $CursorDefinitions = $vResults.Values | Where-Object { $_ -is [Microsoft.SqlServer.TransactSql.ScriptDom.DeclareCursorStatement] }
                            $CursorDefinitions = $CursorDefinitions | Where-Object { $_.Name.Value -eq $LastAssignment.Cursor.Name.Value }
                            $CursorDefinitions = $CursorDefinitions | Where-Object { $_.StartLine -le $LastAssignment.StartLine }
                            # If there is more than one definition for the same cursor, consider the last one
                            $CursorDefinitions = $CursorDefinitions | Sort-Object StartOffset -Descending | Select-Object -First 1

                            if ($null -eq $CursorDefinitions) {
                                # If we couldn't find the cursor definition, check if it was declared in a set variable statement
                                $CursorDefinitions = $vResults.Values | Where-Object { $_ -is [Microsoft.SqlServer.TransactSql.ScriptDom.SetVariableStatement] }
                                $CursorDefinitions = $CursorDefinitions | Where-Object { $_.Variable.Name -eq $LastAssignment.Cursor.Name.Value }
                                $CursorDefinitions = $CursorDefinitions | Where-Object { $_.StartLine -le $LastAssignment.StartLine }
                                # If there is more than one definition for the same cursor, consider the last one
                                $CursorDefinitions = $CursorDefinitions | Sort-Object StartOffset -Descending | Select-Object -First 1
                            }
                            if ($null -eq $CursorDefinitions) {
                                $IsSafe = $true
                                $SafeOrUnsafeReason = "No cursor definition found for cursor $($LastAssignment.Cursor.Name.Value), assuming fetch is safe."
                                Write-Msg -Message "$($Ident + "    " + "| ")$($SafeOrUnsafeReason)" -VerboseMsg
                                $Global:VariablesChecked[$VarName] = [PSCustomObject]@{
                                    Fragment = $Fragment
                                    IsSafe = $IsSafe
                                    SafeOrUnsafeReason = $SafeOrUnsafeReason
                                }
                            }
                            else {
                                # If the number of elements in the cursor definition is 0, it is probably a SelectStarElement, in that case, I can't 
                                # check if it is safe or not
                                # Loop through the cursor BinaryQueryExpression until we find a FirstQueryExpression
                                $expr = $CursorDefinitions.CursorDefinition.Select.QueryExpression
                                while ($expr -is [Microsoft.SqlServer.TransactSql.ScriptDom.BinaryQueryExpression]) {
                                    $expr = $expr.FirstQueryExpression
                                }
                                $CursorDefinitions.CursorDefinition.Select.QueryExpression = $expr

                                if ($null -ne $CursorDefinitions.CursorDefinition.Select.QueryExpression.SelectElements){
                                    if ($CursorDefinitions.CursorDefinition.Select.QueryExpression.SelectElements[0] -is [Microsoft.SqlServer.TransactSql.ScriptDom.SelectStarExpression]) {
                                        $IsSafe = $false
                                        $SafeOrUnsafeReason = "$($Ident + "    " + "| ")Cursor definition is a SelectStarElement, assuming fetch is unsafe."
                                        Write-Msg -Message $SafeOrUnsafeReason -VerboseMsg -Level Warning
                                        Add-ExecVulnerability -Fragment $Fragment -Msg $SafeOrUnsafeReason
                                        $Global:VariablesChecked[$VarName] = [PSCustomObject]@{
                                            Fragment = $Fragment
                                            IsSafe = $false
                                            SafeOrUnsafeReason = $SafeOrUnsafeReason
                                        }
                                        $UnsafeReported = $true
                                        continue
                                    } 
                                }                                
                                # If the cursor definition is found, check if it is a safe expression
                                $i = 0
                                # Find the expression in the cursor definition
                                foreach ($Var_Row in $LastAssignment.IntoVariables) {
                                    if ($Var_Row.Name -eq $VarName) {
                                        $Expression = $null
                                        if ($null -ne $CursorDefinitions.CursorDefinition.Select.QueryExpression.SelectElements){
                                            if (($null -eq $CursorDefinitions.CursorDefinition.Select.QueryExpression.SelectElements[$i]) -or ($CursorDefinitions.CursorDefinition.Select.QueryExpression.SelectElements[$i] -isnot [Microsoft.SqlServer.TransactSql.ScriptDom.SelectScalarExpression])) {
                                                $IsSafe = $false
                                                $SafeOrUnsafeReason = "$($Ident + "    " + "| ")Couldn't identify the expression type used ($($CursorDefinitions.CursorDefinition.Select.QueryExpression.SelectElements[$i].GetType().Name)) in the cursor $($LastAssignment.Cursor.Name.Value), assuming fetch is unsafe."
                                                Write-Msg -Message $SafeOrUnsafeReason -VerboseMsg -Level Warning
                                                Add-ExecVulnerability -Fragment $Fragment -Msg $SafeOrUnsafeReason
                                                $Global:VariablesChecked[$VarName] = [PSCustomObject]@{
                                                    Fragment = $Fragment
                                                    IsSafe = $false
                                                    SafeOrUnsafeReason = $SafeOrUnsafeReason
                                                }
                                                $UnsafeReported = $true
                                                continue
                                            }
                                            else{
                                                $Expression = $CursorDefinitions.CursorDefinition.Select.QueryExpression.SelectElements[$i].Expression
                                            }
                                        }
                                        elseif ($null -ne $CursorDefinitions.CursorDefinition.Select.QueryExpression.QueryExpression.SelectElements){
                                            $Expression = $CursorDefinitions.CursorDefinition.Select.QueryExpression.QueryExpression.SelectElements[$i].Expression
                                        }
                                        break
                                    }
                                    $i++
                                }
                                if ($UnsafeReported -eq $true){
                                    Write-Msg -Message "$($Ident + "| ")Finished to check $($Fragment.GetType().Name): {$VarName}" -VerboseMsg -Level Finished
                                    continue
                                }
                                # If the expression is not found, mark as unsafe
                                if ($null -eq $Expression) {
                                    $SafeOrUnsafeReason = "$($Ident + "    " + "| ")No cursor definition found for cursor $($LastAssignment.Cursor.Name.Value), assuming fetch is unsafe."
                                    Write-Msg -Message $SafeOrUnsafeReason -VerboseMsg -Level Warning
                                    Add-ExecVulnerability -Fragment $Fragment -Msg $SafeOrUnsafeReason
                                    $Global:VariablesChecked[$VarName] = [PSCustomObject]@{
                                        Fragment = $Fragment
                                        IsSafe = $false
                                        SafeOrUnsafeReason = $SafeOrUnsafeReason
                                    }
                                    $UnsafeReported = $true
                                }
                            }
                        }
                        elseif ($LastAssignment -is [Microsoft.SqlServer.TransactSql.ScriptDom.DeclareVariableStatement] -or $LastAssignment -is [Microsoft.SqlServer.TransactSql.ScriptDom.DeclareVariableElement]) {
                            $Expression = $LastAssignment.Value
                            if ($null -eq $Expression) {
                                $IsSafe = $true
                                $SafeOrUnsafeReason = "Safe assignment, no default value assigned"
                                Write-Msg -Message "$($Ident + "    " + "| ")$($SafeOrUnsafeReason)" -VerboseMsg
                                $Global:VariablesChecked[$VarName] = [PSCustomObject]@{
                                    Fragment = $Fragment
                                    IsSafe = $IsSafe
                                    SafeOrUnsafeReason = $SafeOrUnsafeReason
                                }
                            }
                        }
                        elseif ($LastAssignment -is [Microsoft.SqlServer.TransactSql.ScriptDom.ExecuteStatement]) {
                            # If the variable is assigned via an Execute statement, I need to check if it is using sp_MSguidtostr, which is a safe function that returns a string type, 
                            # if so, I can consider it safe, otherwise, I have to consider it unsafe, since I don't know how the variable is being assigned inside the execute statement
                            $ProcName = $LastAssignment.ExecuteSpecification.ExecutableEntity.ProcedureReference.ProcedureReference.Name.BaseIdentifier.Value
                            if ($ProcName -in @("sp_MSguidtostr")) {
                                continue
                            }
                            # if the variable is assigned via an Execute statement, mark as unsafe
                            $IsSafe = $false
                            $SafeOrUnsafeReason = "Unsafe, variable assigned via Execute->Output statement. Since I don't know how this was assigned inside the execute, assuming unsafe."
                            Write-Msg -Message "$($Ident + "    " + "| ")$($SafeOrUnsafeReason)" -VerboseMsg -Level Warning
                            Add-ExecVulnerability -Fragment $Fragment -Msg $SafeOrUnsafeReason
                            $Global:VariablesChecked[$VarName] = [PSCustomObject]@{
                                Fragment = $Fragment
                                IsSafe = $IsSafe
                                SafeOrUnsafeReason = $SafeOrUnsafeReason
                            }
                            $UnsafeReported = $true
                            continue
                        }
                        if ($null -ne $Expression){
                            # Call Get-CheckExpression again
                            $GetCheckExpressionResults = $null
                            $GetCheckExpressionResults = Get-CheckExpression -Expression $Expression -vResults $vResults -VarOnExec $VarOnExec -VarUsedOnSet $VarName -DataTypeVarOnExec $DataTypeVarOnExec -Depth ($Depth + 1)
                            foreach ($GetCheckExpressionResults_Row in $GetCheckExpressionResults.Values | Where-Object {$_.IsSafe -eq $false}) {
                                # Add the fragment to the list of unsafe fragments
                                Add-ExecVulnerability -Fragment $GetCheckExpressionResults_Row.Fragment -Msg $GetCheckExpressionResults_Row.SafeOrUnsafeReason
                            }
                            $Global:VariablesChecked[$VarName] = [PSCustomObject]@{
                                Fragment = $Fragment
                                IsSafe = $IsSafe
                                SafeOrUnsafeReason = $SafeOrUnsafeReason
                            }
                            Remove-VisitedFrag -VarRef $Fragment
                        }
                    }
                }
            }
            Write-Msg -Message "$($Ident + "| ")Finished to check $($Fragment.GetType().Name): {$VarName}" -VerboseMsg -Level Finished
        }
        if ($IsSafe -eq $false) {
            # Generate a unique ID for the fragment based on its type and position
            $FragmentID = "$($Fragment.GetType().Name)-$($Fragment.StartOffset)-$($Fragment.FragmentLength)"
            $CheckExpressionResults[$FragmentID] = [PsCustomObject]@{
                Fragment = $Fragment
                IsSafe = $IsSafe
                SafeOrUnsafeReason = $SafeOrUnsafeReason
            }
        }
    }

    # Some extra checks for references inside a safe function
    # Checking if both variables being used are using a safe unicode data type
    # Get all variable references
    $Variables = $CombinedFragments.Values | Where-Object { $_.Fragment -is [Microsoft.SqlServer.TransactSql.ScriptDom.VariableReference] }
    foreach ($Variables_Row in $Variables) {
        $VarUsedOnSetDataType = $null
        $VarUsedOnExecDataType = $null
        $FragmentVarDataType = $null
        $IsVarUsedOnExecDataTypeUnicode = $false
        $IsVarUsedOnSetDataTypeUnicode = $false
        $IsFragmentVarDataTypeUnicode = $false
        
        $FragmentVarDataType = Get-VarDataType -VarRef $Variables_Row.Fragment.Name -vResults $vResults
        # Only check unicode difference if variable is a string or user data type
        $StringDataTypes = @("NVARCHAR", "VARCHAR", "CHAR", "NCHAR", "TEXT", "NTEXT", "XML")
        if (($StringDataTypes -contains $FragmentVarDataType.SqlDataTypeOption) -or ($FragmentVarDataType -is [Microsoft.SqlServer.TransactSql.ScriptDom.UserDataTypeReference])) {
            if ($FragmentVarDataType.SqlDataTypeOption -eq "NCHAR" -or $FragmentVarDataType.SqlDataTypeOption -eq "NVARCHAR" -or $FragmentVarDataType -is [Microsoft.SqlServer.TransactSql.ScriptDom.UserDataTypeReference]) {
                $IsFragmentVarDataTypeUnicode = $true 
            }
        }
        else{
            $IsFragmentVarDataTypeUnicode = $true
        }

        if ($FragmentVarDataType -is [Microsoft.SqlServer.TransactSql.ScriptDom.UserDataTypeReference]) {
            $FragmentVarDataTypeName = $FragmentVarDataType.Name.BaseIdentifier.Value
        }
        else{
            $FragmentVarDataTypeName = $FragmentVarDataType.SqlDataTypeOption
        }

        # If VarUsedOnSet is set, it means we're doing a recursive call, in this case
        # check VarUsedOnSet and the Fragment Var
        if ($VarUsedOnSet -ne $null -and $VarUsedOnSet -ne "") {
            $VarUsedOnSetDataType = Get-VarDataType -VarRef $VarUsedOnSet -vResults $vResults
            # Only check unicode difference if variable is a string or user data type
            $StringDataTypes = @("NVARCHAR", "VARCHAR", "CHAR", "NCHAR", "TEXT", "NTEXT", "XML")
            if (($StringDataTypes -contains $VarUsedOnSetDataType.SqlDataTypeOption) -or ($VarUsedOnSetDataType -is [Microsoft.SqlServer.TransactSql.ScriptDom.UserDataTypeReference])) {
                if ($VarUsedOnSetDataType.SqlDataTypeOption -eq "NCHAR" -or $VarUsedOnSetDataType.SqlDataTypeOption -eq "NVARCHAR" -or $VarUsedOnSetDataType -is [Microsoft.SqlServer.TransactSql.ScriptDom.UserDataTypeReference]) {
                    $IsVarUsedOnSetDataTypeUnicode = $true 
                }
            }
            else{
                $IsVarUsedOnSetDataTypeUnicode = $true
            }            

            if ($IsFragmentVarDataTypeUnicode -eq $false -or $IsVarUsedOnSetDataTypeUnicode -eq $false) {
                # If any of the variables is not unicode, set IsSafe to false and report it
                $IsSafe = $false
                if ($VarUsedOnSetDataType -is [Microsoft.SqlServer.TransactSql.ScriptDom.UserDataTypeReference]) {
                    $VarUsedOnSetDataTypeName = $VarUsedOnSetDataType.Name.BaseIdentifier.Value
                }
                else{
                    $VarUsedOnSetDataTypeName = $VarUsedOnSetDataType.SqlDataTypeOption
                }
                $SafeOrUnsafeReason = "Unsafe, variables $($Variables_Row.Fragment.Name) ($FragmentVarDataTypeName) and $VarUsedOnSet ($VarUsedOnSetDataTypeName) are not unicode"
                Write-Msg -Message "$($Ident + "    " + "| ")$($SafeOrUnsafeReason)" -VerboseMsg -Level Warning
                Add-ExecVulnerability -Fragment $Variables_Row.Fragment -Msg $SafeOrUnsafeReason
                return $CheckExpressionResults
            }
        }
        # Otherwise, check VarOnExec and the Fragment Var
        else{
            $VarUsedOnExecDataType = Get-VarDataType -VarRef $VarOnExec -vResults $vResults
            # Only check unicode difference if variable is a string or user data type
            $StringDataTypes = @("NVARCHAR", "VARCHAR", "CHAR", "NCHAR", "TEXT", "NTEXT", "XML")
            if (($StringDataTypes -contains $VarUsedOnSetDataType.SqlDataTypeOption) -or ($VarUsedOnExecDataType -is [Microsoft.SqlServer.TransactSql.ScriptDom.UserDataTypeReference])) {
                if ($VarUsedOnExecDataType.SqlDataTypeOption -eq "NCHAR" -or $VarUsedOnExecDataType.SqlDataTypeOption -eq "NVARCHAR" -or $VarUsedOnExecDataType -is [Microsoft.SqlServer.TransactSql.ScriptDom.UserDataTypeReference]) {
                    $IsVarUsedOnExecDataTypeUnicode = $true 
                }
            }
            else{
                $IsVarUsedOnExecDataTypeUnicode = $true
            }

            if ($IsFragmentVarDataTypeUnicode -eq $false -or $IsVarUsedOnExecDataTypeUnicode -eq $false) {
                # If any of the variables is not unicode, set IsSafe to false and report it
                $IsSafe = $false
                if ($VarUsedOnExecDataType -is [Microsoft.SqlServer.TransactSql.ScriptDom.UserDataTypeReference]) {
                    $VarUsedOnExecDataTypeName = $VarUsedOnExecDataType.Name.BaseIdentifier.Value
                }
                else{
                    $VarUsedOnExecDataTypeName = $VarUsedOnExecDataType.SqlDataTypeOption
                }
                $SafeOrUnsafeReason = "Unsafe, variables $($Variables_Row.Fragment.Name) ($FragmentVarDataTypeName) and $VarOnExec ($VarUsedOnExecDataTypeName) are not unicode"
                Write-Msg -Message "$($Ident+ "    " + "| ")$($SafeOrUnsafeReason)" -VerboseMsg -Level Warning
                Add-ExecVulnerability -Fragment $Variables_Row.Fragment -Msg $SafeOrUnsafeReason
                return $CheckExpressionResults
            }            
        }
    }

    return $CheckExpressionResults
}

function Invoke-SQLInjectionCheck([Microsoft.SqlServer.TransactSql.ScriptDom.TSqlFragment]$TSqlFragment, [string]$StatementRef, [bool]$ReportTriggerVuln = $false) {
    $Global:SafeContextFirstTokenIndex = 0
    $Global:SafeContextLastTokenIndex = 0
    $Global:VisitedVarRef = @{}
    $Global:DMLEvents = @()
    $Global:DDLEvents = @()
    # Define $Global:DMLKeywords and $Global:DDLKeywords as lists of keywords you want to check for in the string literals
    $Global:DMLKeywords = @("INTO ", "INSERT INTO", "UPDATE", "DELETE", "MERGE")
    $Global:DDLKeywords = @("CREATE", "ALTER", "DROP", "TRUNCATE", "RENAME", "GRANT", "REVOKE", "DENY")

    # Call visitor to visit the TSQL fragment and fill out the Global variables we'll use to check for SQL injection
    $VisitorStartTime = Get-Date
    $vResults = $null
    $SqlInjectionVisitor = [SqlInjectionVisitor]::new()
    $TSqlFragment.Accept($SqlInjectionVisitor)
    $vResults = $SqlInjectionVisitor.GetVisitorResults()
    $VisitorTime = ((Get-Date) - $VisitorStartTime).TotalMilliseconds
    $Global:OperationTimers['VisitorTraversal'] += $VisitorTime
    Write-Msg -Message "Fragment visitor traversal completed (Duration: $VisitorTime ms)" -VerboseMsg
    # Print out information about DML and DDL events found
    if ($Global:DMLEvents.Count -gt 0) {
        Write-Msg -Message "DML Events found:" -VerboseMsg
        foreach ($DMLEvent in $Global:DMLEvents) {
            if ($ReportTriggerVuln) {
                $Msg = "DML Event found: $($DMLEvent.Type) at line $($DMLEvent.Line)"
                # Add-TSqlCheckResult -Message $Msg
                Add-ExecVulnerability -Fragment $DMLEvent.Fragment -Msg $Msg -VulnerabilityType "Trigger permission hijacking" -ReportTriggerVuln $true
            }
        }
    }
    if ($Global:DDLEvents.Count -gt 0) {
        Write-Msg -Message "DDL Events found:" -VerboseMsg
        foreach ($DDLEvent in $Global:DDLEvents) {
            if ($ReportTriggerVuln) {
                $Msg = "DDL Event found: $($DDLEvent.Type) at line $($DDLEvent.Line)" 
                # Add-TSqlCheckResult -Message $Msg
                Add-ExecVulnerability -Fragment $DDLEvent.Fragment -Msg $Msg -VulnerabilityType "Trigger permission hijacking" -ReportTriggerVuln $true
            }
        }
    }

    # Checking for SQL injection vulnerabilities
    # Starting the code with the parts I'm interested in, which are exec and sp_executesql
    $ExecStatements = $null
    $ExecStatements = $vResults.Values | Where-Object { $_ -is [Microsoft.SqlServer.TransactSql.ScriptDom.ExecuteStatement] -or $_ -is [Microsoft.SqlServer.TransactSql.ScriptDom.ExecuteInsertSource] } | Sort-Object StartOffset

    $DynamicExecutions = @{}
    Write-Msg -Message "Looking for dynamic executions..." -VerboseMsg -Level Starting
    foreach ($ExecStatement_Row in $ExecStatements) {
        $ExecutableEntity = $null
        if ($ExecStatement_Row -is [Microsoft.SqlServer.TransactSql.ScriptDom.ExecuteStatement]){
            $ExecutableEntity = $ExecStatement_Row.ExecuteSpecification.ExecutableEntity
        }
        elseif ($ExecStatement_Row -is [Microsoft.SqlServer.TransactSql.ScriptDom.ExecuteInsertSource]){
            $ExecutableEntity = $ExecStatement_Row.Execute.ExecutableEntity
        }        
        if ($ExecutableEntity -is [Microsoft.SqlServer.TransactSql.ScriptDom.ExecutableProcedureReference]) {
            if ($null -ne $ExecutableEntity.ProcedureReference.ProcedureVariable) {
                # If the procedure is being called via a variable, consider it a dynamic execution
                Write-Msg -Message "Found a dynamic execution via procedure variable: $($ExecutableEntity.ProcedureReference.ProcedureVariable.Name)" -VerboseMsg -Level Output
                $DynamicExecutions.Add($ExecStatement_Row.StartOffset, $ExecutableEntity)
                continue
            }
            else{
                $ProcName = $ExecutableEntity.ProcedureReference.ProcedureReference.Name.BaseIdentifier.Value
                if ($ProcName -in @("sp_prepexec", "sp_prepare", "sp_executesql", "sp_cursoropen")) {
                    $DynamicExecutions.Add($ExecStatement_Row.StartOffset, $ExecutableEntity)
                }
            }
        }
        else{
            $DynamicExecutions.Add($ExecStatement_Row.StartOffset, $ExecutableEntity)
        }
    }
    $DynamicExecutionsCount = $DynamicExecutions.Count
    if ($DynamicExecutionsCount -eq 0) {
        $DynamicExecutionsMsg = "No dynamic executions found"
        Add-TSqlCheckResult -Message $DynamicExecutionsMsg
        Write-Msg -Message $DynamicExecutionsMsg -VerboseMsg -Level Finished
        return $Global:TSqlCheckResults
    }
    else {
        $DynamicExecutionsMsg = "Found $DynamicExecutionsCount dynamic executions"
        Add-TSqlCheckResult -Message $DynamicExecutionsMsg
        Write-Msg -Message $DynamicExecutionsMsg -VerboseMsg -Level Finished        
    }

    foreach ($DynamicExecutions_Row in $DynamicExecutions.Keys | Sort-Object $_.StartOffset) {
        $DynamicExecStartTime = Get-Date
        $Global:StringsChecked = @{}
        $Global:VariablesChecked = @{}
        
        $ExecStatement_Row = $DynamicExecutions[$DynamicExecutions_Row]
        # Get the text for the whole dynamic statement
        $ExecStatementText = Get-FragmentText($ExecStatement_Row)
        Write-Msg -Message "Checking dynamic execution on line $($ExecStatement_Row.StartLine)" -VerboseMsg -Level Starting
        $ExecStatementTextLimitedTo50char = $ExecStatementText.Substring(0, [Math]::Min($ExecStatementText.Length, 50)) + "..."
        # Remove line breaks from the string literal
        $ExecStatementTextLimitedTo50char = $ExecStatementTextLimitedTo50char -replace "`r`n", " "
        if ($ExecStatementText.Length -gt 50) {
            Write-Msg -Message "    | Stmt: $ExecStatementTextLimitedTo50char" -VerboseMsg
        }
        else {
            Write-Msg -Message "    | Stmt: $ExecStatementText" -VerboseMsg
        }

        # An exec statement can only reference to a string literal or a variable
        class VisitVariableAndStringReference : Microsoft.SqlServer.TransactSql.ScriptDom.TSqlFragmentVisitor {
            # Declare a local variable to store the results of the visitor
            $VisitorResults = @{}
            [void] AddVisitorResult([Microsoft.SqlServer.TransactSql.ScriptDom.TSqlFragment] $Fragment) {
                $FragmentID = "$($Fragment.GetType().Name)-$($Fragment.StartOffset)-$($Fragment.FragmentLength)"
                if (-not $this.VisitorResults.ContainsKey($FragmentID)) {
                    $this.VisitorResults[$FragmentID] = $Fragment
                }
            }
            [System.Collections.Hashtable] GetVisitorResults() {
                return $this.VisitorResults
            }
            [void] ExplicitVisit([Microsoft.SqlServer.TransactSql.ScriptDom.StringLiteral] $Fragment) {
                $this.AddVisitorResult($Fragment)
                $Fragment.AcceptChildren($this)
            }
            [void] ExplicitVisit([Microsoft.SqlServer.TransactSql.ScriptDom.VariableReference] $Fragment) {
                $this.AddVisitorResult($Fragment)
                $Fragment.AcceptChildren($this)
            }
        }
        $VisitVariableAndStringReferenceResults = $null
        $VisitVariableAndStringReference = [VisitVariableAndStringReference]::new()
        $ExecStatement_Row.Accept($VisitVariableAndStringReference)
        $VisitVariableAndStringReferenceResults = $VisitVariableAndStringReference.GetVisitorResults()

        # Ignore procedure parameters like:
        # exec sp_executesql @stmt = @sql, @params = N'@Param1 varchar(255)', @Param1 = @var1
        # or a exec proc1 @param1 = @var1, @param2 = @var2, @param3 = @var3
        if ($ExecStatement_Row -is [Microsoft.SqlServer.TransactSql.ScriptDom.ExecutableProcedureReference]) {
            $ProcName = $ExecStatement_Row.ProcedureReference.ProcedureReference.Name.BaseIdentifier.Value
            if ($ProcName -eq "sp_executesql" -or $ProcName -eq "sp_cursoropen") {
                $ParamPositionWithStmt = 0 # On sp_executesql and sp_cursoropen, the stmt is on the first parameter
            }
            elseif ($ProcName -eq "sp_prepexec" -or $ProcName -eq "sp_prepare"){
                $ParamPositionWithStmt = 2 # On sp_prepexec and sp_prepare, the stmt is on the third parameter
            }

            # Remove input parameter name variable references from the visitor results
            foreach ($Param in $ExecStatement_Row.Parameters) {
                if ($null -ne $Param.Variable) {
                    # If the parameter is a variable, remove it from the visitor results
                    $FragmentID = "$($Param.Variable.GetType().Name)-$($Param.Variable.StartOffset)-$($Param.Variable.FragmentLength)"
                    $VisitVariableAndStringReferenceResults.Remove($FragmentID)
                }
            }
            # Remove the parameter value references from the visitor results
            # The parameter value references are the ones that are not the one with the statement
            $i = 0
            foreach ($Param in $ExecStatement_Row.Parameters) {
                # Ignore parameter value references, except for the one with the statement
                if ($i -ne $ParamPositionWithStmt) {
                    # If the parameter is not the one with the statement, ignore it
                    $FragmentID = "$($Param.ParameterValue.GetType().Name)-$($Param.ParameterValue.StartOffset)-$($Param.ParameterValue.FragmentLength)"
                    $VisitVariableAndStringReferenceResults.Remove($FragmentID)
                }
                $i++
            }
        }

        # Loop through all variable references and check if buffer size is enough
        # to hold avoid SQL injection by data truncation
        foreach ($VariableReference in ($VisitVariableAndStringReferenceResults.Values | Where-Object { $_ -is [Microsoft.SqlServer.TransactSql.ScriptDom.VariableReference] })) {
            $LengthSizeForVariableReference = 0
            $UserDataTypeName = ""
            $VarName = $VariableReference.Name
            $VarDecls = $vResults.Values | Where-Object { $_ -is [Microsoft.SqlServer.TransactSql.ScriptDom.DeclareVariableStatement] }
            $VarDecls = $VarDecls.Declarations | Where-Object { $_.VariableName.Value -eq $VarName } | Sort-Object StartOffset -Descending | Select-Object -First 1
            if ($null -eq $VarDecls) {
                $VarDecls = $vResults.Values | Where-Object { $_ -is [Microsoft.SqlServer.TransactSql.ScriptDom.ProcedureParameter] }
                $VarDecls = $VarDecls | Where-Object { $_.VariableName.Value -eq $VarName } | Sort-Object StartOffset -Descending | Select-Object -First 1
            }
            if ($null -ne $VarDecls) {
                $VarSize = $null
                $VarSize = Get-DataTypeCharacterSize -VarDecls $VarDecls
                $UserDataTypeName = $VarDecls.DataType.Name.BaseIdentifier.Value
                $LengthSizeForVariableReference = [int]$VarSize
            }
            Write-Msg -Message "    | Variable used in the dynamic exec: $VarName $UserDataTypeName($($VarSize))" -VerboseMsg
            # If variable size is 2147483647, it means it is a varchar(max) or nvarchar(max)
            # In this case, ignore the variable size check
            if ($VarSize -in @(2147483647, 4000, 8000)){
                Write-Msg -Message "        | Variable size is 4000/8000/2147483647, ignoring buffer size check" -VerboseMsg
                continue
            }
            Write-Msg -Message "        | Starting to calculate buffer required to avoid SQL Injection by data truncation" -VerboseMsg -Level Starting
            $BufferCheckStartTime = Get-Date
            # $BufferCheckStartTime = Get-Date

            # Find the last assignment for the variable used on exec
            $LastAssignment = $null
            $LastAssignment = Get-LastVariableAssignment -VarName $VarName -vResults $vResults -ExecExpression $VariableReference
            if ($null -eq $LastAssignment) {
                $LastAssignment = $vResults.Values | Where-Object { $_ -is [Microsoft.SqlServer.TransactSql.ScriptDom.ProcedureParameter] }
                $LastAssignment = $LastAssignment | Where-Object { $_.VariableName.Value -eq $VarName }
            }
            if ($null -ne $LastAssignment) {
                Write-Msg -Message "        | Found the last assignment for $VarName at line $($LastAssignment.StartLine), assigned with a $($LastAssignment.GetType().Name)" -VerboseMsg
            }
            else {
                Write-Msg -Message "        | No last assignment found for $VarName, skipping buffer size check" -VerboseMsg
                continue
            }

            # Visit expression used to assign the variable used on exec
            # to get all string literals and variable references
            $VisitLastAssignmentVariableAndStringReferenceResults = $null
            $VisitVariableAndStringReference2 = [VisitVariableAndStringReference]::new()
            $LastAssignment.Accept($VisitVariableAndStringReference2)
            $VisitLastAssignmentVariableAndStringReferenceResults = $VisitVariableAndStringReference2.GetVisitorResults()

            $FragmentID = ""
            if ($LastAssignment -is [Microsoft.SqlServer.TransactSql.ScriptDom.DeclareVariableElement]) {
                $FragmentID = "$($LastAssignment.VariableName.GetType().Name)-$($LastAssignment.VariableName.StartOffset)-$($LastAssignment.VariableName.FragmentLength)"
            }
            elseif($LastAssignment -is [Microsoft.SqlServer.TransactSql.ScriptDom.SelectSetVariable] -or $LastAssignment -is [Microsoft.SqlServer.TransactSql.ScriptDom.SetVariableStatement]) {
                $FragmentID = "$($LastAssignment.Variable.GetType().Name)-$($LastAssignment.Variable.StartOffset)-$($LastAssignment.Variable.FragmentLength)"
            }
            # Ignore the variable used in the exec, I mean, the one being assigned
            $VisitLastAssignmentVariableAndStringReferenceResults.Remove($FragmentID)

            class VisitAllFunctionCalls : Microsoft.SqlServer.TransactSql.ScriptDom.TSqlFragmentVisitor {
                $VisitorResults = @{}
                [System.Collections.Hashtable] GetVisitorResults() {
                    return $this.VisitorResults
                }
                [void] ExplicitVisit([Microsoft.SqlServer.TransactSql.ScriptDom.FunctionCall] $Fragment) {
                    $FragmentID = "$($Fragment.GetType().Name)-$($Fragment.StartOffset)-$($Fragment.FragmentLength)"
                    if (-not $this.VisitorResults.ContainsKey($FragmentID)) {
                        $this.VisitorResults[$FragmentID] = $Fragment
                    }
                    $Fragment.AcceptChildren($this)
                }
            }  
            # Visit expression used to assign the variable used on exec
            # to get all function calls
            $AllFunctionCallResults = $null
            $AllFunctionCalls = [VisitAllFunctionCalls]::new()
            $LastAssignment.Accept($AllFunctionCalls)
            $AllFunctionCallResults = $AllFunctionCalls.GetVisitorResults()

            $FinalVariableAndStringReferenceResults = @()
            # Removing all string literals from FinalVariableAndStringReferenceResults that were used inside a function call
            foreach ($StringLiteral in $VisitLastAssignmentVariableAndStringReferenceResults.Values | Where-Object { $_ -is [Microsoft.SqlServer.TransactSql.ScriptDom.StringLiteral] }) {
                $IsInsideFunctionCall = $false
                foreach ($FunctionCall in $AllFunctionCallResults.Values) {
                    if ($StringLiteral.FirstTokenIndex -gt $FunctionCall.FirstTokenIndex -and $StringLiteral.LastTokenIndex -lt $FunctionCall.LastTokenIndex) {
                        $IsInsideFunctionCall = $true
                        break
                    }
                }
                if ($IsInsideFunctionCall -eq $false) {
                    # Add string literal that is not inside a function call
                    $FinalVariableAndStringReferenceResults += $StringLiteral
                }
            }
            # Add all variable references into the final list
            $FinalVariableAndStringReferenceResults += $VisitLastAssignmentVariableAndStringReferenceResults.Values | Where-Object { $_ -is [Microsoft.SqlServer.TransactSql.ScriptDom.VariableReference] }

            # Data truncation can happen when the string literal is larger than the variable size
            # or when the variable is larger than the string literal
            # This will only happen if the expression used to assign the variable has some concatentations
            # So, ignoring if the number of strings and variables is 1
            if ($FinalVariableAndStringReferenceResults.Count -eq 1) {
                Write-Msg -Message "        | Only one string literal or variable used in the assignment, skipping buffer size check" -VerboseMsg
                continue
            }

            # Loop through all string literals and sum the string literal size of all literals used on last assignment
            $LengthSizeForAllStringLiterals = 0
            foreach ($StringLiteral in $FinalVariableAndStringReferenceResults | Where-Object { $_ -is [Microsoft.SqlServer.TransactSql.ScriptDom.StringLiteral] } | Sort-Object StartOffset) {
                if ($StringLiteral.Value -eq "") {
                    # If the string literal is empty, ignore it
                    continue
                }

                $StringLiteralValueLimitedTo50char = $StringLiteral.Value
                if ($StringLiteral.Value.Length -gt 50) {
                    $StringLiteralValueLimitedTo50char = $StringLiteral.Value.Substring(0, 50) + "..."
                }
                $StringLiteralValueLimitedTo50char = $StringLiteralValueLimitedTo50char -replace "`r`n", " "
                $LengthSizeForAllStringLiterals += $StringLiteral.Value.Length
                Write-Msg -Message "        | Size: $($StringLiteral.Value.Length) | String Ref: {$StringLiteralValueLimitedTo50char}" -VerboseMsg
            }
            if ($LengthSizeForAllStringLiterals -gt 0) {
                Write-Msg -Message "        | Total size of all ($(($FinalVariableAndStringReferenceResults | Where-Object { $_ -is [Microsoft.SqlServer.TransactSql.ScriptDom.StringLiteral] }).Count)) string literals used in the last assignment for $($Varname): $LengthSizeForAllStringLiterals" -VerboseMsg
            }

            # Loop through all variable references and sum the variable buffer size of all variables used on last assignment
            $LengthSizeForAllVariableReferences = 0
            foreach ($VariableReference in ($FinalVariableAndStringReferenceResults | Where-Object { $_ -is [Microsoft.SqlServer.TransactSql.ScriptDom.VariableReference] } | Sort-Object StartOffset)) {
                $VarName2 = $VariableReference.Name
                $VarDecls2 = $vResults.Values | Where-Object { $_ -is [Microsoft.SqlServer.TransactSql.ScriptDom.DeclareVariableStatement] }
                $VarDecls2 = $VarDecls2.Declarations | Where-Object { $_.VariableName.Value -eq $VarName2 } | Sort-Object StartOffset -Descending | Select-Object -First 1
                if ($null -eq $VarDecls2) {
                    $VarDecls2 = $vResults.Values | Where-Object { $_ -is [Microsoft.SqlServer.TransactSql.ScriptDom.ProcedureParameter] }
                    $VarDecls2 = $VarDecls2 | Where-Object { $_.VariableName.Value -eq $VarName2 } | Sort-Object StartOffset -Descending | Select-Object -First 1
                }
                if ($null -ne $VarDecls2) {
                    $VarSize2 = Get-DataTypeCharacterSize -VarDecls $VarDecls2
                    $UserDataTypeName2 = $VarDecls2.DataType.Name.BaseIdentifier.Value
                    # If the variable was used inside a function call, check if it was QUOTENAME
                    foreach ($FunctionCall in $AllFunctionCallResults.Values) {
                        if ($VariableReference.FirstTokenIndex -gt $FunctionCall.FirstTokenIndex -and $VariableReference.LastTokenIndex -lt $FunctionCall.LastTokenIndex) {
                            if ($FunctionCall.FunctionName.Value -eq "QUOTENAME") {
                                if ($VarSize2 -lt 258){
                                    # If the variable size is less than 258, double the size and add 2
                                    # This is because QUOTENAME adds 2 to the size of the string, which are the brackets
                                    $VarSize2 = ($VarSize2 * 2) + 2
                                    if ($VarSize2 -gt 258){
                                        $VarSize2 = 258
                                    }
                                    Write-Msg -Message "        | Variable $($VarName2) is used inside a QUOTENAME function call, adding (*2)+2 to the size" -VerboseMsg
                                }
                            }
                        }
                    }
                    $LengthSizeForAllVariableReferences += [int]$VarSize2
                }
                Write-Msg -Message "        | Variable used in the last assignment: $($VarName2) $UserDataTypeName2($($VarSize2))" -VerboseMsg
            }
            if ($LengthSizeForAllVariableReferences -gt 0) {
                Write-Msg -Message "        | Total size of all ($(($FinalVariableAndStringReferenceResults | Where-Object { $_ -is [Microsoft.SqlServer.TransactSql.ScriptDom.VariableReference] }).Count)) variables used in the last assignment for $($Varname): $($LengthSizeForAllVariableReferences)" -VerboseMsg
            }
            # Calculate the total size required to store all possible characters in the string literals and variable references used in the last assignment
            $TotalRequiredSize = $LengthSizeForAllStringLiterals + $LengthSizeForAllVariableReferences
            if ($TotalRequiredSize -gt $LengthSizeForVariableReference) {
                $Comment = "        | Buffer size for variable $($VarName) is not enough to data truncation, required size: $TotalRequiredSize ($LengthSizeForAllStringLiterals + $LengthSizeForAllVariableReferences), available size: $LengthSizeForVariableReference"
                Write-Msg -Message $Comment -VerboseMsg -Level Warning
                if ($ReportBuyfferSizeVuln) {
                    Add-ExecVulnerability -Fragment $VariableReference -Msg $Comment
                }
            }
            else{
                $Comment = "        | All good, buffer size for variable $($VarName) is enough to avoid data truncation, required size: $TotalRequiredSize ($LengthSizeForAllStringLiterals + $LengthSizeForAllVariableReferences), available size: $LengthSizeForVariableReference"
                Write-Msg -Message $Comment -VerboseMsg
            }
            Write-Msg -Message "        | Finished to calculate buffer required to avoid SQL Injection by data truncation" -VerboseMsg -Level Finished

            # # Checking assignments for the variables referenced in the last assignment
            # # Check if their assignment are ok, references to broken (with not enough buffer) variables can break the code
            # foreach ($VariableReference in ($FinalVariableAndStringReferenceResults | Where-Object { $_ -is [Microsoft.SqlServer.TransactSql.ScriptDom.VariableReference] } | Sort-Object StartOffset)) {
            #     $VarName2 = $VariableReference.Name
            #     $Result = Get-FindLastAssignmentAndValidadeBufferSize -VarName $VarName2 -vResults $vResults
            # }
            
            $BufferCheckTime = ((Get-Date) - $BufferCheckStartTime).TotalMilliseconds
            Write-Msg -Message "        | Finished to calculate buffer required (Duration: $BufferCheckTime ms)" -VerboseMsg -Level Finished
            $Global:OperationTimers['BufferSizeChecking'] += $BufferCheckTime
        }

        # Foreach variable and string reference, check the expressions
        $StringsCheckStartTime = Get-Date
        if ($null -ne $VisitVariableAndStringReferenceResults){
            foreach ($key in $VisitVariableAndStringReferenceResults.Keys) {
                $Fragment = $VisitVariableAndStringReferenceResults[$key]
                if ($Fragment -is [Microsoft.SqlServer.TransactSql.ScriptDom.StringLiteral]) {
                    if ($Fragment.Value.Length -gt 50) {
                        $FragmentValueLimitedTo50char = $Fragment.Value.Substring(0, 50) + "..."
                    }
                    else {
                        $FragmentValueLimitedTo50char = $Fragment.Value
                    }
                    # Remove line breaks from the string literal
                    $FragmentValueLimitedTo50char = $FragmentValueLimitedTo50char -replace "`r`n", " "
                    Write-Msg -Message "    | Checking $($Fragment.GetType().Name): {$FragmentValueLimitedTo50char}" -VerboseMsg -Level Starting
                    
                    # Skip checking if string literal exceeds maximum length to improve performance
                    if ($Fragment.Value.Length -gt $Global:MaximumStringLength) {
                        Write-Msg -Message "    | String literal size ($($Fragment.Value.Length)) exceeds MaximumStringLength ($Global:MaximumStringLength), skipping check for performance reasons" -VerboseMsg -Level Warning
                        Write-Msg -Message "    | Finished to check $($Fragment.GetType().Name): {$FragmentValueLimitedTo50char}" -VerboseMsg  -Level Finished
                        continue
                    }
                    
                    # Check if the string literal was already checked
                    $hashValue = ""
                    $hashProvider = [System.Security.Cryptography.SHA1CryptoServiceProvider]::new()
                    $hashValue = [Convert]::ToBase64String($hashProvider.ComputeHash([System.Text.Encoding]::Unicode.GetBytes($Fragment.Value)))
                    if (-Not ($Global:StringsChecked.ContainsKey($hashValue))) {
                        # Check for DML and DDL events in the string literal and add it on DDL and DML events list if found
                        foreach ($DMLKeyword in $Global:DMLKeywords) {
                            # (?i) → ignore case
                            $escaped = '(?i)' + [regex]::Escape($DMLKeyword)
                            if ($Fragment.Value -match $escaped) {
                                if ($ReportTriggerVuln) {
                                    $Msg = "        | DML keyword found in string literal: keyword: $DMLKeyword"
                                    Write-Msg -Message $Msg -VerboseMsg -Level Warning
                                    # Add-TSqlCheckResult -Message $Msg
                                    Add-ExecVulnerability -Fragment $Fragment -Msg $Msg -VulnerabilityType "Trigger permission hijacking" -ReportTriggerVuln $true
                                    break
                                }
                            }
                        }
                        foreach ($DDLKeyword in $Global:DDLKeywords) {
                            # (?i) → ignore case
                            $escaped = '(?i)' + [regex]::Escape($DDLKeyword)
                            if ($Fragment.Value -match $escaped) {
                                if ($ReportTriggerVuln) {
                                    $Msg = "        | DDL keyword found in string literal: keyword: $DDLKeyword"
                                    Write-Msg -Message $Msg -VerboseMsg -Level Warning
                                    # Add-TSqlCheckResult -Message $Msg
                                    Add-ExecVulnerability -Fragment $Fragment -Msg $Msg -VulnerabilityType "Trigger permission hijacking" -ReportTriggerVuln $true
                                    break
                                }
                            }
                        }

                        # Check if the string literal is a safe expression
                        # Look for suspicious patterns
                        $FoundSuspiciousPattern = $false
                        $suspiciousPatterns = @("］", "ʼ", "xp_cmdshell", "xp_execresultset", "xp_sprintf", "xp_subdirs", "xp_cmdshell_proxy_account")
                        foreach ($pattern in $suspiciousPatterns) {
                            # (?i) → ignore case
                            $escaped = '(?i)' + [regex]::Escape($pattern)
                            if ($Fragment.Value -match $escaped) {
                                $SafeOrUnsafeReason = "Unsafe, suspicious pattern for string literal: pattern: $pattern"
                                Write-Msg -Message $SafeOrUnsafeReason -VerboseMsg -Level Warning
                                Add-ExecVulnerability -Fragment $Fragment -Msg $SafeOrUnsafeReason
                                # Add the hash value to the list of checked strings
                                $Global:StringsChecked[$hashValue] = [PSCustomObject]@{
                                    Fragment = $Fragment
                                    IsSafe = $false
                                    SafeOrUnsafeReason = $SafeOrUnsafeReason
                                }
                                $FoundSuspiciousPattern = $true
                                break
                            }
                            else {
                                # Add the hash value to the list of checked strings
                                $Global:StringsChecked[$hashValue] = [PSCustomObject]@{
                                    Fragment = $Fragment
                                    IsSafe = $false
                                    SafeOrUnsafeReason = $SafeOrUnsafeReason
                                }
                            }
                        }
                        if ($FoundSuspiciousPattern -eq $false){
                            Write-Msg -Message "    | Safe, string expression" -VerboseMsg
                        }                        
                    }
                    else{
                        Write-Msg -Message "    | Already checked this string literal, skipping..." -VerboseMsg
                    }
                    Write-Msg -Message "    | Finished to check $($Fragment.GetType().Name): {$FragmentValueLimitedTo50char}" -VerboseMsg  -Level Finished
                }
                elseif ($Fragment -is [Microsoft.SqlServer.TransactSql.ScriptDom.VariableReference]) {
                    Write-Msg -Message "    | Checking $($Fragment.GetType().Name): $($Fragment.Name), used on line $($Fragment.StartLine), column position $($Fragment.StartColumn)" -VerboseMsg -Level Starting
                    # Find the variable declaration
                    $VarName = $Fragment.Name
                    # Check if the variable was already checked
                    if (-Not ($Global:VariablesChecked.ContainsKey($VarName))) {
                        $VarDecls = $vResults.Values | Where-Object { $_ -is [Microsoft.SqlServer.TransactSql.ScriptDom.DeclareVariableStatement] }
                        $VarDecls = $VarDecls.Declarations | Where-Object { $_.VariableName.Value -eq $VarName } | Sort-Object StartOffset -Descending | Select-Object -First 1
                        if ($null -eq $VarDecls) {
                            $VarDecls = $vResults.Values | Where-Object { $_ -is [Microsoft.SqlServer.TransactSql.ScriptDom.ProcedureParameter] }
                            $VarDecls = $VarDecls | Where-Object { $_.VariableName.Value -eq $VarName } | Sort-Object StartOffset -Descending | Select-Object -First 1
                        }
                        if ($null -ne $VarDecls) {
                            $StringDataTypes = @("NVARCHAR", "VARCHAR", "CHAR", "NCHAR", "TEXT", "NTEXT", "XML")
                            if ($StringDataTypes -notcontains $VarDecls.DataType.SqlDataTypeOption -and $VarDecls.DataType -isnot [Microsoft.SqlServer.TransactSql.ScriptDom.UserDataTypeReference]) {
                                # If the variable is not a string type, mark as safe
                                $SafeOrUnsafeReason = "        | Safe assignment, variable is not a string type"
                                Write-Msg -Message $SafeOrUnsafeReason -VerboseMsg
                                $Global:VariablesChecked[$VarName] = [PSCustomObject]@{
                                    Fragment = $Fragment
                                    IsSafe = $false
                                    SafeOrUnsafeReason = $SafeOrUnsafeReason
                                }
                                Write-Msg -Message "    | Finished to check $($Fragment.GetType().Name): $($Fragment.Name)" -VerboseMsg  -Level Finished
                                continue
                            }
                        }
                        # Check the last/previous variable assignment in the script
                        $LastAssignment = $null
                        $LastAssignment = Get-LastVariableAssignment -VarName $VarName -vResults $vResults -ExecExpression $Fragment
                        if ($null -ne $LastAssignment) {
                            Write-Msg -Message "        | Found the last assignment for $VarName at line $($LastAssignment.StartLine), assigned with a $($LastAssignment.GetType().Name)" -VerboseMsg
                        }
                        # If the last assignment is not found, check if it is a input parameter
                        if ($null -eq $LastAssignment) {
                            $LastAssignment = $vResults.Values | Where-Object { $_ -is [Microsoft.SqlServer.TransactSql.ScriptDom.ProcedureParameter] }
                            $LastAssignment = $LastAssignment | Where-Object { $_.VariableName.Value -eq $VarName }
                            if ($null -ne $LastAssignment) {
                                $UserDataTypeName = $LastAssignment.DataType.Name.BaseIdentifier.Value
                                $StringDataTypes = @("NVARCHAR", "VARCHAR", "CHAR", "NCHAR", "TEXT", "NTEXT", "XML")
                                if (($StringDataTypes -contains $LastAssignment.DataType.SqlDataTypeOption -or $UserDataTypeName -eq "SYSNAME")) {
                                    # If the input parameter is a string type
                                    # Mark as unsafe and return
                                    $SafeOrUnsafeReason = "        | Unsafe, expression using an input parameter defined as a string data type: $VarName"
                                    Write-Msg -Message $SafeOrUnsafeReason -VerboseMsg -Level Warning
                                    Add-ExecVulnerability -Fragment $Fragment -Msg $SafeOrUnsafeReason
                                    $Global:VariablesChecked[$VarName] = [PSCustomObject]@{
                                        Fragment = $Fragment
                                        IsSafe = $false
                                        SafeOrUnsafeReason = $SafeOrUnsafeReason
                                    }
                                    Write-Msg -Message "    | Finished to check $($Fragment.GetType().Name): $($Fragment.Name)" -VerboseMsg  -Level Finished
                                    continue
                                }
                                else{
                                    # If the input parameter is not a string type, mark as safe
                                    $SafeOrUnsafeReason = "        | Safe, expression using a safe input parameter: $VarName"
                                    Write-Msg -Message $SafeOrUnsafeReason -VerboseMsg
                                    $Global:VariablesChecked[$VarName] = [PSCustomObject]@{
                                        Fragment = $Fragment
                                        IsSafe = $true
                                        SafeOrUnsafeReason = $SafeOrUnsafeReason
                                    }
                                    Write-Msg -Message "    | Finished to check $($Fragment.GetType().Name): $($Fragment.Name)" -VerboseMsg  -Level Finished
                                    continue
                                }
                            }
                        }
                        # If the last assignment is found, check if it is a safe expression
                        if ($null -ne $LastAssignment) {
                            if ($LastAssignment -is [Microsoft.SqlServer.TransactSql.ScriptDom.SelectSetVariable] -or $LastAssignment -is [Microsoft.SqlServer.TransactSql.ScriptDom.SetVariableStatement]) {
                                $Expression = $LastAssignment.Expression
                            }
                            elseif ($LastAssignment -is [Microsoft.SqlServer.TransactSql.ScriptDom.AssignmentSetClause]) {
                                $Expression = $LastAssignment.NewValue
                            }
                            elseif ($LastAssignment -is [Microsoft.SqlServer.TransactSql.ScriptDom.FetchCursorStatement]) {
                                $UnsafeReported = $false
                                $CursorDefinitions = $vResults.Values | Where-Object { $_ -is [Microsoft.SqlServer.TransactSql.ScriptDom.DeclareCursorStatement] }
                                $CursorDefinitions = $CursorDefinitions | Where-Object { $_.Name.Value -eq $LastAssignment.Cursor.Name.Value }
                                $CursorDefinitions = $CursorDefinitions | Where-Object { $_.StartLine -le $LastAssignment.StartLine }
                                # If there is more than one definition for the same cursor, consider  the last one
                                $CursorDefinitions = $CursorDefinitions | Sort-Object StartOffset -Descending | Select-Object -First 1

                                if ($null -eq $CursorDefinitions) {
                                    # If we couldn't find the cursor definition, check if it was declared in a set variable statement
                                    $CursorDefinitions = $vResults.Values | Where-Object { $_ -is [Microsoft.SqlServer.TransactSql.ScriptDom.SetVariableStatement] }
                                    $CursorDefinitions = $CursorDefinitions | Where-Object { $_.Variable.Name -eq $LastAssignment.Cursor.Name.Value }
                                    $CursorDefinitions = $CursorDefinitions | Where-Object { $_.StartLine -le $LastAssignment.StartLine }
                                    # If there is more than one definition for the same cursor, consider the last one
                                    $CursorDefinitions = $CursorDefinitions | Sort-Object StartOffset -Descending | Select-Object -First 1                                    
                                }
                                if ($null -eq $CursorDefinitions) {
                                    $SafeOrUnsafeReason = "        | No cursor definition found for cursor $($LastAssignment.Cursor.Name.Value), assuming fetch is safe."
                                    Write-Msg -Message $SafeOrUnsafeReason -VerboseMsg
                                    $Global:VariablesChecked[$VarName] = [PSCustomObject]@{
                                        Fragment = $Fragment
                                        IsSafe = $true
                                        SafeOrUnsafeReason = $SafeOrUnsafeReason
                                    }
                                    Write-Msg -Message "    | Finished to check $($Fragment.GetType().Name): $($Fragment.Name)" -VerboseMsg  -Level Finished
                                    continue
                                }
                                else {
                                    # If the number of elements in the cursor definition is 0, it is probably a SelectStarElement, in that case, I can't 
                                    # check if it is safe or not
                                    $expr = $CursorDefinitions.CursorDefinition.Select.QueryExpression
                                    while ($expr -is [Microsoft.SqlServer.TransactSql.ScriptDom.BinaryQueryExpression]) {
                                        $expr = $expr.FirstQueryExpression
                                    }
                                    $CursorDefinitions.CursorDefinition.Select.QueryExpression = $expr

                                    if ($null -ne $CursorDefinitions.CursorDefinition.Select.QueryExpression.SelectElements){
                                        if ($CursorDefinitions.CursorDefinition.Select.QueryExpression.SelectElements[0] -is [Microsoft.SqlServer.TransactSql.ScriptDom.SelectStarExpression]) {
                                            $SafeOrUnsafeReason = "        | Cursor definition is a SelectStarElement, assuming fetch is unsafe."
                                            Write-Msg -Message $SafeOrUnsafeReason -VerboseMsg -Level Warning
                                            Add-ExecVulnerability -Fragment $Fragment -Msg $SafeOrUnsafeReason
                                            $Global:VariablesChecked[$VarName] = [PSCustomObject]@{
                                                Fragment = $Fragment
                                                IsSafe = $false
                                                SafeOrUnsafeReason = $SafeOrUnsafeReason
                                            }
                                            $UnsafeReported = $true
                                            continue
                                        } 
                                    }
                                    # If the cursor definition is found, check if it is a safe expression
                                    $i = 0
                                    # Find the expression in the cursor definition
                                    foreach ($Var_Row in $LastAssignment.IntoVariables) {
                                        if ($Var_Row.Name -eq $VarName) {
                                            $Expression = $null
                                            if ($null -ne $CursorDefinitions.CursorDefinition.Select.QueryExpression.SelectElements){
                                                if (($null -eq $CursorDefinitions.CursorDefinition.Select.QueryExpression.SelectElements[$i]) -or ($CursorDefinitions.CursorDefinition.Select.QueryExpression.SelectElements[$i] -isnot [Microsoft.SqlServer.TransactSql.ScriptDom.SelectScalarExpression])) {
                                                    $SafeOrUnsafeReason = "        | Couldn't identify the expression type used ($($CursorDefinitions.CursorDefinition.Select.QueryExpression.SelectElements[$i].GetType().Name)) in the cursor $($LastAssignment.Cursor.Name.Value), assuming fetch is unsafe."
                                                    Write-Msg -Message $SafeOrUnsafeReason -VerboseMsg -Level Warning
                                                    Add-ExecVulnerability -Fragment $Fragment -Msg $SafeOrUnsafeReason
                                                    $Global:VariablesChecked[$VarName] = [PSCustomObject]@{
                                                        Fragment = $Fragment
                                                        IsSafe = $false
                                                        SafeOrUnsafeReason = $SafeOrUnsafeReason
                                                    }
                                                    $UnsafeReported = $true
                                                    continue
                                                }
                                                else{
                                                    $Expression = $CursorDefinitions.CursorDefinition.Select.QueryExpression.SelectElements[$i].Expression
                                                }
                                            }
                                            elseif ($null -ne $CursorDefinitions.CursorDefinition.Select.QueryExpression.QueryExpression.SelectElements){
                                                $Expression = $CursorDefinitions.CursorDefinition.Select.QueryExpression.QueryExpression.SelectElements[$i].Expression
                                            }
                                            break
                                        }
                                        $i++
                                    }
                                    if ($UnsafeReported -eq $true){
                                        Write-Msg -Message "    | Finished to check $($Fragment.GetType().Name): $($Fragment.Name)" -VerboseMsg  -Level Finished
                                        continue
                                    }
                                    # If the expression is not found, mark as unsafe
                                    if ($null -eq $Expression) {
                                        $SafeOrUnsafeReason = "        | No cursor definition found for cursor $($LastAssignment.Cursor.Name.Value), assuming fetch is unsafe."
                                        Write-Msg -Message $SafeOrUnsafeReason -VerboseMsg -Level Warning
                                        Add-ExecVulnerability -Fragment $Fragment -Msg $SafeOrUnsafeReason
                                        $Global:VariablesChecked[$VarName] = [PSCustomObject]@{
                                            Fragment = $Fragment
                                            IsSafe = $false
                                            SafeOrUnsafeReason = $SafeOrUnsafeReason
                                        }
                                        $UnsafeReported = $true
                                    }
                                }
                            }
                            elseif ($LastAssignment -is [Microsoft.SqlServer.TransactSql.ScriptDom.DeclareVariableStatement] -or $LastAssignment -is [Microsoft.SqlServer.TransactSql.ScriptDom.DeclareVariableElement]) {
                                $Expression = $LastAssignment.Value
                                if ($null -eq $Expression) {
                                    $SafeOrUnsafeReason = "        | Safe assignment, no default value assigned"
                                    Write-Msg -Message "$SafeOrUnsafeReason" -VerboseMsg
                                    $Global:VariablesChecked[$VarName] = [PSCustomObject]@{
                                        Fragment = $Fragment
                                        IsSafe = $true
                                        SafeOrUnsafeReason = $SafeOrUnsafeReason
                                    }
                                    Write-Msg -Message "    | Finished to check $($Fragment.GetType().Name): $($Fragment.Name)" -VerboseMsg  -Level Finished
                                    continue
                                }
                                # I was ignoring non-string types, but there are some cases where a variable  may be converted into a string... for instance DB_NAME(@DBID)...
                                # So, I still need to check non-string variables...
                                # $StringDataTypes = @("NVARCHAR", "VARCHAR", "CHAR", "NCHAR", "TEXT", "NTEXT", "XML")
                                # if (($StringDataTypes -notcontains $LastAssignment.DataType.SqlDataTypeOption) -and ($LastAssignment.DataType -isnot [Microsoft.SqlServer.TransactSql.ScriptDom.UserDataTypeReference])) {
                                #     $SafeOrUnsafeReason = "        | Safe assignment, variable is not a string type"
                                #     Write-Msg -Message "$SafeOrUnsafeReason" -VerboseMsg
                                #     $Global:VariablesChecked[$VarName] = [PSCustomObject]@{
                                #         Fragment = $Fragment
                                #         IsSafe = $true
                                #         SafeOrUnsafeReason = $SafeOrUnsafeReason
                                #     }
                                #     Write-Msg -Message "    | Finished to check $($Fragment.GetType().Name): $($Fragment.Name)" -VerboseMsg  -Level Finished
                                #     continue
                                # }
                            }
                            elseif ($LastAssignment -is [Microsoft.SqlServer.TransactSql.ScriptDom.ExecuteStatement]) {
                                # If the variable is assigned via an Execute statement, I need to check if it is using sp_MSguidtostr, which is a safe function that returns a string type, 
                                # if so, I can consider it safe, otherwise, I have to consider it unsafe, since I don't know how the variable is being assigned inside the execute statement
                                $ProcName = $LastAssignment.ExecuteSpecification.ExecutableEntity.ProcedureReference.ProcedureReference.Name.BaseIdentifier.Value
                                if ($ProcName -in @("sp_MSguidtostr", "sp_hexadecimal")) {
                                    continue
                                }                                
                                # if the variable is assigned via an Execute statement, mark as unsafe
                                $IsSafe = $false
                                $SafeOrUnsafeReason = "Unsafe, variable assigned via Execute->Output statement. Since I don't know how this was assigned inside the execute, assuming unsafe."
                                Write-Msg -Message "$($Ident + "    " + "| ")$($SafeOrUnsafeReason)" -VerboseMsg -Level Warning
                                Add-ExecVulnerability -Fragment $Fragment -Msg $SafeOrUnsafeReason
                                $Global:VariablesChecked[$VarName] = [PSCustomObject]@{
                                    Fragment = $Fragment
                                    IsSafe = $IsSafe
                                    SafeOrUnsafeReason = $SafeOrUnsafeReason
                                }
                                $UnsafeReported = $true
                                continue
                            }
                            # Check if the expression is safe
                            $GetCheckExpressionResults = Get-CheckExpression -Expression $Expression -vResults $vResults -VarOnExec $VarName -DataTypeVarOnExec $UserDataTypeName -Depth 2
                            foreach ($GetCheckExpressionResults_Row in $GetCheckExpressionResults.Values | Where-Object { $_.IsSafe -eq $false }) {
                                Add-ExecVulnerability -Fragment $GetCheckExpressionResults_Row.Fragment -Msg $GetCheckExpressionResults_Row.SafeOrUnsafeReason
                            }
                            $Global:VariablesChecked[$VarName] = [PSCustomObject]@{
                                        Fragment = $Fragment
                                        IsSafe = $null
                                        SafeOrUnsafeReason = $null
                            }
                        }
                    }
                    else{
                        Write-Msg -Message "        | Already checked this variable, skipping..." -VerboseMsg
                    }
                    Write-Msg -Message "    | Finished to check $($Fragment.GetType().Name): $($Fragment.Name)" -VerboseMsg  -Level Finished
                }
            }
        }
        $StringsCheckTime = ((Get-Date) - $StringsCheckStartTime).TotalMilliseconds
        if ($StringsCheckTime -gt 0) {
            Write-Msg -Message "    | String and Variable checking completed (Duration: $StringsCheckTime ms)" -VerboseMsg
            $Global:OperationTimers['StringLiteralChecking'] += $StringsCheckTime
        }
        $DynamicExecTime = ((Get-Date) - $DynamicExecStartTime).TotalMilliseconds
        Write-Msg -Message "Finished to check dynamic execution on line $($ExecStatement_Row.StartLine) (Duration: $DynamicExecTime ms)" -VerboseMsg -Level Finished
        $Global:OperationTimers['DynamicExecProcessing'] += $DynamicExecTime
    }
    return
}

function Invoke-TSqlChecks([string] $InputText, [switch] $ShowVerboseMessages = $false, [switch]$CheckForPasswords = $false, [switch]$ReportBuyfferSizeVuln = $false, [switch]$ReportTriggerVuln = $false, [int] $MaximumStringLength = 200000) {
    $script:TraceBuffer  = @()   # collects messages for the *current* check
    $Global:TSqlCheckResults = @()
    $Global:ShowVerboseMessages = $ShowVerboseMessages
    $Global:MaximumStringLength = $MaximumStringLength
    
    # Initialize execution timers - fresh for each execution
    $Global:ExecutionTimers = @{
        'TotalExecution' = [datetime]::Now
        'ParseTime' = 0
        'SQLInjectionCheckTime' = 0
        'PasswordCheckTime' = 0
    }
    
    # Initialize operation timers - fresh for each execution
    $Global:OperationTimers = @{
        'VisitorTraversal' = 0
        'DynamicExecProcessing' = 0
        'BufferSizeChecking' = 0
        'StringLiteralChecking' = 0
    }
    
    if ([string]::IsNullOrEmpty($InputText)) {
        $Global:TSqlCheckResults += [PsCustomObject]@{
            Message = "Empty SQL Statement"
            Trace = ""
        }
        return $Global:TSqlCheckResults
    }

    try {

        Write-Msg -Message "Input text length: $($InputText.Length) characters" -VerboseMsg -Level Output

        # # If number of characters exceeds maximum length, skip the checks
        # if ($InputText.Length -gt $Global:MaximumStringLength) {
        #     $Msg = "Input text length ($($InputText.Length) characters) exceeds MaximumStringLength ($Global:MaximumStringLength), skipping T-SQL checks for performance reasons"
        #     Write-Msg -Message $Msg -Level Warning
        #     Add-TSqlCheckResult -Message $Msg
        #     return $Global:TSqlCheckResults
        # }

        # Do some cleanup in the input statement to parse XML (whoisactive results), QueryStore and CachePlan queries.
        Write-Msg -Message "Running CleanUpAndParseTSqlText..." -VerboseMsg -Level Starting
        $ParseStartTime = Get-Date
        $CleanUpAndParseTSqlTextResult = Get-CleanUpAndParseTSqlText -InputText $InputText
        $Global:ExecutionTimers['ParseTime'] = ((Get-Date) - $ParseStartTime).TotalMilliseconds
        Write-Msg -Message "Finished to run CleanUpAndParseTSqlText... (Duration: $($Global:ExecutionTimers['ParseTime']) ms)" -VerboseMsg -Level Finished
        
        $InputText = $CleanUpAndParseTSqlTextResult.InputText
        $Tree = $CleanUpAndParseTSqlTextResult.Tree
        $Errors = $CleanUpAndParseTSqlTextResult.Errors

        # If there were no errors, go ahead and run the checks
        if ($Errors.Count -eq 0) {
            $SQLInjectionCheckStartTime = Get-Date
            foreach ($Batch in ($Tree -as [Microsoft.SqlServer.TransactSql.ScriptDom.TSqlScript]).Batches) {
                $Global:TSqlCheckResults = @()
                Write-Msg -Message "Running TSQL Checks on Batch starting on line $($Batch.StartLine)..." -VerboseMsg -Level Starting

                # Check for SQL Injection
                Invoke-SQLInjectionCheck -TSqlFragment $Batch -StatementRef $InputText -ReportTriggerVuln $ReportTriggerVuln

                Write-Msg -Message "Finished to run TSQL Checks on Batch starting on line $($Batch.StartLine)..." -VerboseMsg -Level Finished
            }
            $Global:ExecutionTimers['SQLInjectionCheckTime'] = ((Get-Date) - $SQLInjectionCheckStartTime).TotalMilliseconds

            # Check for leaked passwords in the t-sql
            if ($CheckForPasswords -eq $true) {
                Write-Msg -Message "Checking for potential passwords in the t-sql..." -VerboseMsg -Level Starting
                $PasswordCheckStartTime = Get-Date
                $Passwords = Find-PotentialPasswordsInTSQL -Fragment $Batch
                $Global:ExecutionTimers['PasswordCheckTime'] = ((Get-Date) - $PasswordCheckStartTime).TotalMilliseconds
                foreach ($Password in $Passwords) {
                    $PasswordValue = $Password | Select-Object StartLine, Fragment, Secret, InFragment, Pattern | Format-List | Out-String
                    $Msg = "Found a potential password in the t-sql stmt: {$($Password.Secret)}, password value: {$($PasswordValue)}"
                    Write-Msg -Message $Msg -VerboseMsg -Level Warning
                    Add-TSqlCheckResult -Message $Msg
                }
                Write-Msg -Message "Finished to check for potential passwords in the t-sql..." -VerboseMsg -Level Finished
            }

            # Final call to Add-TSqlCheckResult to make sure complete trace details is returned
            
            # Calculate total execution time and log summary
            $TotalTime = ((Get-Date) - $Global:ExecutionTimers['TotalExecution']).TotalMilliseconds
            $OperationTimerSummary = @"
=== EXECUTION TIME SUMMARY ===
Total Execution Time: $TotalTime ms
    - Parsing:                    $($Global:ExecutionTimers['ParseTime']) ms
    - SQL Injection Check:        $($Global:ExecutionTimers['SQLInjectionCheckTime']) ms
        -- Visitor Traversal:       $($Global:OperationTimers['VisitorTraversal']) ms
        -- Dynamic Exec Processing: $($Global:OperationTimers['DynamicExecProcessing']) ms
            -- Buffer Size Checking: $($Global:OperationTimers['BufferSizeChecking']) ms
            -- String/Var Checking:  $($Global:OperationTimers['StringLiteralChecking']) ms
    - Password Check:             $($Global:ExecutionTimers['PasswordCheckTime']) ms
"@
            if ($null -ne $Global:OperationTimers -and $Global:OperationTimers.Count -gt 4) {
                $OperationTimerSummary += "`nOther Operation Times:`n"
                $KnownOps = @('VisitorTraversal', 'DynamicExecProcessing', 'BufferSizeChecking', 'StringLiteralChecking')
                foreach ($operation in $Global:OperationTimers.GetEnumerator() | Where-Object { $_.Name -notin $KnownOps } | Sort-Object Value -Descending) {
                    $OperationTimerSummary += "  - $($operation.Name): $($operation.Value) ms`n"
                }
            }
            
            Write-Msg -Message $OperationTimerSummary -VerboseMsg
            $OperationTimerSummary = "Finalizing T-SQL Checks results." + [Environment]::NewLine + $OperationTimerSummary
            Add-TSqlCheckResult -Message $OperationTimerSummary
            return $Global:TSqlCheckResults
        }
        # Report the parsing errors
        else{
            [string]$ParseErrorMsgs = ""
            foreach ($err in $Errors) {
                $ParseErrorMsgs += "Error trying to parse stmt;" + [Environment]::NewLine + "Syntax error message: $($err.Message);" + [Environment]::NewLine + "Error line: $($err.Line);"
            }
            $ParseErrorMsgs = '/*' + [Environment]::NewLine + $ParseErrorMsgs + [Environment]::NewLine + '*/'

            Add-TSqlCheckResult -Message $ParseErrorMsgs
            return $Global:TSqlCheckResults
        }
    }
    catch {
        Write-Msg -Message "Error trying to run Script, check the following message for more info." -Level Error
        Write-Msg -Message "ErrorMessage: $($_.Exception.Message)" -Level Error
        $Err = $null
        $Err = "ErrorMessage: $($_.Exception.Message)"
        $Err = $Err + [Environment]::NewLine + $InputText
        Add-TSqlCheckResult -Message $ParseErrorMsgs
        return $Global:TSqlCheckResults
    }
}