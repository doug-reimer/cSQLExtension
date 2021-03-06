Import-Module -Name (Join-Path -Path (Split-Path (Split-Path $PSScriptRoot -Parent) -Parent) -ChildPath 'cSQLExtensionHelper.psm1') -Force

function Get-TargetResource
{
    [CmdletBinding()]
    [OutputType([System.Collections.Hashtable])]
    param
    (
        [parameter(Mandatory = $true)]
        [System.String]
        $SQLServer,

        [parameter(Mandatory = $true)]
        [System.String]
        $SQLInstanceName,

        [parameter(Mandatory = $true)]
        [System.String]
        $SQLAgentJob,

        [parameter(Mandatory = $true)]
        [System.String]
        $Name,

        [parameter(Mandatory = $true)]
        [ValidateSet("Powershell","CmdExec","TransactSql")]
        [System.String]
        $Type,

        [System.String]
        $Database,

        [System.String]
        $Command,

        [ValidateSet("Present","Absent")]
        [System.String]
        $Ensure
    )

    $Database = ""
    $Command = ""
    $Ensure = "Absent"

    $sqlServerObject = Connect-cSQL -SQLServer $SQLServer -SQLInstanceName $SQLInstanceName

    if (-not $sqlServerObject) {
        Write-Error -Message "Could not connect to SQL Server"
        break;
    }

    $sql_agent_job = Get-cSQLAgentJob -SqlServerObject $sqlServerObject -Name $SQLAgentJob

    if (-not $sql_agent_job) {
        Write-Error -Message "No SQL Agent Job found that matches: $SqlAgentJob"
        break;
    }

    $sql_agent_job_step = Get-cSQLAgentJobStep -SqlServerAgentJob $sql_agent_job -Name $Name

    if ($sql_agent_job_step) {
        $Type = $sql_agent_job_step.Subsystem
        $Database = $sql_agent_job_step.DatabaseName
        $Command = $sql_agent_job_step.Command
        $Ensure = "Present"
    } else {
        Write-Verbose -Message "No SQL Agent Job Step found that matches: $Name" 
    }

    $returnValue = @{
        Name = $Name
        Type = $Type
        Database = $Database
        Command = $Command
        Ensure = $Ensure
    }

    $returnValue
}


function Set-TargetResource
{
    [CmdletBinding()]
    param
    (
        [parameter(Mandatory = $true)]
        [System.String]
        $SQLServer,

        [parameter(Mandatory = $true)]
        [System.String]
        $SQLInstanceName,

        [parameter(Mandatory = $true)]
        [System.String]
        $SQLAgentJob,

        [parameter(Mandatory = $true)]
        [System.String]
        $Name,

        [parameter(Mandatory = $true)]
        [ValidateSet("Powershell","CmdExec","TransactSql")]
        [System.String]
        $Type,

        [System.String]
        $Database,

        [System.String]
        $Command,

        [ValidateSet("Present","Absent")]
        [System.String]
        $Ensure
    )

    $sqlServerObject = Connect-cSQL -SQLServer $SQLServer -SQLInstanceName $SQLInstanceName

    if (-not $sqlServerObject) {
        Write-Error -Message "Could not connect to SQL Server"
        break;
    }

    $sql_agent_job = Get-cSQLAgentJob -SqlServerObject $sqlServerObject -Name $SQLAgentJob

    if (-not $sql_agent_job) {
        Write-Error -Message "No SQL Agent Job found that matches: $SqlAgentJob"
        break;
    }

    if ($Ensure -eq "Present") {
        $params = @{
            SqlServerAgentJob = $sql_agent_job
            Name = $Name
            Type = $Type
        }

        if ($Type -eq "TransactSql") {
            $params.Add("Database",$Database)
        }

        if ($Command) {
            $params.Add("Command",$Command)
        }
        Write-Verbose "Creating SQL Agent Job Step: $Name on $($sql_agent_job.Name) of Subsystem type: $Type"
        Add-cSQLAgentJobStep @params
    }

    if ($Ensure -eq "Absent") {
        Write-Verbose "Removing SQL Agent Job Step"

        $sql_agent_job_step = Get-cSQLAgentJobStep -SqlServerAgentJob $sql_agent_job -Name $Name
        Remove-cSQLAgentJobStep -SqlServerAgentJobStep $sql_agent_job_step
    }

}


function Test-TargetResource
{
    [CmdletBinding()]
    [OutputType([System.Boolean])]
    param
    (
        [parameter(Mandatory = $true)]
        [System.String]
        $SQLServer,

        [parameter(Mandatory = $true)]
        [System.String]
        $SQLInstanceName,

        [parameter(Mandatory = $true)]
        [System.String]
        $SQLAgentJob,

        [parameter(Mandatory = $true)]
        [System.String]
        $Name,

        [parameter(Mandatory = $true)]
        [ValidateSet("Powershell","CmdExec","TransactSql")]
        [System.String]
        $Type,

        [System.String]
        $Database,

        [System.String]
        $Command,

        [ValidateSet("Present","Absent")]
        [System.String]
        $Ensure
    )

    $current = Get-TargetResource @PSBoundParameters

    switch ($current)
    {
        {$_.Ensure -ne $Ensure}
        {
            Write-Verbose -Message "Current State Ensure: $($_.Ensure)"
            Write-Verbose -Message "Desired State Ensure: $Ensure"
            return $False 
        }
        Default { return $True}
    }
}


Export-ModuleMember -Function *-TargetResource

