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
        [ValidateSet("Daily","Weekly","Monthly")]
        [System.String]
        $Frequency,

        [parameter(Mandatory = $true)]
        [System.Boolean]
        $Enabled,

        [parameter(Mandatory = $true)]
        [System.DateTime]
        $StartTime,

        [ValidateSet("Present","Absent")]
        [System.String]
        $Ensure
    )

    $Enabled = $False
    $StartTime = Get-Date 0
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

    $sql_agent_job_sched = Get-cSQLAgentJobSchedule -SqlServerAgentJob $sql_agent_job -Name $Name

    if ($sql_agent_job_sched) {
        $Frequency = $sql_agent_job_sched.FrequencyTypes
        $StartTime = $(Get-Date $sql_agent_job_sched.ActiveStartDate).Add($sql_agent_job_sched.ActiveStartTimeOfDay)
        $Enabled = $sql_agent_job_sched.IsEnabled
        $Ensure = "Present"
    } else {
        Write-Verbose -Message "No SQL Agent Job Step found that matches: $Name" 
    }

    $returnValue = @{
        Name = $Name
        Frequency = $Frequency
        StartTime = $StartTime
        Enabled = $Enabled
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
        [ValidateSet("Daily","Weekly","Monthly")]
        [System.String]
        $Frequency,

        [parameter(Mandatory = $true)]
        [System.Boolean]
        $Enabled,

        [parameter(Mandatory = $true)]
        [System.DateTime]
        $StartTime,

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
            Frequency = $Frequency
            Enabled = $Enabled
            StartTime = $StartTime
        }

        Write-Verbose -Message "Creating SQL Agent Job Schedule"
        Write-Verbose -Message "Job: $($sql_agent_job.Name)"
        Write-Verbose -Message "ScheduleName: $Name"
        Write-Verbose -Message "Frequency: $Freqency"
        Write-Verbose -Message "Start: $StartTime" 
        Add-cSQLAgentJobSchedule @params
    }

    if ($Ensure -eq "Absent") {
        $sql_agent_job_sched = Get-cSQLAgentJobSchedule -SqlServerAgentJob $sql_agent_job -Name $Name
        Write-Verbose -Message "Removing SQL Agent Job Schedule: $($sql_agent_job_sched.Name)"
        Remove-cSQLAgentJobSchedule -SqlServerAgentJobSchedule $sql_agent_job_sched
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
        [ValidateSet("Daily","Weekly","Monthly")]
        [System.String]
        $Frequency,

        [parameter(Mandatory = $true)]
        [System.Boolean]
        $Enabled,

        [parameter(Mandatory = $true)]
        [System.DateTime]
        $StartTime,

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

