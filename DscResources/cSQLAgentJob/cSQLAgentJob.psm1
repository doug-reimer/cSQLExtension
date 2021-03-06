Import-Module -Name (Join-Path -Path (Split-Path (Split-Path $PSScriptRoot -Parent) -Parent) -ChildPath 'cSQLExtensionHelper.psm1') -Force

# Category IDs
[int]$CI_UNCATEGORIZED = 0
[int]$CI_DATABASE_MAINTENANCE = 3

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

        [ValidateSet("Present","Absent")]
        [System.String]
        $Ensure,

        [System.String]
        $Owner,

        [parameter(Mandatory = $true)]
        [System.String]
        $Name,

        [System.String]
        $Description,

        [System.Boolean]
        $Enabled
    )

    $Description = ""
    $Enabled = $False
    $Ensure = "Absent"
    $Owner = ""

    $sqlServerObject = Connect-cSQL -SQLServer $SQLServer -SQLInstanceName $SQLInstanceName

    if ($sqlServerObject)
    {
        $sql_agent_job = Get-cSQLAgentJob -SqlServerObject $sqlServerObject -Name $Name

        if ($sql_agent_job) 
        {
            $Description = $sql_agent_job.Description
            $Enabled = $sql_agent_job.IsEnabled
            $Ensure = "Present"
            $Owner = $sql_agent_job.OwnerLoginName
        } else {
            Write-Verbose -Message "No SQL Agent Job found that matches $Name"
        }
    } else {
        Write-Verbose -Message "Unable to connect to SQL Server: $SQLServer\$SQLInstanceName"
    }

    $returnValue = @{
        SQLServer = $SQLServer
        SQLInstanceName = $SqlInstanceName
        Ensure = $Ensure
        Name = $Name
        Owner = $Owner
        Description = $Description
        Enabled = $Enabled
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

        [ValidateSet("Present","Absent")]
        [System.String]
        $Ensure,

        [System.String]
        $Owner,

        [parameter(Mandatory = $true)]
        [System.String]
        $Name,

        [System.String]
        $Description,

        [System.Boolean]
        $Enabled
    )

    $sqlServerObject = Connect-cSQL -SQLServer $SQLServer -SQLInstanceName $SQLInstanceName

    if ($sqlServerObject)
    {
        $sql_agent_job = Get-cSQLAgentJob -SqlServerObject $sqlServerObject -Name $Name

        if ($Ensure -eq "Present") {
            if ($sql_agent_job) {
                Write-Verbose -Message "SQL Agent Job $Name is present.  Updating properties"
                Write-Verbose -Message "Setting Description: $Description"
                Set-cSQLAgentJob -SqlServerObject $sqlServerObject -Name $Name -PropertyName Description -PropertyValue $Description
                Write-Verbose -Message "Setting IsEnabled: $Enabled"
                Set-cSQLAgentJob -SqlServerObject $sqlServerObject -Name $Name -PropertyName IsEnabled -PropertyValue $Enabled
                Write-Verbose -Message "Setting OwnerLoginName: $Owner"
                Set-cSQLAgentJob -SqlServerObject $sqlServerObject -Name $Name -PropertyName OwnerLoginName -PropertyValue $Owner
            } else {
                
                $parameters = @{
                    SQLServer = $sqlServerObject
                    Name = $Name
                    Enabled = $False
                    CategoryId = $CI_DATABASE_MAINTENANCE
                }

                if ($Description) {
                    $parameters.Add("Description",$Description)
                }

                if ($Enabled) {
                    $parameters["Enabled"] = $Enabled
                }

                if ($Owner) {
                    $parameters.Add("OwnerLoginName", $Owner)
                }
                Write-Verbose -Message "Creating SQL Agent Job: $Name"
                New-cSQLAgentJob @parameters
            }
        } else {
            if ($sql_agent_job) {
                Write-Verbose -Message "Removing SQL Agent Job: $($sql_agent_job.Name)"
                Remove-cSQLAgentJob -SqlServerObject $sqlServerObject -Name $sql_agent_job.Name
            }
        }
    }
    else
    {
        Write-Error -Message "Unable to connect to SQL Server: $SQLServer\$SQLInstanceName" 
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

        [ValidateSet("Present","Absent")]
        [System.String]
        $Ensure,

        [System.String]
        $Owner,

        [parameter(Mandatory = $true)]
        [System.String]
        $Name,

        [System.String]
        $Description,

        [System.Boolean]
        $Enabled
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
        {$_.Enabled -ne $Enabled} 
        {
            Write-Verbose -Message "Current State Enabled: $($_.Enabled)"
            Write-Verbose -Message "Desired State Enabled: $Enabled"
            return $False 
        }
        {$_.Owner -ne $Owner}
        {
            Write-Verbose -Message "Current State Owner: $($_.Owner)"
            Write-Verbose -Message "Desired State Owner: $Owner"
            return $False
        }
        Default { return $True}
    }
}


Export-ModuleMember -Function *-TargetResource

