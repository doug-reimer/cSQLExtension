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
        $Name,

        [parameter(Mandatory = $true)]
        [System.Management.Automation.PSCredential]
        $Credential,

        [ValidateSet("Present","Absent")]
        [System.String]
        $Ensure
    )

    $Ensure = "Absent"

    $sqlServerObject = Connect-cSQL -SQLServer $SQLServer -SQLInstanceName $SQLInstanceName

    if ($sqlServerObject)
    {
        $sql_cred = Get-cSQLCredential -SqlServerObject $sqlServerObject -Name $Name

        if ($sql_cred) {
            $Name = $sql_cred.Name
            $Ensure = "Present"
        } else {
            Write-Verbose -Message "No SQL Credential found that matches $Name"
        }
    } else {
        Write-Verbose -Message "Unable to connect to SQL Server: $SQLServer\$SQLInstanceName"
    }

    $returnValue = @{
    SQLServer = $SqlServer
    SQLInstanceName = $SqlInstanceName
    Name = $Name
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
        $Name,

        [parameter(Mandatory = $true)]
        [System.Management.Automation.PSCredential]
        $Credential,

        [ValidateSet("Present","Absent")]
        [System.String]
        $Ensure
    )

    $sqlServerObject = Connect-cSQL -SQLServer $SQLServer -SQLInstanceName $SQLInstanceName

    if ($sqlServerObject)
    {
        $sql_cred = Get-cSQLCredential -SqlServerObject $sqlServerObject -Name $Name

        if ($Ensure -eq "Present") {
            Write-Verbose -Message "Creating SQL Credential $Name for Identity: $($Credential.Username)"
            Add-cSQLCredential -SqlServerObject $sqlServerObject -Name $Name -Credential $Credential
        } 
        
        if ($Ensure -eq "Absent") {
            if ($sql_cred) {
                Write-Verbose -Message "Removing SQL Credential: $($sql_cred.Name)"
                Remove-cSQLCredential -SqlServerCredential $sql_cred
            } else {
                Write-Verbose -Message "No Credential found for $Name"
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

        [parameter(Mandatory = $true)]
        [System.String]
        $Name,

        [parameter(Mandatory = $true)]
        [System.Management.Automation.PSCredential]
        $Credential,

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

