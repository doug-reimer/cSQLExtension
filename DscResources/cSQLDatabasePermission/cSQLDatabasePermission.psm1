# Adopted and modified from: https://github.com/PowerShell/xSQLServer/blob/dev/DSCResources/MSFT_xSQLServerDatabasePermission/MSFT_xSQLServerDatabasePermission.psm1

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
        $SQLDatabase,

        [parameter(Mandatory = $true)]
        [ValidateSet("Grant","Deny")]
        [System.String]
        $PermissionState,

        [parameter(Mandatory = $true)]
        [System.String[]]
        $Permissions,

        [parameter(Mandatory = $true)]
        [System.String]
        $LoginName,

        [parameter(Mandatory = $false)]
        [System.String]
        $UserName,

        [parameter(Mandatory = $false)]
        [System.Boolean]
        $WithoutLogin = $false,

        [parameter(Mandatory = $false)]
        [ValidateSet("Present","Absent")]
        [System.String]
        $Ensure
    )

    [System.String[]] $getSqlDatabasePermissionResult = @()

    $sqlServerObject = Connect-cSQL -SQLServer $SQLServer -SQLInstanceName $SQLInstanceName

    if ($sqlServerObject)
    {
        if ($sqlServerObject.Logins[$LoginName]) {
            Write-Verbose -Message "SQL Login found"
            $WithoutLogin = $False
        }
        else {
            Write-Verbose -Message "SQL Login not found"
            $WithoutLogin = $True
        }
        $sqlDatabaseObject = $sqlServerObject.Databases[$SQLDatabase]
        Write-Verbose -Message "Database: $($sqlDatabaseObject.Name)"

        if ($UserName) {
            $Name = $UserName
        }
        else {
            $Name = $LoginName
        }

        if ($sqlDatabaseObject.Users[$Name]) {
            Write-Verbose -Message "Getting Database Permission for $Name on Database $($sqlDatabaseObject.Name)"
            $getSqlDatabasePermissionResult += Get-cSqlDatabasePermission -SqlServerObject $sqlServerObject `
                                                                          -Name $Name `
                                                                          -Database $SQLDatabase `
                                                                          -PermissionState $PermissionState
        }
        if ($getSqlDatabasePermissionResult)
        {
            Write-Verbose -Message "Comparing permissions"
            $resultOfPermissionCompare = Compare-Object -ReferenceObject $Permissions `
                                                        -DifferenceObject $getSqlDatabasePermissionResult
            if ($null -eq $resultOfPermissionCompare)
            {
                Write-Verbose -Message "Permissions appear to match"
                $Ensure = 'Present'
            }
            else
            {
                Write-Verbose -Message "Permissions appear to NOT match"
                $Ensure = 'Absent'
            }
        }
        else 
        {
            Write-verbose -Message "No Permissions found"
            $Ensure = 'Absent'
        }
    }
    else
    {
        throw "ConnectSQLError: $($_.Exception.Message)"
    }
    
    Write-Verbose -Message "Creating return value"
    $returnValue = @{
        Ensure          = $Ensure
        SQLDatabase     = $SQLDatabase
        LoginName       = $LoginName
        UserName        = $UserName
        PermissionState = $PermissionState
        Permissions     = $getSqlDatabasePermissionResult
        SQLServer       = $SQLServer
        SQLInstanceName = $SQLInstanceName
    }
    Write-Verbose -Message "Return Values: "
    foreach ($key in $returnValue.Keys) {
        Write-Verbose -Message "${Key}: $($returnValue[$key])"
    }

    Write-Verbose -Message "Returning"
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
        $SQLDatabase,

        [parameter(Mandatory = $true)]
        [ValidateSet("Grant","Deny")]
        [System.String]
        $PermissionState,

        [parameter(Mandatory = $true)]
        [System.String[]]
        $Permissions,

        [parameter(Mandatory = $true)]
        [System.String]
        $LoginName,

        [parameter(Mandatory = $false)]
        [System.String]
        $UserName,

        [parameter(Mandatory = $false)]
        [System.Boolean]
        $WithoutLogin = $false,

        [parameter(Mandatory = $false)]
        [ValidateSet("Present","Absent")]
        [System.String]
        $Ensure
    )

    #Write-Verbose "Use this cmdlet to deliver information about command processing."

    #Write-Debug "Use this cmdlet to write debug information while troubleshooting."

    #Include this line if the resource requires a system reboot.
    #$global:DSCMachineStatus = 1

    if (-not $UserName) {
        $UserName = $LoginName
    }

    $sqlServerObject = Connect-cSQL -SQLServer $SQLServer -SQLInstanceName $SQLInstanceName
    
    if ($sqlServerObject)
    {
        Write-Verbose -Message "Setting permissions of database '$SQLDatabase' for login '$LoginName'"

        if ($Ensure -eq 'Present')
        {
            Add-cSqlDatabasePermission -SqlServerObject $sqlServerObject `
                                      -LoginName $LoginName `
                                      -UserName $UserName `
                                      -Database $SQLDatabase `
                                      -PermissionState $PermissionState `
                                      -Permissions $Permissions `
                                      -WithoutLogin $WithoutLogin
            
            Write-Verbose -Message "$PermissionState - SQL Permissions for $LoginName, successfully added in $SQLDatabase"
        }
        else
        {
            Remove-cSqlDatabasePermission -SqlServerObject $sqlServerObject `
                                         -Name $LoginName `
                                         -Database $SQLDatabase `
                                         -PermissionState $PermissionState `
                                         -Permissions $Permissions
            
            Write-Verbose -Message "$PermissionState - SQL Permissions for $LoginName, successfully removed in $SQLDatabase"
        }
    }
    else
    {
        throw "ConnectSQLError: $($_.Exception.Message)" 
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
        $SQLDatabase,

        [parameter(Mandatory = $true)]
        [ValidateSet("Grant","Deny")]
        [System.String]
        $PermissionState,

        [parameter(Mandatory = $true)]
        [System.String[]]
        $Permissions,

        [parameter(Mandatory = $true)]
        [System.String]
        $LoginName,

        [parameter(Mandatory = $false)]
        [System.String]
        $UserName,

        [parameter(Mandatory = $false)]
        [System.Boolean]
        $WithoutLogin = $false,

        [parameter(Mandatory = $false)]
        [ValidateSet("Present","Absent")]
        [System.String]
        $Ensure
    )

    $DatabasePermissions = Get-TargetResource @PSBoundParameters

    $result = $DatabasePermissions.Ensure -eq $Ensure

    $result

}


Export-ModuleMember -Function *-TargetResource

