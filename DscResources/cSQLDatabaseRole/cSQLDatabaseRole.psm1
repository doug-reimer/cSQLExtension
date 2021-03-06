# Adopted and modified from: https://github.com/PowerShell/xSQLServer/blob/dev/DSCResources/MSFT_xSQLServerDatabaseRole/MSFT_xSQLServerDatabaseRole.psm1
Import-Module -Name (Join-Path -Path (Split-Path (Split-Path $PSScriptRoot -Parent) -Parent) -ChildPath 'cSQLExtensionHelper.psm1') -Force

<#
    .SYNOPSIS
    Returns the current state of the user memberships in the role(s).

    .PARAMETER Ensure
    Specifies the desired state of the membership of the role(s).
    
    .PARAMETER Name
    Specifies the name of the login that evaluated if it is member of the role(s).
    
    .PARAMETER SQLServer
    Specifies the SQL server on which the instance exist.
    
    .PARAMETER SQLInstanceName
    Specifies the SQL instance in which the database exist.
    
    .PARAMETER Database
    Specifies the database in which the login (user) and role(s) exist.
    
    .PARAMETER Role
    Specifies one or more roles to which the login (user) will be evaluated if it should be added or removed.
#>
function Get-TargetResource
{
    [CmdletBinding()]
    [OutputType([System.Collections.Hashtable])]
    param
    (
        [ValidateSet('Present','Absent')]
        [System.String]
        $Ensure,

        [Parameter(Mandatory = $true)]
        [System.String]
        $Name,

        [Parameter(Mandatory = $true)]
        [System.String]
        $SQLServer,

        [Parameter(Mandatory = $true)]
        [System.String]
        $SQLInstanceName,

        [Parameter(Mandatory = $true)]
        [System.String]
        $Database,

        [Parameter(Mandatory = $true)]
        [System.String[]]
        $Role
    )

    $sql = Connect-cSQL -SQLServer $SQLServer -SQLInstanceName $SQLInstanceName

    if ($sql)
    {
        # Check database exists
        if ( !($sqlDatabase = $sql.Databases[$Database]) )
        {
            throw "NoDatabaseError: $SqlDatabase does not exist"
        }

        # Check role exists
        foreach ($currentRole in $Role)
        {
            if( !($sqlDatabase.Roles[$currentRole]) )
            {
                throw "RoleNotFound: $currentRole not found"
            }
        }

        # Check login exists
        if ( !($sql.Logins[$Name]) -and !($sqlDatabase.Users[$Name]) )
        {
            throw "LoginNotFound: $Name not found on SQL Server or Database"
        }

        $Ensure = 'Absent'
        $grantedRole = @()

        if ($sqlDatabaseUser = $sqlDatabase.Users[$Name] )
        {
            foreach ($currentRole in $Role)
            {
                if ($sqlDatabaseUser.IsMember($currentRole))
                {
                    Write-Verbose -Message "The login '$Name' is a member of the role '$currentRole' on the database '$Database', on the instance $SQLServer\$SQLInstanceName"
                    
                    $grantedRole += $currentRole
                }
                else
                {
                    Write-Verbose -Message "The login '$Name' is not a member of the role '$currentRole' on the database '$Database', on the instance $SQLServer\$SQLInstanceName"
                }
            }

            if ( !(Compare-Object -ReferenceObject $Role -DifferenceObject $grantedRole) )
            {
                $Ensure = 'Present'
            }
        }
        else
        {
            Write-Verbose -Message "The login '$Name' is not a user of the database '$Database' on the instance $SQLServer\$SQLInstanceName"
        }
    }
    else
    {
        throw "NotConnectedToInstance: $SQLServer\$SQLInstanceName"
    }

    $returnValue = @{
        Ensure = $Ensure
        Name = $Name
        SQLServer = $SQLServer
        SQLInstanceName = $SQLInstanceName
        Database = $Database
        Role = $grantedRole
    }

    $returnValue
}

<#
    .SYNOPSIS
    Adds the login (user) to each of the provided roles when Ensure is set to 'Present'.
    When Ensure is set to 'Absent' the login (user) will be removed from each of the provided roles.
    If the login does not exist as a user in the database, then the user will be created in the database using the login.

    .PARAMETER Ensure
    Specifies the desired state of the membership of the role(s).
    
    .PARAMETER Name
    Specifies the name of the login that evaluated if it is member of the role(s), if it is not it will be added.
    If the login does not exist as a user, a user will be created using the login. 
    
    .PARAMETER SQLServer
    Specifies the SQL server on which the instance exist.
    
    .PARAMETER SQLInstanceName
    Specifies the SQL instance in which the database exist.
    
    .PARAMETER Database
    Specifies the database in which the login (user) and role(s) exist.
    
    .PARAMETER Role
    Specifies one or more roles to which the login (user) will be added or removed.
#>
function Set-TargetResource
{
    [CmdletBinding()]
    param
    (
        [ValidateSet('Present','Absent')]
        [System.String]
        $Ensure = 'Present',

        [Parameter(Mandatory = $true)]
        [System.String]
        $Name,

        [Parameter(Mandatory = $true)]
        [System.String]
        $SQLServer,

        [Parameter(Mandatory = $true)]
        [System.String]
        $SQLInstanceName,

        [Parameter(Mandatory = $true)]
        [System.String]
        $Database,

        [Parameter(Mandatory = $true)]
        [System.String[]]
        $Role
    )

    $sql = Connect-cSQL -SQLServer $SQLServer -SQLInstanceName $SQLInstanceName

    if ($sql)
    {
        $sqlDatabase = $sql.Databases[$Database]
        
        switch ($Ensure)
        {
            'Present'
            {
                # Adding database user if it does not exist.
                if ( !($sqlDatabase.Users[$Name]) )
                {
                    try
                    {
                        Write-Verbose -Message "Adding the login '$Name' as a user of the database '$Database', on the instance $SQLServer\$SQLInstanceName"

                        $sqlDatabaseUser = New-Object Microsoft.SqlServer.Management.Smo.User $SQLDatabase, $Name
                        $sqlDatabaseUser.Login = $Name
                        $sqlDatabaseUser.Create()
                    }
                    catch
                    {
                        "Failed adding the login '$Name' as a user of the database '$Database', on the instance $SQLServer\$SQLInstanceName"

                        throw $_
                    }
                }

                # Adding database user to the role.
                foreach ($currentRole in $Role) 
                {
                    try
                    {
                        Write-Verbose -Message "Adding the login '$Name' to the role '$currentRole' on the database '$Database', on the instance $SQLServer\$SQLInstanceName"

                        $sqlDatabaseRole = $sqlDatabase.Roles[$currentRole]
                        $sqlDatabaseRole.AddMember($Name)
                    }
                    catch
                    {
                        Write-Verbose -Message "Failed adding the login '$Name' to the role '$currentRole' on the database '$Database', on the instance $SQLServer\$SQLInstanceName"

                        throw $_
                    }
                }
            }

            'Absent'
            {
                try
                {
                    foreach ($currentRole in $Role) 
                    {
                        Write-Verbose -Message "Removing the login '$Name' to the role '$currentRole' on the database '$Database', on the instance $SQLServer\$SQLInstanceName"

                        $sqlDatabaseRole = $sqlDatabase.Roles[$currentRole]
                        $sqlDatabaseRole.DropMember($Name)
                    }
                }
                catch
                {
                    Write-Verbose -Message "Failed removing the login '$Name' from the role '$Role' on the database '$Database', on the instance $SQLServer\$SQLInstanceName"

                    throw $_
                }
            }
        }
    }

    if ( !(Test-TargetResource @PSBoundParameters) )
    {
        throw "TestFailedAfterSet: InvalidResult"
    }
}

<#
    .SYNOPSIS
    Tests if the login (user) has the desired state in each of the provided roles.

    .PARAMETER Ensure
    Specifies the desired state of the membership of the role(s).
    
    .PARAMETER Name
    Specifies the name of the login that evaluated if it is member of the role(s).
    
    .PARAMETER SQLServer
    Specifies the SQL server on which the instance exist.
    
    .PARAMETER SQLInstanceName
    Specifies the SQL instance in which the database exist.
    
    .PARAMETER Database
    Specifies the database in which the login (user) and role(s) exist.
    
    .PARAMETER Role
    Specifies one or more roles to which the login (user) will be tested if it should added or removed.
#>
function Test-TargetResource
{
    [CmdletBinding()]
    [OutputType([System.Boolean])]
    param
    (
        [ValidateSet('Present','Absent')]
        [System.String]
        $Ensure = 'Present',

        [Parameter(Mandatory = $true)]
        [System.String]
        $Name,

        [Parameter(Mandatory = $true)]
        [System.String]
        $SQLServer,

        [Parameter(Mandatory = $true)]
        [System.String]
        $SQLInstanceName,

        [Parameter(Mandatory = $true)]
        [System.String]
        $Database,

        [Parameter(Mandatory = $true)]
        [System.String[]]
        $Role
    )

    return (((Get-TargetResource @PSBoundParameters).Ensure) -eq $Ensure)
}

Export-ModuleMember -Function *-TargetResource
