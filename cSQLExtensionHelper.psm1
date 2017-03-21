# Adopted and modified from https://github.com/PowerShell/xSQLServer/blob/dev/xSQLServerHelper.psm1
<#
    .SYNOPSIS
        Connect to a SQL Server Database Engine and return the server object.

    .PARAMETER SQLServer
        String containing the host name of the SQL Server to connect to.

    .PARAMETER SQLInstanceName
        String containing the SQL Server Database Engine instance to connect to.

    .PARAMETER SetupCredential
        PSCredential object with the credentials to use to impersonate a user when connecting.
        If this is not provided then the current user will be used to connect to the SQL Server Database Engine instance.
#>
function Connect-cSQL
{
    [CmdletBinding()]
    param
    (
        [ValidateNotNull()]
        [System.String]
        $SQLServer = $env:COMPUTERNAME,

        [ValidateNotNull()]
        [System.String]
        $SQLInstanceName = "MSSQLSERVER",

        [System.Management.Automation.PSCredential]
        $SetupCredential,
        
        [ValidateSet("Windows","SQL")]
        [System.String]
        $CredentialLoginType
    )

    $null = [System.Reflection.Assembly]::LoadWithPartialName('Microsoft.SqlServer.Smo')

    if ($SQLInstanceName -eq "MSSQLSERVER")
    {
        $connectSql = $SQLServer
    }
    else
    {
        $connectSql = "$SQLServer\$SQLInstanceName"
    }

    if ($SetupCredential)
    {
        $sql = New-Object Microsoft.SqlServer.Management.Smo.Server

        if ($CredentialLoginType -eq "SQL") {
            $sql.ConnectionContext.LoginSecure = $false
            $sql.ConnectionContext.Login = $SetupCredential.GetNetworkCredential().UserName
            $sql.ConnectionContext.SecurePassword = $SetupCredential.Password
        }
        else {

            $sql.ConnectionContext.ConnectAsUser = $true
            $sql.ConnectionContext.ConnectAsUserPassword = $SetupCredential.GetNetworkCredential().Password
            $sql.ConnectionContext.ConnectAsUserName = $SetupCredential.GetNetworkCredential().UserName
        }

        $sql.ConnectionContext.ServerInstance = $connectSQL
        $sql.ConnectionContext.connect()
    }
    else
    {
        $sql = New-Object Microsoft.SqlServer.Management.Smo.Server $connectSql
    }

    if (!$sql)
    {
        throw "Failed connecting to SQL $connectSql"
    }

    Write-Verbose -Message "Connected to SQL $connectSql"

    return $sql
}

<#
    .SYNOPSIS
    This cmdlet is used to return the permission for a user in a database

    .PARAMETER SqlServerObject
    This is the Server object returned by Connect-SQL

    .PARAMETER Name
    This is the name of the user to get the current permissions for

    .PARAMETER Database
    This is the name of the SQL database

    .PARAMETER PermissionState
    If the permission should be granted or denied. Valid values are Grant or Deny
#>
function Get-cSqlDatabasePermission
{
    [CmdletBinding()]
    param
    (
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [System.Object]
        $SqlServerObject,

        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [System.String]
        $Name,

        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [System.String]
        $Database,

        [Parameter(Mandatory = $true)]
        [ValidateSet('Grant','Deny')]
        [ValidateNotNullOrEmpty()]
        [System.String]
        $PermissionState
    )

    Write-Verbose -Message 'Evaluating database and login.'
    $sqlDatabase = $SqlServerObject.Databases[$Database]
    $sqlLogin = $SqlServerObject.Logins[$Name]
    $sqlInstanceName = $SqlServerObject.InstanceName
    $sqlServer = $SqlServerObject.ComputerNamePhysicalNetBIOS

    # Initialize variable permission
    [System.String[]] $permission = @()

    if ($sqlDatabase)
    {
        if ($sqlLogin -or $sqlDatabase.Users[$Name])
        {
            Write-Verbose -Message "Getting permissions for user '$Name' in database '$Database'."

            $databasePermissionInfo = $sqlDatabase.EnumDatabasePermissions($Name)
            $databasePermissionInfo = $databasePermissionInfo | Where-Object -FilterScript {
                $_.PermissionState -eq $PermissionState
            }

            foreach ($currentDatabasePermissionInfo in $databasePermissionInfo)
            {
                $permissionProperty = ($currentDatabasePermissionInfo.PermissionType | Get-Member -MemberType Property).Name
                foreach ($currentPermissionProperty in $permissionProperty)
                {
                    if ($currentDatabasePermissionInfo.PermissionType."$currentPermissionProperty")
                    {
                        $permission += $currentPermissionProperty
                    }
                }
            }
        }
        else
        {
            Write-Verbose -Message "LoginNotFound"
        }
    }
    else
    {
        throw "NoDatabase: $($_.Exception.Message)"
    }

    $permission
}

<#
    .SYNOPSIS
    This cmdlet is used to grant or deny permissions for a user in a database

    .PARAMETER SqlServerObject
    This is the Server object returned by Connect-SQL

    .PARAMETER LoginName
    This is the 'Login name' of the user to get the current permissions for

    .PARAMETER UserName
    This is the 'User name' of the user to get the current permissions for

    .PARAMETER Database
    This is the name of the SQL database

    .PARAMETER PermissionState
    If the permission should be granted or denied. Valid values are Grant or Deny

    .PARAMETER Permissions
    The permissions to be granted or denied for the user in the database.
    Valid permissions can be found in the article SQL Server Permissions:
    https://msdn.microsoft.com/en-us/library/ms191291.aspx#SQL Server Permissions

    .PARAMETER WithoutLogin
    If the permission should be created WITHOUT LOGIN.
#>
function Add-cSqlDatabasePermission
{
    [CmdletBinding()]
    param
    (
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [System.Object]
        $SqlServerObject,

        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [System.String]
        $LoginName,

        [Parameter(Mandatory = $false)]
        [ValidateNotNullOrEmpty()]
        [System.String]
        $UserName,

        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [System.String]
        $Database,

        [Parameter(Mandatory = $true)]
        [ValidateSet('Grant','Deny')]
        [ValidateNotNullOrEmpty()]
        [System.String]
        $PermissionState,

        [parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [System.String[]]
        $Permissions,

        [Parameter(Mandatory = $false)]
        [ValidateNotNullOrEmpty()]
        [System.Boolean]
        $WithoutLogin = $false
    )

    Write-Verbose -Message 'Evaluating database and login.'
    $sqlDatabase = $SqlServerObject.Databases[$Database]
    $sqlLogin = $SqlServerObject.Logins[$LoginName]
    $sqlInstanceName = $SqlServerObject.InstanceName
    $sqlServer = $SqlServerObject.ComputerNamePhysicalNetBIOS

    if ($sqlDatabase)
    {
        if (-not $sqlLogin -and -not $WithoutLogin) {
            throw "LoginNotFound: $($_.Exception.Message)"
        } 
        else {

            if (-not $UserName) {
                $UserName = $LoginName
            }
            if (!$sqlDatabase.Users[$LoginName])
            {
                try
                {
                    Write-Verbose -Message ("Adding SQL login UserName: $UserName as LoginName: $LoginName as a user of database " + `
                                            "$Database on $sqlServer\$sqlInstanceName")
                    $sqlDatabaseUser = New-Object Microsoft.SqlServer.Management.Smo.User $sqlDatabase,$LoginName
                    $sqlDatabaseUser.Login = $LoginName
                    $sqlDatabaseUser.Name = $UserName
                    $sqlDatabaseUser.Create()
                }
                catch
                {
                    Write-Verbose -Message ("Failed adding SQL login UserName: $UserName as LoginName: $LoginName as a user of " + `
                                            "database $Database on $sqlServer\$sqlInstanceName with error: $($_.Exception.Message)")
                }
            }

            if ($sqlDatabase.Users[$LoginName])
            {
                try
                {
                    Write-Verbose -Message ("$PermissionState the permissions '$Permissions' to the " + `
                                            "database '$Database' on the server $sqlServer$sqlInstanceName")
                    $permissionSet = New-Object -TypeName Microsoft.SqlServer.Management.Smo.DatabasePermissionSet

                    foreach ($permission in $permissions)
                    {
                        $permissionSet."$permission" = $true
                    }

                    switch ($PermissionState)
                    {
                        'Grant'
                        {
                            $sqlDatabase.Grant($permissionSet,$LoginName)
                        }

                        'Deny'
                        {
                            $sqlDatabase.Deny($permissionSet,$LoginName)
                        }
                    }
                }
                catch
                {
                    Write-Verbose -Message ("Failed setting SQL login $LoginName to permissions $permissions " + `
                                            "on database $Database on $sqlServer\$sqlInstanceName")
                }
            }
        }
    }
    else
    {
        throw "NoDatabase: $($_.Exception.Message)"
    }
}

<#
    .SYNOPSIS
    This cmdlet is used to remove (revoke) permissions for a user in a database

    .PARAMETER SqlServerObject
    This is the Server object returned by Connect-SQL.

    .PARAMETER Name
    This is the name of the user for which permissions will be removed (revoked)

    .PARAMETER Database
    This is the name of the SQL database

    .PARAMETER PermissionState
    f the permission that should be removed was granted or denied. Valid values are Grant or Deny

    .PARAMETER Permissions
    The permissions to be remove (revoked) for the user in the database.
    Valid permissions can be found in the article SQL Server Permissions:
    https://msdn.microsoft.com/en-us/library/ms191291.aspx#SQL Server Permissions.
#>
function Remove-cSqlDatabasePermission
{
    [CmdletBinding()]
    param
    (
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [System.Object]
        $SqlServerObject,

        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [System.String]
        $Name,

        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [System.String]
        $Database,

        [Parameter(Mandatory = $true)]
        [ValidateSet('Grant','Deny')]
        [ValidateNotNullOrEmpty()]
        [System.String]
        $PermissionState,

        [parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [System.String[]]
        $Permissions
    )

    Write-Verbose -Message 'Evaluating database and login'
    $sqlDatabase = $SqlServerObject.Databases[$Database]
    $sqlLogin = $SqlServerObject.Logins[$Name]
    $sqlInstanceName = $SqlServerObject.InstanceName
    $sqlServer = $SqlServerObject.ComputerNamePhysicalNetBIOS

    if ($sqlDatabase)
    {
        if ($sqlLogin)
        {
            if (!$sqlDatabase.Users[$Name])
            {
                try
                {
                    Write-Verbose -Message ("Adding SQL login $Name as a user of database " + `
                                            "$Database on $sqlServer\$sqlInstanceName")
                    $sqlDatabaseUser = New-Object -TypeName Microsoft.SqlServer.Management.Smo.User `
                                                  -ArgumentList $sqlDatabase,$Name
                    $sqlDatabaseUser.Login = $Name
                    $sqlDatabaseUser.Create()
                }
                catch
                {
                    Write-Verbose -Message ("Failed adding SQL login $Name as a user of " + `
                                            "database $Database on $sqlServer\$sqlInstanceName")
                }
            }

            if ($sqlDatabase.Users[$Name])
            {
                try
                {
                    Write-Verbose -Message ("Revoking $PermissionState permissions '$Permissions' to the " + `
                                            "database '$Database' on the server $sqlServer$sqlInstanceName")
                    $permissionSet = New-Object -TypeName Microsoft.SqlServer.Management.Smo.DatabasePermissionSet

                    foreach ($permission in $permissions)
                    {
                        $permissionSet."$permission" = $false
                    }

                    switch ($PermissionState)
                    {
                        'Grant'
                        {
                            $sqlDatabase.Grant($permissionSet,$Name)
                        }

                        'Deny'
                        {
                            $sqlDatabase.Deny($permissionSet,$Name)
                        }
                    }
                }
                catch
                {
                    Write-Verbose -Message ("Failed removing SQL login $Name to permissions $permissions " + `
                                            "on database $Database on $sqlServer\$sqlInstanceName")
                }
            }
        }
        else
        {
            throw "LoginNotFound: $($_.Exception.Message)"
        }
    }
    else
    {
        throw "NoDatabase: $($_.Exception.Message)"
    }
}

function Get-cSQLLinkedServer
{
    [CmdletBinding()]
    param
    (
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [System.Object]
        $SqlServerObject,

        [Parameter(Mandatory = $false)]
        [ValidateNotNullOrEmpty()]
        [System.String]
        $Name
    )

    if ($Name) 
    {
        $sqlLinkedServer = $SqlServerObject.LinkedServers[$Name]
    }
    else 
    {
        $sqlLinkedServer = $SqlServerObject.LinkedServers
    }    

    return $sqlLinkedServer
}

function Add-cSQLLinkedServer
{
    [CmdletBinding()]
    param
    (
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [System.Object]
        $SqlServerObject,

        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [System.String]
        $Name,

        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [System.String]
        $ProviderName,

        [Parameter(Mandatory = $false)]
        [ValidateNotNullOrEmpty()]
        [System.String]
        $ProviderString,

        [Parameter(Mandatory = $false)]
        [ValidateNotNullOrEmpty()]
        [System.String]
        $ProductName,

        [Parameter(Mandatory = $false)]
        [ValidateNotNullOrEmpty()]
        [System.String]
        $DataSource
    )

    Write-Verbose -Message "Creating SQL Linked Server"
    $sqlLinkedServer = New-Object -TypeName "Microsoft.SqlServer.Management.SMO.LinkedServer" -ArgumentList $sqlServerObject, $Name
    
    $sqlLinkedServer.ProviderName = $ProviderName

    if ($ProviderString) 
    {
        $sqlLinkedServer.ProviderString = $ProviderName
    }

    if ($DataSource)
    {
        $sqlLinkedServer.DataSource = $DataSource
    }

    if ($ProductName) 
    {
        $sqlLinkedServer.ProductName = $ProductName
    }

    try 
    {
        $sqlLinkedServer.Create()
    }
    catch [System.Exception]
    {
        Write-Error -Message "Unable to create Linked Server. $($_.Exception.Message)"
    }
    
}

function Remove-cSQLLinkedServer
{
    [CmdletBinding()]
    param
    (
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [System.Object]
        $SqlLinkedServerObject
    )

    if ($sqlLinkedServerObject)
    {
        Write-Verbose -Message "Dropping Linked Server: $($sqlLinkedServerObject.Name)"
        $sqlLinkedServer.Drop()
    }
}


function Add-cSQLLinkedServerLogin
{
    [CmdletBinding()]
    param
    (
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [System.Object]
        $SqlLinkedServerObject,

        [Parameter(Mandatory = $false)]
        [ValidateNotNullOrEmpty()]
        [System.Management.Automation.PSCredential]
        $RemoteLogin,

        [Parameter(Mandatory = $false)]
        [ValidateNotNullOrEmpty()]
        [System.Boolean]
        $Impersonate

    )

    Write-Verbose -Message "Creating Linked Server login"
    $sqlLinkedLogin = New-Object -TypeName Microsoft.SqlServer.Management.Smo.LinkedServerLogin -ArgumentList $SqlLinkedServerObject, ""

    Write-Verbose -Message "Setting Impersonate"
    if ($Impersonate)
    {
        $sqlLinkedLogin.Impersonate = $Impersonate
    }
    else 
    {
        $sqlLinkedLogin.Impersonate = $False
    }

    if ($RemoteLogin) 
    {
        Write-Verbose -Message "Setting Remote Username and Password"
        $sqlLinkedLogin.RemoteUser = $RemoteLogin.UserName
        $sqlLinkedLogin.SetRemotePassword($RemoteLogin.Password)
    }

    $sqlLinkedLogin.Create()
}