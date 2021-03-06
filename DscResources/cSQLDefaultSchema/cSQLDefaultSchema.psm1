function Get-TargetResource
{
    [CmdletBinding()]
    [OutputType([System.Collections.Hashtable])]
    param
    (
        [System.String]
        $SQLServer = $env:COMPUTERNAME,

        [System.String]
        $SQLInstanceName = "MSSQLSERVER",

        [parameter(Mandatory = $true)]
        [System.String]
        $SQLDatabase,

        [parameter(Mandatory = $true)]
        [System.String]
        $SQLLogin,

        [parameter(Mandatory = $true)]
        [System.String]
        $DefaultSchema

        
    )

    Write-Debug -Message "Connecting to SQL Instance"
    $smoSqlServer = New-Object -TypeName Microsoft.SqlServer.Management.Smo.Server -ArgumentList "$SQLServer\$SQLInstanceName"
    
    Write-Debug -Message "Connecting to SQL Database"
    $smoSQLDatabase = $smoSqlServer.Databases.Item($SQLDatabase)

    Write-Debug -Message "Getting SQL Login"
    $smoSQLLogin = $smoSQLDatabase.Users.Item($SQLLogin)

    if ($smoSQLLogin) {
        
        $smoSQLLoginDefaultSchema = $smoSQLLogin.DefaultSchema
        Write-Verbose -Message "Default Schema for SQL Login $SQLLogin is $smoSQLLoginDefaultSchema"
    } else {
        
        $smoSQLLoginDefaultSchema = $null
    }


    $returnValue = @{
    SQLServer = $SQLServer
    SQLInstanceName = $SQLInstanceName
    SQLDatabase = $SQLDatabase
    SQLLogin = $SQLLogin
    DefaultSchema = $smoSQLLoginDefaultSchema

    }

    $returnValue

}


function Set-TargetResource
{
    [CmdletBinding()]
    param
    (
        [System.String]
        $SQLServer = $env:COMPUTERNAME,

        [System.String]
        $SQLInstanceName = "MSSQLSERVER",

        [parameter(Mandatory = $true)]
        [System.String]
        $SQLDatabase,

        [parameter(Mandatory = $true)]
        [System.String]
        $SQLLogin,

        [parameter(Mandatory = $true)]
        [System.String]
        $DefaultSchema
    )

    Write-Debug -Message "Connecting to SQL Instance"
    $smoSqlServer = New-Object -TypeName Microsoft.SqlServer.Management.Smo.Server -ArgumentList "$SQLServer\$SQLInstanceName"
    
    Write-Debug -Message "Connecting to SQL Database"
    $smoSQLDatabase = $smoSqlServer.Databases.Item($SQLDatabase)

    Write-Debug -Message "Getting SQL Login"
    $smoSQLLogin = $smoSQLDatabase.Users.Item($SQLLogin)

    if ($smoSQLLogin) {

        $smoSQLLogin.DefaultSchema = $DefaultSchema
        try {

            $smoSQLLogin.Alter()
        }
        catch {
            throw [Exception] ("Failed to setting the default schema for ${SQLLogin} to ${DefaultSchema}: $($_.Exception.Message)")
        }
        Write-Verbose -Message "SQL Login: $SQLLogin Default Schema set: $DefaultSchema "
    } else {
        
        Write-Verbose -Message "SQL Login: $SQLLogin not found"
    }

}


function Test-TargetResource
{
    [CmdletBinding()]
    [OutputType([System.Boolean])]
    param
    (
        [System.String]
        $SQLServer = $env:COMPUTERNAME,

        [System.String]
        $SQLInstanceName = "MSSQLSERVER",

        [parameter(Mandatory = $true)]
        [System.String]
        $SQLDatabase,

        [parameter(Mandatory = $true)]
        [System.String]
        $SQLLogin,

        [parameter(Mandatory = $true)]
        [System.String]
        $DefaultSchema
    )

    $sqlDefaultSchema = Get-TargetResource @PSBoundParameters

    $result = ($sqlDefaultSchema.DefaultSchema -eq $DefaultSchema)
    $result
}


Export-ModuleMember -Function *-TargetResource

