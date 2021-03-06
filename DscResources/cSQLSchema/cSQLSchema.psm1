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
        [System.String]
        $Name,

        [ValidateSet("Present","Absent")]
        [System.String]
        $Ensure
    )

    Write-Debug -Message "Connecting to SQL Instance"
    $smoSqlServer = New-Object -TypeName Microsoft.SqlServer.Management.Smo.Server -ArgumentList "$SQLServer\$SQLInstanceName"
    Write-Debug -Message "Connecting to SQL Database"
    $smoSQLDatabase = $smoSqlServer.Databases.Item($SQLDatabase)
    Write-Debug -Message "Connecting to SQL Database Schema"
    $smoSQLDatabaseSchema = $smoSQLDatabase.Schemas.Item($Name)
    
    if ($smoSQLDatabaseSchema) {
        Write-Verbose -Message "SQL Schema $Name is present"
        $Ensure = 'Present'
    } else {
        Write-Verbose -Message "SQL Schema $Name is absent"
        $Ensure = 'Absent'
    }
    
    $returnValue = @{
        SQLServer = $SQLServer
        SQLInstanceName = $SQLInstanceName
        SQLDatabase = $SQLDatabase
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
        $SQLDatabase,

        [parameter(Mandatory = $true)]
        [System.String]
        $Name,

        [ValidateSet("Present","Absent")]
        [System.String]
        $Ensure
    )

    Write-Debug -Message "Connecting to SQL Instance"
    $smoSqlServer = New-Object -TypeName Microsoft.SqlServer.Management.Smo.Server -ArgumentList "$SQLServer\$SQLInstanceName"
    Write-Debug -Message "Connecting to SQL Database"
    $smoSQLDatabase = $smoSqlServer.Databases.Item($SQLDatabase)
    

    if ($Ensure -eq 'Present') {

        $schema = New-Object -TypeName Microsoft.SqlServer.Management.Smo.Schema -ArgumentList $smoSQLDatabase, $Name
        $schema.Create()
        Write-Verbose -Message "Created schema $Name"

    } else {

        if ($smoSQLDatabase.Schemas.Item($Name)) {

            $schema = $smoSQLDatabase.Schemas.Item($Name)
            $schema.Drop()
            Write-Verbose -Message "Dropped schema $Name"
        }
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
        [System.String]
        $Name,

        [ValidateSet("Present","Absent")]
        [System.String]
        $Ensure
    )

    $sqlDatabaseSchema = Get-TargetResource @PSBoundParameters

    $result = ($sqlDatabaseSchema.Ensure -eq $Ensure)
    $result

}


Export-ModuleMember -Function *-TargetResource

