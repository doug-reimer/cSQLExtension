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
        $SQLDatabaseSchema,

        [parameter(Mandatory = $true)]
        [System.String]
        $Name
    )

    Write-Debug -Message "Connecting to SQL Instance"
    $smoSqlServer = New-Object -TypeName Microsoft.SqlServer.Management.Smo.Server -ArgumentList "$SQLServer\$SQLInstanceName"
    
    Write-Debug -Message "Connecting to SQL Database"
    $smoSQLDatabase = $smoSqlServer.Databases.Item($SQLDatabase)
    
    Write-Debug -Message "Connecting to SQL Database Schema"
    $smoSQLDatabaseSchema = $smoSQLDatabase.Schemas.Item($SQLDatabaseSchema)
    
    if ($smoSQLDatabaseSchema) {

        $schemaOwner = $smoSQLDatabaseSchema.Owner
        Write-Verbose "Owner for Database ($SQLDatabase) Schema is $schemaOwner"

    } else {

        $schemaOwner = $null
    }


    $returnValue = @{
        SQLServer = $SQLServer
        SQLInstanceName = $SQLInstanceName
        SQLDatabase = $SQLDatabase
        SQLDatabaseSchema = $SQLDatabaseSchema
        Name = $schemaOwner
    }

    $returnValue

}


function Set-TargetResource
{
    [CmdletBinding()]
    param
    (
        [System.String]
        $SQLServer,

        [System.String]
        $SQLInstanceName,

        [parameter(Mandatory = $true)]
        [System.String]
        $SQLDatabase,

        [parameter(Mandatory = $true)]
        [System.String]
        $SQLDatabaseSchema,

        [parameter(Mandatory = $true)]
        [System.String]
        $Name
    )

    Write-Debug -Message "Connecting to SQL Instance"
    $smoSqlServer = New-Object -TypeName Microsoft.SqlServer.Management.Smo.Server -ArgumentList "$SQLServer\$SQLInstanceName"
    
    Write-Debug -Message "Connecting to SQL Database"
    $smoSQLDatabase = $smoSqlServer.Databases.Item($SQLDatabase)
    
    Write-Debug -Message "Connecting to SQL Database Schema"
    $schema = $smoSQLDatabase.Schemas.Item($SQLDatabaseSchema)

    if ($schema) {
        
        $schema.Owner = $Name
        try {
            $schema.Alter()
        } 
        catch {
            throw [Exception] ("Failed to setting the owner of schema $SQLDatabaseSchema")    
        }
        
        Write-Verbose -Message "Database: $smoSQLDatabase Schema: $SQLDatabaseSchema Owner set: $Name"
    } else {
        
        Write-Verbose -Message "Schema: $SQLDatabaseSchema not found"
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
        $SQLDatabaseSchema,

        [parameter(Mandatory = $true)]
        [System.String]
        $Name
    )

    $sqlSchemaOwner = Get-TargetResource @PSBoundParameters

    $result = ($sqlSchemaOwner.Name -eq $Name)
    $result
}


Export-ModuleMember -Function *-TargetResource

