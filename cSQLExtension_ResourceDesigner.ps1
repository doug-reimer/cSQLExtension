Import-Module xDSCResourceDesigner


New-xDscResource -Name cSQLSchema -Path C:\Scripts\Dsc\cSQLExtension -Property $(
    New-xDscResourceProperty -Name SQLServer -Description "The SQL Server for the Database" -Type String -Attribute Write
    New-xDscResourceProperty -Name SQLInstanceName -Description "The SQL instance for the database" -Type String -Attribute Write
    New-xDscResourceProperty -Name SQLDatabase -Description "The SQL database for the schema" -Type String -Attribute Required
    New-xDscResourceProperty -Name Name -Description "The name of the schema" -Type String -Attribute Key
    New-xDscResourceProperty -Name Ensure -Description "If the schema should be present or absent. Valid values are 'Present' or 'Absent'. Default Value is 'Present'." -Type String -Attribute Write -ValidateSet Present,Absent
)

New-xDscResource -Name cSQLSchemaOwner -Path C:\Scripts\Dsc\cSQLExtension -Property @(
    New-xDscResourceProperty -Name SQLServer -Description "The SQL Server for the Database" -Type String -Attribute Write
    New-xDscResourceProperty -Name SQLInstanceName -Description "The SQL instance for the database" -Type String -Attribute Write
    New-xDscResourceProperty -Name SQLDatabase -Description "The SQL database for the schema" -Type String -Attribute Required
    New-xDscResourceProperty -Name SQLDatabaseSchema -Description "The name of the schema for the owner" -Type String -Attribute Key
    New-xDscResourceProperty -Name Name -Description "The name of the SQL login for the owner." -Type String -Attribute Required
)

New-xDscResource -Name cSQLDefaultSchema -Path C:\Scripts\Dsc\cSQLExtension -Property @(
    New-xDscResourceProperty -Name SQLServer -Description "The SQL Server for the Database" -Type String -Attribute Write
    New-xDscResourceProperty -Name SQLInstanceName -Description "The SQL instance for the database" -Type String -Attribute Write
    New-xDscResourceProperty -Name SQLDatabase -Description "The SQL database for the schema" -Type String -Attribute Required
    New-xDscResourceProperty -Name DefaultSchema -Description "The name of the default schema for the user" -Type String -Attribute Required
    New-xDscResourceProperty -Name SQLLogin -Description "The name of the SQL Login" -Type String -Attribute Key

)

New-xDscResource -Name cSQLDatabasePermission -Path C:\Scripts\Dsc\cSQLExtension -Property @(
    New-xDscResourceProperty -Name SQLServer -Description "The SQL Server for the Database" -Type String -Attribute Key
    New-xDscResourceProperty -Name SQLInstanceName -Description "The SQL instance for the database" -Type String -Attribute Key
    New-xDscResourceProperty -Name SQLDatabase -Description "The SQL database for the schema" -Type String -Attribute Key
    New-xDscResourceProperty -Name PermissionState -Description "The state of the permission. Valid values are 'Grant' or 'Deny'." -Type String -Attribute Key -ValueMap "Grant","Deny" -Values "Grant","Deny"
    New-xDscResourceProperty -Name Permissions -Description "The set of permissions for the SQL database." -Type String[] -Attribute Required
    New-xDscResourceProperty -Name Ensure -Description "If the values should be present or absent. Valid values are 'Present' or 'Absent'." -Type String -Attribute Write -ValueMap "Present","Absent" -Values "Present","Absent"
    New-xDscResourceProperty -Name UserName -Description "The SQL User Name or 'Friendly' name for the login." -Type String -Attribute Write
    New-xDscResourceProperty -Name LoginName -Description "The SQL Login Name for the login." -Type String -Attribute Key
)

New-xDscResource -Name cSQLLinkedServer -Path C:\Scripts\Dsc\cSQLExtension -Property @(
    New-xDscResourceProperty -Name SQLServer -Description "The SQL Server" -Type String -Attribute Key
    New-xDscResourceProperty -Name SQLInstanceName -Description "The SQL instance" -Type String -Attribute Key
    New-xDscResourceProperty -Name Ensure -Description "If the SQL Linked Server should be present or absent.  Valid values are 'Present' or 'Absent'." -Type String -Attribute Write -ValueMap "Present","Absent" -Values "Present","Absent"
    New-xDscResourceProperty -Name Name -Description "This is the name the linked server will be referenced by." -Type String -Attribute Key
    New-xDscResourceProperty -Name DataSource -Description "The Data Source for the Linked Server.  The Data Source is usually the name of the server or filename." -Type String -Attribute Key
    New-xDscResourceProperty -Name ProviderName -Description "One of the Providers installed on the server" -Type String -Attribute Key
    New-xDscResourceProperty -Name ProductName -Description "The Product Name is the OLE DB data source to add as a linked server." -Type String -Attribute Key
    New-xDscResourceProperty -Name Impersonate -Description "Security Context for connections" -Type Boolean -Attribute Write
    New-xDscResourceProperty -Name RemoteLogin -Description "The Remote User must be an SQL Server Authentication login on the remote server" -Type PSCredential -Attribute Write   
)

New-ModuleManifest -Path C:\Scripts\Dsc\cSQLExtension\cSQLExtension.psd1 `
    -Guid ([Guid]::NewGuid()) `
    -ModuleVersion 0.0.1 `
    -Author "Doug Reimer" `
    -CompanyName "Enerplus" `
    -Description "SQL extension resource module" `
    -RootModule 'cSQLExtension.psm1'