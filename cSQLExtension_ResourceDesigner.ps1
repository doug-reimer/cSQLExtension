Import-Module xDSCResourceDesigner

$dsc_resource_path = "H:\DSC\Modules\cSQLExtension\0.0.1"

New-xDscResource -Name cSQLSchema -Path $dsc_resource_path -Property $(
    New-xDscResourceProperty -Name SQLServer -Description "The SQL Server for the Database" -Type String -Attribute Write
    New-xDscResourceProperty -Name SQLInstanceName -Description "The SQL instance for the database" -Type String -Attribute Write
    New-xDscResourceProperty -Name SQLDatabase -Description "The SQL database for the schema" -Type String -Attribute Key
    New-xDscResourceProperty -Name Name -Description "The name of the schema" -Type String -Attribute Key
    New-xDscResourceProperty -Name Ensure -Description "If the schema should be present or absent. Valid values are 'Present' or 'Absent'. Default Value is 'Present'." -Type String -Attribute Write -ValidateSet Present,Absent
)

New-xDscResource -Name cSQLSchemaOwner -Path $dsc_resource_path -Property @(
    New-xDscResourceProperty -Name SQLServer -Description "The SQL Server for the Database" -Type String -Attribute Write
    New-xDscResourceProperty -Name SQLInstanceName -Description "The SQL instance for the database" -Type String -Attribute Write
    New-xDscResourceProperty -Name SQLDatabase -Description "The SQL database for the schema" -Type String -Attribute Key
    New-xDscResourceProperty -Name SQLDatabaseSchema -Description "The name of the schema for the owner" -Type String -Attribute Key
    New-xDscResourceProperty -Name Name -Description "The name of the SQL login for the owner." -Type String -Attribute Required
)

New-xDscResource -Name cSQLDefaultSchema -Path $dsc_resource_path -Property @(
    New-xDscResourceProperty -Name SQLServer -Description "The SQL Server for the Database" -Type String -Attribute Write
    New-xDscResourceProperty -Name SQLInstanceName -Description "The SQL instance for the database" -Type String -Attribute Write
    New-xDscResourceProperty -Name SQLDatabase -Description "The SQL database for the schema" -Type String -Attribute Key
    New-xDscResourceProperty -Name DefaultSchema -Description "The name of the default schema for the user" -Type String -Attribute Required
    New-xDscResourceProperty -Name SQLLogin -Description "The name of the SQL Login" -Type String -Attribute Key

)

New-xDscResource -Name cSQLDatabasePermission -Path $dsc_resource_path -Property @(
    New-xDscResourceProperty -Name SQLServer -Description "The SQL Server for the Database" -Type String -Attribute Key
    New-xDscResourceProperty -Name SQLInstanceName -Description "The SQL instance for the database" -Type String -Attribute Key
    New-xDscResourceProperty -Name SQLDatabase -Description "The SQL database for the schema" -Type String -Attribute Key
    New-xDscResourceProperty -Name PermissionState -Description "The state of the permission. Valid values are 'Grant' or 'Deny'." -Type String -Attribute Key -ValueMap "Grant","Deny" -Values "Grant","Deny"
    New-xDscResourceProperty -Name Permissions -Description "The set of permissions for the SQL database." -Type String[] -Attribute Required
    New-xDscResourceProperty -Name Ensure -Description "If the values should be present or absent. Valid values are 'Present' or 'Absent'." -Type String -Attribute Write -ValueMap "Present","Absent" -Values "Present","Absent"
    New-xDscResourceProperty -Name UserName -Description "The SQL User Name or 'Friendly' name for the login." -Type String -Attribute Write
    New-xDscResourceProperty -Name LoginName -Description "The SQL Login Name for the login." -Type String -Attribute Key
)

New-xDscResource -Name cSQLLinkedServer -Path $dsc_resource_path -Property @(
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

# Updated version of cSQLLinkedServer
New-xDscResource -Name cSQLLinkedServer -Path $dsc_resource_path -Property @(
    New-xDscResourceProperty -Name SQLServer -Description "The SQL Server" -Type String -Attribute Key
    New-xDscResourceProperty -Name SQLInstanceName -Description "The SQL instance" -Type String -Attribute Key
    New-xDscResourceProperty -Name Ensure -Description "If the SQL Linked Server should be present or absent.  Valid values are 'Present' or 'Absent'." -Type String -Attribute Write -ValueMap "Present","Absent" -Values "Present","Absent"
    New-xDscResourceProperty -Name Name -Description "This is the name the linked server will be referenced by." -Type String -Attribute Key
    New-xDscResourceProperty -Name DataSource -Description "The Data Source for the Linked Server.  The Data Source is usually the name of the server or filename." -Type String -Attribute Key
    New-xDscResourceProperty -Name ProviderName -Description "One of the Providers installed on the server" -Type String -Attribute Key
    New-xDscResourceProperty -Name ProductName -Description "The Product Name is the OLE DB data source to add as a linked server." -Type String -Attribute Key
)

New-xDscResource -Name cSQLLinkedServerLogin -Path $dsc_resource_path -Property @(
    New-xDscResourceProperty -Name SQLServer -Description "The SQL Server" -Type String -Attribute Key
    New-xDscResourceProperty -Name SQLInstanceName -Description "The SQL Instance" -Type String -Attribute Key
    New-xDscResourceProperty -Name Ensure -Description "If the SQL Linked Server login should be present or absent. Valid values are 'Present' or 'Absent'" -Type String -Attribute Write -ValueMap "Present","Absent" -Values "Present","Absent"
    New-xDscResourceProperty -Name SQLLinkedServer -Description "The name of the SQL Linked server" -Type String -Attribute Key
    New-xDscResourceProperty -Name Impersonate -Description "" -Type Boolean -Attribute Write
    New-xDscResourceProperty -Name Name -Description "The name of the local login resource" -Type String -Attribute Write
    New-xDscResourceProperty -Name RemoteUserName -Description "The username of the remote use" -Type String -Attribute Key
    New-xDscResourceProperty -Name RemoteUserCredential -Description "The credential for the remote user" -Type PSCredential -Attribute Write
)

New-xDscResource -Name cSQLAgentJob -Path $dsc_resource_path -Property @(
    New-xDscResourceProperty -Name SQLServer -Description "The SQL Server" -Type String -Attribute Key
    New-xDscResourceProperty -Name SQLInstanceName -Description "The SQL Instance" -Type String -Attribute Key
    New-xDscResourceProperty -Name Ensure -Description "If the SQL Agent job should be present or absent. Valid values are 'Present' or 'Absent'" -Type String -Attribute Write -ValueMap "Present","Absent" -Values "Present","Absent"
    New-xDscResourceProperty -Name Owner -Description "The owner for the SQL Agent job" -Type String -Attribute Write
    New-xDscResourceProperty -Name Name -Description "The name of the SQL Agent Job" -Type String -Attribute Key
    New-xDscResourceProperty -Name Description -Description "The description of the SQL Agent Job" -Type String -Attribute Write
    New-xDscResourceProperty -Name Enabled -Description "If the SQL Agent Job should be Enabled" -Type Boolean -Attribute Write
)

New-xDscResource -Name cSQLAgentJobStep -Path $dsc_resource_path -Property @(
    New-xDscResourceProperty -Name SQLServer -Description "The SQL Server" -Type String -Attribute Key
    New-xDscResourceProperty -Name SQLInstanceName -Description "The SQL Instance" -Type String -Attribute Key
    New-xDscResourceProperty -Name SQLAgentJob -Description "The name of the SQL Agent Job" -Type String -Attribute Key
    New-xDscResourceProperty -Name Name -Description "The name of the SQL Agent Job Step" -Type String -Attribute Key
    New-xDscResourceProperty -Name Type -Description "The subsystem type for the job step. Eg. Powershell, CmdExec, TransactSql" -Type String -Attribute Required -ValueMap "Powershell","CmdExec","TransactSql" -Values "Powershell","CmdExec","TransactSql"
    New-xDscResourceProperty -Name Database -Description "The database to execute the job step against. Only required for T-SQL step type" -Type String -Attribute Write
    New-xDscResourceProperty -Name Command -Description "The command/s to execute in the job step" -Type String -Attribute Write
    New-xDscResourceProperty -Name Ensure -Description "If the SQL Agent job Step should be present or absent. Valid values are 'Present' or 'Absent'" -Type String -Attribute Write -ValueMap "Present","Absent" -Values "Present","Absent"
)

New-xDscResource -Name cSQLAgentJobSchedule -Path $dsc_resource_path -Property @(
    New-xDscResourceProperty -Name SQLServer -Description "The SQL Server" -Type String -Attribute Key
    New-xDscResourceProperty -Name SQLInstanceName -Description "The SQL Instance" -Type String -Attribute Key
    New-xDscResourceProperty -Name SQLAgentJob -Description "The name of the SQL Agent Job" -Type String -Attribute Key
    New-xDscResourceProperty -Name Name -Description "The name of the schedule" -Type String -Attribute Key
    New-xDscResourceProperty -Name Frequency -Description "The schedule frequency. Valid values are 'Daily','Weekly', or 'Monthly'" -Type String -Attribute Required -ValueMap "Daily","Weekly","Monthly" -Values "Daily","Weekly","Monthly"
    New-xDscResourceProperty -Name Enabled -Description "If the schedule should be enabled" -Type Boolean -Attribute Required
    New-xDscResourceProperty -Name StartTime -Description "The start time for the schedule" -Type DateTime -Attribute Required
    New-xDscResourceProperty -Name Ensure -Description "If the SQL Agent job schedule should be present or absent. Valid values are 'Present' or 'Absent'" -Type String -Attribute Write -ValueMap "Present","Absent" -Values "Present","Absent"
)

New-xDscResource -Name cSQLCredential -Path $dsc_resource_path -Property @(
    New-xDscResourceProperty -Name SQLServer -Description "The SQL Server" -Type String -Attribute Key
    New-xDscResourceProperty -Name SQLInstanceName -Description "The SQL Instance" -Type String -Attribute Key
    New-xDscResourceProperty -Name Name -Description "Name of the Credential" -Type String -Attribute Key
    New-xDscResourceProperty -Name Credential -Description "The Credential for the SQL Idenity" -Type PSCredential -Attribute Required
    New-xDscResourceProperty -Name Ensure -Description "If the credential should be present or absent. Valid values are 'Present' or 'Absent'" -Type String -Attribute Write -ValueMap "Present","Absent" -Values "Present","Absent"
)

New-xDscResource -Name cSQLAgentProxyAccount -Path $dsc_resource_path -Property @(
    New-xDscResourceProperty -Name SQLServer -Description "The SQL Server" -Type String -Attribute Key
    New-xDscResourceProperty -Name SQLInstanceName -Description "The SQL Instance" -Type String -Attribute Key
    New-xDscResourceProperty -Name CredentialName -Description "The name of the Credential to use as the proxy" -Type String -Attribute Key
    New-xDscResourceProperty -Name Description -Description "Description of the Proxy" -Type String -Attribute Write
    New-xDscResourceProperty -Name SubSystems -Description "List of Subsystems to activate for the Proxy" -Type String[] -Attribute Write
)


New-ModuleManifest -Path $dsc_resource_path\cSQLExtension.psd1 `
    -Guid ([Guid]::NewGuid()) `
    -ModuleVersion 0.0.1 `
    -Author "Doug Reimer" `
    -CompanyName "" `
    -Description "SQL extension resource module" `
    -RootModule 'cSQLExtension.psm1'