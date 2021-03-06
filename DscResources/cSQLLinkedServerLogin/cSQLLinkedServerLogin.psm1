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

        [ValidateSet("Present","Absent")]
        [System.String]
        $Ensure,

        [parameter(Mandatory = $true)]
        [System.String]
        $SQLLinkedServer,

        [System.Boolean]
        $Impersonate,

        [System.String]
        $Name,

        [parameter(Mandatory = $true)]
        [System.String]
        $RemoteUserName,

        [System.Management.Automation.PSCredential]
        $RemoteUserCredential
    )

    $sqlServerObject = Connect-cSQL -SQLServer $SQLServer -SQLInstanceName $SQLInstanceName
    

    if ($sqlServerObject)
    {
        $sqlLinkedServerObject = $sqlServerObject.LinkedServers | Where {$_.Name -match $SQLLinkedServer}

        if ($sqlLinkedServerObject) 
        {
            Write-Verbose "Linked Server: $($sqlLinkedServerObject.Name)"
            if ($Name) {
                $sqlLinkedServerLogin = $sqlLinkedServerObject.LinkedServerLogins | Where {$_.Name -eq $Name -or $_.RemoteUser -eq $RemoteUserCredential.Username}
            } else {
                $sqlLinkedServerLogin = $sqlLinkedServerObject.LinkedServerLogins | Where {$_.RemoteUser -eq $RemoteUserCredential.Username}
            }
            
            
            if ($sqlLinkedServerLogin) {
                
                $Impersonate = $sqlLinkedServerLogin.Impersonate
                $Name = $sqlLinkedServerLogin.Name
                Write-Verbose -Message "Linked Server Login Name: $Name"
                $RemoteUserName = $sqlLinkedServerLogin.RemoteUser
                Write-Verbose -Message "Linked Server Remote User: $RemoteUserName"
                $Ensure = "Present"
                
            } else {
                Write-Verbose -Message "Linked Server Login not found"
                $Ensure = "Absent"
            }
            
        }
        else 
        {
            Write-Verbose -Message "Linked Server not found"
            $Ensure = "Absent"
        }
    }

    $returnValue = @{
        SQLServer = $SQLServer
        SQLInstanceName = $SQLInstanceName
        Ensure = $Ensure
        Name = $Name
        Impersonate = $Impersonate
        RemoteUsername = $RemoteUserName
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

        [parameter(Mandatory = $true)]
        [System.String]
        $SQLLinkedServer,

        [System.Boolean]
        $Impersonate,

        [System.String]
        $Name,

        [parameter(Mandatory = $true)]
        [System.String]
        $RemoteUserName,

        [System.Management.Automation.PSCredential]
        $RemoteUserCredential
    )

    $sqlServerObject = Connect-cSQL -SQLServer $SQLServer -SQLInstanceName $SQLInstanceName
    
    if ($sqlServerObject) {
        Write-Verbose -Message "Connected to SQL Server: $($sqlServerObject.name)"
        $sqlLinkedServerObject = $sqlServerObject.LinkedServers | Where {$_.Name -match $SQLLinkedServer}
        if ($sqlLinkedServerObject) {
            Write-Verbose -Message "Linked Server found: $($sqlLinkedServerObject.Name)"

            $linked_server_params = @{
                SqlLinkedServerObject = $sqlLinkedServerObject
            }

            if ($Name) {
                $linked_server_params.Add("Name",$Name)
            }

            if ($RemoteUserCredential) {
                $linked_server_params.Add("RemoteUser",$RemoteUserCredential)
            }

            if ($Impersonate) {
                $linked_server_params.Add("Impersonate",$Impersonate)
            }

            Write-Verbose -Message "Adding Linked Server Login"
            Add-cSqlLinkedServerLogin @linked_server_params
        }
        else {
            Write-Error -Message "Could not find Linked Server"
        }
    } else {
        Write-Error -Message "Could not connect to SQL Server"
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

        [parameter(Mandatory = $true)]
        [System.String]
        $SQLLinkedServer,

        [System.Boolean]
        $Impersonate,

        [System.String]
        $Name,

        [parameter(Mandatory = $true)]
        [System.String]
        $RemoteUserName,

        [System.Management.Automation.PSCredential]
        $RemoteUserCredential
    )

    $CurrentConfiguration = Get-TargetResource @PSBoundParameters

    $result = ($CurrentConfiguration.Ensure -eq $Ensure)
    $result
}


Export-ModuleMember -Function *-TargetResource

