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

        [ValidateSet("Present","Absent")]
        [System.String]
        $Ensure,

        [parameter(Mandatory = $true)]
        [System.String]
        $Name,

        [parameter(Mandatory = $true)]
        [System.String]
        $DataSource,

        [parameter(Mandatory = $true)]
        [System.String]
        $ProviderName,

        [parameter(Mandatory = $true)]
        [System.String]
        $ProductName
    )

    $sqlServerObject = Connect-cSQL -SQLServer $SQLServer -SQLInstanceName $SQLInstanceName
    

    if ($sqlServerObject)
    {
        $sqlLinkedServer = $sqlServerObject.LinkedServers[$Name]

        if ($sqlLinkedServer) 
        {
            $DataSource = $sqlLinkedServer.DataSource
            $ProviderName = $sqlLinkedServer.ProviderName
            $ProductName = $sqlLinkedServer.ProductName
            $Ensure = "Present"
        }
        else 
        {
            $Ensure = "Absent"
        }
    }

    $returnValue = @{
        SQLServer = $SQLServer
        SQLInstanceName = $SQLInstanceName
        Ensure = $Ensure
        Name = $Name
        DataSource = $DataSource
        ProviderName = $ProviderName
        ProductName = $ProductName
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
        $Name,

        [parameter(Mandatory = $true)]
        [System.String]
        $DataSource,

        [parameter(Mandatory = $true)]
        [System.String]
        $ProviderName,

        [parameter(Mandatory = $true)]
        [System.String]
        $ProductName
    )

    $sqlServerObject = Connect-cSQL -SQLServer $SQLServer -SQLInstanceName $SQLInstanceName
    
    if ($sqlServerObject)
    {
        $sqlLinkedServer = $sqlServerObject.LinkedServers[$Name]
        if ($sqlLinkedServer) 
        {
            Write-Verbose -Message "Removing existing Linked Server"
            Remove-cSqlLinkedServer -SqlLinkedServerObject $sqlLinkedServer
        }
        
        if ($Ensure -eq "Present")
        {
            
            $AddLinkedServerArgs = @{
                SqlServerObject = $sqlServerObject
                Name = $Name
                ProviderName = $ProviderName
            }

            if ($DataSource) 
            {
                $AddLinkedServerArgs.Add("DataSource",$DataSource)
            }

            if ($ProductName)
            {
                $AddLinkedServerArgs.Add("ProductName",$ProductName)
            }

            Write-Verbose -Message "Creating Linked Server"
            Add-cSqlLinkedServer @AddLinkedServerArgs
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

        [ValidateSet("Present","Absent")]
        [System.String]
        $Ensure,

        [parameter(Mandatory = $true)]
        [System.String]
        $Name,

        [parameter(Mandatory = $true)]
        [System.String]
        $DataSource,

        [parameter(Mandatory = $true)]
        [System.String]
        $ProviderName,

        [parameter(Mandatory = $true)]
        [System.String]
        $ProductName
    )

    $CurrentConfiguration = Get-TargetResource @PSBoundParameters

    switch ($CurrentConfiguration)
    {
        {$_.Ensure -ne $Ensure}
        {
            Write-Verbose -Message "Current State Ensure: $($_.Ensure) Desired State Ensure: $($Ensure)"
            return $False 
        }
        {$_.Name -ne $Name} 
        {
            Write-Verbose -Message "Current State Name: $($_.Name) Desired State Name: $($Name)"
            return $False 
        }
        {$_.DataSource -ne $DataSource} 
        { 
            Write-Verbose -Message "Current State DataSource: $($_.DataSource) Desired State DataSource: $($DataSource)"
            return $False 
        }
        {$_.ProviderName -ne $ProviderName } 
        { 
            Write-Verbose -Message "Current State ProviderName: $($_.ProviderName) Desired State Ensure: $($ProviderName)"
            return $False 
        }
        {$_.ProductName -ne $ProductName } 
        { 
            Write-Verbose -Message "Current State ProductName: $($_.ProductName) Desired State Ensure: $($ProductName)"
            return $False
        }
        Default { return $True}
    }
}


Export-ModuleMember -Function *-TargetResource

