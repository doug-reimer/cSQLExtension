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
        $ProviderName,

        [parameter(Mandatory = $true)]
        [ValidateSet(
            'AllowInProcess',
            'DisallowAdHocAccess',
            'DynamicParameters',
            'IndexAsAccessPath',
            'LevelZeroOnly',
            'NestedQueries',
            'NonTransactedUpdates',
            'SqlServerLike'
        )]
        [System.String]
        $ProviderOption,

        [System.Boolean]
        $Enabled
    )


    $sqlServerObject = Connect-cSQL -SQLServer $SQLServer -SQLInstanceName $SQLInstanceName
    
    if (-not $sqlServerObject) {
        Write-Error -Message "Could not connect to SQL Server"
        break;
    }

    $sql_provider = Get-cSQLProvider -SqlServerObject $sqlServerObject -ProviderName $ProviderName

    Write-Verbose -Message "SQL Provider: $($sql_provider.Name)"
    $sql_provider_option = $sql_provider.$ProviderOption
    Write-Verbose -Message "Sql Provider Option: $ProviderOption"
    Write-Verbose -Message "Sql Provider Option Value: $sql_provider_option"

    $returnValue = @{
        SQLServer = $sqlServerObject.NetName
        SQLInstanceName = $sqlServerObject.InstanceName
        ProviderName = $sql_provider.Name
        ProviderOption = $ProviderOption
        Enabled = $sql_provider_option
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
        $ProviderName,

        [parameter(Mandatory = $true)]
        [ValidateSet(
            'AllowInProcess',
            'DisallowAdHocAccess',
            'DynamicParameters',
            'IndexAsAccessPath',
            'LevelZeroOnly',
            'NestedQueries',
            'NonTransactedUpdates',
            'SqlServerLike'
        )]
        [System.String]
        $ProviderOption,

        [System.Boolean]
        $Enabled
    )

    $sqlServerObject = Connect-cSQL -SQLServer $SQLServer -SQLInstanceName $SQLInstanceName
    
    if (-not $sqlServerObject) {
        Write-Error -Message "Could not connect to SQL Server"
        break;
    }

    if ($Enabled) {
        Write-Verbose -Message "Enabling SQL Provider Option: $ProviderOption on Provider: $ProviderName"
        Set-cSQLProviderOption -SqlServerObject $sqlServerObject -ProviderName $ProviderName -OptionName $ProviderOption -Enabled $true
    } else {
        Write-Verbose -Message "Disabling SQL Provider Option: $ProviderOption on Provider: $ProviderName"
        Set-cSQLProviderOption -SqlServerObject $sqlServerObject -ProviderName $ProviderName -OptionName $ProviderOption -Enabled $false
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
        $ProviderName,

        [parameter(Mandatory = $true)]
        [ValidateSet(
            'AllowInProcess',
            'DisallowAdHocAccess',
            'DynamicParameters',
            'IndexAsAccessPath',
            'LevelZeroOnly',
            'NestedQueries',
            'NonTransactedUpdates',
            'SqlServerLike'
        )]
        [System.String]
        $ProviderOption,

        [System.Boolean]
        $Enabled
    )

    $current = Get-TargetResource @PSBoundParameters
    
    switch ($current)
    {
        {$_.Enabled -ne $Enabled}
        {
            Write-Verbose -Message "Current State Ensure: $($_.Enabled)"
            Write-Verbose -Message "Desired State Ensure: $Enabled"
            return $False 
        }
        Default { return $True}
    }
}


Export-ModuleMember -Function *-TargetResource

