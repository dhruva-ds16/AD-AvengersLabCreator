# Script to configure Active Directory Domain Services
param (
    [Parameter(Mandatory=$true)]
    [string]$DomainName,
    
    [Parameter(Mandatory=$true)]
    [string]$NetBIOSName,
    
    [Parameter(Mandatory=$true)]
    [SecureString]$SafeModePassword,
    
    [Parameter(Mandatory=$false)]
    [string]$VMType = "dc",  # Can be 'dc', 'vm1', or 'vm2'
    
    [Parameter(Mandatory=$false)]
    [hashtable]$NetworkConfig
)

# Function to configure networking for single NIC
function Set-SingleNetworkConfiguration {
    param (
        [string]$IPAddress,
        [string]$SubnetMask,
        [string]$Gateway,
        [string]$DNS
    )
    
    $adapter = Get-NetAdapter | Where-Object { $_.Status -eq "Up" } | Select-Object -First 1
    $interface = $adapter.InterfaceIndex
    
    # Configure IP address
    New-NetIPAddress -InterfaceIndex $interface -IPAddress $IPAddress -PrefixLength 24 -DefaultGateway $Gateway
    Set-DnsClientServerAddress -InterfaceIndex $interface -ServerAddresses $DNS
}

# Function to configure networking for dual NICs
function Set-DualNetworkConfiguration {
    param (
        [hashtable]$Nic1Config,
        [hashtable]$Nic2Config
    )
    
    $adapters = Get-NetAdapter | Where-Object { $_.Status -eq "Up" } | Sort-Object -Property Name
    
    # Configure first NIC (Internal)
    New-NetIPAddress -InterfaceIndex $adapters[0].InterfaceIndex `
        -IPAddress $Nic1Config.IPAddress `
        -PrefixLength 24 `
        -DefaultGateway $Nic1Config.Gateway
    
    Set-DnsClientServerAddress -InterfaceIndex $adapters[0].InterfaceIndex `
        -ServerAddresses $Nic1Config.DNS
    
    # Configure second NIC (External)
    New-NetIPAddress -InterfaceIndex $adapters[1].InterfaceIndex `
        -IPAddress $Nic2Config.IPAddress `
        -PrefixLength 24 `
        -DefaultGateway $Nic2Config.Gateway
}

# Function to install AD DS role
function Install-ADDSRole {
    Install-WindowsFeature -Name AD-Domain-Services -IncludeManagementTools
}

# Function to configure domain controller
function Configure-DomainController {
    param (
        [string]$DomainName,
        [string]$NetBIOSName,
        [SecureString]$SafeModePassword
    )
    
    Install-ADDSForest `
        -DomainName $DomainName `
        -DomainNetbiosName $NetBIOSName `
        -InstallDns `
        -SafeModeAdministratorPassword $SafeModePassword `
        -Force
}

# Main execution
try {
    # Configure networking based on VM type
    Write-Host "Configuring network settings..."
    switch ($VMType) {
        "dc" {
            Set-SingleNetworkConfiguration @NetworkConfig
        }
        "vm1" {
            Set-SingleNetworkConfiguration @NetworkConfig
        }
        "vm2" {
            Set-DualNetworkConfiguration @NetworkConfig
        }
    }

    # If this is the DC, install AD DS
    if ($VMType -eq "dc") {
        Write-Host "Installing AD DS role..."
        Install-ADDSRole

        Write-Host "Configuring domain controller..."
        Configure-DomainController -DomainName $DomainName -NetBIOSName $NetBIOSName -SafeModePassword $SafeModePassword
    }

    Write-Host "Configuration completed successfully."
}
catch {
    Write-Error "An error occurred during configuration: $_"
    exit 1
} 