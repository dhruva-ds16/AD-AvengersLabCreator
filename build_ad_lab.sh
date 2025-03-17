#!/bin/bash

# AD Lab Creator - Master Build Script
# This script automates the complete setup of an Active Directory lab environment on Proxmox

# Colors for better output
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m' # No Color

# Configuration file
CONFIG_FILE="config.yaml"

# Function to display step information
print_step() {
    echo -e "${GREEN}[+] $1${NC}"
}

# Function to display warnings
print_warning() {
    echo -e "${YELLOW}[!] $1${NC}"
}

# Function to display errors
print_error() {
    echo -e "${RED}[ERROR] $1${NC}"
}

# Function to check if a command was successful
check_success() {
    if [ $? -ne 0 ]; then
        print_error "$1"
        exit 1
    fi
}

# Check if Python is installed
check_python() {
    print_step "Checking Python installation..."
    if ! command -v python3 &> /dev/null; then
        print_error "Python 3 is not installed. Please install Python 3 and try again."
        exit 1
    fi
    
    python3 -c "import yaml, proxmoxer" &> /dev/null
    if [ $? -ne 0 ]; then
        print_step "Installing required Python packages..."
        pip3 install -r requirements.txt
        check_success "Failed to install required packages"
    fi
}

# Check if required files exist
check_files() {
    print_step "Checking for required files..."
    
    if [ ! -f "$CONFIG_FILE" ]; then
        print_error "Configuration file $CONFIG_FILE not found."
        exit 1
    fi
    
    if [ ! -f "create_ad_environment.py" ]; then
        print_error "create_ad_environment.py not found."
        exit 1
    fi
    
    if [ ! -f "create_ad_users.ps1" ]; then
        print_error "create_ad_users.ps1 not found."
        exit 1
    fi
    
    if [ ! -f "configure_ad.ps1" ]; then
        print_error "configure_ad.ps1 not found."
        exit 1
    fi
}

# Create and configure the VMs
create_vms() {
    print_step "Creating and configuring VMs..."
    python3 create_ad_environment.py
    check_success "Failed to create and configure VMs"
}

# Generate network configuration scripts for VMs
generate_network_scripts() {
    print_step "Generating network configuration scripts..."
    
    # Create configure_vm_networking.ps1
    cat > configure_vm_networking.ps1 << 'EOL'
# Script to configure VM networking and routing
param (
    [Parameter(Mandatory=$true)]
    [string]$VMName,
    
    [Parameter(Mandatory=$false)]
    [switch]$EnableRouting,
    
    [Parameter(Mandatory=$false)]
    [switch]$ConfigureDNS,
    
    [Parameter(Mandatory=$false)]
    [string]$InternalInterface = "Ethernet",
    
    [Parameter(Mandatory=$false)]
    [string]$ExternalInterface = "Ethernet 2"
)

function Enable-IPForwarding {
    Write-Host "Enabling IP Forwarding..."
    Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" -Name "IPEnableRouter" -Value 1
    Write-Host "IP Forwarding has been enabled. A restart is required for this change to take effect."
}

function Configure-Routing {
    param (
        [string]$InternalInterface,
        [string]$ExternalInterface
    )
    
    # Get interface indices
    $internalIdx = (Get-NetAdapter -Name $InternalInterface).ifIndex
    $externalIdx = (Get-NetAdapter -Name $ExternalInterface).ifIndex
    
    # Enable NAT on the external interface
    Write-Host "Configuring NAT on external interface..."
    New-NetNat -Name "NATNetwork" -InternalIPInterfaceAddressPrefix "192.168.1.0/24"
    
    # Add routes
    Write-Host "Adding route for internal network traffic..."
    New-NetRoute -DestinationPrefix "192.168.1.0/24" -InterfaceIndex $internalIdx -NextHop "192.168.1.11"
    
    Write-Host "Routing has been configured."
}

function Configure-DNS {
    param (
        [string]$InternalInterface,
        [string]$ExternalInterface
    )
    
    # Get interface indices
    $internalIdx = (Get-NetAdapter -Name $InternalInterface).ifIndex
    $externalIdx = (Get-NetAdapter -Name $ExternalInterface).ifIndex
    
    # Configure DNS settings - using Google DNS for external and DC for internal
    Write-Host "Configuring DNS settings..."
    Set-DnsClientServerAddress -InterfaceIndex $externalIdx -ServerAddresses "8.8.8.8","8.8.4.4"
    Set-DnsClientServerAddress -InterfaceIndex $internalIdx -ServerAddresses "192.168.1.10"
    
    Write-Host "DNS has been configured."
}

# Main script execution
try {
    if ($VMName -eq "SANCTUM") {
        if ($EnableRouting) {
            Enable-IPForwarding
            Configure-Routing -InternalInterface $InternalInterface -ExternalInterface $ExternalInterface
        }
        
        if ($ConfigureDNS) {
            Configure-DNS -InternalInterface $InternalInterface -ExternalInterface $ExternalInterface
        }
    }
    elseif ($VMName -eq "SHIELD-HQ") {
        # For the domain controller, we just need to set the default gateway to point to SANCTUM
        if ($ConfigureDNS) {
            Write-Host "Configuring Domain Controller networking..."
            $interface = Get-NetAdapter | Where-Object { $_.Status -eq "Up" } | Select-Object -First 1
            $interfaceIndex = $interface.InterfaceIndex
            
            # Set SANCTUM as the gateway for the DC
            New-NetRoute -DestinationPrefix "0.0.0.0/0" -InterfaceIndex $interfaceIndex -NextHop "192.168.1.11"
            Write-Host "Domain Controller gateway has been set to SANCTUM (192.168.1.11)"
        }
    }
    
    Write-Host "Network configuration for $VMName completed successfully."
}
catch {
    Write-Error "An error occurred during network configuration: $_"
    exit 1
}
EOL

    # Create setup_connectivity.ps1
    cat > setup_connectivity.ps1 << 'EOL'
# Script to set up connectivity between all VMs
param (
    [Parameter(Mandatory=$false)]
    [switch]$ConfigureAll = $true,
    
    [Parameter(Mandatory=$false)]
    [switch]$ConfigureDC = $false,
    
    [Parameter(Mandatory=$false)]
    [switch]$ConfigureRouter = $false,
    
    [Parameter(Mandatory=$false)]
    [string]$RouterVM = "SANCTUM",
    
    [Parameter(Mandatory=$false)]
    [string]$DCVM = "SHIELD-HQ"
)

function Setup-ScheduledTask {
    param (
        [string]$VMName,
        [string]$ScriptPath,
        [string]$ScriptArgs
    )
    
    Write-Host "Setting up scheduled task for network configuration on $VMName startup..."
    
    # Create action to run the script on startup
    $action = New-ScheduledTaskAction -Execute "powershell.exe" -Argument "-NoProfile -ExecutionPolicy Bypass -File `"$ScriptPath`" $ScriptArgs"
    
    # Trigger at system startup
    $trigger = New-ScheduledTaskTrigger -AtStartup
    
    # Run with highest privileges
    $principal = New-ScheduledTaskPrincipal -UserId "SYSTEM" -LogonType ServiceAccount -RunLevel Highest
    
    # Register the task
    Register-ScheduledTask -TaskName "ConfigureNetworking_$VMName" -Action $action -Trigger $trigger -Principal $principal -Force
    
    Write-Host "Scheduled task for $VMName has been set up."
}

function Configure-RouterVM {
    param (
        [string]$VMName
    )
    
    Write-Host "Configuring $VMName as a router between internal and external networks..."
    
    # Execute the networking script for the router VM
    & ".\configure_vm_networking.ps1" -VMName $VMName -EnableRouting -ConfigureDNS
    
    # Set up the script to run on startup
    $scriptPath = (Get-Item ".\configure_vm_networking.ps1").FullName
    $scriptArgs = "-VMName $VMName -EnableRouting -ConfigureDNS"
    
    Setup-ScheduledTask -VMName $VMName -ScriptPath $scriptPath -ScriptArgs $scriptArgs
    
    Write-Host "$VMName has been configured as a router."
}

function Configure-DomainController {
    param (
        [string]$VMName,
        [string]$RouterIP = "192.168.1.11"
    )
    
    Write-Host "Configuring Domain Controller ($VMName) networking to use $RouterIP as gateway..."
    
    # Execute the networking script for the DC
    & ".\configure_vm_networking.ps1" -VMName $VMName -ConfigureDNS
    
    # Set up the script to run on startup
    $scriptPath = (Get-Item ".\configure_vm_networking.ps1").FullName
    $scriptArgs = "-VMName $VMName -ConfigureDNS"
    
    Setup-ScheduledTask -VMName $VMName -ScriptPath $scriptPath -ScriptArgs $scriptArgs
    
    Write-Host "Domain Controller ($VMName) has been configured to use $RouterIP as gateway."
}

# Main script execution
try {
    # Check if the configuration script exists
    $networkingScript = ".\configure_vm_networking.ps1"
    if (-not (Test-Path $networkingScript)) {
        Write-Error "Networking configuration script not found: $networkingScript"
        exit 1
    }
    
    # Configure based on parameters
    if ($ConfigureAll -or $ConfigureRouter) {
        Configure-RouterVM -VMName $RouterVM
    }
    
    if ($ConfigureAll -or $ConfigureDC) {
        Configure-DomainController -VMName $DCVM
    }
    
    Write-Host "All VM network configurations completed successfully."
    Write-Host "Note: Some changes require a VM restart to take effect."
}
catch {
    Write-Error "An error occurred during VM network configuration: $_"
    exit 1
}
EOL

    # Create network_config_instructions.txt
    cat > network_config_instructions.txt << 'EOL'
# Network Configuration Instructions

After the VMs are created, follow these steps to configure networking:

1. Copy the following files to each VM:
   - configure_vm_networking.ps1
   - setup_connectivity.ps1

2. Run the following command on SANCTUM:
   ```powershell
   .\setup_connectivity.ps1 -ConfigureRouter
   ```

3. Run the following command on SHIELD-HQ:
   ```powershell
   .\setup_connectivity.ps1 -ConfigureDC
   ```

4. Restart both VMs for the changes to take full effect.

NOTE: These steps are executed automatically by this script if you've enabled the option.
EOL

}

# Create a function to upload files to VMs using qm guest command
upload_to_vm() {
    VMID=$1
    FILENAME=$2
    
    print_step "Uploading $FILENAME to VM $VMID..."
    
    # Wait for VM to be responsive
    timeout=300
    interval=10
    elapsed=0
    
    while [ $elapsed -lt $timeout ]; do
        if qm guest cmd $VMID ping; then
            break
        fi
        sleep $interval
        elapsed=$((elapsed + interval))
        echo "Waiting for VM $VMID to be responsive... ($elapsed/$timeout seconds)"
    done
    
    if [ $elapsed -ge $timeout ]; then
        print_error "Timeout waiting for VM $VMID to be responsive."
        return 1
    fi
    
    # Upload file
    qm guest cmd $VMID file-upload -source "$FILENAME" -destination "C:\\$FILENAME"
    check_success "Failed to upload $FILENAME to VM $VMID"
    
    return 0
}

# Function to execute PowerShell script on a VM
execute_on_vm() {
    VMID=$1
    COMMAND=$2
    
    print_step "Executing command on VM $VMID: $COMMAND"
    
    qm guest cmd $VMID exec -param-cmd="powershell.exe" -param-args="-ExecutionPolicy Bypass -Command \"$COMMAND\""
    check_success "Failed to execute command on VM $VMID"
    
    return 0
}

# Configure VM networking
configure_vm_networking() {
    print_step "Configuring VM networking..."
    
    # Get VM IDs from Python script or config
    # This is a placeholder - you would need to extract the actual VM IDs
    SANCTUM_VMID=$(python3 -c "import yaml; print(yaml.safe_load(open('$CONFIG_FILE'))['vm_ids']['SANCTUM'])")
    SHIELD_HQ_VMID=$(python3 -c "import yaml; print(yaml.safe_load(open('$CONFIG_FILE'))['vm_ids']['SHIELD-HQ'])")
    
    # Upload networking scripts to VMs
    upload_to_vm $SANCTUM_VMID "configure_vm_networking.ps1"
    upload_to_vm $SANCTUM_VMID "setup_connectivity.ps1"
    upload_to_vm $SHIELD_HQ_VMID "configure_vm_networking.ps1"
    upload_to_vm $SHIELD_HQ_VMID "setup_connectivity.ps1"
    
    # Configure SANCTUM as router
    execute_on_vm $SANCTUM_VMID ".\\setup_connectivity.ps1 -ConfigureRouter"
    
    # Configure SHIELD-HQ to use SANCTUM as gateway
    execute_on_vm $SHIELD_HQ_VMID ".\\setup_connectivity.ps1 -ConfigureDC"
    
    # Restart VMs to apply changes
    print_step "Restarting VMs to apply networking changes..."
    qm reboot $SANCTUM_VMID
    qm reboot $SHIELD_HQ_VMID
}

# Main execution
main() {
    print_step "Starting AD Lab setup"
    
    # Check prerequisites
    check_python
    check_files
    
    # Create VMs using the Python script
    create_vms
    
    # Generate network configuration scripts
    generate_network_scripts
    
    # Ask if user wants to configure networking automatically
    read -p "Do you want to configure VM networking automatically? (y/n): " configure_network
    if [[ $configure_network == "y" || $configure_network == "Y" ]]; then
        configure_vm_networking
    else
        print_warning "Skipping automatic network configuration."
        print_warning "Please follow the instructions in network_config_instructions.txt to configure networking manually."
    fi
    
    print_step "AD Lab setup completed successfully!"
    print_step "Check network_config_instructions.txt for manual networking configuration if needed."
}

# Run the main function
main 