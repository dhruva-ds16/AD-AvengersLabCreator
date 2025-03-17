# Script to create Avengers-themed Active Directory users and groups
# This script should be run on the Domain Controller (SHIELD-HQ) after AD is set up

param (
    [Parameter(Mandatory=$false)]
    [string]$ConfigPath = "config.yaml"
)

# Function to load YAML configuration
function Load-YamlConfig {
    param (
        [string]$ConfigPath
    )
    
    try {
        # Check if the module is installed
        if (-not (Get-Module -ListAvailable -Name "powershell-yaml")) {
            Write-Host "Installing PowerShell-Yaml module..."
            Install-Module -Name powershell-yaml -Force -Scope CurrentUser
        }
        
        # Import the module
        Import-Module powershell-yaml
        
        # Load the YAML file
        $yamlContent = Get-Content -Path $ConfigPath -Raw
        $config = ConvertFrom-Yaml -Yaml $yamlContent
        
        return $config
    }
    catch {
        Write-Error "Failed to load configuration: $_"
        exit 1
    }
}

# Function to create AD groups
function Create-ADGroups {
    param (
        [array]$Groups
    )
    
    foreach ($group in $Groups) {
        try {
            # Check if group exists
            $existingGroup = Get-ADGroup -Filter "Name -eq '$($group.name)'" -ErrorAction SilentlyContinue
            
            if (-not $existingGroup) {
                New-ADGroup -Name $group.name -GroupScope Global -Description $group.description
                Write-Host "Created group: $($group.name)" -ForegroundColor Green
            }
            else {
                Write-Host "Group already exists: $($group.name)" -ForegroundColor Yellow
            }
        }
        catch {
            Write-Error "Failed to create group $($group.name): $_"
        }
    }
}

# Function to create AD users
function Create-ADUsers {
    param (
        [array]$Users
    )
    
    foreach ($user in $Users) {
        try {
            # Check if user exists
            $existingUser = Get-ADUser -Filter "SamAccountName -eq '$($user.username)'" -ErrorAction SilentlyContinue
            
            if (-not $existingUser) {
                # Create secure password
                $securePassword = ConvertTo-SecureString $user.password -AsPlainText -Force
                
                # Create user
                New-ADUser -SamAccountName $user.username `
                    -UserPrincipalName "$($user.username)@$env:USERDNSDOMAIN" `
                    -Name $user.fullname `
                    -GivenName $user.fullname.Split(' ')[0] `
                    -Surname $user.fullname.Split(' ')[1] `
                    -DisplayName $user.fullname `
                    -AccountPassword $securePassword `
                    -Enabled $true `
                    -PasswordNeverExpires $false `
                    -ChangePasswordAtLogon $false
                
                Write-Host "Created user: $($user.username)" -ForegroundColor Green
                
                # Add user to groups
                foreach ($groupName in $user.groups) {
                    Add-ADGroupMember -Identity $groupName -Members $user.username
                    Write-Host "  Added to group: $groupName" -ForegroundColor Cyan
                }
            }
            else {
                Write-Host "User already exists: $($user.username)" -ForegroundColor Yellow
            }
        }
        catch {
            Write-Error "Failed to create user $($user.username): $_"
        }
    }
}

# Main execution
try {
    Write-Host "Starting Avengers AD user and group creation..." -ForegroundColor Cyan
    
    # Load configuration
    $config = Load-YamlConfig -ConfigPath $ConfigPath
    
    # Create groups first
    Write-Host "`nCreating AD Groups..." -ForegroundColor Cyan
    Create-ADGroups -Groups $config.groups
    
    # Create users
    Write-Host "`nCreating AD Users..." -ForegroundColor Cyan
    Create-ADUsers -Users $config.users
    
    Write-Host "`nUser and group creation completed successfully!" -ForegroundColor Green
    Write-Host "The Avengers are now ready to assemble!" -ForegroundColor Cyan
}
catch {
    Write-Error "An error occurred during user and group creation: $_"
    exit 1
} 