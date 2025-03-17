# Script to introduce common AD misconfigurations with difficulty levels
# WARNING: This script introduces security vulnerabilities for educational purposes only

param (
    [Parameter(Mandatory=$true)]
    [ValidateSet('Easy', 'Medium', 'Hard', 'Insane')]
    [string]$DifficultyLevel
)

# Easy Level Misconfigurations
function Set-EasyMisconfigurations {
    Write-Host "Introducing Easy level misconfigurations..."
    
    # Create a user with password never expires and weak password
    $password = ConvertTo-SecureString "Password123!" -AsPlainText -Force
    New-ADUser -Name "WeakUser" -SamAccountName "weakuser" -AccountPassword $password -Enabled $true -PasswordNeverExpires $true
    
    # Add user to Remote Desktop Users
    Add-ADGroupMember -Identity "Remote Desktop Users" -Members "weakuser"
    
    # Enable LLMNR
    $gpo = New-GPO -Name "Enable LLMNR"
    Set-GPRegistryValue -Name "Enable LLMNR" `
        -Key "HKLM\Software\Policies\Microsoft\Windows NT\DNSClient" `
        -ValueName "EnableMulticast" `
        -Type DWord -Value 1
}

# Medium Level Misconfigurations
function Set-MediumMisconfigurations {
    Write-Host "Introducing Medium level misconfigurations..."
    
    # Create Kerberoastable service account with weak password
    $password = ConvertTo-SecureString "ServicePass123" -AsPlainText -Force
    New-ADUser -Name "SQLService" -SamAccountName "sqlservice" -AccountPassword $password -Enabled $true
    Set-ADUser -Identity "sqlservice" -ServicePrincipalNames @("MSSQLSvc/corp-sql:1433")
    
    # Create ASREPRoastable account
    $password = ConvertTo-SecureString "NoPreAuth123!" -AsPlainText -Force
    New-ADUser -Name "NoPreAuth" -SamAccountName "nopreauth" -AccountPassword $password -Enabled $true
    Set-ADAccountControl -Identity "nopreauth" -DoesNotRequirePreAuth $true
    
    # Weak Password Policy
    $weakPolicy = New-ADFineGrainedPasswordPolicy -Name "WeakPasswordPolicy" `
        -Precedence 10 `
        -MinPasswordLength 4 `
        -PasswordHistoryCount 1 `
        -ComplexityEnabled $false `
        -MinPasswordAge "0.00:00:00" `
        -MaxPasswordAge "365.00:00:00" `
        -LockoutThreshold 0
    
    New-ADGroup -Name "WeakPasswordUsers" -GroupScope Global -GroupCategory Security
    Add-ADFineGrainedPasswordPolicySubject -Identity $weakPolicy -Subjects "WeakPasswordUsers"
}

# Hard Level Misconfigurations
function Set-HardMisconfigurations {
    Write-Host "Introducing Hard level misconfigurations..."
    
    # Create nested group privilege escalation path
    New-ADGroup -Name "HelpDesk" -GroupScope Global -GroupCategory Security
    New-ADGroup -Name "ITSupport" -GroupScope Global -GroupCategory Security
    New-ADGroup -Name "ServiceDesk" -GroupScope Global -GroupCategory Security
    
    Add-ADGroupMember -Identity "HelpDesk" -Members "ITSupport"
    Add-ADGroupMember -Identity "ITSupport" -Members "ServiceDesk"
    Add-ADGroupMember -Identity "Account Operators" -Members "HelpDesk"
    
    # Create user with DCSync rights
    $password = ConvertTo-SecureString "User123!" -AsPlainText -Force
    New-ADUser -Name "SyncUser" -SamAccountName "syncuser" -AccountPassword $password -Enabled $true
    
    $acl = Get-Acl "AD:DC=corp,DC=local"
    $sid = (Get-ADUser "syncuser").SID
    $identity = [System.Security.Principal.IdentityReference]$sid
    $adRights = [System.DirectoryServices.ActiveDirectoryRights]"DS-Replication-Get-Changes, DS-Replication-Get-Changes-All"
    $type = [System.Security.AccessControl.AccessControlType]"Allow"
    $inheritanceType = [System.DirectoryServices.ActiveDirectorySecurityInheritance]"All"
    $ace = New-Object System.DirectoryServices.ActiveDirectoryAccessRule $identity, $adRights, $type, $inheritanceType
    $acl.AddAccessRule($ace)
    Set-Acl -Path "AD:DC=corp,DC=local" -AclObject $acl
}

# Insane Level Misconfigurations
function Set-InsaneMisconfigurations {
    Write-Host "Introducing Insane level misconfigurations..."
    
    # Create multiple attack paths with interdependent vulnerabilities
    
    # 1. Shadow Credentials Attack Path
    $password = ConvertTo-SecureString "Complex123!" -AsPlainText -Force
    New-ADUser -Name "KeyAdmin" -SamAccountName "keyadmin" -AccountPassword $password -Enabled $true
    
    # Grant msDS-KeyCredentialLink write permissions
    $acl = Get-Acl "AD:CN=KeyAdmin,CN=Users,DC=corp,DC=local"
    $sid = (Get-ADUser "weakuser").SID
    $identity = [System.Security.Principal.IdentityReference]$sid
    $adRights = [System.DirectoryServices.ActiveDirectoryRights]"WriteProperty"
    $type = [System.Security.AccessControl.AccessControlType]"Allow"
    $ace = New-Object System.DirectoryServices.ActiveDirectoryAccessRule $identity, $adRights, $type, $null, "msDS-KeyCredentialLink"
    $acl.AddAccessRule($ace)
    Set-Acl -Path "AD:CN=KeyAdmin,CN=Users,DC=corp,DC=local" -AclObject $acl
    
    # 2. Resource-Based Constrained Delegation Chain
    New-ADComputer -Name "RBCD-Server" -Enabled $true
    $computer = Get-ADComputer "RBCD-Server"
    
    # Grant machine account write privileges
    $acl = Get-Acl "AD:$($computer.DistinguishedName)"
    $sid = (Get-ADUser "sqlservice").SID
    $identity = [System.Security.Principal.IdentityReference]$sid
    $adRights = [System.DirectoryServices.ActiveDirectoryRights]"GenericWrite"
    $type = [System.Security.AccessControl.AccessControlType]"Allow"
    $ace = New-Object System.DirectoryServices.ActiveDirectoryAccessRule $identity, $adRights, $type
    $acl.AddAccessRule($ace)
    Set-Acl -Path "AD:$($computer.DistinguishedName)" -AclObject $acl
    
    # 3. Cross-Domain Attack Path
    # Note: Requires multiple domains - this is a placeholder
    Write-Host "Note: For cross-domain attacks, set up trust relationships with selective authentication disabled"
    
    # 4. Complex Nested Group Membership
    $groups = @(
        "ServiceAdmins",
        "AppAdmins",
        "DBAdmins",
        "InfraAdmins"
    )
    
    foreach ($group in $groups) {
        New-ADGroup -Name $group -GroupScope Global -GroupCategory Security
    }
    
    # Create circular group memberships
    Add-ADGroupMember -Identity "ServiceAdmins" -Members "AppAdmins"
    Add-ADGroupMember -Identity "AppAdmins" -Members "DBAdmins"
    Add-ADGroupMember -Identity "DBAdmins" -Members "InfraAdmins"
    Add-ADGroupMember -Identity "InfraAdmins" -Members "ServiceAdmins"
    
    # Grant dangerous permissions
    Add-ADGroupMember -Identity "Backup Operators" -Members "ServiceAdmins"
    Add-ADGroupMember -Identity "Server Operators" -Members "AppAdmins"
    Add-ADGroupMember -Identity "Account Operators" -Members "DBAdmins"
}

# Main execution
try {
    Write-Host "Starting misconfiguration deployment for difficulty level: $DifficultyLevel"
    
    switch ($DifficultyLevel) {
        'Easy' {
            Set-EasyMisconfigurations
        }
        'Medium' {
            Set-EasyMisconfigurations
            Set-MediumMisconfigurations
        }
        'Hard' {
            Set-EasyMisconfigurations
            Set-MediumMisconfigurations
            Set-HardMisconfigurations
        }
        'Insane' {
            Set-EasyMisconfigurations
            Set-MediumMisconfigurations
            Set-HardMisconfigurations
            Set-InsaneMisconfigurations
        }
    }
    
    Write-Host "`nMisconfigurations for $DifficultyLevel level have been successfully introduced!"
    Write-Host "WARNING: These misconfigurations create security vulnerabilities."
    Write-Host "This environment should only be used for testing and learning purposes."
    
    # Print attack paths available based on difficulty
    Write-Host "`nAvailable Attack Paths for $DifficultyLevel level:"
    switch ($DifficultyLevel) {
        'Easy' {
            Write-Host "- Password Spraying (weak passwords)"
            Write-Host "- LLMNR/NBT-NS Poisoning"
            Write-Host "- Remote Desktop Access"
        }
        'Medium' {
            Write-Host "- All Easy level attacks"
            Write-Host "- Kerberoasting (SQLService)"
            Write-Host "- ASREPRoasting (NoPreAuth)"
            Write-Host "- Password Policy Abuse"
        }
        'Hard' {
            Write-Host "- All Medium level attacks"
            Write-Host "- Nested Group Privilege Escalation"
            Write-Host "- DCSync Attack Vector"
            Write-Host "- Service Account Privilege Abuse"
        }
        'Insane' {
            Write-Host "- All Hard level attacks"
            Write-Host "- Shadow Credentials Attack"
            Write-Host "- Resource-Based Constrained Delegation"
            Write-Host "- Circular Group Membership Abuse"
            Write-Host "- Multi-Path Privilege Escalation Chains"
        }
    }
}
catch {
    Write-Error "An error occurred while introducing misconfigurations: $_"
    exit 1
} 