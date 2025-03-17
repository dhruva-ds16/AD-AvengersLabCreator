# Avengers Active Directory Lab Creator

This project automates the creation of an Avengers-themed Active Directory environment on a 2-node Proxmox cluster. It creates and configures a Domain Controller and two VMs with specific network configurations.

## Environment Overview

The deployment creates the following VMs:

1. **SHIELD-HQ** (Domain Controller)
   - Internal network only
   - Hosts Active Directory services
   - Node: pve1

2. **STARK-TOWER** (External-facing VM)
   - External network only
   - Node: pve2

3. **SANCTUM** (Dual-NIC VM)
   - Both internal and external networks
   - Node: pve1

## Prerequisites

1. Two Proxmox nodes in a cluster
2. Windows Server 2022 ISO file
3. VirtIO drivers ISO for Windows
4. Python 3.8 or higher
5. Proxmox API token with appropriate permissions

## Getting Started

### 1. Clone the Repository

```bash
git clone https://github.com/yourusername/avengers-ad-lab.git
cd avengers-ad-lab
```

### 2. Install Dependencies

```bash
pip install -r requirements.txt
```

### 3. Obtain Proxmox API Token

1. Log in to the Proxmox web interface
2. Navigate to Datacenter → Permissions → API Tokens
3. Click "Add" to create a new token
4. Select a user (typically root@pam)
5. Enter a token ID (e.g., "ad-creator")
6. Uncheck "Privilege Separation" if you need full access
7. Click "Create" and save the token value

### 4. Configure the Environment

Edit the `config.yaml` file:

```bash
nano config.yaml
```

Update the following:
- Proxmox node hostnames and credentials
- API token details
- Network settings (if different from defaults)
- VM specifications (if needed)
- Set secure passwords for AD admin and safe mode
- Review and update user passwords if needed

### 5. Deploy the Environment

```bash
python create_ad_environment.py
```

This script will:
1. Configure network bridges and VLANs on both Proxmox nodes
2. Create the VMs with the specified configurations
3. Set up the necessary network connections

### 6. Set Up Active Directory Users and Groups

After installing Active Directory on the Domain Controller (SHIELD-HQ), run the user creation script:

```powershell
# Copy the config.yaml and create_ad_users.ps1 to the Domain Controller
# Then run:
.\create_ad_users.ps1
```

This will create all the Avengers-themed users and groups with secure passwords as defined in the configuration file.

### 7. Introduce Misconfigurations (Optional)

For security testing purposes, you can introduce various misconfigurations:

```powershell
.\introduce_misconfigurations.ps1 -DifficultyLevel "Easy"  # Options: Easy, Medium, Hard, Insane
```

## Network Configuration

The environment uses two networks:

1. **Internal Network (vmbr0)**
   - Subnet: 192.168.1.0/24
   - Gateway: 192.168.1.1
   - VLAN ID: 10 (optional)
   - Used by: SHIELD-HQ and SANCTUM

2. **External Network (vmbr1)**
   - Subnet: 10.0.0.0/24
   - Gateway: 10.0.0.1
   - VLAN ID: 20 (optional)
   - Used by: STARK-TOWER and SANCTUM
   - Can use default network settings from Proxmox

## Avengers Theme

The environment uses an Avengers theme:

- Domain: avengers.local
- Domain Controller: SHIELD-HQ
- External VM: STARK-TOWER
- Dual-NIC VM: SANCTUM
- Default admin: nick.fury

### Predefined Users

| Username | Full Name | Groups | Password |
|----------|-----------|--------|----------|
| tony.stark | Tony Stark | Avengers, Administrators | Ir0nM@n2023!# |
| steve.rogers | Steve Rogers | Avengers | C@pt@in4m3r1ca! |
| bruce.banner | Bruce Banner | Avengers, Scientists | Hulk$m@sh2023! |
| natasha.romanoff | Natasha Romanoff | Avengers, SHIELD-Agents | Bl@ckW1d0w$py! |
| thor.odinson | Thor Odinson | Avengers | Mj0ln1r!Asg@rd |
| clint.barton | Clint Barton | Avengers, SHIELD-Agents | H@wk3y3Arch3r! |
| maria.hill | Maria Hill | SHIELD-Agents | SHIELD@g3nt#2023 |
| jane.foster | Jane Foster | Scientists, Civilians | A$tr0phys1cs! |
| pepper.potts | Pepper Potts | Civilians, Administrators | St@rkIndu$tr13s! |

## Troubleshooting

### Network Issues

- Ensure both Proxmox nodes can reach each other
- Verify that the network bridges exist on both nodes
- Check that VLANs are properly configured if used

### VM Creation Issues

- Verify that the ISO files are accessible
- Check storage availability on both nodes
- Ensure API token has sufficient permissions

### Connectivity Issues

- To test connectivity between STARK-TOWER and SANCTUM:
  - From STARK-TOWER, ping SANCTUM's external IP (10.0.0.11)
  - Verify firewall rules allow traffic between the VMs

### User Creation Issues

- Ensure the PowerShell-Yaml module is installed
- Verify that Active Directory is properly set up
- Check that the config.yaml file is accessible on the Domain Controller

## Security Considerations

- This environment is designed for testing and learning purposes
- Use strong passwords for all accounts
- Consider isolating this lab environment from production networks
- The misconfigurations script introduces deliberate security vulnerabilities
- Change the default passwords in production environments

## License

This project is licensed under the MIT License - see the LICENSE file for details. 