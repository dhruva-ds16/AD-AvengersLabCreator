#!/usr/bin/env python3

import os
import sys
import time
import yaml
import logging
import subprocess
import re
import socket
from proxmoxer import ProxmoxAPI
from pathlib import Path

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

class ADEnvironmentCreator:
    def __init__(self, config_path='config.yaml'):
        self.config = self._load_config(config_path)
        self.proxmox_connections = {}
        self._setup_proxmox_connections()
        self.default_network_settings = {}

    def _load_config(self, config_path):
        """Load configuration from YAML file."""
        try:
            with open(config_path, 'r') as f:
                return yaml.safe_load(f)
        except Exception as e:
            logger.error(f"Failed to load config: {e}")
            sys.exit(1)

    def _setup_proxmox_connections(self):
        """Setup connections to both Proxmox nodes."""
        for node_key in ['node1', 'node2']:
            node_config = self.config['proxmox'][node_key]
            try:
                # Determine if we're running on this Proxmox node
                hostname = socket.gethostname()
                is_local_node = (hostname == node_config['node'])
                logger.info(f"Current hostname: {hostname}, Node: {node_config['node']}, Is local: {is_local_node}")
                
                # If we're on the local node and no token is provided, use ticket auth
                if is_local_node and not self.config['proxmox']['token_value']:
                    logger.info(f"Using ticket-based authentication for local node {node_config['node']}")
                    # Try to use pvesh to get a ticket
                    try:
                        # Get username and password from environment or config
                        username = os.environ.get('PROXMOX_USER', self.config['proxmox']['user'])
                        password = os.environ.get('PROXMOX_PASSWORD', '')
                        
                        if not password:
                            logger.warning("No password provided for ticket auth. Will try to use existing ticket or cookie.")
                        
                        proxmox = ProxmoxAPI(
                            node_config['host'],
                            user=username,
                            password=password,
                            verify_ssl=self.config['proxmox'].get('verify_ssl', False)
                        )
                    except Exception as e:
                        logger.error(f"Failed to authenticate with ticket: {e}")
                        raise
                else:
                    # Use token-based authentication
                    proxmox = ProxmoxAPI(
                        node_config['host'],
                        user=self.config['proxmox']['user'],
                        token_name=self.config['proxmox']['token_name'],
                        token_value=self.config['proxmox']['token_value'],
                        verify_ssl=self.config['proxmox'].get('verify_ssl', False)
                    )
                
                self.proxmox_connections[node_config['node']] = proxmox
                logger.info(f"Connected to Proxmox node: {node_config['node']}")
            except Exception as e:
                logger.error(f"Failed to connect to {node_key}: {e}")
                sys.exit(1)

    def _detect_default_network(self, node_key):
        """Detect default network settings on the node."""
        node = self.config['proxmox'][node_key]['node']
        external_interface = self.config['proxmox'][node_key]['network']['external_interface']
        
        try:
            # Get network information from the node
            network_info = self.proxmox_connections[node].nodes(node).network.get()
            
            # Find the external interface
            for iface in network_info:
                if iface.get('iface') == external_interface:
                    if 'cidr' in iface:
                        # Extract IP and subnet
                        ip_parts = iface['cidr'].split('/')
                        ip = ip_parts[0]
                        subnet = ip_parts[1] if len(ip_parts) > 1 else '24'
                        
                        # Extract gateway
                        gateway = iface.get('gateway', '')
                        
                        self.default_network_settings[node] = {
                            'ip': ip,
                            'subnet': subnet,
                            'gateway': gateway
                        }
                        
                        logger.info(f"Detected default network settings on {node}: IP={ip}, Subnet={subnet}, Gateway={gateway}")
                        return True
            
            logger.warning(f"Could not detect default network settings on {node}")
            return False
        except Exception as e:
            logger.error(f"Error detecting default network on {node}: {e}")
            return False

    def configure_networks(self):
        """Configure network bridges on Proxmox nodes."""
        for node_key in ['node1', 'node2']:
            node_config = self.config['proxmox'][node_key]
            node = node_config['node']
            
            # Determine if we're running on this Proxmox node
            hostname = socket.gethostname()
            is_local_node = (hostname == node)
            
            if is_local_node:
                # If we're on the local node, try direct file editing first
                logger.info(f"Configuring networks on local node {node} using direct file editing")
                if self._configure_networks_cli(node_key):
                    continue
                
                # If direct file editing fails, try using iproute2 commands as fallback
                logger.warning(f"Direct file editing failed, trying iproute2 commands as fallback")
                if self._configure_networks_fallback(node_key):
                    continue
                
                # If both methods fail, return failure
                logger.error(f"All network configuration methods failed for {node}")
                return False
            else:
                # If we're not on the local node, use the API
                logger.info(f"Configuring networks on remote node {node} using API")
                if not self._configure_networks_api(node_key):
                    return False
        
        return True
    
    def _configure_networks_cli(self, node_key):
        """Configure networks using direct file editing instead of pvesh commands."""
        node_config = self.config['proxmox'][node_key]
        node = node_config['node']
        
        try:
            # Configure internal network
            internal_bridge = node_config['network']['internal_bridge']
            internal_name = self.config['networks']['internal']['name']
            internal_autostart = 1 if self.config['networks']['internal'].get('autostart', True) else 0
            
            # Configure external network
            external_bridge = node_config['network']['external_bridge']
            external_name = self.config['networks']['external']['name']
            external_autostart = 1 if self.config['networks']['external'].get('autostart', True) else 0
            
            # Check if bridges already exist using ip command
            logger.info(f"Checking if bridges already exist on {node}...")
            ip_output = self._run_local_command("ip link show")
            existing_bridges = []
            for line in ip_output.splitlines():
                if ': ' in line:
                    iface_name = line.split(': ')[1].split(':')[0].strip()
                    existing_bridges.append(iface_name)
            
            logger.info(f"Existing bridges detected: {existing_bridges}")
            
            # Check if the bridge is already defined in /etc/network/interfaces
            interfaces_content = self._run_local_command("cat /etc/network/interfaces")
            
            # If internal bridge doesn't exist, create it by editing /etc/network/interfaces
            if internal_bridge not in existing_bridges and f"iface {internal_bridge}" not in interfaces_content:
                logger.info(f"Creating internal bridge {internal_bridge} on {node}...")
                
                # Create a temporary file with the bridge configuration
                bridge_config = f"""
# {internal_name}
auto {internal_bridge}
iface {internal_bridge} inet manual
    bridge_ports none
    bridge_stp off
    bridge_fd 0
"""
                # Append the configuration to /etc/network/interfaces
                self._run_local_command(f"echo '{bridge_config}' >> /etc/network/interfaces")
                logger.info(f"Added {internal_bridge} configuration to /etc/network/interfaces")
            else:
                logger.info(f"Internal bridge {internal_bridge} already exists or is configured")
            
            # If external bridge doesn't exist and is not vmbr0 (which already exists), create it
            if external_bridge != "vmbr0" and external_bridge not in existing_bridges and f"iface {external_bridge}" not in interfaces_content:
                logger.info(f"Creating external bridge {external_bridge} on {node}...")
                
                # Create a temporary file with the bridge configuration
                bridge_config = f"""
# {external_name}
auto {external_bridge}
iface {external_bridge} inet manual
    bridge_ports none
    bridge_stp off
    bridge_fd 0
"""
                # Append the configuration to /etc/network/interfaces
                self._run_local_command(f"echo '{bridge_config}' >> /etc/network/interfaces")
                logger.info(f"Added {external_bridge} configuration to /etc/network/interfaces")
            else:
                logger.info(f"External bridge {external_bridge} already exists or is configured")
            
            # Skip VLAN configuration as requested
            logger.info("Skipping VLAN configuration as requested")
            
            # Apply network configuration by bringing up the interfaces
            if internal_bridge not in existing_bridges or (external_bridge != "vmbr0" and external_bridge not in existing_bridges):
                logger.info(f"Applying network configuration on {node}...")
                
                # Bring up the bridges
                if internal_bridge not in existing_bridges:
                    self._run_local_command(f"ifup {internal_bridge}")
                
                if external_bridge != "vmbr0" and external_bridge not in existing_bridges:
                    self._run_local_command(f"ifup {external_bridge}")
                
                logger.info(f"Network configuration applied on {node}")
            else:
                logger.info(f"No new bridges created, skipping network reload")
            
            logger.info(f"Network configuration completed on {node}")
            return True
        except Exception as e:
            logger.error(f"Failed to configure networks on {node} using direct file editing: {e}")
            return False
    
    def _configure_networks_api(self, node_key):
        """Configure network bridges on Proxmox nodes using API (without VLANs)."""
        node_config = self.config['proxmox'][node_key]
        node = node_config['node']
        
        try:
            # Configure internal network
            internal_bridge = node_config['network']['internal_bridge']
            internal_name = self.config['networks']['internal']['name']
            internal_autostart = 1 if self.config['networks']['internal'].get('autostart', True) else 0
            
            # Configure external network
            external_bridge = node_config['network']['external_bridge']
            external_name = self.config['networks']['external']['name']
            external_autostart = 1 if self.config['networks']['external'].get('autostart', True) else 0
            
            # Check if bridges already exist
            logger.info(f"Checking if bridges already exist on {node}...")
            
            # Use the ProxmoxAPI to check if the bridges exist
            proxmox = self.proxmox_connections[node]
            try:
                network_info = proxmox.nodes(node).network.get()
                existing_bridges = [iface.get('iface') for iface in network_info]
                logger.info(f"Existing bridges detected via API: {existing_bridges}")
            except Exception as e:
                logger.warning(f"Failed to get network info via API: {e}")
                # Fallback to empty list, we'll try to create the bridges anyway
                existing_bridges = []
            
            # If bridges don't exist, create them using API
            created_bridges = False
            
            if internal_bridge in existing_bridges:
                logger.info(f"Internal bridge {internal_bridge} already exists on {node}")
            else:
                try:
                    logger.info(f"Creating internal bridge {internal_bridge} on {node}...")
                    proxmox.nodes(node).network.post(
                        iface=internal_bridge,
                        type='bridge',
                        autostart=internal_autostart,
                        comments=internal_name
                    )
                    created_bridges = True
                    logger.info(f"Successfully created internal bridge {internal_bridge}")
                except Exception as e:
                    logger.error(f"Failed to create internal bridge {internal_bridge}: {e}")
                    # Continue with external bridge even if internal bridge creation failed
            
            if external_bridge in existing_bridges:
                logger.info(f"External bridge {external_bridge} already exists on {node}")
            else:
                try:
                    logger.info(f"Creating external bridge {external_bridge} on {node}...")
                    proxmox.nodes(node).network.post(
                        iface=external_bridge,
                        type='bridge',
                        autostart=external_autostart,
                        comments=external_name
                    )
                    created_bridges = True
                    logger.info(f"Successfully created external bridge {external_bridge}")
                except Exception as e:
                    logger.error(f"Failed to create external bridge {external_bridge}: {e}")
            
            # Skip VLAN configuration as requested
            logger.info("Skipping VLAN configuration as requested")
            
            # Apply network configuration only if we created new bridges
            if created_bridges:
                try:
                    logger.info(f"Applying network configuration on {node}...")
                    proxmox.nodes(node).network.put('reload')
                    logger.info(f"Network configuration applied on {node}")
                except Exception as e:
                    logger.error(f"Failed to reload network configuration: {e}")
                    # Continue even if reload failed
            else:
                logger.info(f"No new bridges created, skipping network reload")
            
            logger.info(f"Network configuration completed on {node}")
            return True
        except Exception as e:
            logger.error(f"Failed to configure networks on {node} using API: {e}")
            return False

    def _configure_networks_fallback(self, node_key):
        """Configure networks using iproute2 commands as a fallback method."""
        node_config = self.config['proxmox'][node_key]
        node = node_config['node']
        
        try:
            # Configure internal network
            internal_bridge = node_config['network']['internal_bridge']
            internal_name = self.config['networks']['internal']['name']
            
            # Configure external network
            external_bridge = node_config['network']['external_bridge']
            external_name = self.config['networks']['external']['name']
            
            # Check if bridges already exist
            logger.info(f"Checking if bridges already exist on {node}...")
            ip_output = self._run_local_command("ip link show")
            existing_bridges = []
            for line in ip_output.splitlines():
                if ': ' in line:
                    iface_name = line.split(': ')[1].split(':')[0].strip()
                    existing_bridges.append(iface_name)
            
            logger.info(f"Existing bridges detected: {existing_bridges}")
            
            # Create internal bridge if it doesn't exist
            if internal_bridge not in existing_bridges:
                logger.info(f"Creating internal bridge {internal_bridge} using iproute2...")
                self._run_local_command(f"ip link add name {internal_bridge} type bridge")
                self._run_local_command(f"ip link set {internal_bridge} up")
                logger.info(f"Internal bridge {internal_bridge} created successfully")
            else:
                logger.info(f"Internal bridge {internal_bridge} already exists")
            
            # Create external bridge if it doesn't exist and is not vmbr0
            if external_bridge != "vmbr0" and external_bridge not in existing_bridges:
                logger.info(f"Creating external bridge {external_bridge} using iproute2...")
                self._run_local_command(f"ip link add name {external_bridge} type bridge")
                self._run_local_command(f"ip link set {external_bridge} up")
                logger.info(f"External bridge {external_bridge} created successfully")
            else:
                logger.info(f"External bridge {external_bridge} already exists or is vmbr0")
            
            # Skip VLAN configuration as requested
            logger.info("Skipping VLAN configuration as requested")
            
            logger.info(f"Network configuration completed on {node} using fallback method")
            return True
        except Exception as e:
            logger.error(f"Failed to configure networks on {node} using fallback method: {e}")
            return False

    def _run_local_command(self, command):
        """Run a command locally on the Proxmox node."""
        try:
            logger.info(f"Running local command: {command}")
            result = subprocess.run(command, shell=True, check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            return result.stdout.decode('utf-8')
        except subprocess.CalledProcessError as e:
            error_output = e.stderr.decode('utf-8')
            logger.error(f"Command failed with exit code {e.returncode}: {error_output}")
            raise

    def _verify_iso_files(self, node):
        """Verify that the required ISO files exist on the specified node."""
        try:
            proxmox = self.proxmox_connections[node]
            iso_storage = self.config['windows']['iso_storage']
            iso_file = self.config['windows']['iso_file']
            virtio_iso = self.config['windows']['virtio_iso']
            
            # Format the ISO paths
            iso_path = self._format_iso_path(iso_storage, iso_file)
            virtio_path = self._format_iso_path(iso_storage, virtio_iso)
            
            logger.info(f"Checking for Windows ISO: {iso_path}")
            logger.info(f"Checking for VirtIO ISO: {virtio_path}")
            
            # Get the list of ISOs in the storage
            try:
                # Extract the storage name without the path
                storage_name = iso_storage.split(':')[0] if ':' in iso_storage else iso_storage
                
                # Get the content list from the storage
                iso_list = proxmox.nodes(node).storage(storage_name).content.get()
                
                # Extract the volume IDs
                iso_volids = [iso.get('volid', '') for iso in iso_list]
                
                logger.info(f"Available ISOs on {node}: {iso_volids}")
                
                # Check if the required ISOs exist
                windows_iso_exists = any(iso_file in volid for volid in iso_volids)
                virtio_iso_exists = any(virtio_iso in volid for volid in iso_volids)
                
                if not windows_iso_exists:
                    logger.warning(f"Windows ISO '{iso_file}' not found on {node}")
                
                if not virtio_iso_exists:
                    logger.warning(f"VirtIO ISO '{virtio_iso}' not found on {node}")
                
                return windows_iso_exists and virtio_iso_exists
            except Exception as e:
                logger.warning(f"Failed to list ISOs on {node}: {e}")
                # If we can't list ISOs, assume they exist and let the VM creation fail if they don't
                return True
        except Exception as e:
            logger.error(f"Failed to verify ISO files on {node}: {e}")
            return False

    def _format_iso_path(self, storage, filename):
        """Format an ISO path correctly for Proxmox."""
        # Check if the storage name already contains a colon
        if ':' in storage:
            storage_prefix = storage
        else:
            storage_prefix = f"{storage}:iso"
        
        # Return the formatted path
        return f"{storage_prefix}/{filename}"

    def create_vm(self, vm_config, vm_type):
        """Create a new VM with specified configuration."""
        node = vm_config['node']
        proxmox = self.proxmox_connections[node]
        
        # Verify that the ISO files exist
        if not self._verify_iso_files(node):
            logger.warning(f"Required ISO files may be missing on {node}. VM creation may fail.")
        
        # Get next available VM ID
        vmid = self._get_next_vmid(proxmox)
        
        # Prepare network configuration
        net_config = {}
        for idx, net in enumerate(vm_config['network']):
            # Determine bridge based on network type
            if net['type'] == 'internal':
                bridge = self.config['proxmox'][self._get_node_key(node)]['network']['internal_bridge']
            else:
                bridge = self.config['proxmox'][self._get_node_key(node)]['network']['external_bridge']
            
            # Skip VLAN tags as requested
            net_config[f'net{idx}'] = f"model=virtio,bridge={bridge}"
            logger.info(f"Configured network {idx} with bridge {bridge} (no VLAN)")

        # Create VM
        try:
            # Format ISO paths correctly
            iso_storage = self.config['windows']['iso_storage']
            iso_file = self.config['windows']['iso_file']
            virtio_iso = self.config['windows']['virtio_iso']
            
            # Use the helper method to format ISO paths
            iso_path = self._format_iso_path(iso_storage, iso_file)
            virtio_path = self._format_iso_path(iso_storage, virtio_iso)
            
            logger.info(f"Using Windows ISO: {iso_path}")
            logger.info(f"Using VirtIO ISO: {virtio_path}")
            
            # Get storage and disk size
            storage = vm_config['storage']
            disk_size = vm_config['disk_size']
            
            # Step 1: Create VM without disk
            create_params = {
                'vmid': vmid,
                'name': vm_config['name'],
                'memory': vm_config['memory'],
                'cores': vm_config['cores'],
                'sockets': 1,
                'ostype': "win11",
                'scsihw': "virtio-scsi-pci",
                'ide2': f"{iso_path},media=cdrom",
                'ide3': f"{virtio_path},media=cdrom",
                **net_config
            }
            
            # Convert any boolean values to integers (1/0)
            for key, value in create_params.items():
                if isinstance(value, bool):
                    create_params[key] = 1 if value else 0
            
            # Log the complete VM creation parameters for debugging
            logger.info(f"VM creation parameters: {create_params}")
            
            # Create the VM without disk first
            proxmox.nodes(node).qemu.create(**create_params)
            logger.info(f"Created VM {vm_config['name']} with ID {vmid} on node {node}")
            
            # Step 2: Add disk using pvesh command instead of the API
            # This ensures we're using the exact format that Proxmox expects
            try:
                # Clean the disk size format
                if disk_size.endswith('G') or disk_size.endswith('g'):
                    clean_size = disk_size
                else:
                    clean_size = f"{disk_size}G"  # Default to GB if no unit specified
                
                # Use subprocess to run pvesh command to add disk
                disk_command = f"pvesh create /nodes/{node}/qemu/{vmid}/config -scsi0 {storage}:{clean_size}"
                logger.info(f"Adding disk with command: {disk_command}")
                
                # Run the command if we're on the local node
                hostname = socket.gethostname()
                is_local_node = (hostname == node)
                
                if is_local_node:
                    self._run_local_command(disk_command)
                    logger.info(f"Added disk to VM {vm_config['name']} using local command")
                else:
                    # If not on local node, use API to add disk
                    logger.info(f"Not on local node, using API to add disk")
                    proxmox.nodes(node).qemu(vmid).config.put(scsi0=f"{storage}:{clean_size}")
                    logger.info(f"Added disk to VM {vm_config['name']} using API")
                
            except Exception as disk_error:
                logger.error(f"Failed to add disk to VM: {disk_error}")
                # Continue even if disk creation fails, as we can add it manually later
            
            return vmid
        except Exception as e:
            logger.error(f"Failed to create VM: {e}")
            logger.error(f"Error details: {str(e)}")
            return None

    def _get_node_key(self, node_name):
        """Get the node key (node1 or node2) from the node name."""
        for key in ['node1', 'node2']:
            if self.config['proxmox'][key]['node'] == node_name:
                return key
        return None

    def _get_next_vmid(self, proxmox):
        """Get the next available VM ID."""
        vmid = 100
        existing_vms = [vm['vmid'] for vm in proxmox.cluster.resources.get(type='vm')]
        while vmid in existing_vms:
            vmid += 1
        return vmid

    def verify_node_resources(self):
        """Verify that nodes have sufficient resources."""
        for node_key in ['node1', 'node2']:
            node = self.config['proxmox'][node_key]['node']
            proxmox = self.proxmox_connections[node]
            
            try:
                node_status = proxmox.nodes(node).status.get()
                memory_total = node_status['memory']['total']
                memory_used = node_status['memory']['used']
                memory_available = memory_total - memory_used
                
                cpu_count = node_status['cpuinfo']['cpus']
                
                logger.info(f"Node {node} status:")
                logger.info(f"Memory available: {memory_available / (1024*1024*1024):.2f} GB")
                logger.info(f"CPU cores: {cpu_count}")
            except Exception as e:
                logger.error(f"Failed to verify resources on {node}: {e}")
                return False
        return True

    def create_environment(self):
        """Create the complete environment with distributed VMs."""
        # Configure networks first
        logger.info("Configuring networks...")
        if not self.configure_networks():
            return False

        # Verify resources
        logger.info("Verifying node resources...")
        if not self.verify_node_resources():
            return False

        # Create Domain Controller on primary node
        logger.info("Creating Domain Controller...")
        dc_vmid = self.create_vm(self.config['vm_distribution']['domain_controller'], 'dc')
        if not dc_vmid:
            return False

        # Create VM1 on secondary node
        logger.info("Creating VM1 (External-facing)...")
        vm1_vmid = self.create_vm(self.config['vm_distribution']['vm1'], 'vm1')
        if not vm1_vmid:
            return False

        # Create VM2 on primary node (with DC)
        logger.info("Creating VM2 (Dual-NIC)...")
        vm2_vmid = self.create_vm(self.config['vm_distribution']['vm2'], 'vm2')
        if not vm2_vmid:
            return False

        logger.info("Environment creation initiated successfully")
        logger.info("VM Distribution:")
        logger.info(f"SHIELD-HQ: Node {self.config['vm_distribution']['domain_controller']['node']}")
        logger.info(f"STARK-TOWER: Node {self.config['vm_distribution']['vm1']['node']}")
        logger.info(f"SANCTUM: Node {self.config['vm_distribution']['vm2']['node']}")
        return True

def main():
    creator = ADEnvironmentCreator()
    if creator.create_environment():
        logger.info("Environment creation process completed successfully")
    else:
        logger.error("Failed to create environment")

if __name__ == "__main__":
    main() 