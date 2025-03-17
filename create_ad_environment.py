#!/usr/bin/env python3

import os
import sys
import time
import yaml
import logging
import subprocess
import re
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
        """Configure network bridges and VLANs on Proxmox nodes using direct pvesh commands."""
        for node_key in ['node1', 'node2']:
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
                network_info = proxmox.nodes(node).network.get()
                
                existing_bridges = [iface.get('iface') for iface in network_info]
                
                # If bridges don't exist, create them using direct pvesh commands
                if internal_bridge not in existing_bridges:
                    logger.info(f"Creating internal bridge {internal_bridge} on {node}...")
                    try:
                        self._run_local_command(f"pvesh create /nodes/{node}/network -iface {internal_bridge} -type bridge -autostart {internal_autostart} -comments '{internal_name}'")
                    except Exception as e:
                        logger.warning(f"pvesh command failed, trying API directly: {e}")
                        # Fallback to API
                        proxmox.nodes(node).network.post(
                            iface=internal_bridge,
                            type='bridge',
                            autostart=internal_autostart,
                            comments=internal_name
                        )
                else:
                    logger.info(f"Internal bridge {internal_bridge} already exists on {node}")
                
                if external_bridge not in existing_bridges:
                    logger.info(f"Creating external bridge {external_bridge} on {node}...")
                    try:
                        self._run_local_command(f"pvesh create /nodes/{node}/network -iface {external_bridge} -type bridge -autostart {external_autostart} -comments '{external_name}'")
                    except Exception as e:
                        logger.warning(f"pvesh command failed, trying API directly: {e}")
                        # Fallback to API
                        proxmox.nodes(node).network.post(
                            iface=external_bridge,
                            type='bridge',
                            autostart=external_autostart,
                            comments=external_name
                        )
                else:
                    logger.info(f"External bridge {external_bridge} already exists on {node}")
                
                # Refresh network info after creating bridges
                network_info = proxmox.nodes(node).network.get()
                existing_bridges = [iface.get('iface') for iface in network_info]
                
                # Configure VLANs if specified
                if 'vlan' in self.config['networks']['internal'] and internal_bridge in existing_bridges:
                    vlan_id = self.config['networks']['internal']['vlan']
                    vlan_iface = f"vlan{vlan_id}"
                    
                    if vlan_iface not in existing_bridges:
                        logger.info(f"Configuring VLAN {vlan_id} on internal network...")
                        try:
                            self._run_local_command(f"pvesh create /nodes/{node}/network -iface {vlan_iface} -type vlan -bridge {internal_bridge} -vlan_id {vlan_id} -autostart 1")
                        except Exception as e:
                            logger.warning(f"pvesh command failed, trying API directly: {e}")
                            # Fallback to API
                            proxmox.nodes(node).network.post(
                                iface=vlan_iface,
                                type='vlan',
                                bridge=internal_bridge,
                                vlan_id=vlan_id,
                                autostart=1
                            )
                
                if 'vlan' in self.config['networks']['external'] and external_bridge in existing_bridges:
                    vlan_id = self.config['networks']['external']['vlan']
                    vlan_iface = f"vlan{vlan_id}"
                    
                    if vlan_iface not in existing_bridges:
                        logger.info(f"Configuring VLAN {vlan_id} on external network...")
                        try:
                            self._run_local_command(f"pvesh create /nodes/{node}/network -iface {vlan_iface} -type vlan -bridge {external_bridge} -vlan_id {vlan_id} -autostart 1")
                        except Exception as e:
                            logger.warning(f"pvesh command failed, trying API directly: {e}")
                            # Fallback to API
                            proxmox.nodes(node).network.post(
                                iface=vlan_iface,
                                type='vlan',
                                bridge=external_bridge,
                                vlan_id=vlan_id,
                                autostart=1
                            )
                
                # Apply network configuration
                logger.info(f"Applying network configuration on {node}...")
                try:
                    self._run_local_command(f"pvesh create /nodes/{node}/network -reload 1")
                except Exception as e:
                    logger.warning(f"pvesh command failed, trying API directly: {e}")
                    # Fallback to API
                    proxmox.nodes(node).network.put('reload')
                
                logger.info(f"Network configuration completed on {node}")
            except Exception as e:
                logger.error(f"Failed to configure networks on {node}: {e}")
                return False
        return True
    
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

    def create_vm(self, vm_config, vm_type):
        """Create a new VM with specified configuration."""
        node = vm_config['node']
        proxmox = self.proxmox_connections[node]
        
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
            
            # Add VLAN tag if specified
            vlan_tag = f",tag={net.get('vlan', '')}" if 'vlan' in net else ""
            
            net_config[f'net{idx}'] = f"model=virtio,bridge={bridge}{vlan_tag}"

        # Create VM
        try:
            # Convert any boolean parameters to integers for Proxmox API
            create_params = {
                'vmid': vmid,
                'name': vm_config['name'],
                'memory': vm_config['memory'],
                'cores': vm_config['cores'],
                'sockets': 1,
                'ostype': "win11",
                'scsihw': "virtio-scsi-pci",
                'scsi0': f"{vm_config['storage']}:{vm_config['disk_size']}",
                'ide2': f"{self.config['windows']['iso_storage']:iso}/{self.config['windows']['iso_file']},media=cdrom",
                'ide3': f"{self.config['windows']['iso_storage']:iso}/{self.config['windows']['virtio_iso']},media=cdrom",
                **net_config
            }
            
            # Convert any boolean values to integers (1/0)
            for key, value in create_params.items():
                if isinstance(value, bool):
                    create_params[key] = 1 if value else 0
            
            proxmox.nodes(node).qemu.create(**create_params)
            logger.info(f"Created VM {vm_config['name']} with ID {vmid} on node {node}")
            return vmid
        except Exception as e:
            logger.error(f"Failed to create VM: {e}")
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