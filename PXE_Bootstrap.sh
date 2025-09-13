#!/bin/bash

# PXE Server Bootstrap Script for Ubuntu 24.04
# Author: John Gautreaux
# Description: Automated setup of PXE boot server with Ubuntu 24.04

set -e  # Exit on any error

# Color codes for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Configuration variables
PXE_INTERFACE=""
PXE_IP="192.168.100.1"
PXE_SUBNET="192.168.100"
DHCP_START="192.168.100.100"
DHCP_END="192.168.100.200"
UBUNTU_VERSION="24.04.1"
UBUNTU_ISO_URL="https://releases.ubuntu.com/24.04/ubuntu-24.04.1-live-server-amd64.iso"

# Function to print colored output
print_status() {
    echo -e "${GREEN}[INFO]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

print_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

print_header() {
    echo -e "${BLUE}================================================${NC}"
    echo -e "${BLUE}$1${NC}"
    echo -e "${BLUE}================================================${NC}"
}

# Function to check if running as root
check_root() {
    if [[ $EUID -eq 0 ]]; then
        print_error "This script should not be run as root. Please run as a regular user with sudo privileges."
        exit 1
    fi
    
    # Check if user has sudo privileges
    if ! sudo -n true 2>/dev/null; then
        print_error "This script requires sudo privileges. Please ensure your user can run sudo commands."
        exit 1
    fi
}

# Function to detect available network interfaces
detect_interfaces() {
    print_header "NETWORK INTERFACE DETECTION"
    echo "Available network interfaces:"
    ip addr show | grep -E "^[0-9]+:" | sed 's/^[0-9]*: //' | sed 's/:.*$//' | grep -v lo | nl
    echo ""
    echo "Current network configuration:"
    ip addr show | grep -E "(inet|^[0-9]+:)" | grep -v "127.0.0.1"
    echo ""
}

# Function to get user input for configuration
get_user_input() {
    detect_interfaces
    
    # Get PXE interface
    read -p "Enter the network interface for PXE (e.g., ens160, eth1): " PXE_INTERFACE
    
    if [[ -z "$PXE_INTERFACE" ]]; then
        print_error "Interface name cannot be empty"
        exit 1
    fi
    
    # Validate interface exists
    if ! ip addr show "$PXE_INTERFACE" &>/dev/null; then
        print_error "Interface $PXE_INTERFACE does not exist"
        exit 1
    fi
    
    # Get network configuration
    read -p "Enter PXE server IP address [$PXE_IP]: " input_ip
    PXE_IP=${input_ip:-$PXE_IP}
    
    # Extract subnet from IP
    PXE_SUBNET=$(echo $PXE_IP | cut -d'.' -f1-3)
    DHCP_START="$PXE_SUBNET.100"
    DHCP_END="$PXE_SUBNET.200"
    
    read -p "Enter DHCP range start [$DHCP_START]: " input_start
    DHCP_START=${input_start:-$DHCP_START}
    
    read -p "Enter DHCP range end [$DHCP_END]: " input_end
    DHCP_END=${input_end:-$DHCP_END}
    
    echo ""
    print_status "Configuration Summary:"
    echo "  PXE Interface: $PXE_INTERFACE"
    echo "  PXE Server IP: $PXE_IP"
    echo "  DHCP Range: $DHCP_START - $DHCP_END"
    echo ""
    read -p "Continue with this configuration? [y/N]: " confirm
    if [[ ! "$confirm" =~ ^[Yy]$ ]]; then
        print_error "Installation cancelled by user"
        exit 0
    fi
}

# Function to update system and install packages
install_packages() {
    print_header "UPDATING SYSTEM AND INSTALLING PACKAGES"
    
    print_status "Updating package repositories..."
    sudo apt update
    
    print_status "Upgrading existing packages..."
    sudo apt upgrade -y
    
    print_status "Installing required packages..."
    sudo DEBIAN_FRONTEND=noninteractive apt install -y \
        dnsmasq \
        tftpd-hpa \
        apache2 \
        syslinux-common \
        pxelinux \
        nfs-kernel-server \
        wget \
        curl \
        net-tools
    
    print_status "Packages installed successfully"
}

# Function to configure network interface
configure_network() {
    print_header "CONFIGURING NETWORK INTERFACE"
    
    # Backup existing netplan configuration
    sudo cp /etc/netplan/*.yaml /etc/netplan/backup-$(date +%Y%m%d-%H%M%S).yaml 2>/dev/null || true
    
    # Create new netplan configuration
    print_status "Creating netplan configuration..."
    
    cat << EOF | sudo tee /etc/netplan/01-pxe-config.yaml > /dev/null
network:
  version: 2
  ethernets:
    $PXE_INTERFACE:
      dhcp4: false
      addresses:
        - $PXE_IP/24
      nameservers:
        addresses:
          - 8.8.8.8
          - 8.8.4.4
EOF
    
    # Set correct permissions for netplan configuration
    print_status "Setting secure permissions for netplan configuration..."
    sudo chmod 600 /etc/netplan/01-pxe-config.yaml
    sudo chown root:root /etc/netplan/01-pxe-config.yaml
    
    print_status "Applying network configuration..."
    sudo netplan apply
    
    # Wait for interface to come up
    sleep 3
    
    print_status "Network interface $PXE_INTERFACE configured with IP $PXE_IP"
}

# Function to configure dnsmasq
configure_dnsmasq() {
    print_header "CONFIGURING DNSMASQ (DHCP/TFTP)"
    
    # Backup original configuration
    sudo cp /etc/dnsmasq.conf /etc/dnsmasq.conf.backup
    
    print_status "Creating dnsmasq configuration..."
    
    cat << EOF | sudo tee /etc/dnsmasq.conf > /dev/null
# PXE Server Configuration
interface=$PXE_INTERFACE
bind-interfaces
dhcp-range=$DHCP_START,$DHCP_END,12h

# TFTP Configuration
enable-tftp
tftp-root=/var/lib/tftpboot
tftp-secure

# PXE Boot Configuration
dhcp-boot=pxelinux.0

# Architecture-specific boot files
dhcp-match=set:bios,option:client-arch,0
dhcp-boot=tag:bios,pxelinux.0
dhcp-match=set:efi32,option:client-arch,6
dhcp-boot=tag:efi32,bootia32.efi
dhcp-match=set:efibc,option:client-arch,7
dhcp-boot=tag:efibc,bootx64.efi
dhcp-match=set:efi64,option:client-arch,9
dhcp-boot=tag:efi64,bootx64.efi

# DNS Configuration
server=8.8.8.8
server=8.8.4.4

# Logging
log-dhcp
log-queries
log-facility=/var/log/dnsmasq.log
EOF
    
    print_status "dnsmasq configured successfully"
}

# Function to setup TFTP boot directory
setup_tftp() {
    print_header "SETTING UP TFTP BOOT DIRECTORY"
    
    print_status "Creating TFTP directory structure..."
    sudo mkdir -p /var/lib/tftpboot
    sudo mkdir -p /var/lib/tftpboot/pxelinux.cfg
    sudo mkdir -p /var/lib/tftpboot/images
    
    print_status "Copying PXE boot files..."
    sudo cp /usr/lib/PXELINUX/pxelinux.0 /var/lib/tftpboot/
    sudo cp /usr/lib/syslinux/modules/bios/*.c32 /var/lib/tftpboot/
    
    # Create PXE boot menu
    print_status "Creating PXE boot menu..."
    cat << EOF | sudo tee /var/lib/tftpboot/pxelinux.cfg/default > /dev/null
DEFAULT menu.c32
PROMPT 0
TIMEOUT 300
ONTIMEOUT local

MENU TITLE PXE Boot Server - Ubuntu $UBUNTU_VERSION
MENU BACKGROUND splash.png

LABEL local
    MENU LABEL Boot from local drive
    LOCALBOOT 0

LABEL ubuntu2404
    MENU LABEL Install Ubuntu $UBUNTU_VERSION Server
    KERNEL images/vmlinuz
    APPEND initrd=images/initrd ip=dhcp url=http://$PXE_IP/ubuntu/ autoinstall quiet splash

LABEL ubuntu2404-manual
    MENU LABEL Install Ubuntu $UBUNTU_VERSION Server (Manual)
    KERNEL images/vmlinuz
    APPEND initrd=images/initrd ip=dhcp url=http://$PXE_IP/ubuntu/ quiet splash
EOF
    
    print_status "TFTP boot directory setup completed"
}

# Function to configure Apache web server
configure_apache() {
    print_header "CONFIGURING APACHE WEB SERVER"
    
    print_status "Creating web directory structure..."
    sudo mkdir -p /var/www/html/ubuntu
    
    print_status "Configuring Apache..."
    sudo systemctl enable apache2
    sudo systemctl start apache2
    
    # Create a simple index page
    cat << EOF | sudo tee /var/www/html/index.html > /dev/null
<!DOCTYPE html>
<html>
<head>
    <title>PXE Boot Server</title>
</head>
<body>
    <h1>PXE Boot Server</h1>
    <p>Ubuntu $UBUNTU_VERSION PXE Boot Server is running</p>
    <p>Server IP: $PXE_IP</p>
    <p>Available resources:</p>
    <ul>
        <li><a href="/ubuntu/">Ubuntu Installation Files</a></li>
    </ul>
</body>
</html>
EOF
    
    print_status "Apache web server configured successfully"
}

# Function to download and setup Ubuntu ISO
download_ubuntu() {
    print_header "DOWNLOADING AND SETTING UP UBUNTU ISO"
    
    cd /tmp
    
    # Check if ISO already exists
    ISO_FILE="ubuntu-$UBUNTU_VERSION-live-server-amd64.iso"
    
    if [[ ! -f "$ISO_FILE" ]]; then
        print_status "Downloading Ubuntu $UBUNTU_VERSION ISO..."
        print_warning "This may take a while depending on your internet connection..."
        
        wget -O "$ISO_FILE" "$UBUNTU_ISO_URL" || {
            print_error "Failed to download Ubuntu ISO"
            exit 1
        }
    else
        print_status "Ubuntu ISO already exists, skipping download"
    fi
    
    print_status "Mounting and extracting ISO..."
    sudo mkdir -p /mnt/iso
    sudo mount -o loop "$ISO_TARGET" /mnt/iso
    
    # Copy ISO contents to web directory
    sudo cp -r /mnt/iso/* /var/www/html/ubuntu/
    
    # Copy kernel and initrd for network boot
    sudo cp /var/www/html/ubuntu/casper/vmlinuz /var/lib/tftpboot/images/
    sudo cp /var/www/html/ubuntu/casper/initrd /var/lib/tftpboot/images/
    
    # Unmount ISO
    sudo umount /mnt/iso
    sudo rmdir /mnt/iso
    
    print_status "Ubuntu files setup completed"
}

# Function to set correct permissions
set_permissions() {
    print_header "SETTING FILE PERMISSIONS"
    
    print_status "Setting TFTP permissions..."
    sudo chmod -R 755 /var/lib/tftpboot
    sudo chown -R tftp:tftp /var/lib/tftpboot
    
    print_status "Setting web directory permissions..."
    sudo chmod -R 755 /var/www/html/ubuntu
    sudo chown -R www-data:www-data /var/www/html
    
    print_status "Permissions set successfully"
}

# Function to configure firewall
configure_firewall() {
    print_header "CONFIGURING FIREWALL"
    
    # Check if UFW is active
    if sudo ufw status | grep -q "Status: active"; then
        print_status "UFW is active, adding firewall rules..."
        sudo ufw allow 67/udp comment "DHCP"
        sudo ufw allow 69/udp comment "TFTP"
        sudo ufw allow 80/tcp comment "HTTP"
        sudo ufw allow 53/udp comment "DNS"
        print_status "Firewall rules added"
    else
        print_warning "UFW is not active, skipping firewall configuration"
    fi
}

# Function to start and enable services
start_services() {
    print_header "STARTING AND ENABLING SERVICES"
    
    print_status "Starting dnsmasq..."
    sudo systemctl enable dnsmasq
    sudo systemctl restart dnsmasq
    
    print_status "Starting TFTP server..."
    sudo systemctl enable tftpd-hpa
    sudo systemctl restart tftpd-hpa
    
    print_status "Ensuring Apache is running..."
    sudo systemctl restart apache2
    
    # Wait a moment for services to start
    sleep 3
    
    print_status "Checking service status..."
    if sudo systemctl is-active --quiet dnsmasq; then
        print_status "dnsmasq is running"
    else
        print_error "dnsmasq failed to start"
    fi
    
    if sudo systemctl is-active --quiet tftpd-hpa; then
        print_status "TFTP server is running"
    else
        print_error "TFTP server failed to start"
    fi
    
    if sudo systemctl is-active --quiet apache2; then
        print_status "Apache web server is running"
    else
        print_error "Apache web server failed to start"
    fi
}

# Function to create autoinstall configuration
create_autoinstall() {
    print_header "CREATING AUTOINSTALL CONFIGURATION (OPTIONAL)"
    
    read -p "Do you want to create an autoinstall configuration for unattended installations? [y/N]: " create_auto
    
    if [[ "$create_auto" =~ ^[Yy]$ ]]; then
        print_status "Creating autoinstall configuration..."
        
        sudo mkdir -p /var/www/html/ubuntu/server
        
        cat << 'EOF' | sudo tee /var/www/html/ubuntu/server/user-data > /dev/null
#cloud-config
autoinstall:
  version: 1
  locale: en_US.UTF-8
  keyboard:
    layout: us
  network:
    network:
      version: 2
      ethernets:
        eth0:
          dhcp4: yes
  storage:
    layout:
      name: lvm
  identity:
    hostname: pxe-installed
    username: ubuntu
    password: "$6$rounds=4096$anotherSalt$EQZhgDBMTRpjjFvnKdQdKBhKNjJ.HGX.IQPGe.J/kbYF/pJsOCQoFoJ1QGP.CdaT.p7n4x4dPY3Qr.k6T1t3y1"
    # Password is: ubuntu123 (please change this!)
  ssh:
    install-server: yes
    allow-pw: yes
  packages:
    - openssh-server
    - curl
    - wget
    - vim
  late-commands:
    - echo 'ubuntu ALL=(ALL) NOPASSWD:ALL' > /target/etc/sudoers.d/ubuntu
    - chmod 440 /target/etc/sudoers.d/ubuntu
EOF

        # Create empty meta-data file
        echo "" | sudo tee /var/www/html/ubuntu/server/meta-data > /dev/null
        
        # Update PXE menu to include autoinstall option
        sudo sed -i '/APPEND initrd=images\/initrd ip=dhcp url=/s/$/ ds=nocloud-net;s=http:\/\/'$PXE_IP'\/ubuntu\/server\//' /var/lib/tftpboot/pxelinux.cfg/default
        
        print_status "Autoinstall configuration created"
        print_warning "Default password is 'ubuntu123' - please change this in production!"
    fi
}

# Function to display final information
display_final_info() {
    print_header "INSTALLATION COMPLETED SUCCESSFULLY"
    
    echo ""
    print_status "PXE Boot Server Configuration:"
    echo "  Server IP: $PXE_IP"
    echo "  Interface: $PXE_INTERFACE"
    echo "  DHCP Range: $DHCP_START - $DHCP_END"
    echo "  Web Interface: http://$PXE_IP"
    echo ""
    
    print_status "To use the PXE server:"
    echo "  1. Connect client machines to the same network as $PXE_INTERFACE"
    echo "  2. Configure client BIOS/UEFI to boot from network (PXE)"
    echo "  3. Boot the client machine"
    echo "  4. Select 'Install Ubuntu $UBUNTU_VERSION Server' from the menu"
    echo ""
    
    print_status "Useful commands for troubleshooting:"
    echo "  Check services: sudo systemctl status dnsmasq tftpd-hpa apache2"
    echo "  View DHCP leases: sudo journalctl -u dnsmasq | grep DHCP"
    echo "  Check TFTP: tftp $PXE_IP -c get pxelinux.0"
    echo "  View logs: sudo journalctl -u dnsmasq -f"
    echo "  Test URLs: curl -I $UBUNTU_ISO_URL"
    echo ""
    
    print_status "Manual ISO download alternatives:"
    echo "  Primary: $UBUNTU_ISO_URL"
    for alt_url in "${UBUNTU_ISO_ALT_URLS[@]}"; do
        echo "  Mirror: $alt_url"
    done
    echo ""
    
    print_warning "Security Note: This setup is intended for isolated networks."
    print_warning "For production use, implement proper security measures."
    echo ""
}

# Function to perform cleanup on error
cleanup() {
    print_error "Installation failed. Performing cleanup..."
    
    # Stop services that might have been started
    sudo systemctl stop dnsmasq 2>/dev/null || true
    sudo systemctl stop tftpd-hpa 2>/dev/null || true
    
    # Restore dnsmasq config if backup exists
    if [[ -f /etc/dnsmasq.conf.backup ]]; then
        sudo mv /etc/dnsmasq.conf.backup /etc/dnsmasq.conf
    fi
    
    print_error "Cleanup completed. Please check the error messages above."
}

# Main function
main() {
    # Set trap for cleanup on error
    trap cleanup ERR
    
    print_header "PXE SERVER BOOTSTRAP SCRIPT FOR UBUNTU 24.04"
    echo "This script will set up a complete PXE boot server"
    echo "Press Ctrl+C to cancel at any time"
    echo ""
    
    # Preliminary checks
    check_root
    
    # Get configuration from user
    get_user_input
    
    # Execute installation steps
    install_packages
    configure_network
    configure_dnsmasq
    setup_tftp
    configure_apache
    download_ubuntu
    set_permissions
    configure_firewall
    start_services
    create_autoinstall
    
    # Display final information
    display_final_info
    
    print_status "Bootstrap script completed successfully!"
}

# Run main function
main "$@"
