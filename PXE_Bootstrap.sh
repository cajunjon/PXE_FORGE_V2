#!/bin/bash

# Enhanced PXE Server Bootstrap Script
# Integrated ISO management with full PXE server setup
# Author: Enhanced version combining multiple scripts
# Version: 1.0.0
# Description: Complete PXE boot server with multi-distro support

set -euo pipefail

# Color codes for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
NC='\033[0m' # No Color

# Configuration variables
PXE_INTERFACE=""
PXE_IP="192.168.100.1"
PXE_SUBNET="192.168.100"
DHCP_START="192.168.100.100"
DHCP_END="192.168.100.200"
UBUNTU_VERSION="24.04.1"
UBUNTU_ISO_URL="https://releases.ubuntu.com/24.04/ubuntu-24.04.1-live-server-amd64.iso"

# Enhanced configuration
ISO_STORAGE_DIR="/opt/pxe-isos"
TFTP_ROOT="/var/lib/tftpboot"
WEB_ROOT="/var/www/html"
MENU_TIMEOUT=300
BACKUP_DIR="/opt/pxe-backups"
LOG_DIR="/var/log/pxe-server"

# Distro detection patterns
declare -A DISTRO_PATTERNS=(
    ["ubuntu"]="ubuntu-.*-server.*\.iso|ubuntu-.*-desktop.*\.iso"
    ["debian"]="debian-.*\.iso"
    ["centos"]="CentOS-.*\.iso|centos-.*\.iso"
    ["fedora"]="Fedora-.*\.iso|fedora-.*\.iso"
    ["opensuse"]="openSUSE-.*\.iso|opensuse-.*\.iso"
    ["arch"]="archlinux-.*\.iso"
    ["mint"]="linuxmint-.*\.iso"
    ["rocky"]="Rocky-.*\.iso|rocky-.*\.iso"
    ["alma"]="AlmaLinux-.*\.iso|almalinux-.*\.iso"
    ["windows_server"]=".*[Ww]indows.*[Ss]erver.*\.iso|.*[Ss]erver.*[0-9]{4}.*\.iso"
    ["windows_desktop"]=".*[Ww]indows.*[0-9]{1,2}.*\.iso|.*[Ww]in[0-9]{1,2}.*\.iso"
    ["windows_pe"]=".*[Ww]inPE.*\.iso|.*[Pp]e.*\.iso"
)

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

print_debug() {
    if [[ "${DEBUG:-false}" == "true" ]]; then
        echo -e "${PURPLE}[DEBUG]${NC} $1"
    fi
}

# Function to log actions
log_action() {
    local level="$1"
    local message="$2"
    local timestamp=$(date '+%Y-%m-%d %H:%M:%S')
    echo "[$timestamp] [$level] $message" | sudo tee -a "$LOG_DIR/pxe-server.log" > /dev/null
}

# Function to check if running as root
check_root() {
    if [[ $EUID -eq 0 ]]; then
        print_error "This script should not be run as root. Please run as a regular user with sudo privileges."
        exit 1
    fi
    
    if ! sudo -n true 2>/dev/null; then
        print_error "This script requires sudo privileges. Please ensure your user can run sudo commands."
        exit 1
    fi
}

# Function to create directory structure
create_directories() {
    print_header "CREATING DIRECTORY STRUCTURE"
    
    local dirs=(
        "$ISO_STORAGE_DIR"
        "$BACKUP_DIR"
        "$LOG_DIR"
        "$TFTP_ROOT/images"
        "$TFTP_ROOT/pxelinux.cfg"
        "$WEB_ROOT/pxe"
        "$WEB_ROOT/autoinstall"
    )
    
    for dir in "${dirs[@]}"; do
        sudo mkdir -p "$dir"
        print_debug "Created directory: $dir"
    done
    
    log_action "INFO" "Directory structure created"
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

# Function to get user configuration
get_user_input() {
    detect_interfaces
    
    read -pr "Enter the network interface for PXE (e.g., ens160, eth1): " PXE_INTERFACE
    
    if [[ -z "$PXE_INTERFACE" ]]; then
        print_error "Interface name cannot be empty"
        exit 1
    fi
    
    if ! ip addr show "$PXE_INTERFACE" &>/dev/null; then
        print_error "Interface $PXE_INTERFACE does not exist"
        exit 1
    fi
    
    read -pr "Enter PXE server IP address [$PXE_IP]: " input_ip
    PXE_IP=${input_ip:-$PXE_IP}
    
    PXE_SUBNET=$(echo "$PXE_IP" | cut -d'.' -f1-3)
    DHCP_START="$PXE_SUBNET.100"
    DHCP_END="$PXE_SUBNET.200"
    
    read -pr "Enter DHCP range start [$DHCP_START]: " input_start
    DHCP_START=${input_start:-$DHCP_START}
    
    read -pr "Enter DHCP range end [$DHCP_END]: " input_end
    DHCP_END=${input_end:-$DHCP_END}
    
    read -pr "Enter ISO storage directory [$ISO_STORAGE_DIR]: " input_iso_dir
    ISO_STORAGE_DIR=${input_iso_dir:-$ISO_STORAGE_DIR}
    
    echo ""
    print_status "Configuration Summary:"
    echo "  PXE Interface: $PXE_INTERFACE"
    echo "  PXE Server IP: $PXE_IP"
    echo "  DHCP Range: $DHCP_START - $DHCP_END"
    echo "  ISO Storage: $ISO_STORAGE_DIR"
    echo ""
    read -pr "Continue with this configuration? [y/N]: " confirm
    if [[ ! "$confirm" =~ ^[Yy]$ ]]; then
        print_error "Installation cancelled by user"
        exit 0
    fi
}

# Function to install packages
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
        net-tools \
        rsync \
        p7zip-full \
        genisoimage \
        squashfs-tools \
        file \
        tree \
        htop \
        iotop \
        jq \
        samba \
        samba-common-bin \
        wimtools \
        cabextract \
        genisoimage \
        mkisofs \
        isolinux
    
    # Install Windows-specific tools
    print_status "Installing Windows deployment tools..."
    
    # Install wimlib for Windows imaging
    if ! command -v wiminfo &> /dev/null; then
        sudo apt install -y wimtools libwim-dev
    fi
    
    # Download and install additional Windows tools
    sudo mkdir -p /opt/windows-tools
    
    log_action "INFO" "All packages including Windows tools installed successfully"
}

# Function to configure network interface
configure_network() {
    print_header "CONFIGURING NETWORK INTERFACE"
    
    sudo cp /etc/netplan/*.yaml "$BACKUP_DIR/netplan-backup-$(date +%Y%m%d-%H%M%S).yaml" 2>/dev/null || true
    
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
      routes:
        - to: 0.0.0.0/0
          via: ${PXE_SUBNET}.1
          metric: 100
EOF
    
    sudo chmod 600 /etc/netplan/01-pxe-config.yaml
    sudo chown root:root /etc/netplan/01-pxe-config.yaml
    
    print_status "Applying network configuration..."
    sudo netplan apply
    sleep 3
    
    log_action "INFO" "Network interface configured: $PXE_INTERFACE -> $PXE_IP"
}

# Function to configure enhanced dnsmasq
configure_dnsmasq() {
    print_header "CONFIGURING ENHANCED DNSMASQ"
    
    sudo cp /etc/dnsmasq.conf "$BACKUP_DIR/dnsmasq.conf.backup"
    
    cat << EOF | sudo tee /etc/dnsmasq.conf > /dev/null
# Enhanced PXE Server Configuration
interface=$PXE_INTERFACE
bind-interfaces
dhcp-range=$DHCP_START,$DHCP_END,12h

# TFTP Configuration
enable-tftp
tftp-root=$TFTP_ROOT
tftp-secure
tftp-lowercase

# PXE Boot Configuration for multiple architectures
dhcp-match=set:bios,option:client-arch,0
dhcp-boot=tag:bios,pxelinux.0

dhcp-match=set:efi32,option:client-arch,6
dhcp-boot=tag:efi32,bootia32.efi

dhcp-match=set:efibc,option:client-arch,7
dhcp-boot=tag:efibc,bootx64.efi

dhcp-match=set:efi64,option:client-arch,9
dhcp-boot=tag:efi64,bootx64.efi

# Windows-specific DHCP options
dhcp-option=vendor:PXEClient,6,2b
dhcp-option=option:bootfile-name,pxelinux.0

# Microsoft DHCP options for Windows deployment
dhcp-option=252,"http://$PXE_IP/pxe/"
dhcp-option=15,"pxe.local"

# Enhanced DHCP options
dhcp-option=vendor:PXEClient,6,2b
dhcp-option=option:bootfile-name,pxelinux.0

# DNS Configuration
server=8.8.8.8
server=1.1.1.1
cache-size=1000
neg-ttl=60

# Logging
log-dhcp
log-queries
log-facility=$LOG_DIR/dnsmasq.log

# Performance tuning
dns-forward-max=150
cache-size=10000

# Local domain
local=/pxe.local/
domain=pxe.local
expand-hosts
EOF
    
    log_action "INFO" "dnsmasq configured with Windows and enhanced features"
}

# Function to detect distro type
detect_distro_type() {
    local iso_file="$1"
    local basename_iso
    basename_iso=$(basename "$iso_file")
    
    for distro in "${!DISTRO_PATTERNS[@]}"; do
        if [[ "$basename_iso" =~ ${DISTRO_PATTERNS[$distro]} ]]; then
            echo "$distro"
            return 0
        fi
    done
    
    echo "unknown"
}

# Function to extract ISO with distro-specific handling
extract_iso() {
    local iso="$1"
    local distro_name
    distro_name="$(basename "$iso" .iso)"
    local distro_type
    
    distro_type=$(detect_distro_type "$iso")
    
    print_status "Processing ISO: $iso (detected: $distro_type)"
    
    # Handle Windows ISOs differently
    if [[ "$distro_type" =~ ^windows ]]; then
        extract_windows_iso "$iso" "$distro_name" "$distro_type"
    else
        # Standard Linux ISO extraction
        local mount_dir="/mnt/pxe_iso_mount"
        local extract_dir="$TFTP_ROOT/images/$distro_name"
        local web_dir="$WEB_ROOT/pxe/$distro_name"
        
        # Create directories
        sudo mkdir -p "$mount_dir" "$extract_dir" "$web_dir"
        
        # Mount and extract
        sudo mount -o loop "$iso" "$mount_dir"
        sudo rsync -a --progress "$mount_dir/" "$extract_dir/"
        sudo rsync -a --progress "$mount_dir/" "$web_dir/"
        sudo umount "$mount_dir"
        sudo rmdir "$mount_dir"
        
        # Generate distro-specific PXE entries
        generate_pxe_entry "$distro_name" "$distro_type"
        
        print_status "Extracted: $distro_name"
        log_action "INFO" "ISO extracted: $distro_name ($distro_type)"
    fi
}
    local iso="$1"
    local distro_name="$2"
    local distro_type="$3"
    local mount_dir="/mnt/pxe_iso_mount"
    local extract_dir="$TFTP_ROOT/images/$distro_name"
    local web_dir="$WEB_ROOT/pxe/$distro_name"
    local windows_dir="$TFTP_ROOT/windows/$distro_name"
    
    print_status "Processing Windows ISO: $iso"
    
    # Create directories
    sudo mkdir -p "$mount_dir" "$extract_dir" "$web_dir" "$windows_dir"
    
    # Mount and extract
    sudo mount -o loop "$iso" "$mount_dir"
    
    # Extract full ISO contents
    sudo rsync -a --progress "$mount_dir/" "$extract_dir/"
    sudo rsync -a --progress "$mount_dir/" "$web_dir/"
    
    # Copy Windows-specific files to appropriate locations
    if [[ -d "$mount_dir/boot" ]]; then
        sudo cp -r "$mount_dir/boot"/* "$windows_dir/" 2>/dev/null || true
    fi
    
    if [[ -d "$mount_dir/sources" ]]; then
        sudo cp -r "$mount_dir/sources"/* "$TFTP_ROOT/windows/sources/" 2>/dev/null || true
    fi
    
    # Extract boot.wim for network boot if present
    if [[ -f "$mount_dir/sources/boot.wim" ]]; then
        print_status "Processing Windows boot.wim for network boot..."
        sudo mkdir -p "$windows_dir/boot"
        
        # Extract specific files needed for network boot
        sudo wimextract "$mount_dir/sources/boot.wim" 1 \
            /Windows/Boot/PXE/bootmgr.exe \
            /Windows/Boot/PXE/pxeboot.n12 \
            --dest-dir="$windows_dir/boot/" 2>/dev/null || true
    fi
    
    sudo umount "$mount_dir"
    sudo rmdir "$mount_dir"
    
    # Generate Windows-specific PXE entry
    generate_windows_pxe_entry "$distro_name" "$distro_type"
    
    print_status "Windows ISO extracted: $distro_name"
    log_action "INFO" "Windows ISO extracted: $distro_name ($distro_type)"
}

# Function to generate Windows PXE entry
generate_windows_pxe_entry() {
    local distro_name="$1"
    local distro_type="$2"
    
    case "$distro_type" in
        "windows_server"|"windows_desktop")
            # Windows network installation entry
            echo "LABEL $distro_name" >> /tmp/pxe_entries.tmp
            echo "  MENU LABEL $distro_name (Windows Network Install)" >> /tmp/pxe_entries.tmp
            echo "  KERNEL memdisk" >> /tmp/pxe_entries.tmp
            echo "  APPEND iso initrd=images/$distro_name/sources/boot.wim" >> /tmp/pxe_entries.tmp
            echo "" >> /tmp/pxe_entries.tmp
            
            # Windows PE boot entry if available
            if [[ -f "$TFTP_ROOT/images/$distro_name/sources/boot.wim" ]]; then
                echo "LABEL ${distro_name}_pe" >> /tmp/pxe_entries.tmp
                echo "  MENU LABEL $distro_name (Windows PE)" >> /tmp/pxe_entries.tmp
                echo "  KERNEL wimboot" >> /tmp/pxe_entries.tmp
                echo "  APPEND initrdfile=images/$distro_name/sources/boot.wim" >> /tmp/pxe_entries.tmp
                echo "" >> /tmp/pxe_entries.tmp
            fi
            ;;
        "windows_pe")
            echo "LABEL $distro_name" >> /tmp/pxe_entries.tmp
            echo "  MENU LABEL $distro_name (Windows PE)" >> /tmp/pxe_entries.tmp
            echo "  KERNEL wimboot" >> /tmp/pxe_entries.tmp
            echo "  APPEND initrdfile=images/$distro_name/sources/boot.wim" >> /tmp/pxe_entries.tmp
            echo "" >> /tmp/pxe_entries.tmp
            ;;
    esac
}

# Function to generate PXE menu entry based on distro type
generate_pxe_entry() {
    local distro_name="$1"
    local distro_type="$2"
    local kernel_path=""
    local initrd_path=""
    local append_options=""
    
    case "$distro_type" in
        "ubuntu"|"debian")
            kernel_path="images/$distro_name/casper/vmlinuz"
            initrd_path="images/$distro_name/casper/initrd"
            append_options="boot=casper netboot=nfs nfsroot=$PXE_IP:/var/www/html/pxe/$distro_name/ ip=dhcp splash quiet --"
            ;;
        "centos"|"fedora"|"rocky"|"alma")
            kernel_path="images/$distro_name/isolinux/vmlinuz"
            initrd_path="images/$distro_name/isolinux/initrd.img"
            append_options="inst.repo=http://$PXE_IP/pxe/$distro_name/ ip=dhcp"
            ;;
        "opensuse")
            kernel_path="images/$distro_name/boot/x86_64/loader/linux"
            initrd_path="images/$distro_name/boot/x86_64/loader/initrd"
            append_options="install=http://$PXE_IP/pxe/$distro_name/ splash=silent"
            ;;
        "arch")
            kernel_path="images/$distro_name/arch/boot/x86_64/vmlinuz-linux"
            initrd_path="images/$distro_name/arch/boot/x86_64/initramfs-linux.img"
            append_options="archiso_http_srv=http://$PXE_IP/pxe/$distro_name/ archisobasedir=arch ip=dhcp"
            ;;
        *)
            # Generic fallback
            kernel_path="images/$distro_name/vmlinuz"
            initrd_path="images/$distro_name/initrd.img"
            append_options="root=/dev/ram0 ramdisk_size=1500000"
            ;;
    esac
    
    # Store entry for menu generation (only for non-Windows)
    echo "LABEL $distro_name" >> /tmp/pxe_entries.tmp
    echo "  MENU LABEL $distro_name ($distro_type)" >> /tmp/pxe_entries.tmp
    echo "  KERNEL $kernel_path" >> /tmp/pxe_entries.tmp
    echo "  APPEND initrd=$initrd_path $append_options" >> /tmp/pxe_entries.tmp
    echo "" >> /tmp/pxe_entries.tmp
}

# Function to setup enhanced TFTP structure
setup_tftp() {
    print_header "SETTING UP ENHANCED TFTP STRUCTURE"
    
    print_status "Creating TFTP directory structure..."
    sudo mkdir -p "$TFTP_ROOT"/{pxelinux.cfg,images,menus,themes,windows}
    sudo mkdir -p "$TFTP_ROOT/windows"/{boot,sources,winpe}
    
    print_status "Copying PXE boot files..."
    sudo cp /usr/lib/PXELINUX/pxelinux.0 "$TFTP_ROOT/"
    sudo cp /usr/lib/syslinux/modules/bios/*.c32 "$TFTP_ROOT/"
    
    # Copy EFI boot files if available
    if [[ -f /usr/lib/shim/shimx64.efi ]]; then
        sudo cp /usr/lib/shim/shimx64.efi "$TFTP_ROOT/bootx64.efi"
    fi
    
    # Setup Windows boot files directory structure
    print_status "Setting up Windows boot structure..."
    sudo mkdir -p "$TFTP_ROOT/windows/Boot/BCD"
    sudo mkdir -p "$TFTP_ROOT/windows/Boot/Fonts"
    sudo mkdir -p "$TFTP_ROOT/windows/sources"
    
    # Create initial empty menu entries file
    touch /tmp/pxe_entries.tmp
    
    log_action "INFO" "Enhanced TFTP structure with Windows support setup completed"
}

# Function to generate dynamic PXE menu
generate_pxe_menu() {
    print_header "GENERATING DYNAMIC PXE MENU"
    
    local menu_file="$TFTP_ROOT/pxelinux.cfg/default"
    
    cat << EOF | sudo tee "$menu_file" > /dev/null
DEFAULT menu.c32
PROMPT 0
TIMEOUT $MENU_TIMEOUT
ONTIMEOUT local

MENU TITLE Enhanced PXE Boot Server - Linux and Windows
MENU BACKGROUND pxe-bg.png
MENU COLOR border       30;44   #40ffffff #a0000000
MENU COLOR title        1;36;44 #9033ccff #a0000000
MENU COLOR sel          7;37;40 #e0ffffff #20ffffff
MENU COLOR unsel        37;44   #50ffffff #a0000000
MENU COLOR help         37;40   #c0ffffff #a0000000
MENU COLOR timeout_msg  37;40   #80ffffff #00000000
MENU COLOR timeout      1;37;40 #c0ffffff #00000000
MENU COLOR msg07        37;40   #90ffffff #a0000000
MENU COLOR tabmsg       31;40   #30ffffff #00000000

LABEL local
    MENU LABEL Boot from Local Drive
    MENU DEFAULT
    LOCALBOOT 0

LABEL memtest
    MENU LABEL Memory Test (Memtest86+)
    KERNEL memtest86+.bin

MENU SEPARATOR
MENU LABEL --- Windows Installation Options ---

EOF
    
    # Add Windows-specific entries first
    if [[ -f /tmp/pxe_entries.tmp ]]; then
        grep -A 10 "windows" /tmp/pxe_entries.tmp >> "$menu_file" 2>/dev/null || true
    fi
    
    cat << EOF | sudo tee -a "$menu_file" > /dev/null

MENU SEPARATOR
MENU LABEL --- Linux Installation Options ---

EOF
    
    # Add Linux distro entries
    if [[ -f /tmp/pxe_entries.tmp ]]; then
        grep -v -A 10 "windows" /tmp/pxe_entries.tmp >> "$menu_file" 2>/dev/null || true
    fi
    
    cat << EOF | sudo tee -a "$menu_file" > /dev/null

MENU SEPARATOR
MENU LABEL --- Windows PE and Recovery ---

LABEL winpe_rescue
    MENU LABEL Windows PE Rescue Environment
    KERNEL memdisk
    APPEND iso raw

LABEL windows_recovery
    MENU LABEL Windows Recovery Console
    KERNEL memdisk
    APPEND iso raw

MENU SEPARATOR
MENU LABEL --- Utilities ---

LABEL reboot
    MENU LABEL Reboot System
    KERNEL reboot.c32

LABEL poweroff
    MENU LABEL Power Off System
    KERNEL poweroff.c32

EOF
    
    print_status "PXE menu generated with Windows and Linux entries"
    log_action "INFO" "PXE menu generated with Windows support"
}
    KERNEL poweroff.c32

EOF
    
    print_status "PXE menu generated with dynamic entries"
    log_action "INFO" "PXE menu generated"
}

# Function to scan and process ISOs
scan_and_process_isos() {
    print_header "SCANNING AND PROCESSING ISO FILES"
    
    local iso_dir="${1:-$ISO_STORAGE_DIR}"
    local all_mode="${2:-false}"
    
    if [[ ! -d "$iso_dir" ]]; then
        print_warning "ISO directory not found: $iso_dir"
        return 0
    fi
    
    print_status "Searching for ISOs in: $iso_dir"
    
    mapfile -t iso_files < <(find "$iso_dir" -maxdepth 2 -type f -iname "*.iso")
    
    if [[ ${#iso_files[@]} -eq 0 ]]; then
        print_warning "No ISO files found in $iso_dir"
        return 0
    fi
    
    print_status "Found ${#iso_files[@]} ISO files"
    
    for iso in "${iso_files[@]}"; do
        if [[ "$all_mode" == "true" ]]; then
            extract_iso "$iso"
        else
            echo ""
            print_status "Found: $(basename "$iso")"
            read -rp "Process this ISO? [y/N]: " confirm
            if [[ "$confirm" =~ ^[Yy]$ ]]; then
                extract_iso "$iso"
            fi
        fi
    done
}

# Function to configure enhanced Apache
configure_apache() {
    print_header "CONFIGURING ENHANCED APACHE WEB SERVER"
    
    print_status "Creating web directory structure..."
    sudo mkdir -p "$WEB_ROOT"/{pxe,autoinstall,tools,logs}
    
    # Create enhanced Apache configuration
    cat << EOF | sudo tee /etc/apache2/sites-available/pxe-server.conf > /dev/null
<VirtualHost *:80>
    ServerName pxe.local
    DocumentRoot $WEB_ROOT
    
    <Directory "$WEB_ROOT">
        Options Indexes FollowSymLinks MultiViews
        AllowOverride All
        Require all granted
        IndexOptions +FancyIndexing +HTMLTable +SuppressRules
        IndexIgnore README* HEADER* header.html footer.html
    </Directory>
    
    <Directory "$WEB_ROOT/pxe">
        Options Indexes FollowSymLinks
        AllowOverride None
        Require all granted
    </Directory>
    
    <Directory "$WEB_ROOT/autoinstall">
        Options Indexes FollowSymLinks
        AllowOverride None
        Require all granted
    </Directory>
    
    ErrorLog $LOG_DIR/apache_error.log
    CustomLog $LOG_DIR/apache_access.log combined
    
    # Enable compression
    LoadModule deflate_module modules/mod_deflate.so
    <Location />
        SetOutputFilter DEFLATE
    </Location>
</VirtualHost>
EOF
    
    # Enable site and modules
    sudo a2enmod rewrite deflate
    sudo a2ensite pxe-server
    sudo a2dissite 000-default
    
    # Create enhanced index page
    create_web_interface
    
    sudo systemctl enable apache2
    sudo systemctl restart apache2
    
    log_action "INFO" "Apache configured with enhanced features"
}

# Function to create web management interface
create_web_interface() {
    print_status "Creating web management interface..."
    
    cat << 'EOF' | sudo tee "$WEB_ROOT/index.html" > /dev/null
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Enhanced PXE Boot Server</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 0; padding: 20px; background: #f5f5f5; }
        .container { max-width: 1200px; margin: 0 auto; background: white; padding: 20px; border-radius: 8px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }
        .header { text-align: center; color: #333; border-bottom: 2px solid #007acc; padding-bottom: 20px; margin-bottom: 30px; }
        .grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(300px, 1fr)); gap: 20px; }
        .card { background: #f8f9fa; padding: 20px; border-radius: 6px; border-left: 4px solid #007acc; }
        .card h3 { margin-top: 0; color: #007acc; }
        .status { display: inline-block; padding: 4px 8px; border-radius: 4px; color: white; font-size: 12px; }
        .status.online { background: #28a745; }
        .status.offline { background: #dc3545; }
        ul { list-style-type: none; padding: 0; }
        li { padding: 8px; margin: 4px 0; background: white; border-radius: 4px; }
        a { color: #007acc; text-decoration: none; }
        a:hover { text-decoration: underline; }
        .btn { display: inline-block; padding: 10px 20px; background: #007acc; color: white; border-radius: 4px; text-decoration: none; margin: 5px; }
        .btn:hover { background: #005a9e; }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>Enhanced PXE Boot Server</h1>
            <p>Network Boot Management System</p>
        </div>
        
        <div class="grid">
            <div class="card">
                <h3>Server Status</h3>
                <p><strong>Server IP:</strong> PXE_IP_PLACEHOLDER</p>
                <p><strong>Interface:</strong> PXE_INTERFACE_PLACEHOLDER</p>
                <p><strong>DHCP Range:</strong> DHCP_START_PLACEHOLDER - DHCP_END_PLACEHOLDER</p>
                <p><strong>Services:</strong> 
                    <span class="status online">DHCP</span>
                    <span class="status online">TFTP</span>
                    <span class="status online">HTTP</span>
                </p>
            </div>
            
            <div class="card">
                <h3>Available Distributions</h3>
                <ul id="distro-list">
                    <li>Scanning for available distributions...</li>
                </ul>
                <a href="/pxe/" class="btn">Browse ISO Files</a>
            </div>
            
            <div class="card">
                <h3>Quick Actions</h3>
                <a href="/tools/iso-manager.html" class="btn">ISO Manager</a>
                <a href="/autoinstall/" class="btn">Autoinstall Configs</a>
                <a href="/logs/" class="btn">View Logs</a>
                <a href="#" onclick="refreshStatus()" class="btn">Refresh Status</a>
            </div>
            
            <div class="card">
                <h3>Usage Instructions</h3>
                <ol>
                    <li>Connect client machines to the PXE network</li>
                    <li>Configure BIOS/UEFI to boot from network</li>
                    <li>Boot client and select installation option</li>
                    <li>Follow installation prompts</li>
                </ol>
            </div>
        </div>
        
        <div class="card" style="margin-top: 20px;">
            <h3>System Information</h3>
            <p><strong>Uptime:</strong> <span id="uptime">Loading...</span></p>
            <p><strong>Last Updated:</strong> <span id="timestamp">Loading...</span></p>
            <p><strong>Total Distributions:</strong> <span id="distro-count">0</span></p>
        </div>
    </div>
    
    <script>
        function refreshStatus() {
            location.reload();
        }
        
        function updateTimestamp() {
            document.getElementById('timestamp').textContent = new Date().toLocaleString();
        }
        
        updateTimestamp();
        setInterval(updateTimestamp, 60000);
    </script>
</body>
</html>
EOF
    
    # Replace placeholders
    sudo sed -i "s/PXE_IP_PLACEHOLDER/$PXE_IP/g" "$WEB_ROOT/index.html"
    sudo sed -i "s/PXE_INTERFACE_PLACEHOLDER/$PXE_INTERFACE/g" "$WEB_ROOT/index.html"
    sudo sed -i "s/DHCP_START_PLACEHOLDER/$DHCP_START/g" "$WEB_ROOT/index.html"
    sudo sed -i "s/DHCP_END_PLACEHOLDER/$DHCP_END/g" "$WEB_ROOT/index.html"
}

# Function to set enhanced permissions
set_permissions() {
    print_header "SETTING ENHANCED FILE PERMISSIONS"
    
    print_status "Setting TFTP permissions..."
    sudo chmod -R 755 "$TFTP_ROOT"
    sudo chown -R tftp:tftp "$TFTP_ROOT"
    
    print_status "Setting web directory permissions..."
    sudo chmod -R 755 "$WEB_ROOT"
    sudo chown -R www-data:www-data "$WEB_ROOT"
    
    print_status "Setting ISO storage permissions..."
    sudo chmod -R 755 "$ISO_STORAGE_DIR"
    sudo chown -R $(whoami):$(whoami) "$ISO_STORAGE_DIR"
    
    print_status "Setting log permissions..."
    sudo chmod -R 644 "$LOG_DIR"
    sudo chown -R syslog:adm "$LOG_DIR"
    
    log_action "INFO" "Enhanced permissions set successfully"
}

# Function to configure enhanced firewall
configure_firewall() {
    print_header "CONFIGURING ENHANCED FIREWALL"
    
    if sudo ufw status | grep -q "Status: active"; then
        print_status "UFW is active, adding enhanced firewall rules..."
        
        # Basic PXE services
        sudo ufw allow 67/udp comment "DHCP"
        sudo ufw allow 69/udp comment "TFTP"
        sudo ufw allow 80/tcp comment "HTTP"
        sudo ufw allow 53/udp comment "DNS"
        
        # Additional services
        sudo ufw allow 443/tcp comment "HTTPS"
        sudo ufw allow 111/tcp comment "NFS portmapper"
        sudo ufw allow 111/udp comment "NFS portmapper"
        sudo ufw allow 2049/tcp comment "NFS"
        sudo ufw allow 2049/udp comment "NFS"
        
        # SSH for management
        sudo ufw allow 22/tcp comment "SSH"
        
        print_status "Enhanced firewall rules added"
        log_action "INFO" "Firewall configured with enhanced rules"
    else
        print_warning "UFW is not active, skipping firewall configuration"
    fi
}

# Function to start and monitor services
start_services() {
    print_header "STARTING AND MONITORING SERVICES"
    
    local services=("dnsmasq" "tftpd-hpa" "apache2" "nfs-kernel-server")
    
    for service in "${services[@]}"; do
        print_status "Starting $service..."
        sudo systemctl enable "$service"
        sudo systemctl restart "$service"
        
        sleep 2
        
        if sudo systemctl is-active --quiet "$service"; then
            print_status "$service is running"
            log_action "INFO" "$service started successfully"
        else
            print_error "$service failed to start"
            log_action "ERROR" "$service failed to start"
        fi
    done
}

# Function to create monitoring scripts
create_monitoring() {
    print_header "CREATING MONITORING SCRIPTS"
    
    # Create service monitoring script
    cat << 'EOF' | sudo tee /usr/local/bin/pxe-monitor > /dev/null
#!/bin/bash
# PXE Server Monitoring Script

LOG_FILE="/var/log/pxe-server/monitor.log"
EMAIL_ALERT=""  # Set email for alerts

log_message() {
    echo "$(date '+%Y-%m-%d %H:%M:%S') - $1" | sudo tee -a "$LOG_FILE"
}

check_service() {
    local service="$1"
    if ! systemctl is-active --quiet "$service"; then
        log_message "WARNING: $service is not running, attempting restart"
        systemctl restart "$service"
        if systemctl is-active --quiet "$service"; then
            log_message "INFO: $service restarted successfully"
        else
            log_message "ERROR: Failed to restart $service"
            [[ -n "$EMAIL_ALERT" ]] && echo "$service failed on $(hostname)" | mail -s "PXE Server Alert" "$EMAIL_ALERT"
        fi
    fi
}

# Check critical services
for service in dnsmasq tftpd-hpa apache2; do
    check_service "$service"
done

# Check disk space
DISK_USAGE=$(df /var/lib/tftpboot | awk 'NR==2 {print $5}' | sed 's/%//')
if [[ "$DISK_USAGE" -gt 80 ]]; then
    log_message "WARNING: Disk usage is ${DISK_USAGE}%"
fi

# Check DHCP leases
ACTIVE_LEASES=$(grep -c "lease" /var/lib/dhcp/dhcpd.leases 2>/dev/null || echo "0")
log_message "INFO: Active DHCP leases: $ACTIVE_LEASES"
EOF

    sudo chmod +x /usr/local/bin/pxe-monitor
    
    # Create cron job for monitoring
    echo "*/5 * * * * root /usr/local/bin/pxe-monitor" | sudo tee /etc/cron.d/pxe-monitor > /dev/null
    
    # Create ISO management script
    cat << 'EOF' | sudo tee /usr/local/bin/pxe-iso-manager > /dev/null
#!/bin/bash
# PXE ISO Management Script

ISO_STORAGE="/opt/pxe-isos"
TFTP_ROOT="/var/lib/tftpboot"
WEB_ROOT="/var/www/html"

show_help() {
    cat << HELP
PXE ISO Manager

Usage: $0 [COMMAND] [OPTIONS]

Commands:
    list                List all available ISOs
    add <iso_path>      Add ISO to PXE server
    remove <iso_name>   Remove ISO from PXE server
    scan [directory]    Scan directory for ISOs and add them
    rebuild-menu        Rebuild PXE menu from available ISOs
    status              Show server status
    cleanup             Clean up unused files

Examples:
    $0 list
    $0 add /path/to/ubuntu-24.04.iso
    $0 scan /home/user/isos
    $0 remove ubuntu-24.04
    $0 rebuild-menu
HELP
}

list_isos() {
    echo "Available ISOs in PXE server:"
    echo "================================================"
    if [[ -d "$TFTP_ROOT/images" ]]; then
        for iso_dir in "$TFTP_ROOT/images"/*; do
            if [[ -d "$iso_dir" ]]; then
                iso_name=$(basename "$iso_dir")
                size=$(du -sh "$iso_dir" 2>/dev/null | cut -f1)
                echo "  $iso_name ($size)"
            fi
        done
    else
        echo "  No ISOs found"
    fi
    echo "================================================"
}

case "${1:-help}" in
    list) list_isos ;;
    add) echo "Adding ISO: $2" ;;
    remove) echo "Removing ISO: $2" ;;
    scan) echo "Scanning directory: ${2:-$ISO_STORAGE}" ;;
    rebuild-menu) echo "Rebuilding PXE menu..." ;;
    status) systemctl status dnsmasq tftpd-hpa apache2 ;;
    cleanup) echo "Cleaning up unused files..." ;;
    *) show_help ;;
esac
EOF

    sudo chmod +x /usr/local/bin/pxe-iso-manager
    
    print_status "Monitoring and management scripts created"
    log_action "INFO" "Monitoring scripts created successfully"
}

# Function to create backup and restore functionality
create_backup_restore() {
    print_header "CREATING BACKUP AND RESTORE FUNCTIONALITY"
    
    cat << 'EOF' | sudo tee /usr/local/bin/pxe-backup > /dev/null
#!/bin/bash
# PXE Server Backup Script

BACKUP_DIR="/opt/pxe-backups"
TIMESTAMP=$(date +%Y%m%d_%H%M%S)
BACKUP_NAME="pxe-backup-$TIMESTAMP"

create_backup() {
    echo "Creating PXE server backup: $BACKUP_NAME"
    
    mkdir -p "$BACKUP_DIR/$BACKUP_NAME"
    
    # Backup configurations
    cp -r /etc/dnsmasq.conf "$BACKUP_DIR/$BACKUP_NAME/"
    cp -r /etc/netplan/ "$BACKUP_DIR/$BACKUP_NAME/"
    cp -r /etc/apache2/sites-available/ "$BACKUP_DIR/$BACKUP_NAME/"
    
    # Backup PXE menu
    cp -r /var/lib/tftpboot/pxelinux.cfg/ "$BACKUP_DIR/$BACKUP_NAME/"
    
    # Create manifest
    cat << MANIFEST > "$BACKUP_DIR/$BACKUP_NAME/manifest.txt"
PXE Server Backup
Created: $(date)
Hostname: $(hostname)
Configurations included:
- dnsmasq.conf
- netplan configuration
- apache2 sites
- PXE menu configuration
MANIFEST
    
    # Create archive
    cd "$BACKUP_DIR"
    tar -czf "$BACKUP_NAME.tar.gz" "$BACKUP_NAME"
    rm -rf "$BACKUP_NAME"
    
    echo "Backup created: $BACKUP_DIR/$BACKUP_NAME.tar.gz"
}

list_backups() {
    echo "Available backups:"
    ls -la "$BACKUP_DIR"/*.tar.gz 2>/dev/null || echo "No backups found"
}

case "${1:-create}" in
    create) create_backup ;;
    list) list_backups ;;
    *) echo "Usage: $0 [create|list]" ;;
esac
EOF

    sudo chmod +x /usr/local/bin/pxe-backup
    
    # Create weekly backup cron job
    echo "0 2 * * 0 root /usr/local/bin/pxe-backup create" | sudo tee /etc/cron.d/pxe-backup > /dev/null
    
    print_status "Backup and restore functionality created"
}

# Function to create autoinstall configurations
create_autoinstall_configs() {
    print_header "CREATING AUTOINSTALL CONFIGURATIONS"
    
    read -pr "Do you want to create autoinstall configurations? [y/N]: " create_auto
    
    if [[ "$create_auto" =~ ^[Yy]$ ]]; then
        sudo mkdir -p "$WEB_ROOT/autoinstall"/{ubuntu,debian,centos}
        
        # Ubuntu autoinstall
        cat << 'EOF' | sudo tee "$WEB_ROOT/autoinstall/ubuntu/user-data" > /dev/null
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
      sizing-policy: all
  identity:
    hostname: pxe-client
    username: pxeuser
    password: "$6$rounds=4096$saltySalt$encrypted_password_hash"
  ssh:
    install-server: yes
    allow-pw: yes
    authorized-keys:
      - "ssh-rsa YOUR_SSH_KEY_HERE"
  packages:
    - openssh-server
    - curl
    - wget
    - vim
    - htop
    - net-tools
  late-commands:
    - echo 'pxeuser ALL=(ALL) NOPASSWD:ALL' > /target/etc/sudoers.d/pxeuser
    - chmod 440 /target/etc/sudoers.d/pxeuser
    - chroot /target systemctl enable ssh
EOF

        echo "" | sudo tee "$WEB_ROOT/autoinstall/ubuntu/meta-data" > /dev/null
        
        # Create Debian preseed
        cat << 'EOF' | sudo tee "$WEB_ROOT/autoinstall/debian/preseed.cfg" > /dev/null
# Debian Preseed Configuration
d-i debian-installer/locale string en_US.UTF-8
d-i keyboard-configuration/xkb-keymap select us

# Network configuration
d-i netcfg/choose_interface select auto
d-i netcfg/get_hostname string debian-pxe
d-i netcfg/get_domain string localdomain

# Mirror configuration
d-i mirror/country string manual
d-i mirror/http/hostname string deb.debian.org
d-i mirror/http/directory string /debian
d-i mirror/http/proxy string

# User configuration
d-i passwd/root-login boolean false
d-i passwd/user-fullname string PXE User
d-i passwd/username string pxeuser
d-i passwd/user-password-crypted password $6$rounds=4096$saltySalt$encrypted_password_hash

# Partitioning
d-i partman-auto/method string lvm
d-i partman-auto-lvm/guided_size string max
d-i partman-lvm/device_remove_lvm boolean true
d-i partman-lvm/confirm boolean true
d-i partman-lvm/confirm_nooverwrite boolean true
d-i partman-auto/choose_recipe select atomic
d-i partman/confirm_write_new_label boolean true
d-i partman/choose_partition select finish
d-i partman/confirm boolean true
d-i partman/confirm_nooverwrite boolean true

# Package selection
tasksel tasksel/first multiselect standard, ssh-server
d-i pkgsel/include string vim curl wget htop
d-i pkgsel/upgrade select full-upgrade

# Boot loader
d-i grub-installer/only_debian boolean true
d-i grub-installer/with_other_os boolean true

# Finish installation
d-i finish-install/reboot_in_progress note
EOF
        
        print_status "Autoinstall configurations created"
        print_warning "Please update passwords and SSH keys in the configuration files"
    fi
}

# Function to perform system health check
system_health_check() {
    print_header "PERFORMING SYSTEM HEALTH CHECK"
    
    local health_score=0
    local max_score=10
    
    # Check services
    for service in dnsmasq tftpd-hpa apache2; do
        if sudo systemctl is-active --quiet "$service"; then
            print_status "$service: Running"
            ((health_score++))
        else
            print_error "$service: Not running"
        fi
    done
    
    # Check network interface
    if ip addr show "$PXE_INTERFACE" | grep -q "$PXE_IP"; then
        print_status "Network interface: Configured correctly"
        ((health_score++))
    else
        print_error "Network interface: Configuration issue"
    fi
    
    # Check TFTP files
    if [[ -f "$TFTP_ROOT/pxelinux.0" ]]; then
        print_status "TFTP files: Available"
        ((health_score++))
    else
        print_error "TFTP files: Missing"
    fi
    
    # Check web server
    if curl -s "http://$PXE_IP" > /dev/null; then
        print_status "Web server: Accessible"
        ((health_score++))
    else
        print_error "Web server: Not accessible"
    fi
    
    # Check disk space
    local disk_usage
    disk_usage=$(df "$TFTP_ROOT" | awk 'NR==2 {print $5}' | sed 's/%//')
    if [[ "$disk_usage" -lt 80 ]]; then
        print_status "Disk space: ${disk_usage}% used"
        ((health_score++))
    else
        print_warning "Disk space: ${disk_usage}% used (high)"
    fi
    
    # Check available ISOs
    local iso_count
    iso_count=$(find "$TFTP_ROOT/images" -maxdepth 1 -type d 2>/dev/null | wc -l)
    if [[ "$iso_count" -gt 1 ]]; then
        print_status "Available distributions: $((iso_count - 1))"
        ((health_score++))
    else
        print_warning "No distributions available"
    fi
    
    echo ""
    print_status "Health Score: $health_score/$max_score"
    
    if [[ "$health_score" -ge 8 ]]; then
        print_status "System health: EXCELLENT"
    elif [[ "$health_score" -ge 6 ]]; then
        print_warning "System health: GOOD"
    elif [[ "$health_score" -ge 4 ]]; then
        print_warning "System health: FAIR"
    else
        print_error "System health: POOR - Immediate attention required"
    fi
    
    log_action "INFO" "Health check completed: $health_score/$max_score"
}

# Function to display final information with enhancements
display_final_info() {
    print_header "ENHANCED PXE SERVER INSTALLATION COMPLETED"
    
    echo ""
    print_status "Server Configuration:"
    echo "  Server IP: $PXE_IP"
    echo "  Interface: $PXE_INTERFACE"
    echo "  DHCP Range: $DHCP_START - $DHCP_END"
    echo "  Web Interface: http://$PXE_IP"
    echo "  ISO Storage: $ISO_STORAGE_DIR"
    echo ""
    
    print_status "Management Commands:"
    echo "  ISO Management: pxe-iso-manager [list|add|remove|scan]"
    echo "  System Monitor: pxe-monitor"
    echo "  Backup System: pxe-backup [create|list]"
    echo "  Health Check: Run this script with --health-check"
    echo ""
    
    print_status "Web Management:"
    echo "  Main Dashboard: http://$PXE_IP"
    echo "  ISO Browser: http://$PXE_IP/pxe/"
    echo "  Autoinstall Configs: http://$PXE_IP/autoinstall/"
    echo ""
    
    print_status "Usage Instructions:"
    echo "  1. Place ISO files in $ISO_STORAGE_DIR"
    echo "  2. Run: pxe-iso-manager scan"
    echo "  3. Configure client machines for PXE boot"
    echo "  4. Boot clients and select desired OS"
    echo ""
    
    print_status "Troubleshooting:"
    echo "  View logs: tail -f $LOG_DIR/pxe-server.log"
    echo "  Check services: systemctl status dnsmasq tftpd-hpa apache2"
    echo "  Test DHCP: sudo journalctl -u dnsmasq -f"
    echo "  Test TFTP: tftp $PXE_IP -c get pxelinux.0"
    echo ""
    
    print_warning "Security Recommendations:"
    echo "  - Change default passwords in autoinstall configs"
    echo "  - Configure firewall rules for your network"
    echo "  - Use isolated network segment for PXE operations"
    echo "  - Regularly backup configurations"
    echo ""
    
    # Perform initial health check
    system_health_check
}

# Function to handle command line arguments
handle_arguments() {
    case "${1:-}" in
        --health-check)
            system_health_check
            exit 0
            ;;
        --scan-isos)
            shift
            scan_and_process_isos "${1:-$ISO_STORAGE_DIR}" "${2:-false}"
            generate_pxe_menu
            exit 0
            ;;
        --backup)
            /usr/local/bin/pxe-backup create
            exit 0
            ;;
        --help|-h)
            cat << HELP
Enhanced PXE Server Bootstrap Script

Usage: $0 [OPTION]

Options:
  --health-check    Perform system health check
  --scan-isos DIR   Scan directory for ISOs and process them
  --backup          Create system backup
  --help, -h        Show this help message

Interactive Mode:
  Run without arguments for full installation

Examples:
  $0                           # Full interactive installation
  $0 --health-check           # Check system health
  $0 --scan-isos /home/isos   # Process ISOs in directory
  $0 --backup                 # Create backup
HELP
            exit 0
            ;;
    esac
}

# Function to perform cleanup on error
cleanup() {
    print_error "Installation failed. Performing cleanup..."
    
    sudo systemctl stop dnsmasq 2>/dev/null || true
    sudo systemctl stop tftpd-hpa 2>/dev/null || true
    
    if [[ -f "$BACKUP_DIR/dnsmasq.conf.backup" ]]; then
        sudo mv "$BACKUP_DIR/dnsmasq.conf.backup" /etc/dnsmasq.conf
    fi
    
    # Clean up temporary files
    rm -f /tmp/pxe_entries.tmp
    
    log_action "ERROR" "Installation failed and cleanup performed"
    print_error "Cleanup completed. Check logs for details."
}

# Main function with enhanced error handling
main() {
    # Handle command line arguments first
    handle_arguments "$@"
    
    # Set trap for cleanup on error
    trap cleanup ERR
    
    print_header "ENHANCED PXE SERVER BOOTSTRAP SCRIPT"
    echo "This script will set up a complete PXE boot server with advanced features"
    echo "Features: Multi-distro support, Web management, Monitoring, Backup/Restore"
    echo "Press Ctrl+C to cancel at any time"
    echo ""
    
    # Preliminary checks
    check_root
    
    # Create initial directory structure
    create_directories
    
    # Get configuration from user
    get_user_input
    
    # Execute installation steps
    install_packages
    configure_network
    configure_dnsmasq
    setup_tftp
    configure_apache
    
    # Process any existing ISOs
    scan_and_process_isos "$ISO_STORAGE_DIR" "false"
    
    # Generate initial PXE menu
    generate_pxe_menu
    
    # Set permissions and security
    set_permissions
    configure_firewall
    
    # Start services
    start_services
    
    # Create advanced features
    create_monitoring
    create_backup_restore
    create_autoinstall_configs
    
    # Display final information
    display_final_info
    
    # Clean up temporary files
    rm -f /tmp/pxe_entries.tmp
    
    log_action "INFO" "Enhanced PXE server installation completed successfully"
    print_status "Enhanced PXE Server installation completed successfully!"
}

# Run main function with all arguments
main "$@"
