#!/bin/bash
#
# VPS Initial Setup Script
# For Contabo, DigitalOcean, and other VPS providers
# This script follows security best practices for initial server setup
#
# Usage: bash vps_setup.sh
#

# Exit on any error
set -e

# Text colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Function to print colored messages
print_message() {
    echo -e "${2}${1}${NC}"
}

# Function to print section headers
print_section() {
    echo
    print_message "============================================" $BLUE
    print_message "$1" $BLUE
    print_message "============================================" $BLUE
    echo
}

# Check if script is run as root
if [[ $EUID -ne 0 ]]; then
    print_message "This script must be run as root" $RED
    exit 1
fi

# Get user input for configuration
print_section "INITIAL CONFIGURATION"

# Get new username
read -p "Enter username for the new admin account: " NEW_USERNAME
while [[ -z "$NEW_USERNAME" ]]; do
    read -p "Username cannot be empty. Enter username: " NEW_USERNAME
done

# Get SSH port
read -p "Enter SSH port (default: 22): " SSH_PORT
SSH_PORT=${SSH_PORT:-22}

# Get timezone
read -p "Enter timezone (default: UTC): " TIMEZONE
TIMEZONE=${TIMEZONE:-UTC}

# Get hostname
read -p "Enter hostname (default: server): " HOSTNAME
HOSTNAME=${HOSTNAME:-server}

# Ask if user wants to enable automatic updates
read -p "Enable automatic security updates? (y/n, default: y): " AUTO_UPDATES
AUTO_UPDATES=${AUTO_UPDATES:-y}

# Ask if user wants to set up fail2ban
read -p "Set up fail2ban for intrusion prevention? (y/n, default: y): " SETUP_FAIL2BAN
SETUP_FAIL2BAN=${SETUP_FAIL2BAN:-y}

# Ask if user wants to set up UFW
read -p "Set up UFW firewall? (y/n, default: y): " SETUP_UFW
SETUP_UFW=${SETUP_UFW:-y}

# Ask if user wants to create additional team member accounts
read -p "Create additional user accounts for team members? (y/n, default: n): " CREATE_TEAM_ACCOUNTS
CREATE_TEAM_ACCOUNTS=${CREATE_TEAM_ACCOUNTS:-n}

# Update system and install essential packages
print_section "UPDATING SYSTEM AND INSTALLING PACKAGES"

# Update package lists
print_message "Updating package lists..." $GREEN
apt update

# Upgrade packages
print_message "Upgrading packages..." $GREEN
apt upgrade -y

# Install essential packages
print_message "Installing essential packages..." $GREEN
apt install -y \
    sudo \
    ufw \
    fail2ban \
    unattended-upgrades \
    apt-listchanges \
    logwatch \
    apticron \
    curl \
    wget \
    vim \
    htop \
    tmux \
    git \
    mlocate \
    net-tools \
    ca-certificates \
    gnupg \
    lsb-release \
    apt-transport-https

# Set timezone
print_message "Setting timezone to $TIMEZONE..." $GREEN
timedatectl set-timezone $TIMEZONE

# Set hostname
print_message "Setting hostname to $HOSTNAME..." $GREEN
hostnamectl set-hostname $HOSTNAME
echo "127.0.0.1 $HOSTNAME" >> /etc/hosts

# Create new admin user
print_section "CREATING ADMIN USER"
print_message "Creating new admin user: $NEW_USERNAME..." $GREEN

# Check if user already exists
if id "$NEW_USERNAME" &>/dev/null; then
    print_message "User $NEW_USERNAME already exists" $YELLOW
else
    # Create user with home directory
    useradd -m -s /bin/bash "$NEW_USERNAME"

    # Generate a secure password
    USER_PASSWORD=$(openssl rand -base64 12)
    echo "$NEW_USERNAME:$USER_PASSWORD" | chpasswd

    # Add user to sudo group
    usermod -aG sudo "$NEW_USERNAME"

    print_message "User created with password: $USER_PASSWORD" $GREEN
    print_message "IMPORTANT: Please change this password immediately after logging in!" $RED
fi

# Configure SSH
print_section "CONFIGURING SSH"
print_message "Configuring SSH for security..." $GREEN

# Backup original SSH config
cp /etc/ssh/sshd_config /etc/ssh/sshd_config.bak

# Configure SSH
cat > /etc/ssh/sshd_config << EOL
# SSH Server Configuration
Port $SSH_PORT
Protocol 2
HostKey /etc/ssh/ssh_host_rsa_key
HostKey /etc/ssh/ssh_host_ecdsa_key
HostKey /etc/ssh/ssh_host_ed25519_key

# Logging
SyslogFacility AUTH
LogLevel VERBOSE

# Authentication
LoginGraceTime 30
PermitRootLogin no
StrictModes yes
MaxAuthTries 3
MaxSessions 5

# Only use SSH protocol 2
Protocol 2

# Only use strong ciphers
Ciphers chacha20-poly1305@openssh.com,aes256-gcm@openssh.com,aes128-gcm@openssh.com,aes256-ctr,aes192-ctr,aes128-ctr
HostKeyAlgorithms ssh-ed25519,ssh-rsa,ecdsa-sha2-nistp256
KexAlgorithms curve25519-sha256@libssh.org,diffie-hellman-group-exchange-sha256
MACs hmac-sha2-512-etm@openssh.com,hmac-sha2-256-etm@openssh.com,umac-128-etm@openssh.com

# User authentication
PubkeyAuthentication yes
PasswordAuthentication yes
PermitEmptyPasswords no
ChallengeResponseAuthentication no
UsePAM yes

# Other options
X11Forwarding no
PrintMotd no
AcceptEnv LANG LC_*
Subsystem sftp /usr/lib/openssh/sftp-server
EOL

# Create SSH directory for new user
mkdir -p /home/$NEW_USERNAME/.ssh
chmod 700 /home/$NEW_USERNAME/.ssh
touch /home/$NEW_USERNAME/.ssh/authorized_keys
chmod 600 /home/$NEW_USERNAME/.ssh/authorized_keys
chown -R $NEW_USERNAME:$NEW_USERNAME /home/$NEW_USERNAME/.ssh

# Handle team SSH access
print_message "Setting up SSH access for team members..." $GREEN
print_message "You can add multiple SSH keys, one per line. When done, type 'done' on a new line." $YELLOW

# Create authorized_keys file
touch /home/$NEW_USERNAME/.ssh/authorized_keys

# Read SSH keys
echo "Enter SSH public keys (one per line, type 'done' when finished):"
while true; do
    read -p "> " SSH_KEY
    if [[ "$SSH_KEY" == "done" ]]; then
        break
    elif [[ ! -z "$SSH_KEY" ]]; then
        echo "$SSH_KEY" >> /home/$NEW_USERNAME/.ssh/authorized_keys
        print_message "SSH key added to authorized_keys" $GREEN
    fi
done

# Check if any keys were added
if [[ ! -s /home/$NEW_USERNAME/.ssh/authorized_keys ]]; then
    print_message "No SSH keys provided. You will need to use password authentication." $YELLOW
else
    print_message "SSH keys added successfully for team access." $GREEN
    print_message "You can add more keys later by appending to /home/$NEW_USERNAME/.ssh/authorized_keys" $YELLOW
fi

# Configure UFW (Firewall)
if [[ "$SETUP_UFW" == "y" || "$SETUP_UFW" == "Y" ]]; then
    print_section "CONFIGURING FIREWALL (UFW)"
    print_message "Setting up UFW firewall..." $GREEN

    # Reset UFW config
    ufw --force reset

    # Set default policies
    ufw default deny incoming
    ufw default allow outgoing

    # Allow SSH
    ufw allow $SSH_PORT/tcp comment 'Allow SSH'

    # Enable UFW
    print_message "Enabling UFW..." $GREEN
    ufw --force enable

    print_message "UFW configured and enabled" $GREEN
else
    print_message "Skipping UFW setup" $YELLOW
fi

# Configure fail2ban
if [[ "$SETUP_FAIL2BAN" == "y" || "$SETUP_FAIL2BAN" == "Y" ]]; then
    print_section "CONFIGURING FAIL2BAN"
    print_message "Setting up fail2ban..." $GREEN

    # Create fail2ban jail.local
    cat > /etc/fail2ban/jail.local << EOL
[DEFAULT]
bantime = 1h
findtime = 10m
maxretry = 5
banaction = ufw
backend = auto

[sshd]
enabled = true
port = $SSH_PORT
filter = sshd
logpath = /var/log/auth.log
maxretry = 3
bantime = 1d
EOL

    # Restart fail2ban
    systemctl restart fail2ban
    systemctl enable fail2ban

    print_message "fail2ban configured and enabled" $GREEN
else
    print_message "Skipping fail2ban setup" $YELLOW
fi

# Configure automatic updates
if [[ "$AUTO_UPDATES" == "y" || "$AUTO_UPDATES" == "Y" ]]; then
    print_section "CONFIGURING AUTOMATIC UPDATES"
    print_message "Setting up automatic security updates..." $GREEN

    # Configure unattended-upgrades
    cat > /etc/apt/apt.conf.d/20auto-upgrades << EOL
APT::Periodic::Update-Package-Lists "1";
APT::Periodic::Unattended-Upgrade "1";
APT::Periodic::AutocleanInterval "7";
APT::Periodic::Download-Upgradeable-Packages "1";
EOL

    # Configure unattended-upgrades
    cat > /etc/apt/apt.conf.d/50unattended-upgrades << EOL
Unattended-Upgrade::Allowed-Origins {
    "\${distro_id}:\${distro_codename}";
    "\${distro_id}:\${distro_codename}-security";
    "\${distro_id}ESMApps:\${distro_codename}-apps-security";
    "\${distro_id}ESM:\${distro_codename}-infra-security";
};
Unattended-Upgrade::Package-Blacklist {
};
Unattended-Upgrade::AutoFixInterruptedDpkg "true";
Unattended-Upgrade::MinimalSteps "true";
Unattended-Upgrade::InstallOnShutdown "false";
Unattended-Upgrade::Mail "root";
Unattended-Upgrade::MailReport "on-change";
Unattended-Upgrade::Remove-Unused-Kernel-Packages "true";
Unattended-Upgrade::Remove-Unused-Dependencies "true";
Unattended-Upgrade::Automatic-Reboot "false";
Unattended-Upgrade::Automatic-Reboot-Time "02:00";
EOL

    print_message "Automatic updates configured" $GREEN
else
    print_message "Skipping automatic updates setup" $YELLOW
fi

# System hardening
print_section "SYSTEM HARDENING"

# Secure shared memory
print_message "Securing shared memory..." $GREEN
echo "tmpfs /run/shm tmpfs defaults,noexec,nosuid 0 0" >> /etc/fstab

# Disable core dumps
print_message "Disabling core dumps..." $GREEN
echo "* hard core 0" >> /etc/security/limits.conf
echo "* soft core 0" >> /etc/security/limits.conf
echo "fs.suid_dumpable = 0" >> /etc/sysctl.conf

# Secure sysctl settings
print_message "Configuring secure sysctl settings..." $GREEN
cat > /etc/sysctl.d/99-security.conf << EOL
# IP Spoofing protection
net.ipv4.conf.all.rp_filter = 1
net.ipv4.conf.default.rp_filter = 1

# Ignore ICMP broadcast requests
net.ipv4.icmp_echo_ignore_broadcasts = 1

# Disable source packet routing
net.ipv4.conf.all.accept_source_route = 0
net.ipv4.conf.default.accept_source_route = 0
net.ipv6.conf.all.accept_source_route = 0
net.ipv6.conf.default.accept_source_route = 0

# Ignore send redirects
net.ipv4.conf.all.send_redirects = 0
net.ipv4.conf.default.send_redirects = 0

# Block SYN attacks
net.ipv4.tcp_syncookies = 1
net.ipv4.tcp_max_syn_backlog = 2048
net.ipv4.tcp_synack_retries = 2
net.ipv4.tcp_syn_retries = 5

# Log Martians
net.ipv4.conf.all.log_martians = 1
net.ipv4.conf.default.log_martians = 1

# Ignore ICMP redirects
net.ipv4.conf.all.accept_redirects = 0
net.ipv4.conf.default.accept_redirects = 0
net.ipv6.conf.all.accept_redirects = 0
net.ipv6.conf.default.accept_redirects = 0

# Ignore Directed pings
net.ipv4.icmp_echo_ignore_all = 0
EOL

# Apply sysctl settings
sysctl -p /etc/sysctl.d/99-security.conf

# Create additional team member accounts if requested
if [[ "$CREATE_TEAM_ACCOUNTS" == "y" || "$CREATE_TEAM_ACCOUNTS" == "Y" ]]; then
    print_section "CREATING TEAM MEMBER ACCOUNTS"

    # Ask how many team members to add
    read -p "How many team member accounts do you want to create? " TEAM_COUNT

    for ((i=1; i<=TEAM_COUNT; i++)); do
        # Get team member username
        read -p "Enter username for team member $i: " TEAM_USERNAME
        while [[ -z "$TEAM_USERNAME" ]]; do
            read -p "Username cannot be empty. Enter username: " TEAM_USERNAME
        done

        # Check if user already exists
        if id "$TEAM_USERNAME" &>/dev/null; then
            print_message "User $TEAM_USERNAME already exists" $YELLOW
            continue
        fi

        # Create user with home directory
        useradd -m -s /bin/bash "$TEAM_USERNAME"

        # Generate a secure password
        TEAM_PASSWORD=$(openssl rand -base64 12)
        echo "$TEAM_USERNAME:$TEAM_PASSWORD" | chpasswd

        # Add user to sudo group
        read -p "Should $TEAM_USERNAME have sudo privileges? (y/n, default: n): " TEAM_SUDO
        TEAM_SUDO=${TEAM_SUDO:-n}
        if [[ "$TEAM_SUDO" == "y" || "$TEAM_SUDO" == "Y" ]]; then
            usermod -aG sudo "$TEAM_USERNAME"
            print_message "User $TEAM_USERNAME added to sudo group" $GREEN
        fi

        # Create SSH directory for team member
        mkdir -p /home/$TEAM_USERNAME/.ssh
        chmod 700 /home/$TEAM_USERNAME/.ssh
        touch /home/$TEAM_USERNAME/.ssh/authorized_keys
        chmod 600 /home/$TEAM_USERNAME/.ssh/authorized_keys
        chown -R $TEAM_USERNAME:$TEAM_USERNAME /home/$TEAM_USERNAME/.ssh

        # Ask for SSH public key
        print_message "Enter SSH public key for $TEAM_USERNAME (leave empty to skip):" $YELLOW
        read TEAM_SSH_KEY
        if [[ ! -z "$TEAM_SSH_KEY" ]]; then
            echo "$TEAM_SSH_KEY" > /home/$TEAM_USERNAME/.ssh/authorized_keys
            print_message "SSH key added for $TEAM_USERNAME" $GREEN
        else
            print_message "No SSH key provided for $TEAM_USERNAME. They will need to use password authentication." $YELLOW
        fi

        print_message "User $TEAM_USERNAME created with password: $TEAM_PASSWORD" $GREEN
        print_message "IMPORTANT: $TEAM_USERNAME should change this password immediately after logging in!" $RED
    done
fi

# Final steps
print_section "FINAL STEPS"

# Restart SSH service
print_message "Restarting SSH service..." $GREEN
systemctl restart sshd

# Update locate database
print_message "Updating locate database..." $GREEN
updatedb

# Final message
print_section "SETUP COMPLETE"
print_message "VPS initial setup completed successfully!" $GREEN
print_message "IMPORTANT INFORMATION:" $RED
print_message "- New admin user: $NEW_USERNAME" $YELLOW
if [[ -z "$SSH_KEY" ]]; then
    print_message "- Password: $USER_PASSWORD (change this immediately!)" $YELLOW
fi
print_message "- SSH port: $SSH_PORT" $YELLOW
print_message "- UFW firewall: $(if [[ "$SETUP_UFW" == "y" || "$SETUP_UFW" == "Y" ]]; then echo "Enabled"; else echo "Disabled"; fi)" $YELLOW
print_message "- Fail2ban: $(if [[ "$SETUP_FAIL2BAN" == "y" || "$SETUP_FAIL2BAN" == "Y" ]]; then echo "Enabled"; else echo "Disabled"; fi)" $YELLOW
print_message "- Automatic updates: $(if [[ "$AUTO_UPDATES" == "y" || "$AUTO_UPDATES" == "Y" ]]; then echo "Enabled"; else echo "Disabled"; fi)" $YELLOW
print_message "- Hostname: $HOSTNAME" $YELLOW
print_message "- Timezone: $TIMEZONE" $YELLOW
echo
print_message "Next steps:" $GREEN
print_message "1. Log in with your new user: ssh $NEW_USERNAME@your_server_ip -p $SSH_PORT" $GREEN
print_message "2. Change your password immediately: passwd" $GREEN
print_message "3. Consider additional security measures like setting up logwatch emails" $GREEN

if [[ "$CREATE_TEAM_ACCOUNTS" == "y" || "$CREATE_TEAM_ACCOUNTS" == "Y" ]]; then
    echo
    print_message "Team access information:" $BLUE
    print_message "- Created $TEAM_COUNT additional team member accounts" $YELLOW
    print_message "- Each team member should change their password immediately after first login" $YELLOW
    print_message "- To add more SSH keys for team members later, append them to:" $YELLOW
    print_message "  /home/username/.ssh/authorized_keys" $YELLOW
    print_message "- To manage team access in the future:" $YELLOW
    print_message "  * Add user: sudo adduser username" $YELLOW
    print_message "  * Remove user: sudo deluser username" $YELLOW
    print_message "  * Add to sudo: sudo usermod -aG sudo username" $YELLOW
fi

echo
print_message "Thank you for using this script!" $GREEN
