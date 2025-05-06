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

# Detect Linux distribution
detect_distribution() {
    # Initialize variables
    DISTRO=""
    PACKAGE_MANAGER=""

    # Check for common distribution identification files
    if [ -f /etc/os-release ]; then
        . /etc/os-release
        DISTRO_ID=$ID
        DISTRO_VERSION_ID=$VERSION_ID

        case $DISTRO_ID in
            ubuntu|debian|pop|mint|elementary|zorin)
                DISTRO="debian"
                PACKAGE_MANAGER="apt"
                ;;
            fedora|rhel|centos|rocky|almalinux|ol)
                DISTRO="redhat"
                PACKAGE_MANAGER="dnf"
                # Use yum for older versions of RHEL/CentOS
                if [ "$DISTRO_ID" = "centos" ] || [ "$DISTRO_ID" = "rhel" ]; then
                    if [ "${VERSION_ID%%.*}" -lt 8 ]; then
                        PACKAGE_MANAGER="yum"
                    fi
                fi
                ;;
            arch|manjaro|endeavouros)
                DISTRO="arch"
                PACKAGE_MANAGER="pacman"
                ;;
            opensuse*|suse|sles)
                DISTRO="suse"
                PACKAGE_MANAGER="zypper"
                ;;
            *)
                # Try to detect using other methods
                if [ -f /etc/debian_version ]; then
                    DISTRO="debian"
                    PACKAGE_MANAGER="apt"
                elif [ -f /etc/fedora-release ] || [ -f /etc/redhat-release ]; then
                    DISTRO="redhat"
                    PACKAGE_MANAGER="dnf"
                    if [ -f /etc/redhat-release ]; then
                        # Check version for older RHEL/CentOS
                        if grep -q "release [567]" /etc/redhat-release; then
                            PACKAGE_MANAGER="yum"
                        fi
                    fi
                elif [ -f /etc/arch-release ]; then
                    DISTRO="arch"
                    PACKAGE_MANAGER="pacman"
                else
                    DISTRO="unknown"
                    PACKAGE_MANAGER="unknown"
                fi
                ;;
        esac
    else
        # Fallback detection
        if [ -f /etc/debian_version ]; then
            DISTRO="debian"
            PACKAGE_MANAGER="apt"
        elif [ -f /etc/fedora-release ] || [ -f /etc/redhat-release ]; then
            DISTRO="redhat"
            PACKAGE_MANAGER="dnf"
            if [ -f /etc/redhat-release ]; then
                if grep -q "release [567]" /etc/redhat-release; then
                    PACKAGE_MANAGER="yum"
                fi
            fi
        elif [ -f /etc/arch-release ]; then
            DISTRO="arch"
            PACKAGE_MANAGER="pacman"
        else
            DISTRO="unknown"
            PACKAGE_MANAGER="unknown"
        fi
    fi

    # Set distribution-specific variables
    case $DISTRO in
        debian)
            SSH_SERVICE="ssh"
            FIREWALL_PACKAGE="ufw"
            LOCATE_PACKAGES="mlocate plocate"
            ;;
        redhat)
            SSH_SERVICE="sshd"
            FIREWALL_PACKAGE="firewalld"
            LOCATE_PACKAGES="mlocate"
            ;;
        arch)
            SSH_SERVICE="sshd"
            FIREWALL_PACKAGE="ufw"
            LOCATE_PACKAGES="mlocate"
            ;;
        suse)
            SSH_SERVICE="sshd"
            FIREWALL_PACKAGE="firewalld"
            LOCATE_PACKAGES="mlocate"
            ;;
        *)
            SSH_SERVICE="sshd"
            FIREWALL_PACKAGE="ufw"
            LOCATE_PACKAGES="mlocate"
            ;;
    esac

    print_message "Detected distribution: $DISTRO_ID ($DISTRO)" $GREEN
    print_message "Using package manager: $PACKAGE_MANAGER" $GREEN
}

# Function to update package lists
update_packages() {
    print_message "Updating package lists..." $GREEN
    case $PACKAGE_MANAGER in
        apt)
            apt update
            ;;
        dnf|yum)
            $PACKAGE_MANAGER check-update || true  # Returns non-zero if updates available
            ;;
        pacman)
            pacman -Sy
            ;;
        zypper)
            zypper refresh
            ;;
        *)
            print_message "Unknown package manager. Skipping update." $YELLOW
            ;;
    esac
}

# Function to upgrade packages
upgrade_packages() {
    print_message "Upgrading packages..." $GREEN
    case $PACKAGE_MANAGER in
        apt)
            apt upgrade -y
            ;;
        dnf|yum)
            $PACKAGE_MANAGER upgrade -y
            ;;
        pacman)
            pacman -Su --noconfirm
            ;;
        zypper)
            zypper update -y
            ;;
        *)
            print_message "Unknown package manager. Skipping upgrade." $YELLOW
            ;;
    esac
}

# Function to install packages
install_package() {
    local package=$1
    local is_optional=${2:-false}

    print_message "Installing $package..." $GREEN

    case $PACKAGE_MANAGER in
        apt)
            if apt-cache show $package &>/dev/null; then
                apt install -y $package
                if [ $? -eq 0 ]; then
                    print_message "✓ Installed $package" $GREEN
                    return 0
                else
                    if [ "$is_optional" = "true" ]; then
                        print_message "⚠ Failed to install optional package: $package" $YELLOW
                        return 1
                    else
                        print_message "✗ Failed to install package: $package" $RED
                        return 1
                    fi
                fi
            else
                if [ "$is_optional" = "true" ]; then
                    print_message "⚠ Optional package not found: $package" $YELLOW
                    return 1
                else
                    print_message "⚠ Package not found: $package, continuing anyway" $YELLOW
                    return 1
                fi
            fi
            ;;
        dnf|yum)
            if $PACKAGE_MANAGER list available $package &>/dev/null; then
                $PACKAGE_MANAGER install -y $package
                if [ $? -eq 0 ]; then
                    print_message "✓ Installed $package" $GREEN
                    return 0
                else
                    if [ "$is_optional" = "true" ]; then
                        print_message "⚠ Failed to install optional package: $package" $YELLOW
                        return 1
                    else
                        print_message "✗ Failed to install package: $package" $RED
                        return 1
                    fi
                fi
            else
                if [ "$is_optional" = "true" ]; then
                    print_message "⚠ Optional package not found: $package" $YELLOW
                    return 1
                else
                    print_message "⚠ Package not found: $package, continuing anyway" $YELLOW
                    return 1
                fi
            fi
            ;;
        pacman)
            if pacman -Ss "^$package$" &>/dev/null; then
                pacman -S --noconfirm $package
                if [ $? -eq 0 ]; then
                    print_message "✓ Installed $package" $GREEN
                    return 0
                else
                    if [ "$is_optional" = "true" ]; then
                        print_message "⚠ Failed to install optional package: $package" $YELLOW
                        return 1
                    else
                        print_message "✗ Failed to install package: $package" $RED
                        return 1
                    fi
                fi
            else
                if [ "$is_optional" = "true" ]; then
                    print_message "⚠ Optional package not found: $package" $YELLOW
                    return 1
                else
                    print_message "⚠ Package not found: $package, continuing anyway" $YELLOW
                    return 1
                fi
            fi
            ;;
        zypper)
            if zypper search -x $package &>/dev/null; then
                zypper install -y $package
                if [ $? -eq 0 ]; then
                    print_message "✓ Installed $package" $GREEN
                    return 0
                else
                    if [ "$is_optional" = "true" ]; then
                        print_message "⚠ Failed to install optional package: $package" $YELLOW
                        return 1
                    else
                        print_message "✗ Failed to install package: $package" $RED
                        return 1
                    fi
                fi
            else
                if [ "$is_optional" = "true" ]; then
                    print_message "⚠ Optional package not found: $package" $YELLOW
                    return 1
                else
                    print_message "⚠ Package not found: $package, continuing anyway" $YELLOW
                    return 1
                fi
            fi
            ;;
        *)
            print_message "Unknown package manager. Cannot install $package." $YELLOW
            return 1
            ;;
    esac
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

# Detect distribution and set up environment
detect_distribution

# Update system and install essential packages
print_section "UPDATING SYSTEM AND INSTALLING PACKAGES"

# Update package lists
update_packages

# Upgrade packages
upgrade_packages

# Define package groups based on distribution
case $DISTRO in
    debian)
        ESSENTIAL_PACKAGES="sudo ufw fail2ban curl wget vim"
        SECURITY_PACKAGES="unattended-upgrades apt-listchanges logwatch"
        UTILITY_PACKAGES="htop tmux git net-tools ca-certificates gnupg lsb-release apt-transport-https"
        OPTIONAL_PACKAGES="apticron"
        ;;
    redhat)
        ESSENTIAL_PACKAGES="sudo firewalld fail2ban curl wget vim"
        SECURITY_PACKAGES="dnf-automatic logwatch"
        UTILITY_PACKAGES="htop tmux git net-tools ca-certificates gnupg"
        OPTIONAL_PACKAGES=""
        ;;
    arch)
        ESSENTIAL_PACKAGES="sudo ufw fail2ban curl wget vim"
        SECURITY_PACKAGES="pacman-contrib logwatch"
        UTILITY_PACKAGES="htop tmux git net-tools ca-certificates gnupg"
        OPTIONAL_PACKAGES=""
        ;;
    suse)
        ESSENTIAL_PACKAGES="sudo firewalld fail2ban curl wget vim"
        SECURITY_PACKAGES="zypper-aptitude logwatch"
        UTILITY_PACKAGES="htop tmux git net-tools ca-certificates gnupg"
        OPTIONAL_PACKAGES=""
        ;;
    *)
        ESSENTIAL_PACKAGES="sudo curl wget vim"
        SECURITY_PACKAGES=""
        UTILITY_PACKAGES="htop tmux git"
        OPTIONAL_PACKAGES=""
        ;;
esac

# Install essential packages
print_message "Installing essential packages..." $GREEN
for package in $ESSENTIAL_PACKAGES; do
    install_package "$package" "false"
done

# Install security packages
print_message "Installing security packages..." $GREEN
for package in $SECURITY_PACKAGES; do
    install_package "$package" "false"
done

# Install utility packages
print_message "Installing utility packages..." $GREEN
for package in $UTILITY_PACKAGES; do
    install_package "$package" "false"
done

# Install optional packages
print_message "Installing optional packages..." $GREEN
for package in $OPTIONAL_PACKAGES; do
    install_package "$package" "true"
done

# Try to install locate functionality (different package names in different distros)
if ! command -v locate &>/dev/null; then
    for locate_pkg in $LOCATE_PACKAGES; do
        if install_package "$locate_pkg" "true"; then
            break
        fi
    done

    if ! command -v locate &>/dev/null; then
        print_message "⚠ No locate package could be installed. File search functionality will be limited." $YELLOW
    fi
fi

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
    # Create user with home directory and bash shell
    useradd -m -s /bin/bash "$NEW_USERNAME"

    # Generate a secure password
    USER_PASSWORD=$(openssl rand -base64 12)
    echo "$NEW_USERNAME:$USER_PASSWORD" | chpasswd

    # Add user to sudo group and other necessary groups
    usermod -aG sudo "$NEW_USERNAME"

    # On some systems, users need to be in additional groups
    for group in adm dialout cdrom floppy audio video plugdev netdev; do
        if grep -q "^$group:" /etc/group; then
            usermod -aG $group "$NEW_USERNAME"
        fi
    done

    # Ensure the user's home directory has correct permissions
    chown -R "$NEW_USERNAME":"$NEW_USERNAME" /home/"$NEW_USERNAME"
    chmod 750 /home/"$NEW_USERNAME"

    # Create a .profile file if it doesn't exist
    if [ ! -f "/home/$NEW_USERNAME/.profile" ]; then
        cat > "/home/$NEW_USERNAME/.profile" << EOL
# ~/.profile: executed by the command interpreter for login shells.
# This file is not read by bash(1), if ~/.bash_profile or ~/.bash_login
# exists.

# if running bash
if [ -n "\$BASH_VERSION" ]; then
    # include .bashrc if it exists
    if [ -f "\$HOME/.bashrc" ]; then
        . "\$HOME/.bashrc"
    fi
fi

# set PATH so it includes user's private bin if it exists
if [ -d "\$HOME/bin" ] ; then
    PATH="\$HOME/bin:\$PATH"
fi

# set PATH so it includes user's private bin if it exists
if [ -d "\$HOME/.local/bin" ] ; then
    PATH="\$HOME/.local/bin:\$PATH"
fi
EOL
        chown "$NEW_USERNAME":"$NEW_USERNAME" "/home/$NEW_USERNAME/.profile"
        chmod 644 "/home/$NEW_USERNAME/.profile"
    fi

    # Create a .bashrc file if it doesn't exist
    if [ ! -f "/home/$NEW_USERNAME/.bashrc" ]; then
        cat > "/home/$NEW_USERNAME/.bashrc" << EOL
# ~/.bashrc: executed by bash(1) for non-login shells.

# If not running interactively, don't do anything
case \$- in
    *i*) ;;
      *) return;;
esac

# don't put duplicate lines or lines starting with space in the history
HISTCONTROL=ignoreboth

# append to the history file, don't overwrite it
shopt -s histappend

# for setting history length
HISTSIZE=1000
HISTFILESIZE=2000

# check the window size after each command
shopt -s checkwinsize

# make less more friendly for non-text input files
[ -x /usr/bin/lesspipe ] && eval "\$(SHELL=/bin/sh lesspipe)"

# set a fancy prompt
PS1='\[\033[01;32m\]\u@\h\[\033[00m\]:\[\033[01;34m\]\w\[\033[00m\]\$ '

# enable color support of ls
if [ -x /usr/bin/dircolors ]; then
    test -r ~/.dircolors && eval "\$(dircolors -b ~/.dircolors)" || eval "\$(dircolors -b)"
    alias ls='ls --color=auto'
    alias grep='grep --color=auto'
    alias fgrep='fgrep --color=auto'
    alias egrep='egrep --color=auto'
fi

# some more ls aliases
alias ll='ls -alF'
alias la='ls -A'
alias l='ls -CF'

# enable programmable completion features
if ! shopt -oq posix; then
  if [ -f /usr/share/bash-completion/bash_completion ]; then
    . /usr/share/bash-completion/bash_completion
  elif [ -f /etc/bash_completion ]; then
    . /etc/bash_completion
  fi
fi
EOL
        chown "$NEW_USERNAME":"$NEW_USERNAME" "/home/$NEW_USERNAME/.bashrc"
        chmod 644 "/home/$NEW_USERNAME/.bashrc"
    fi

    # Save credentials to a file for reference
    CREDENTIALS_FILE="/root/user_credentials.txt"
    echo "Username: $NEW_USERNAME" > $CREDENTIALS_FILE
    echo "Password: $USER_PASSWORD" >> $CREDENTIALS_FILE
    echo "Created on: $(date)" >> $CREDENTIALS_FILE
    chmod 600 $CREDENTIALS_FILE

    print_message "User created with password: $USER_PASSWORD" $GREEN
    print_message "Credentials saved to $CREDENTIALS_FILE" $GREEN
    print_message "IMPORTANT: Please change this password immediately after logging in!" $RED
    print_message "IMPORTANT: Delete $CREDENTIALS_FILE after noting down the credentials!" $RED
fi

# Configure SSH
print_section "CONFIGURING SSH"
print_message "Configuring SSH for security..." $GREEN

# Ask about root login
read -p "Allow root SSH login? (yes/no/prohibit-password, default: yes): " ROOT_LOGIN
ROOT_LOGIN=${ROOT_LOGIN:-yes}

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
PermitRootLogin $ROOT_LOGIN
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

print_message "SSH configured with root login set to: $ROOT_LOGIN" $GREEN

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

# Configure Firewall
if [[ "$SETUP_UFW" == "y" || "$SETUP_UFW" == "Y" ]]; then
    print_section "CONFIGURING FIREWALL"

    # Check which firewall is available based on distribution
    if [[ "$FIREWALL_PACKAGE" == "ufw" ]]; then
        print_message "Setting up UFW firewall..." $GREEN

        # Check if UFW is installed
        if ! command -v ufw &>/dev/null; then
            print_message "UFW not found. Attempting to install..." $YELLOW
            install_package "ufw" "false"

            # Check again if installation was successful
            if ! command -v ufw &>/dev/null; then
                print_message "Failed to install UFW. Firewall setup will be skipped." $RED
                SETUP_UFW="n"
            fi
        fi

        if [[ "$SETUP_UFW" == "y" || "$SETUP_UFW" == "Y" ]]; then
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

            # Verify UFW is running
            if systemctl is-active --quiet ufw; then
                print_message "UFW configured and enabled successfully" $GREEN
            else
                print_message "Warning: UFW may not be running. Check status with 'systemctl status ufw'" $YELLOW
            fi
        fi
    elif [[ "$FIREWALL_PACKAGE" == "firewalld" ]]; then
        print_message "Setting up firewalld..." $GREEN

        # Check if firewalld is installed
        if ! command -v firewall-cmd &>/dev/null; then
            print_message "firewalld not found. Attempting to install..." $YELLOW
            install_package "firewalld" "false"

            # Check again if installation was successful
            if ! command -v firewall-cmd &>/dev/null; then
                print_message "Failed to install firewalld. Firewall setup will be skipped." $RED
                SETUP_UFW="n"
            fi
        fi

        if [[ "$SETUP_UFW" == "y" || "$SETUP_UFW" == "Y" ]]; then
            # Enable and start firewalld
            systemctl enable firewalld
            systemctl start firewalld

            # Configure firewalld
            print_message "Configuring firewalld..." $GREEN

            # Add SSH port
            firewall-cmd --permanent --add-port=$SSH_PORT/tcp

            # Remove default SSH if we're using a non-standard port
            if [[ "$SSH_PORT" != "22" ]]; then
                firewall-cmd --permanent --remove-service=ssh
            fi

            # Reload to apply changes
            firewall-cmd --reload

            # Verify firewalld is running
            if systemctl is-active --quiet firewalld; then
                print_message "firewalld configured and enabled successfully" $GREEN
            else
                print_message "Warning: firewalld may not be running. Check status with 'systemctl status firewalld'" $YELLOW
            fi
        fi
    else
        print_message "No supported firewall found for your distribution. Firewall setup will be skipped." $YELLOW
    fi
else
    print_message "Skipping firewall setup" $YELLOW
fi

# Configure fail2ban
if [[ "$SETUP_FAIL2BAN" == "y" || "$SETUP_FAIL2BAN" == "Y" ]]; then
    print_section "CONFIGURING FAIL2BAN"
    print_message "Setting up fail2ban..." $GREEN

    # Check if fail2ban is installed
    if ! command -v fail2ban-server &>/dev/null && ! command -v fail2ban-client &>/dev/null; then
        print_message "fail2ban not found. Attempting to install..." $YELLOW
        install_package "fail2ban" "false"

        # Check again if installation was successful
        if ! command -v fail2ban-server &>/dev/null && ! command -v fail2ban-client &>/dev/null; then
            print_message "Failed to install fail2ban. Setup will be skipped." $RED
            SETUP_FAIL2BAN="n"
        fi
    fi

    if [[ "$SETUP_FAIL2BAN" == "y" || "$SETUP_FAIL2BAN" == "Y" ]]; then
        # Check if fail2ban directory exists
        if [ ! -d "/etc/fail2ban" ]; then
            print_message "fail2ban configuration directory not found. Creating..." $YELLOW
            mkdir -p /etc/fail2ban
        fi

        # Determine appropriate banaction based on firewall
        if command -v ufw &>/dev/null && [[ "$FIREWALL_PACKAGE" == "ufw" ]]; then
            BANACTION="ufw"
        elif command -v firewall-cmd &>/dev/null && [[ "$FIREWALL_PACKAGE" == "firewalld" ]]; then
            BANACTION="firewallcmd-ipset"
        else
            BANACTION="iptables-multiport"
        fi

        # Determine appropriate log path based on distribution
        case $DISTRO in
            debian)
                LOGPATH="/var/log/auth.log"
                ;;
            redhat|arch)
                LOGPATH="/var/log/secure"
                # On some systems it might be in /var/log/auth.log
                if [ ! -f "$LOGPATH" ]; then
                    if [ -f "/var/log/auth.log" ]; then
                        LOGPATH="/var/log/auth.log"
                    fi
                fi
                ;;
            *)
                # Try to find the auth log
                if [ -f "/var/log/auth.log" ]; then
                    LOGPATH="/var/log/auth.log"
                elif [ -f "/var/log/secure" ]; then
                    LOGPATH="/var/log/secure"
                else
                    LOGPATH="/var/log/auth.log"  # Default fallback
                    print_message "Warning: Could not determine auth log path. Using default: $LOGPATH" $YELLOW
                fi
                ;;
        esac

        # Create fail2ban jail.local
        cat > /etc/fail2ban/jail.local << EOL
[DEFAULT]
bantime = 1h
findtime = 10m
maxretry = 5
banaction = $BANACTION
backend = auto

[sshd]
enabled = true
port = $SSH_PORT
filter = sshd
logpath = $LOGPATH
maxretry = 3
bantime = 1d
EOL

        # Restart fail2ban
        if systemctl restart fail2ban; then
            systemctl enable fail2ban
            print_message "fail2ban configured and enabled successfully" $GREEN
        else
            print_message "Warning: Failed to restart fail2ban. Check status with 'systemctl status fail2ban'" $RED
        fi
    fi
else
    print_message "Skipping fail2ban setup" $YELLOW
fi

# Configure automatic updates
if [[ "$AUTO_UPDATES" == "y" || "$AUTO_UPDATES" == "Y" ]]; then
    print_section "CONFIGURING AUTOMATIC UPDATES"
    print_message "Setting up automatic security updates..." $GREEN

    case $DISTRO in
        debian)
            # Debian/Ubuntu: Use unattended-upgrades
            if ! command -v unattended-upgrade &>/dev/null; then
                print_message "unattended-upgrades not found. Attempting to install..." $YELLOW
                install_package "unattended-upgrades" "false"

                # Check again if installation was successful
                if ! command -v unattended-upgrade &>/dev/null; then
                    print_message "Failed to install unattended-upgrades. Setup will be skipped." $RED
                    AUTO_UPDATES="n"
                fi
            fi

            if [[ "$AUTO_UPDATES" == "y" || "$AUTO_UPDATES" == "Y" ]]; then
                # Make sure apt directory exists
                mkdir -p /etc/apt/apt.conf.d/

                # Configure unattended-upgrades
                cat > /etc/apt/apt.conf.d/20auto-upgrades << EOL
APT::Periodic::Update-Package-Lists "1";
APT::Periodic::Unattended-Upgrade "1";
APT::Periodic::AutocleanInterval "7";
APT::Periodic::Download-Upgradeable-Packages "1";
EOL

                # Configure unattended-upgrades with distro detection
                DISTRO_ID=$(lsb_release -is 2>/dev/null || echo "Debian")
                DISTRO_CODENAME=$(lsb_release -cs 2>/dev/null || echo "stable")

                cat > /etc/apt/apt.conf.d/50unattended-upgrades << EOL
Unattended-Upgrade::Allowed-Origins {
    "${DISTRO_ID}:${DISTRO_CODENAME}";
    "${DISTRO_ID}:${DISTRO_CODENAME}-security";
    "${DISTRO_ID}ESMApps:${DISTRO_CODENAME}-apps-security";
    "${DISTRO_ID}ESM:${DISTRO_CODENAME}-infra-security";
    "${DISTRO_ID}:${DISTRO_CODENAME}-updates";
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

                # Enable the service
                systemctl enable unattended-upgrades
                systemctl restart unattended-upgrades

                print_message "Automatic updates configured successfully" $GREEN
            fi
            ;;

        redhat)
            # RHEL/CentOS/Fedora: Use dnf-automatic
            if ! command -v dnf-automatic &>/dev/null; then
                print_message "dnf-automatic not found. Attempting to install..." $YELLOW
                install_package "dnf-automatic" "false"

                # Check again if installation was successful
                if ! command -v dnf-automatic &>/dev/null; then
                    print_message "Failed to install dnf-automatic. Setup will be skipped." $RED
                    AUTO_UPDATES="n"
                fi
            fi

            if [[ "$AUTO_UPDATES" == "y" || "$AUTO_UPDATES" == "Y" ]]; then
                # Configure dnf-automatic
                if [ -f "/etc/dnf/automatic.conf" ]; then
                    # Backup original config
                    cp /etc/dnf/automatic.conf /etc/dnf/automatic.conf.bak

                    # Update configuration
                    sed -i 's/^apply_updates = .*/apply_updates = yes/' /etc/dnf/automatic.conf
                    sed -i 's/^emit_via = .*/emit_via = email/' /etc/dnf/automatic.conf
                    sed -i 's/^email_from = .*/email_from = root@localhost/' /etc/dnf/automatic.conf
                    sed -i 's/^email_to = .*/email_to = root/' /etc/dnf/automatic.conf

                    # Enable and start the timer
                    systemctl enable --now dnf-automatic.timer

                    print_message "Automatic updates configured successfully" $GREEN
                else
                    print_message "dnf-automatic configuration file not found. Setup will be skipped." $RED
                    AUTO_UPDATES="n"
                fi
            fi
            ;;

        arch)
            # Arch Linux: Use pacman-contrib (checkupdates) with systemd timer
            if ! command -v checkupdates &>/dev/null; then
                print_message "pacman-contrib not found. Attempting to install..." $YELLOW
                install_package "pacman-contrib" "false"

                # Check again if installation was successful
                if ! command -v checkupdates &>/dev/null; then
                    print_message "Failed to install pacman-contrib. Setup will be skipped." $RED
                    AUTO_UPDATES="n"
                fi
            fi

            if [[ "$AUTO_UPDATES" == "y" || "$AUTO_UPDATES" == "Y" ]]; then
                # Create update script
                mkdir -p /usr/local/bin
                cat > /usr/local/bin/auto-update.sh << 'EOL'
#!/bin/bash
# Check for updates and apply them
/usr/bin/checkupdates || exit 0
/usr/bin/pacman -Syu --noconfirm
EOL
                chmod +x /usr/local/bin/auto-update.sh

                # Create systemd service
                mkdir -p /etc/systemd/system
                cat > /etc/systemd/system/pacman-autoupdate.service << 'EOL'
[Unit]
Description=Pacman Auto Update Service
After=network-online.target

[Service]
Type=oneshot
ExecStart=/usr/local/bin/auto-update.sh
EOL

                # Create systemd timer
                cat > /etc/systemd/system/pacman-autoUpdate.timer << 'EOL'
[Unit]
Description=Run pacman update daily

[Timer]
OnCalendar=daily
Persistent=true

[Install]
WantedBy=timers.target
EOL

                # Enable and start the timer
                systemctl enable --now pacman-autoUpdate.timer

                print_message "Automatic updates configured successfully" $GREEN
            fi
            ;;

        suse)
            # openSUSE: Use zypper-aptitude
            if ! command -v zypper &>/dev/null; then
                print_message "zypper not found. Setup will be skipped." $RED
                AUTO_UPDATES="n"
            fi

            if [[ "$AUTO_UPDATES" == "y" || "$AUTO_UPDATES" == "Y" ]]; then
                # Create update script
                mkdir -p /usr/local/bin
                cat > /usr/local/bin/auto-update.sh << 'EOL'
#!/bin/bash
# Check for updates and apply them
/usr/bin/zypper --non-interactive update
EOL
                chmod +x /usr/local/bin/auto-update.sh

                # Create systemd service
                mkdir -p /etc/systemd/system
                cat > /etc/systemd/system/zypper-autoUpdate.service << 'EOL'
[Unit]
Description=Zypper Auto Update Service
After=network-online.target

[Service]
Type=oneshot
ExecStart=/usr/local/bin/auto-update.sh
EOL

                # Create systemd timer
                cat > /etc/systemd/system/zypper-autoUpdate.timer << 'EOL'
[Unit]
Description=Run zypper update daily

[Timer]
OnCalendar=daily
Persistent=true

[Install]
WantedBy=timers.target
EOL

                # Enable and start the timer
                systemctl enable --now zypper-autoUpdate.timer

                print_message "Automatic updates configured successfully" $GREEN
            fi
            ;;

        *)
            print_message "Automatic updates not supported for this distribution. Setup will be skipped." $YELLOW
            AUTO_UPDATES="n"
            ;;
    esac
else
    print_message "Skipping automatic updates setup" $YELLOW
fi

# Verify sudo configuration
print_section "VERIFYING SUDO CONFIGURATION"

# Check if sudo is installed
if ! command -v sudo &>/dev/null; then
    print_message "sudo is not installed. Attempting to install..." $YELLOW
    install_package "sudo" "false"

    if ! command -v sudo &>/dev/null; then
        print_message "Failed to install sudo. Users will not have sudo privileges." $RED
    fi
fi

# Ensure sudo group has proper permissions
if [ -f "/etc/sudoers" ]; then
    # Check if sudo group is properly configured
    if ! grep -q "^%sudo" /etc/sudoers && ! grep -q "^%sudo" /etc/sudoers.d/*; then
        print_message "Adding sudo group to sudoers file..." $GREEN
        echo "%sudo   ALL=(ALL:ALL) ALL" >> /etc/sudoers
    fi

    # Ensure the file has correct permissions
    chmod 440 /etc/sudoers

    print_message "Sudo configuration verified" $GREEN
else
    print_message "Warning: /etc/sudoers file not found. Sudo may not be properly configured." $RED
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

        # Create user with home directory and bash shell
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

        # On some systems, users need to be in additional groups
        for group in adm dialout cdrom floppy audio video plugdev netdev; do
            if grep -q "^$group:" /etc/group; then
                usermod -aG $group "$TEAM_USERNAME"
            fi
        done

        # Ensure the user's home directory has correct permissions
        chown -R "$TEAM_USERNAME":"$TEAM_USERNAME" /home/"$TEAM_USERNAME"
        chmod 750 /home/"$TEAM_USERNAME"

        # Copy the shell configuration files from the main user
        if [ -f "/home/$NEW_USERNAME/.profile" ]; then
            cp "/home/$NEW_USERNAME/.profile" "/home/$TEAM_USERNAME/.profile"
            chown "$TEAM_USERNAME":"$TEAM_USERNAME" "/home/$TEAM_USERNAME/.profile"
            chmod 644 "/home/$TEAM_USERNAME/.profile"
        fi

        if [ -f "/home/$NEW_USERNAME/.bashrc" ]; then
            cp "/home/$NEW_USERNAME/.bashrc" "/home/$TEAM_USERNAME/.bashrc"
            chown "$TEAM_USERNAME":"$TEAM_USERNAME" "/home/$TEAM_USERNAME/.bashrc"
            chmod 644 "/home/$TEAM_USERNAME/.bashrc"
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

        # Save team member credentials to the file
        echo -e "\nUsername: $TEAM_USERNAME" >> $CREDENTIALS_FILE
        echo "Password: $TEAM_PASSWORD" >> $CREDENTIALS_FILE
        echo "Sudo access: ${TEAM_SUDO}" >> $CREDENTIALS_FILE
        echo "Created on: $(date)" >> $CREDENTIALS_FILE

        print_message "User $TEAM_USERNAME created with password: $TEAM_PASSWORD" $GREEN
        print_message "Credentials saved to $CREDENTIALS_FILE" $GREEN
        print_message "IMPORTANT: $TEAM_USERNAME should change this password immediately after logging in!" $RED
    done
fi

# Final steps
print_section "FINAL STEPS"

# Test sudo access for the new user
print_message "Testing sudo access for $NEW_USERNAME..." $GREEN
if id "$NEW_USERNAME" &>/dev/null; then
    # Create a test script
    TEST_SCRIPT="/tmp/sudo_test.sh"
    cat > "$TEST_SCRIPT" << EOL
#!/bin/bash
echo "Sudo is working correctly for $NEW_USERNAME"
EOL
    chmod +x "$TEST_SCRIPT"

    # Try to run the test script with sudo as the new user
    if su - "$NEW_USERNAME" -c "sudo $TEST_SCRIPT" &>/dev/null; then
        print_message "✓ Sudo is working correctly for $NEW_USERNAME" $GREEN
    else
        print_message "⚠ Sudo test failed for $NEW_USERNAME" $RED
        print_message "Attempting to fix sudo configuration..." $YELLOW

        # Make sure the user is in the sudo group
        usermod -aG sudo "$NEW_USERNAME"

        # Add a specific entry for this user in sudoers
        echo "$NEW_USERNAME ALL=(ALL:ALL) ALL" >> /etc/sudoers

        print_message "Sudo configuration updated. Please test sudo access after logging in." $YELLOW
    fi

    # Clean up
    rm -f "$TEST_SCRIPT"
fi

# Restart SSH service
print_message "Restarting SSH service..." $GREEN
# Use the detected SSH service name from distribution detection
if systemctl list-units --type=service | grep -q "${SSH_SERVICE}.service"; then
    systemctl restart $SSH_SERVICE
else
    print_message "SSH service ($SSH_SERVICE) not found. Trying alternatives..." $YELLOW

    # Try common alternatives
    if systemctl list-units --type=service | grep -q "ssh.service"; then
        systemctl restart ssh
        print_message "Restarted ssh service" $GREEN
    elif systemctl list-units --type=service | grep -q "sshd.service"; then
        systemctl restart sshd
        print_message "Restarted sshd service" $GREEN
    else
        print_message "SSH service not found. You may need to restart it manually." $RED
    fi
fi

# Update locate database if available
if command -v updatedb &>/dev/null; then
    print_message "Updating locate database..." $GREEN
    updatedb
else
    print_message "Locate database update skipped (updatedb not available)." $YELLOW
fi

# Final message
print_section "SETUP COMPLETE"
print_message "VPS initial setup completed successfully!" $GREEN
print_message "IMPORTANT INFORMATION:" $RED
print_message "- New admin user: $NEW_USERNAME" $YELLOW
if [[ -z "$SSH_KEY" ]]; then
    print_message "- Password: $USER_PASSWORD (change this immediately!)" $YELLOW
    print_message "- Credentials saved to: $CREDENTIALS_FILE" $YELLOW
fi
print_message "- SSH port: $SSH_PORT" $YELLOW
print_message "- Root SSH login: $ROOT_LOGIN" $YELLOW
print_message "- UFW firewall: $(if [[ "$SETUP_UFW" == "y" || "$SETUP_UFW" == "Y" ]]; then echo "Enabled"; else echo "Disabled"; fi)" $YELLOW
print_message "- Fail2ban: $(if [[ "$SETUP_FAIL2BAN" == "y" || "$SETUP_FAIL2BAN" == "Y" ]]; then echo "Enabled"; else echo "Disabled"; fi)" $YELLOW
print_message "- Automatic updates: $(if [[ "$AUTO_UPDATES" == "y" || "$AUTO_UPDATES" == "Y" ]]; then echo "Enabled"; else echo "Disabled"; fi)" $YELLOW
print_message "- Hostname: $HOSTNAME" $YELLOW
print_message "- Timezone: $TIMEZONE" $YELLOW
echo
print_message "Next steps:" $GREEN
print_message "1. Log in with your new user: ssh $NEW_USERNAME@your_server_ip -p $SSH_PORT" $GREEN
if [[ "$ROOT_LOGIN" == "yes" ]]; then
    print_message "   Alternatively, you can still log in as root: ssh root@your_server_ip -p $SSH_PORT" $GREEN
fi
print_message "2. Change your password immediately: passwd" $GREEN
print_message "3. Note down the credentials from $CREDENTIALS_FILE and then delete the file" $GREEN
print_message "4. Consider additional security measures like setting up logwatch emails" $GREEN

if [[ "$CREATE_TEAM_ACCOUNTS" == "y" || "$CREATE_TEAM_ACCOUNTS" == "Y" ]]; then
    echo
    print_message "Team access information:" $BLUE
    print_message "- Created $TEAM_COUNT additional team member accounts" $YELLOW
    print_message "- All credentials are saved in $CREDENTIALS_FILE" $YELLOW
    print_message "- Each team member should change their password immediately after first login" $YELLOW
    print_message "- To add more SSH keys for team members later, append them to:" $YELLOW
    print_message "  /home/username/.ssh/authorized_keys" $YELLOW
    print_message "- To manage team access in the future:" $YELLOW
    print_message "  * Add user: sudo adduser username" $YELLOW
    print_message "  * Remove user: sudo deluser username" $YELLOW
    print_message "  * Add to sudo: sudo usermod -aG sudo username" $YELLOW

    if [[ "$ROOT_LOGIN" == "yes" ]]; then
        print_message "- Root SSH login is enabled, so you can always access the server as root" $YELLOW
    elif [[ "$ROOT_LOGIN" == "prohibit-password" ]]; then
        print_message "- Root SSH login is set to prohibit-password (key-based authentication only)" $YELLOW
    else
        print_message "- Root SSH login is disabled, make sure you can log in with another user" $YELLOW
    fi
fi

echo
print_message "Thank you for using this script!" $GREEN
