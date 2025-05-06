# VPS Initial Setup Script

A comprehensive bash script to secure and set up a new VPS (Virtual Private Server) on providers like Contabo, DigitalOcean, Linode, Vultr, etc. This script follows security best practices to harden your server against common threats.

## Features

- **Cross-Distribution Compatibility**
  - Works on Debian/Ubuntu, RHEL/CentOS/Fedora, Arch Linux, and openSUSE
  - Automatically detects the distribution and adapts configurations
  - Uses appropriate package managers (apt, dnf/yum, pacman, zypper)
  - Handles distribution-specific paths and service names
- **System Updates and Package Management**
  - Updates system packages using the native package manager
  - Installs essential security and utility packages
  - Handles package availability differences between distributions
- **Team Access Management**
  - Multiple SSH key support
  - Create multiple user accounts for team members
  - Individual SSH key management for each team member
  - Configurable sudo privileges for team members
- **Secure SSH Configuration**
  - Custom SSH port
  - Disable root login
  - Strong ciphers and algorithms
  - Public key authentication support
- **Firewall Configuration**
  - UFW for Debian and Arch-based systems
  - firewalld for RHEL and SUSE-based systems
  - Proper integration with fail2ban
- **Intrusion Prevention with fail2ban**
  - Customized for each distribution
  - Proper log path detection
  - Integration with the appropriate firewall
- **Automatic Security Updates**
  - unattended-upgrades for Debian/Ubuntu
  - dnf-automatic for RHEL/CentOS/Fedora
  - systemd timers for Arch and SUSE
- **System Hardening**
  - Secure shared memory
  - Disable core dumps
  - Secure sysctl settings
- **Timezone and Hostname Configuration**

## Requirements

- A fresh VPS with any of these Linux distributions:
  - Debian-based: Ubuntu, Debian, Linux Mint, Pop!\_OS, etc.
  - Red Hat-based: RHEL, CentOS, Fedora, Rocky Linux, AlmaLinux, etc.
  - Arch-based: Arch Linux, Manjaro, EndeavourOS, etc.
  - SUSE-based: openSUSE, SLES, etc.
- Root access to the server

## Usage

1. Upload the script to your server:

```bash
scp vps_setup.sh root@your_server_ip:/root/
```

2. Connect to your server:

```bash
ssh root@your_server_ip
```

3. Make the script executable:

```bash
chmod +x vps_setup.sh
```

4. Run the script:

```bash
./vps_setup.sh
```

5. Follow the prompts to configure your server.

## Configuration Options

During setup, you'll be prompted for the following information:

- **Username**: Name for the new admin user
- **SSH Port**: Custom port for SSH (default: 22)
- **Timezone**: Server timezone (default: UTC)
- **Hostname**: Server hostname (default: server)
- **SSH Public Keys**: Multiple SSH public keys for team access (optional)
- **Team Accounts**: Whether to create additional user accounts for team members
- **Automatic Updates**: Whether to enable automatic security updates
- **Fail2ban**: Whether to set up intrusion prevention
- **UFW Firewall**: Whether to configure the firewall

### Team Access Configuration

If you choose to create team member accounts, you'll be prompted for:

- **Number of team members**: How many additional accounts to create
- **Username** for each team member
- **Sudo privileges** for each team member (yes/no)
- **SSH public key** for each team member (optional)

The script will generate random passwords for all users and display them at the end of the setup process.

## After Installation

After running the script, you should:

1. Log in with your new user account
2. Change the default password immediately
3. Share login credentials securely with team members
4. Consider additional security measures:
   - Set up logwatch email notifications
   - Configure additional firewall rules as needed
   - Set up regular backups
   - Install and configure additional security tools

### Managing Team Access

After the initial setup, you can manage team access using these commands:

#### Adding a New Team Member

```bash
# Create a new user account
sudo adduser username

# Add to sudo group (if needed)
sudo usermod -aG sudo username

# Create SSH directory and set permissions
sudo mkdir -p /home/username/.ssh
sudo chmod 700 /home/username/.ssh
sudo touch /home/username/.ssh/authorized_keys
sudo chmod 600 /home/username/.ssh/authorized_keys
sudo chown -R username:username /home/username/.ssh

# Add SSH key
echo "ssh-rsa AAAA..." | sudo tee -a /home/username/.ssh/authorized_keys
```

#### Removing a Team Member

```bash
# Remove user account and home directory
sudo deluser --remove-home username

# Or keep the home directory
sudo deluser username
```

#### Revoking SSH Access Without Removing the Account

```bash
# Remove or comment out the user's key in their authorized_keys file
sudo nano /home/username/.ssh/authorized_keys
```

## Security Considerations

This script implements several security best practices:

- **No Root Login**: Disables direct root login via SSH
- **Secure SSH**: Uses strong ciphers and algorithms
- **Firewall**: Blocks all incoming connections except SSH
- **Fail2ban**: Blocks IP addresses after multiple failed login attempts
- **System Hardening**: Configures various kernel parameters for security
- **Automatic Updates**: Keeps the system updated with security patches
- **Team Access Management**:
  - Individual user accounts with separate SSH keys
  - Granular sudo privilege control
  - Easy to add/remove team members

### Team Access Security Best Practices

When managing a server with multiple team members, consider these additional security practices:

1. **Principle of Least Privilege**: Only grant sudo access to team members who absolutely need it
2. **Regular Access Audits**: Periodically review who has access to your server
3. **SSH Key Rotation**: Have team members rotate their SSH keys periodically
4. **Access Logging**: Monitor and review login attempts and system access
5. **Offboarding Process**: Have a clear process for removing access when team members leave

## Customization

You can modify the script to suit your specific needs:

- Add additional firewall rules
- Install specific packages
- Configure additional services
- Adjust security parameters

## Troubleshooting

If you encounter issues:

1. **SSH Connection Issues**: Verify the SSH port and firewall settings
2. **User Creation Problems**: Check if the user already exists
3. **Firewall Blocking**: Temporarily disable UFW with `ufw disable`

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## License

This script is released under the MIT License.

## Disclaimer

This script is provided as-is without any warranty. Always test in a non-production environment first and ensure you have backups before making significant changes to your server.
