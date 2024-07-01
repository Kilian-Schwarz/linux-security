Sure, here is the updated README file for your Linux Security Script:

---

# Linux Security Script

## Overview
This script is designed to enhance the security of a Linux server by performing a series of configurations and installations. It is highly recommended to review and ensure all values in the configuration file `security.conf` are correctly set before running the script.

## Features
The script performs the following operations:
1. **Update package lists and install necessary packages**: Ensures all required packages for security and monitoring are installed.
2. **Configure UFW firewall**: Sets up UFW firewall rules to allow SSH from specified IP addresses and deny all other incoming connections.
3. **Create and configure a new admin user**: Creates a new user with administrative privileges and sets a secure password.
4. **Set up password security**: Enforces password security policies including password expiration.
5. **Insert SSH keys**: Adds specified SSH keys for secure access.
6. **Configure SSH security settings**: Hardens SSH configuration by disabling root login, password authentication, and more.
7. **Configure Fail2Ban for dynamic IP blocking**: Sets up Fail2Ban to block IP addresses that show malicious signs.
8. **Activate ClamAV antivirus**: Installs and configures ClamAV for antivirus protection.
9. **Activate AIDE for file integrity monitoring**: Sets up AIDE to monitor file integrity and detect unauthorized changes.
10. **Configure rkhunter for rootkit detection**: Installs and configures rkhunter for rootkit detection.
11. **Install and configure an autoupdater**: Sets up an automatic updater to keep the system packages up-to-date.
12. **Set a secure banner for Postfix**: Configures Postfix with a secure SMTP banner.
13. **Enable auditing tools and services**: Installs and configures auditd, acct, and sysstat for system auditing.
14. **Apply other security configurations**: Applies various additional security settings to harden the system.
15. **Set GRUB bootloader password**: Configures a password for GRUB bootloader to enhance boot security.

## Prerequisites
- This script must be run as root.
- Ensure `security.conf` file is present in the same directory as the script and correctly configured.

## Installation and Usage

1. **Clone the Repository**:
   ```bash
   git clone https://github.com/Kilian-Schwarz/linux-security.git
   cd linux-security
   ```

2. **Prepare the Configuration File**: Edit the `security.conf` file to include all necessary configuration details such as SSH keys, admin user details, and other security settings.

3. **Run the Script**: Execute the script with root privileges.
   ```bash
   sudo ./security.sh
   ```

## Configuration File (`security.conf`)
The configuration file should include the following variables:
- `SECURITY_UFWSSH_IPS`: IP addresses allowed to SSH into the server.
- `SECURITY_SSH_PORT`: The port number for SSH.
- `SECURITY_USERNAME_ADMINUSER`: The username for the new admin user.
- `SECURITY_SSH_SSH_ADMINUSER_KEYS`: SSH keys for the admin user.
- `SECURITY_SSH_ADMIN_KEYS`: General SSH keys for all users.
- `SECURITY_TIMEZONE`: The timezone for the server.
- Module activation variables (ENABLE_UFW, ENABLE_ADMINUSER, ENABLE_PASSWORDSECURITY, etc.) to control which security features to enable.

## Notes
- Always review the script and configuration file to ensure it meets your security policies and requirements.
- After running the script, it is recommended to reboot the server to apply all changes.

## Known Issues
- **Set GRUB bootloader password**: This feature is currently not functioning. We are working on resolving the issue.
