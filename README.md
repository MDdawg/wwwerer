#!/bin/bash

# Function to create backups of configuration files
backup_config_file() {
    local config_file="$1"
    local backup_dir="/path/to/backup/directory"  # Change this to the desired backup directory

    # Check if the file exists
    if [ -e "$config_file" ]; then
        # Create a backup with a timestamp
        local backup_file="${backup_dir}/$(basename "$config_file").$(date +%Y%m%d%H%M%S)"

        # Copy the original file to the backup location
        cp "$config_file" "$backup_file"

        # Output a message
        echo "Backup created: $backup_file"
    else
        echo "File not found: $config_file"
    fi
}

# Function to manage users
manage_users() {
    local users=$(cut -d: -f1 /etc/passwd)
    for user in $users; do
        echo "Managing user: $user"
        read -p "Change this user (y/n/-a to add a user)? " choice
        case $choice in
            [Yy]* ) manage_user "$user";;
            [Aa]* ) add_new_user;;
            * ) echo "Skipping $user";;
        esac
    done
}

# Function to manage a specific user
manage_user() {
    local username="$1"
    echo "Managing user: $username"
    while true; do
        read -p "Options for $username: [1] Change password [2] Change user type [3] Delete user [4] Skip [5] Done: " option
        case $option in
            1 ) # Change Password
                sudo passwd "$username"
                ;;
            2 ) # Change User Type (e.g., from standard to admin)
                sudo usermod -aG sudo "$username"
                ;;
            3 ) # Delete User
                sudo deluser "$username"
                ;;
            4 ) # Skip User
                break
                ;;
            5 ) # Done with this user
                break
                ;;
            * ) echo "Invalid option";;
        esac
    done
}

# Function to add a new user
add_new_user() {
    read -p "Enter username for the new user: " new_username
    sudo adduser "$new_username"
    sudo usermod -aG sudo "$new_username" # Add to the sudo group if needed
}

# Check if the script is run as root
if [ "$(id -u)" != "0" ]; then
    echo "This script must be run as root. Please use 'sudo'." >&2
    exit 1
fi

# Main script
echo "***| TIP: Do ctrl+z to exit a script! |*** "

# Update and upgrade
while true; do
    read -p "Update and upgrade? y/n " yn
    case $yn in
        [Yy]* ) apt-get update && apt-get upgrade -y && apt-get dist-upgrade -y
	            sudo apt-get install -f -y
	            sudo apt-get autoremove -y
	            sudo apt-get autoclean -y
	            sudo apt-get check -y
                sudo dnf update -y
                sudo apt install --only-upgrade firefox -y
                break;;
        [Nn]* ) echo "Process aborted"; break;;
        * ) echo "Please answer yes or no.";;
    esac
done
echo "Done updating and upgrading."

# Enable Firewall settings
while true; do
    read -p "Enable Firewall settings? y/n " yn
    case $yn in
        [Yy]* ) systemctl enable ufw
                sudo ufw enable
                sudo ufw logging on high
                sudo ufw default allow outgoing
                sudo ufw default deny incoming
                break;;
        [Nn]* ) echo "Process aborted"; break;;
        * ) echo "Please answer y or n.";;
    esac
done
echo "Firewall settings enabled."

# Enable SSH
while true; do
    read -p "Enable SSH? y/n " yn
    case $yn in
        [Yy]* ) sudo ufw allow 22/tcp
                sudo systemctl enable ssh
                sudo systemctl start ssh
                break;;
        [Nn]* ) echo "Process aborted"; break;;
        * ) echo "Please answer y or n.";;
    esac
done
echo "SSH enabled."

# List all installed files
while true; do
    read -p "List all installed files? y/n " yn
    case $yn in
        [Yy]* ) apt list --installed
                break;;
        [Nn]* ) echo "Process aborted"; break;;
        * ) echo "Please answer y or n.";;
    esac
done
echo "Listed all installed files."

# List all users
while true; do
    read -p "List all users and the count? y/n " yn
    case $yn in
        [Yy]* ) getent passwd
                getent passwd | grep tom
                getent passwd | wc -l
                break;;
        [Nn]* ) echo "Process aborted"; break;;
        * ) echo "Please answer y or n.";;
    esac
done
echo "Listed all users."

# List all user groups
while true; do
    read -p "List all user groups?  y/n " yn
    case $yn in
        [Yy]* ) getent group
                break;;
        [Nn]* ) echo "Process aborted"; break;;
        * ) echo "Please answer y or n.";;
    esac
done
echo "Listed all user groups."

# Delete specific file types
while true; do
    read -p "Delete specific file types? y/n " yn
    case $yn in
        [Yy]* ) find / -type f \( -name '*.mp3' -o -name '*.mov' -o -name '*.mp4' -o -name '*.avi' -o -name '*.mpg' -o -name '*.mpeg' -o -name '*.flac' -o -name '*.m4a' -o -name '*.flv' -o -name '*.ogg' -o -name '*.gif' -o -name '*.png' -o -name '*.jpg' -o -name '*.jpeg' \) -exec rm {} \;
                break;;
        [Nn]* ) echo "Process aborted"; break;;
        * ) echo "Please answer y or n.";;
    esac
done
echo "Deleted specific file types."

# Manual Network Inspection
while true; do
    read -p "Manually inspect network? y/n " yn
    case $yn in
        [Yy]* ) lsof -i -n -P
                netstat -tulpn
                break;;
        [Nn]* ) echo "Process aborted"; break;;
        * ) echo "Please answer y or n.";;
    esac
done
echo "Network inspection done."

# Non-root user with UID
while true; do
    read -p "Configure non-root user with UID? y/n " yn
    case $yn in
        [Yy]* ) sudo /usr/lib/lightdm/lightdm-set-defaults -l false
                gksudo gedit /etc/lightdm/lightdm.conf
                break;;
        [Nn]* ) echo "Process aborted"; break;;
        * ) echo "Please answer y or n.";;
    esac
done
echo "Non-root user with UID configured."

# Remove Samba files
while true; do
    read -p "Remove Samba files? y/n " yn
    case $yn in
        [Yy]* ) sudo apt-get remove .*samba.* .*smb.*
                break;;
        [Nn]* ) echo "Process aborted"; break;;
        * ) echo "Please answer y or n.";;
    esac
done
echo "Samba files removed."

# Disable guest accounts
while true; do
    read -p "Disable guest accounts? y/n " yn
    case $yn in
        [Yy]* ) echo "allow-guest=false" >> /etc/lightdm/lightdm.conf
                break;;
        [Nn]* ) echo "Process aborted"; break;;
        * ) echo "Please answer y or n.";;
    esac
done
echo "Guest accounts disabled."

# Check IP forwarding
while true; do
    read -p "Check IP forwarding? y/n " yn
    case $yn in
        [Yy]* ) cat /proc/sys/net/ipv4/ip_forward
                break;;
        [Nn]* ) echo "Process aborted"; break;;
        * ) echo "Please answer y or n.";;
    esac
done
echo "IP forwarding checked."

# Disable IP forwarding
while true; do
    read -p "Disable IP forwarding? y/n " yn
    case $yn in
        [Yy]* ) echo 1 > /proc/sys/net/ipv4/ip_forward
                break;;
        [Nn]* ) echo "Process aborted"; break;;
        * ) echo "Please answer y or n.";;
    esac
done
echo "IP forwarding disabled."

# No keepalive or unattended sessions
while true; do
    read -p "No keepalive or unattended sessions? y/n " yn
    case $yn in
        [Yy]* ) echo "ClientAliveInterval 300" >> /etc/ssh/sshd_config
                echo "ClientAliveCountMax 0" >> /etc/ssh/sshd_config
                break;;
        [Nn]* ) echo "Process aborted"; break;;
        * ) echo "Please answer y or n.";;
    esac
done
echo "No keepalive or unattended sessions configured."

# Lock root user
while true; do
    read -p "Lock root user? y/n " yn
    case $yn in
        [Yy]* ) passwd -l root
                break;;
        [Nn]* ) echo "Process aborted"; break;;
        * ) echo "Please answer y or n.";;
    esac
done

# Change login settings
while true; do
    read -p "Change login settings? y/n " yn
    case $yn in
        [Yy]* ) sed -i 's/PASS_MAX_DAYS.*$/PASS_MAX_DAYS 90/;s/PASS_MIN_DAYS.*$/PASS_MIN_DAYS 10/;s/PASS_WARN_AGE.*$/PASS_WARN_AGE 7/' /etc/login.defs
                break;;
        [Nn]* ) echo "Process aborted"; break;;
        * ) echo "Please answer y or n.";;
    esac
done
echo "Login settings changed."

# Turn on execshield
while true; do
    read -p "Turn on execshield? y/n " yn
    case $yn in
        [Yy]* ) echo "kernel.exec-shield=1" >> /etc/sysctl.conf
                echo "kernel.randomize_va_space=1" >> /etc/sysctl.conf
                break;;
        [Nn]* ) echo "Process aborted"; break;;
        * ) echo "Please answer y or n.";;
    esac
done
echo "Execshield turned on."

# IP Spoofing protection
while true; do
    read -p "IP Spoofing protection? y/n " yn
    case $yn in
        [Yy]* ) grep -qF 'multi on' /etc/host.conf && sed -i 's/multi/nospoof/' /etc/host.conf || echo 'nospoof on' >> /etc/host.conf
                echo "net.ipv4.conf.all.rp_filter = 1" >> /etc/sysctl.conf
                echo "net.ipv4.conf.default.rp_filter = 1" >> /etc/sysctl.conf
                break;;
        [Nn]* ) echo "Process aborted"; break;;
        * ) echo "Please answer y or n.";;
    esac
done
echo "IP Spoofing protection configured."

# Block SYN attacks
while true; do
    read -p "Block SYN attacks? y/n " yn
    case $yn in
        [Yy]* ) echo "net.ipv4.tcp_syncookies = 1" >> /etc/sysctl.conf
                echo "net.ipv4.tcp_max_syn_backlog = 2048" >> /etc/sysctl.conf
                echo "net.ipv4.tcp_synack_retries = 2" >> /etc/sysctl.conf
                echo "net.ipv4.tcp_syn_retries = 5" >> /etc/sysctl.conf
                break;;
        [Nn]* ) echo "Process aborted"; break;;
        * ) echo "Please answer y or n.";;
    esac
done
echo "SYN attack prevention configured."

# Find rootkits, backdoors, etc.
while true; do
    read -p "Find rootkits, backdoors, etc.? y/n " yn
    case $yn in
        [Yy]* ) sudo apt-get install chkrootkit rkhunter
                sudo chkrootkit
                sudo rkhunter --update
                sudo rkhunter --check
                break;;
        [Nn]* ) echo "Process aborted"; break;;
        * ) echo "Please answer y or n.";;
    esac
done

# Done with the script
echo "Script execution completed."
