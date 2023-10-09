#!/bin/bash
if [ "$(id -u)" != "0" ]; then
    echo "This script must be run as root. Please use 'sudo'." >&2
    exit 1
fi
# Define a function to create backups of configuration files
backup_config_file() {
    local config_file="$1"
    local backup_dir="/path/to/backup/directory"  # Change this to the desired backup directory

    # Check if the file exists
    if [ -e "$config_file" ]; then
        # Create a backup with a timestamp
        local backup_file="${backup_dir}/$(basename $config_file).$(date +%Y%m%d%H%M%S)"
       
        # Copy the original file to the backup location
        cp "$config_file" "$backup_file"

        # Output a message
        echo "Backup created: $backup_file"
    else
        echo "File not found: $config_file"
    fi
}

# Usage: backup_config_file "/etc/lightdm/lightdm.conf"

# Your existing script here...

# Example usage of the backup_config_file function
# Uncomment and customize this line to create a backup before making changes
# backup_config_file "/etc/lightdm/lightdm.conf"

# Main script
manage_users

echo "Done managing users."
#update and upgrade
while true; do
    read -p "update and upgrade? y/n " yn
    case $yn in
        [Yy]* ) apt-get update && apt-get upgrade && apt-get dist-upgrade -y
	            sudo apt-get install -f -y
	            sudo apt-get autoremove -y
	            sudo apt-get autoclean -y
	            sudo apt-get check -y
                sudo dnf update -y
                sudo apt install –only-upgrade firefox -y; break;;
        [Nn]* ) echo "Process aborte"; break;;
        * ) echo "Please answer yes or no.";;
    esac
done
echo "Done "
         echo "***| TIP: Do ctrl+z to exit a script! |*** "     
#turns on fire wall
while true; do
    read -p "Enable Firewall settings? " yn
    case $yn in
        [Yy]* ) systemctl enable ufw
                sudo ufw enable
                sudo ufw logging on high
                sudo ufw default allow outgoing
                sudo ufw default deny incoming; break;;
        [Nn]* ) echo "Process aborted "; break;;
        * ) echo "Please answer y or n.";;
    esac
done
echo "Done "
        echo "***| TIP: Doing cd ~ gets you back to the main user! |*** "
#turns on ssh
while true; do
    read -p "enable SSH? y/n " yn
    case $yn in
        [Yy]* ) sudo ufw allow 22/tcp
                sudo systemctl start sshd.service
                sudo systemctl start sshd.service
                sudo ssh.service
                cd /etc/init.d/ssh start -y
                cd /etc/init.d/sshd; break;;
        [Nn]* ) echo "Process aborted"; break;;
        * ) echo "Please answer y or n.";;
    esac
done
echo "Done "
        echo "***| TIP: Check the read me to see what apps do not belong! |*** "
#list all installed files
while true; do
    read -p "list all installed files? y/n " yn
    case $yn in
        [Yy]* ) apt list -i; break;;
        [Nn]* ) echo "Process aborted"; break;;
        * ) echo "Please answer y or n.";;
    esac
done
echo "Done "
        echo "***| TIP: Remember to disable pop up adds on firefox! |*** "
#list all users
while true; do
    read -p "list all users and the wc? y/n " yn
    case $yn in
        [Yy]* ) getent passwd
                getent passwd | grep tom
                ## count all user accounts using the wc ##
                getent passwd | wc -l; break;;
        [Nn]* ) echo "Process aborted"; break;;
        * ) echo "Please answer y or n.";;
    esac
done
echo "Done "
        echo "***| TIP: Remove prohibited software using sudo apt remove (name)! |*** "
#list all user groups
while true; do
    read -p "list all user groups?  y/n " yn
    case $yn in
        [Yy]* ) getent group; break;;
        [Nn]* ) echo "Process aborted"; break;;
        * ) echo "Please answer y or n.";;
    esac
done
echo "Done "
        echo "***| TIP: To add user to group- adduser [username] [groupname] |*** "
#delete files
while true; do
    read -p "Delete files? y/n " yn
    case $yn in
        [Yy]* ) find / -name '*.mp3' -type f -delete
                find / -name '*.mov' -type f -delete
                find / -name '*.mp4' -type f -delete
                find / -name '*.avi' -type f -delete
                find / -name '*.mpg' -type f -delete
                find / -name '*.mpeg' -type f -delete
                find / -name '*.flac' -type f -delete
                find / -name '*.m4a' -type f -delete
                find / -name '*.flv' -type f -delete
                find / -name '*.ogg' -type f -delete
                find /home -name '*.gif' -type f -delete
                find /home -name '*.png' -type f -delete
                find /home -name '*.jpg' -type f -delete
                find /home -name '*.jpeg' -type f -delete; break;;
        [Nn]* ) echo "Process aborted"; break;;
        * ) echo "Please answer y or n.";;
    esac
done
echo "Done "
        echo "***| TIP: |*** "
#Manual Network Inspection
while true; do
    read -p "Manualey inspect network? y/n " yn
    case $yn in
        [Yy]* ) lsof -i -n -P
	            netstat -tulpn; break;;
        [Nn]* ) echo "Process aborted"; break;;
        * ) echo "Please answer y or n.";;
    esac
done
echo "Done "
        echo "***| TIP: |*** "
#non root user with UID
while true; do
    read -p "non-root user with UID? y/n " yn
    case $yn in
        [Yy]* ) sudo /usr/lib/lightdm/lightdm-set-defaults -l false
                gksudo gedit /etc/lightdm/lightdm.conf; break;;
        [Nn]* ) echo "Process aborted"; break;;
        * ) echo "Please answer y or n.";;
    esac
done
echo "Done "
        echo "***| TIP: |*** "
#remove samba files
while true; do
    read -p "non-root user with UID? y/n " yn
    case $yn in
        [Yy]* ) sudo apt-get remove .*samba.* .*smb.*; break;;
        [Nn]* ) echo "Process aborted"; break;;
        * ) echo "Please answer y or n.";;
    esac
done
echo "Done "
        echo "***| TIP: |*** "
#disable user accounts 
while true; do
    read -p "disable guest accounts? y/n " yn
    case $yn in
        [Yy]* ) echo "allow-guest=false" >> /etc/lightdm/lightdm.conf; break;;
        [Nn]* ) echo "Process aborted"; break;;
        * ) echo "Please answer y or n.";;
    esac
done
echo "Done "
        echo "***| TIP: |*** "
#check ip forwarding
while true; do
    read -p "check ip forwarding? y/n " yn
    case $yn in
        [Yy]* ) cat /proc/sys/net/ipv4/ip_forward; break;;
        [Nn]* ) echo "Process aborted"; break;;
        * ) echo "Please answer y or n.";;
    esac
done
echo "Done "
        echo "***| TIP: |*** "
#disable ip forwarding
while true; do
    read -p "disable ip forwarding? y/n " yn
    case $yn in
        [Yy]* ) echo 1 > /proc/sys/net/ipv4/ip_forward; break;;
        [Nn]* ) echo "Process aborted"; break;;
        * ) echo "Please answer y or n.";;
    esac
done
echo "Done "
        echo "***| TIP: |*** "
#No keepalive or unattended sessions
while true; do
    read -p "No keepalive or unattended sessions? y/n " yn
    case $yn in
        [Yy]* ) ClientAliveInterval 300
                ClientAliveCountMax 0; break;;
        [Nn]* ) echo "Process aborted"; break;;
        * ) echo "Please answer y or n.";;
    esac
done
echo "Done "
        echo "***| TIP: |*** "
        passwd -l root
#Lock root user
while true; do
    read -p "Lock root user? y/n " yn
    case $yn in
        [Yy]* ) passwd -l root; break;;
        [Nn]* ) echo "Process aborted"; break;;
        * ) echo "Please answer y or n.";;
    esac
done
#change login settings
while true; do
    read -p "Change login settings? y/n " yn
    case $yn in
        [Yy]* ) sed -i 's/PASS_MAX_DAYS.*$/PASS_MAX_DAYS 90/;s/PASS_MIN_DAYS.*$/PASS_MIN_DAYS 10/;s/PASS_WARN_AGE.*$/PASS_WARN_AGE 7/' /etc/login.defs;;
        [Nn]* ) echo "Process aborted"; break;;
        * ) echo "Please answer y or n.";;
    esac
done
#Turn on execshield
while true; do
    read -p "Turn on execshield? y/n " yn
    case $yn in
        [Yy]* ) kernel.exec-shield=1
                kernel.randomize_va_space=1; break;;
        [Nn]* ) echo "Process aborted"; break;;
        * ) echo "Please answer y or n.";;
    esac
done
#IP Spoofing protection
while true; do
    read -p "? y/n " yn
    case $yn in
        [Yy]* ) grep -qF 'multi on' && sed 's/multi/nospoof/' || echo 'nospoof on' >> /etc/host.conf
                net.ipv4.conf.all.rp_filter = 1
                net.ipv4.conf.default.rp_filter = 1; break;;
        [Nn]* ) echo "Process aborted"; break;;
        * ) echo "Please answer y or n.";;
    esac
done
#Block SYN attacks
while true; do
    read -p "? y/n " yn
    case $yn in
        [Yy]* ) net.ipv4.tcp_syncookies = 1
                net.ipv4.tcp_max_syn_backlog = 2048
                net.ipv4.tcp_synack_retries = 2
                net.ipv4.tcp_syn_retries = 5; break;;
        [Nn]* ) echo "Process aborted"; break;;
        * ) echo "Please answer y or n.";;
    esac
done
#Find rootkits, backdoors, etc.
while true; do
    read -p "Find rootkits, backdoors, etc.? y/n " yn
    case $yn in
        [Yy]* ) sudo apt-get install chkrootkit rkhunter
                sudo chkrootkit
                sudo rkhunter --update
                sudo rkhunter --check; break;;
        [Nn]* ) echo "Process aborted"; break;;
        * ) echo "Please answer y or n.";;
    esac
done
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

# Main script
manage_users

echo "Done managing users."
