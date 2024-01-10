#!/bin/bash

echo " MEOW "
# Main script

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
    read -p "Delete non-work-related media files? y/n " yn
    case $yn in
        [Yy]* ) find /home -type f \( -name '*.mp3' -o -name '*.mov' -o -name '*.mp4' -o -name '*.avi' -o -name '*.mpg' -o -name '*.mpeg' -o -name '*.flac' -o -name '*.m4a' -o -name '*.flv' -o -name '*.ogg' -o -name '*.gif' -o -name '*.png' -o -name '*.jpg' -o -name '*.jpeg' \) -exec rm {} \;
                break;;
        [Nn]* ) echo "Process aborted"; break;;
        * ) echo "Please answer y or n.";;
    esac
done
echo "Deleted non-work-related media files."

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

elif [ $sambaYN == yes ]
then
  ufw allow netbios-ns
  ufw allow netbios-dgm
  ufw allow netbios-ssn
  ufw allow microsoft-ds
  apt-get -y -qq install samba
  apt-get -y -qq install system-config-samba
  cp /etc/samba/smb.conf $USER_HOME/Desktop/backups/
  if [ "$(grep '####### Authentication #######' /etc/samba/smb.conf)"==0 ]
  then
    sed -i 's/####### Authentication #######/####### Authentication #######\nsecurity = user/g' /etc/samba/smb.conf
  fi
  sed -i 's/usershare allow guests = no/usershare allow guests = yes/g' /etc/samba/smb.conf

  echo Type all user account names, with a space in between
  read -a usersSMB
  usersSMBLength=${#usersSMB[@]}  
  for (( i=0;i<$usersSMBLength;i++))
  do
    echo -e 'H=Fmcqz3M]}&rfC%F>b)\nH=Fmcqz3M]}&rfC%F>b)' | smbpasswd -a ${usersSMB[${i}]}
    echo "${usersSMB[${i}]} has been given the password 'H=Fmcqz3M]}&rfC%F>b)' for Samba."
  done
  echo "netbios-ns, netbios-dgm, netbios-ssn, and microsoft-ds ports have been allowed. Samba config file has been configured."

  clear
else
  echo Response not recognized.
fi
echo "Samba is complete."

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

# SSH Configuration
ssh_config_file="/etc/ssh/sshd_config"
if [ -f "$ssh_config_file" ]; then
    sudo sed -i 's/PermitRootLogin.*/PermitRootLogin no/' "$ssh_config_file"
    sudo sed -i 's/AllowTcpForwarding.*/AllowTcpForwarding no/' "$ssh_config_file"
fi

# LightDM Configuration
lightdm_config_file="/etc/lightdm/lightdm.conf"
if [ -f "$lightdm_config_file" ]; then
    sudo sed -i 's/^allow-guest=.*/allow-guest=false/' "$lightdm_config_file"
else
    echo "allow-guest=false" | sudo tee -a "$lightdm_config_file"
fi

# Navigate to /home and list all files for inspection
sudo find /home -type f -exec file {} + | grep -E 'media|tools|hacking'
# Check for malware (you may use a specific malware scanner)

# Password Policy
login_defs_file="/etc/login.defs"
sudo sed -i 's/^PASS_MIN_DAYS.*/PASS_MIN_DAYS 7/' "$login_defs_file"
sudo sed -i 's/^PASS_MAX_DAYS.*/PASS_MAX_DAYS 90/' "$login_defs_file"
sudo sed -i 's/^PASS_WARN_AGE.*/PASS_WARN_AGE 14/' "$login_defs_file"

# Implement password complexity requirements
common_password_file="/etc/pam.d/common-password"
sudo sed -i '/pam_unix.so/s/$/ minlen=8 remember=5/' "$common_password_file"
sudo apt-get install libpam-cracklib
sudo sed -i '/pam.cracklib.so/s/$/ ucredit=-1 lcredit=-1 dcredit=-1 ocredit=-1/' "$common_password_file"

# Account Lockout Policy
common_auth_file="/etc/pam.d/common-auth"
echo "auth required pam_tally2.so deny=5 unlock_time=1800" | sudo tee -a "$common_auth_file"

# Automatic Updates
sudo apt-get install unattended-upgrades
sudo dpkg-reconfigure -plow unattended-upgrades

# SYN Cookie Protection
sudo sysctl -w net.ipv4.tcp_syncookies=1

# System Updates
sudo apt-get update
sudo apt-get upgrade

# IPv6 and IP Forwarding
echo "net.ipv6.conf.all.disable_ipv6 = 1" | sudo tee -a /etc/sysctl.conf
echo "0" | sudo tee /proc/sys/net/ipv4/ip_forward

# Prevent IP Spoofing
while true; do
    read -p "Prevent IP Spoofing? y/n " yn
    case $yn in
        [Yy]* )
            # Prevent IP Spoofing
            echo "nospoof on" | sudo tee -a /etc/host.conf
            break;;
        [Nn]* )
            echo "Skipped."
            break;;
        * )
            echo "Please answer y or n.";;
    esac
done

# Root Account and File Permissions
sudo passwd -l root

# Set appropriate permissions for user directories (replace 'username' with actual usernames)
sudo chmod 0750 /home/username

# List of hacking tools to remove
hacking_tools=("nmap" "wireshark" "john" "hydra" "netcat" "metasploit" "sqlmap" "lynis" "fluxion" "nikto" "skipfish" "zenmap" "apache2" "nginx" "lighttpd" "tcpdump" "netcat-traditional" "ophcrack")

echo "Removing known hacking tools..."

# Loop through the list and remove each tool
for tool in "${hacking_tools[@]}"; do
    echo "Removing $tool..."
    sudo apt-get purge -y $tool
done

# Find rootkits, backdoors, etc.
while true; do
    read -p "Run rootkit and exploit scanner? y/n " yn
    case $yn in
        [Yy]* )
            # Install and run rootkit scanners
            sudo apt-get install -y chkrootkit rkhunter
            sudo chkrootkit
            sudo rkhunter --update
            sudo rkhunter --check
            echo "Rootkit and exploit scan completed."
            break;;
        [Nn]* )
            echo "Skipped rootkit and exploit scan."
            break;;
        * )
            echo "Please answer y or n.";;
    esac
done

while true; do
    read -p "ssh config? y/n " yn
    case $yn in
        [Yy]* )
            # ssh config
            if grep -qF 'PermitRootLogin' /etc/ssh/sshd_config; then sed -i 's/^.*PermitRootLogin.*$/PermitRootLogin no/'                             /etc/ssh/sshd_config; else echo 'PermitRootLogin no' >> /etc/ssh/sshd_config; fi
            PermitRootLogin no
            ChallengeResponseAuthentication no
            PasswordAuthentication no
            UsePAM no
            PermitEmptyPasswords no
            sudo sshd -t
            break;;
        [Nn]* )
            echo "Skipped."
            break;;
        * )
            echo "Please answer y or n.";;
    esac
done

# Install and configure auditd
while true; do
    read -p "Install and configure auditd? y/n " yn
    case $yn in
        [Yy]* )
            # Install and configure auditd
            confirm_action "Install and configure auditd"
            sudo apt-get install auditd
            sudo auditctl -e 1
            break;;
        [Nn]* )
            echo "Skipped."
            break;;
        * )
            echo "Please answer y or n.";;
    esac
done

# Display additional information
while true; do
    read -p "Display additional user information? y/n " yn
    case $yn in
        [Yy]* )
            # Display additional information
            mawk -F: '$1 == "sudo"' /etc/group
            mawk -F: '$3 > 999 && $3 < 65534 {print $1}' /etc/passwd
            mawk -F: '$2 == ""' /etc/passwd
            mawk -F: '$3 == 0 && $1 != "root"' /etc/passwd
            break;;
        [Nn]* )
            echo "Skipped."
            break;;
        * )
            echo "Please answer y or n.";;
    esac
done

# Find specific file types in /home (hacking files) 
while true; do
    read -p "Find specific file types in /home? (hacking files) y/n " yn
    case $yn in
        [Yy]* )
            # Find specific file types in /home
            find /home/ -type f \( -name "*.tar.gz" -o -name "*.tgz" -o -name "*.zip" -o -name "*.deb" \)
            break;;
        [Nn]* )
            echo "Skipped."
            break;;
        * )
            echo "Please answer y or n.";;
    esac
done

# Set appropriate permissions for home directories
while true; do
    read -p "home directory permisions? y/n " yn
    case $yn in
        [Yy]* )
            # Set appropriate permissions for home directories
            for i in $(mawk -F: '$3 > 999 && $3 < 65534 {print $1}' /etc/passwd); do [ -d /home/${i} ] && chmod -R 750 /home/${i}; done
            break;;
        [Nn]* )
            echo "Skipped."
            break;;
        * )
            echo "Please answer y or n.";;
    esac
done

# Disable USB storage
while true; do
    read -p "Disable USB storage? y/n " yn
    case $yn in
        [Yy]* )
            # Disable USB storage
            echo 'install usb-storage /bin/true' >> /etc/modprobe.d/disable-usb-storage.conf
            break;;
        [Nn]* )
            echo "Skipped."
            break;;
        * )
            echo "Please answer y or n.";;
    esac
done

# Disable Firewire and Thunderbolt
while true; do
    read -p "Disable Firewire and Thunderbolt? y/n " yn
    case $yn in
        [Yy]* )
            # Disable Firewire and Thunderbolt
            echo "blacklist firewire-core" >> /etc/modprobe.d/firewire.conf
            echo "blacklist thunderbolt" >> /etc/modprobe.d/thunderbolt.conf
            break;;
        [Nn]* )
            echo "Skipped."
            break;;
        * )
            echo "Please answer y or n.";;
    esac
done

# Disable Avahi daemon
while true; do
    read -p "Disable Avahi daemon? y/n " yn
    case $yn in
        [Yy]* )
            # Disable Avahi daemon
            systemctl disable avahi-daemon
            break;;
        [Nn]* )
            echo "Skipped."
            break;;
        * )
            echo "Please answer y or n.";;
    esac
done

# 
while true; do
    read -p "y/n " yn
    case $yn in
        [Yy]* )
            # 
            break;;
        [Nn]* )
            echo "Skipped."
            break;;
        * )
            echo "Please answer y or n.";;
    esac
done

# Display cleanup completion message
echo "Cleanup completed."

# Display completion message
echo "Security configuration completed."

# Display script completion message
echo "Script execution completed."
