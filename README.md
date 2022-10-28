#!/bin/bash
#update and upgrade
while true; do
    read -p "update and upgrade? y/n " yn
    case $yn in
        [Yy]* ) sudo apt update -y
                sudo apt-get upgrade -y
	            sudo apt-get install -f -y
	            sudo apt-get autoremove -y
	            sudo apt-get autoclean -y
	            sudo apt-get check -y; break;;
        [Nn]* ) echo "Process aborted "; break;;
        * ) echo "Please answer yes or no.";;
    esac
done
echo "Done "
         echo "***| TIP: Do ctrl+z to exit a script! |*** "
         sleep 2      
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
        sleep 2
#turns on ssh
while true; do
    read -p "enable SSH? y/n " yn
    case $yn in
        [Yy]* ) ufw allow 22/tcp; break;;
        [Nn]* ) echo "Process aborted"; break;;
        * ) echo "Please answer y or n.";;
    esac
done
echo "Done "
        echo "***| TIP: Check the read me to see what apps do not belong! |*** "
        sleep 2
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
        sleep 2
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
        sleep 2
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
        sleep 2
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
        sleep 2
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
        sleep 2
#update firefox
while true; do
    read -p "Update firefox? y/n " yn
    case $yn in
        [Yy]* ) sudo apt install –only-upgrade firefox; break;;
        [Nn]* ) echo "Process aborted"; break;;
        * ) echo "Please answer y or n.";;
    esac
done
echo "Done "
        echo "***| TIP: |*** "
        sleep 2
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
        sleep 2
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
        sleep 2
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
        sleep 2
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
        sleep 2
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
        sleep 2
