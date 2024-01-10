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
                #reset whatever current firewall they might have
                sudo ufw reset
                #enable the firewall
                sudo ufw enable
                #turn on logging for the firewall
                sudo ufw logging on high
                #directions and such
                sudo ufw default allow outgoing
                sudo ufw default deny incoming
                #deny multiple things
                sudo ufw deny 21
                sudo ufw deny 23
                sudo ufw deny cups
                #uninstall these services
                sudo apt-get purge -y cups
                sudo apt-get purge -y bluetooth
                #cherry on top
                sudo apt-get autoremove -y
                #Config default deny
                sudo iptables -P INPUT DROP
                sudo iptables -P OUTPUT DROP
                sudo iptables -P FORWARD DROP
                #loopback traffic
                sudo iptables -A INPUT -i lo -j ACCEPT
                sudo iptables -A OUTPUT -o lo -j ACCEPT
                sudo iptables -A INPUT -s 127.0.0.0/8 -j DROP
                #outbound and established connections
                sudo iptables -A OUTPUT -p tcp -m state --state NEW,ESTABLISHED -j ACCEPT
                sudo iptables -A OUTPUT -p udp -m state --state NEW,ESTABLISHED -j ACCEPT
                sudo iptables -A OUTPUT -p icmp -m state --state NEW,ESTABLISHED -j ACCEPT
                sudo iptables -A INPUT -p tcp -m state --state ESTABLISHED -j ACCEPT
                sudo iptables -A INPUT -p udp -m state --state ESTABLISHED -j ACCEPT
                sudo iptables -A INPUT -p icmp -m state --state ESTABLISHED -j ACCEPT
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
            sudo fuser -k //var/lib/dpkg/lock-frontend
            sudo apt-get update -y
            #games
            sudo apt-get purge -y 0ad 0ad-data 0ad-data-common 2048-qt 3dchess 4digits 7kaa 7kaa-data a7xpg a7xpg-data aajm abe abe-data ace-of-penguins acm adanaxisgpl adanaxisgpl-data adonthell adonthell-data airstrike airstrike-common aisleriot alex4 alex4-data alien-arena alien-arena-data alien-arena-server alienblaster alienblaster-data allure amoebax amoebax-data amphetamine amphetamine-data an anagramarama anagramarama-data angband angband-audio angband-data angrydd animals antigravitaattori ardentryst armagetronad armagetronad-common armagetronad-dedicated asc asc-data asc-music asciijump assaultcube assaultcube-data astromenace astromenace-data-src asylum asylum-data atanks atanks-data atom4 atomix atomix-data attal attal-themes-medieval auralquiz balder2d balder2d-data ballerburg ballz ballz-data ballz-dbg bambam barrage bastet bb bear-factory beneath-a-steel-sky berusky berusky-data berusky2 berusky2-data between billard-gl billard-gl-data biloba biloba-data biniax2 biniax2-data black-box blobandconquer blobandconquer-data blobby blobby-data blobby-server bloboats blobwars blobwars-data blockattack blockout2 blocks-of-the-undead blocks-of-the-undead-data bombardier bomber bomberclone bomberclone-data boswars boswars-data bouncy bovo brainparty brainparty-data briquolo briquolo-data brutalchess bsdgames bsdgames-nonfree btanks btanks-data bubbros bucklespring bucklespring-data bugsquish bumprace bumprace-data burgerspace bve-route-cross-city-south bve-train-br-class-323 bve-train-br-class-323-3dcab bygfoot bygfoot-data bzflag bzflag-client bzflag-data bzflag-server cappuccino caveexpress caveexpress-data cavepacker cavepacker-data cavezofphear ceferino ceferino-data cgoban chessx childsplay childsplay-alphabet-sounds-bg childsplay-alphabet-sounds-ca childsplay-alphabet-sounds-de childsplay-alphabet-sounds-el childsplay-alphabet-sounds-en-gb childsplay-alphabet-sounds-es childsplay-alphabet-sounds-fr childsplay-alphabet-sounds-it childsplay-alphabet-sounds-nb childsplay-alphabet-sounds-nl childsplay-alphabet-sounds-pt childsplay-alphabet-sounds-ro childsplay-alphabet-sounds-ru childsplay-alphabet-sounds-sl childsplay-alphabet-sounds-sv chipw chocolate-common chocolate-doom chromium-bsu chromium-bsu-data circuslinux circuslinux-data colobot colobot-common colobot-common-sounds colobot-common-textures colorcode colossal-cave-adventure connectagram connectagram-data cookietool corsix-th corsix-th-data cowsay cowsay-off crack-attack crafty crafty-bitmaps crafty-books-medium crafty-books-medtosmall crafty-books-small crawl crawl-common crawl-tiles crawl-tiles-data crimson criticalmass criticalmass-data crossfire-client crossfire-client-images crossfire-client-sounds crossfire-common crossfire-maps crossfire-maps crossfire-maps-small crossfire-server crrcsim crrcsim-data csmash csmash-data csmash-demosong cube2 cube2-data cube2-server cultivation curseofwar cutemaze cuyo cuyo-data cyphesis-cpp cyphesis-cpp-clients cyphesis-cpp-mason cytadela cytadela-data d1x-rebirth d2x-rebirth dangen darkplaces darkplaces-server ddnet ddnet-data ddnet-server ddnet-tools dds deal dealer defendguin defendguin-data desmume deutex dhewm3 dhewm3-d3xp dhewm3-doom3 dizzy dodgindiamond2 dolphin-emu dolphin-emu-data doom-wad-shareware doomsday doomsday-common doomsday-data doomsday-server dopewars dopewars-data dossizola dossizola-data drascula drascula-french drascula-german drascula-italian drascula-music drascula-spanish dreamchess dreamchess-data dustracing2d dustracing2d-data dvorak7min dwarf-fortress dwarf-fortress-data eboard eboard-extras-pack1 edgar edgar-data efp einstein el-ixir ember ember-media empire empire-hub empire-lafe endless-sky endless-sky-data endless-sky-high-dpi enemylines3 enemylines7 enigma enigma-data epiphany epiphany-data etoys etqw etqw-server etw etw-data excellent-bifurcation extremetuxracer extremetuxracer-data exult exult-studio ezquake fairymax fb-music-high ffrenzy fgo fgrun fheroes2-pkg filler fillets-ng fillets-ng-data fillets-ng-data-cs fillets-ng-data-nl filters five-or-more fizmo-common fizmo-console fizmo-ncursesw fizmo-sdl2 flare flare-data flare-engine flare-game flight-of-the-amazon-queen flightgear flightgear-data-ai flightgear-data-all flightgear-data-base flightgear-data-models flightgear-phi flobopuyo fltk1.1-games fltk1.3-games foobillardplus foobillardplus-data fortunate.app fortune-anarchism fortune-mod fortune-zh fortunes fortunes-bg fortunes-bofh-excuses fortunes-br fortunes-cs fortunes-de fortunes-debian-hints fortunes-eo fortunes-eo-ascii fortunes-eo-iso3 fortunes-es fortunes-es-off fortunes-fr fortunes-ga fortunes-it fortunes-it-off fortunes-mario fortunes-min fortunes-off fortunes-pl fortunes-ru fortunes-spam fortunes-zh four-in-a-row freealchemist freecell-solver-bin freeciv freeciv-client-extras freeciv-client-gtk freeciv-client-gtk3 freeciv-client-qt freeciv-client-sdl freeciv-data freeciv-server freeciv-sound-standard freecol freedink freedink-data freedink-dfarc freedink-dfarc-dbg freedink-engine freedink-engine-dbg freedm freedoom freedroid freedroid-data freedroidrpg freedroidrpg-data freegish freegish-data freeorion freeorion-data freespace2 freespace2-launcher-wxlauncher freesweep freetennis freetennis-common freevial fretsonfire fretsonfire-game fretsonfire-songs-muldjord fretsonfire-songs-sectoid frogatto frogatto-data frotz frozen-bubble frozen-bubble-data fruit funguloids funguloids-data funnyboat gamazons game-data-packager game-data-packager-runtime gameclock gamine gamine-data garden-of-coloured-lights garden-of-coloured-lights-data gargoyle-free gav gav-themes gbrainy gcompris gearhead gearhead-data gearhead-sdl gearhead2 gearhead2-data gearhead2-sdl geekcode geki2 geki3 gemdropx gemrb gemrb-baldurs-gate gemrb-baldurs-gate-2 gemrb-baldurs-gate-2-data gemrb-baldurs-gate-data gemrb-data gemrb-icewind-dale gemrb-icewind-dale-2 gemrb-icewind-dale-2-data gemrb-icewind-dale-data gemrb-planescape-torment gemrb-planescape-torment-data geneatd gfceu gfpoken gl-117 gl-117-data glaurung glhack glob2 glob2-data glpeces glpeces-data gltron gmchess gmult gnome-2048 gnome-breakout gnome-cards-data gnome-chess gnome-games-app gnome-klotski gnome-mahjongg gnome-mastermind gnome-mines gnome-nibbles gnome-robots gnome-sudoku gnome-tetravex gnubg gnubg-data gnubik gnuboy-sdl gnuboy-x gnuchess gnuchess-book gnudoq gnugo gnujump gnujump-data gnuminishogi gnurobbo gnurobbo-data gnushogi golly gomoku.app gplanarity gpsshogi gpsshogi-data granatier granule gravitation gravitywars greed grhino grhino-data gridlock.app groundhog gsalliere gtans gtkballs gtkboard gtkpool gunroar gunroar-data gweled hachu hannah hannah-data hearse hedgewars hedgewars-data heroes heroes-data heroes-sound-effects heroes-sound-tracks hex-a-hop hex-a-hop-data hexalate hexxagon higan hitori hoichess holdingnuts holdingnuts-server holotz-castle holotz-castle-data holotz-castle-editor hyperrogue hyperrogue-music iagno icebreaker ii-esu infon-server infon-viewer instead instead-data ioquake3 ioquake3-server jag jag-data jester jigzo jigzo-data jmdlx jumpnbump jumpnbump-levels jzip kajongg kanagram kanatest kapman katomic kawari8 kball kball-data kblackbox kblocks kbounce kbreakout kcheckers kdegames-card-data kdegames-card-data-kf5 kdegames-mahjongg-data-kf5 kdiamond ketm ketm-data kfourinline kgoldrunner khangman kigo kiki-the-nano-bot kiki-the-nano-bot-data kildclient killbots kiriki kjumpingcube klickety klines kmahjongg kmines knavalbattle knetwalk knights kobodeluxe kobodeluxe-data kolf kollision komi konquest koules kpat krank kraptor kraptor-data kreversi kshisen ksirk ksnakeduel kspaceduel ksquares ksudoku ktuberling kubrick laby lambdahack late late-data lbreakout2 lbreakout2-data lgc-pg lgeneral lgeneral-data libatlas-cpp-0.6-tools libgemrb libmgba libretro-beetle-pce-fast libretro-beetle-psx libretro-beetle-vb libretro-beetle-wswan libretro-bsnes-mercury-accuracy libretro-bsnes-mercury-balanced libretro-bsnes-mercury-performance libretro-desmume libretro-gambatte libretro-genesisplusgx libretro-mgba libretro-mupen64plus libretro-nestopia libretro-snes9x lierolibre lierolibre-data lightsoff lightyears lincity lincity-ng lincity-ng-data liquidwar liquidwar-data liquidwar-server littlewizard littlewizard-data lmarbles lmemory lolcat londonlaw lordsawar lordsawar-data love lskat ltris lugaru lugaru-data luola luola-data luola-levels luola-nostalgy lure-of-the-temptress macopix-gtk2 madbomber madbomber-data maelstrom magicmaze magicor magicor-data magictouch mah-jong mame mame-data mame-extra manaplus manaplus-data mancala marsshooter marsshooter-data matanza mazeofgalious mazeofgalious-data mednafen mednaffe megaglest megaglest-data meritous meritous-data mgba-common mgba-qt mgba-sdl mgt miceamaze micropolis micropolis-data minetest minetest-data minetest-mod-advspawning minetest-mod-animalmaterials minetest-mod-animals minetest-mod-character-creator minetest-mod-craftguide minetest-mod-homedecor minetest-mod-maidroid minetest-mod-mesecons minetest-mod-mobf minetest-mod-mobf-core minetest-mod-mobf-trap minetest-mod-moreblocks minetest-mod-moreores minetest-mod-nether minetest-mod-pipeworks minetest-mod-player-3d-armor minetest-mod-quartz minetest-mod-torches minetest-mod-unifieddyes minetest-mod-worldedit minetest-server mirrormagic mirrormagic-data mokomaze monopd monsterz monsterz-data moon-buggy moon-lander moon-lander-data moria morris mousetrap mrboom mrrescue mttroff mu-cade mu-cade-data mudlet multitet mupen64plus-audio-all mupen64plus-audio-sdl mupen64plus-data mupen64plus-input-all mupen64plus-input-sdl mupen64plus-qt mupen64plus-rsp-all mupen64plus-rsp-hle mupen64plus-rsp-z64 mupen64plus-ui-console mupen64plus-video-all mupen64plus-video-arachnoid mupen64plus-video-glide64 mupen64plus-video-glide64mk2 mupen64plus-video-rice mupen64plus-video-z64 nestopia nethack-common nethack-console nethack-el nethack-lisp nethack-x11 netmaze netpanzer netpanzer-data netris nettoe neverball neverball-common neverball-data neverputt neverputt-data nexuiz nexuiz-data nexuiz-music nexuiz-server nexuiz-textures nikwi nikwi-data ninix-aya ninvaders njam njam-data noiz2sa noiz2sa-data nsnake nudoku numptyphysics ogamesim ogamesim-www omega-rpg oneisenough oneko onscripter open-adventure open-invaders open-invaders-data openarena openarena-081-maps openarena-081-misc openarena-081-players openarena-081-players-mature openarena-081-textures openarena-085-data openarena-088-data openarena-data openarena-oacmp1 openarena-server openbve-data opencity opencity-data openclonk openclonk-data openlugaru openlugaru-data openmw openmw-cs openmw-data openmw-launcher openpref openssn openssn-data openttd openttd-data openttd-opengfx openttd-openmsx openttd-opensfx opentyrian openyahtzee orbital-eunuchs-sniper orbital-eunuchs-sniper-data osmose-emulator out-of-order overgod overgod-data pachi pachi-data pacman pacman4console palapeli palapeli-data pangzero parsec47 parsec47-data passage pathogen pathological pax-britannica pax-britannica-data pcsx2 pcsxr peg-e peg-solitaire pegsolitaire penguin-command pente pentobi performous performous-tools pescetti petris pgn-extract phalanx phlipple phlipple-data pianobooster picmi pinball pinball-data pinball-dev pingus pingus-data pink-pony pink-pony-data pioneers pioneers-console pioneers-console-data pioneers-data pioneers-metaserver pipenightdreams pipenightdreams-data pipewalker piu-piu pixbros pixfrogger planarity planetblupi planetblupi-common planetblupi-music-midi planetblupi-music-ogg plee-the-bear plee-the-bear-data pokemmo-installer pokerth pokerth-data pokerth-server polygen polygen-data polyglot pong2 powder powermanga powermanga-data pq prboom-plus prboom-plus-game-server primrose projectl purity purity-ng purity-off pybik pybik-bin pybridge pybridge-common pybridge-server pykaraoke pykaraoke-bin pynagram pyracerz pyscrabble pyscrabble-common pyscrabble-server pysiogame pysolfc pysolfc-cardsets pysycache pysycache-buttons-beerabbit pysycache-buttons-crapaud pysycache-buttons-ice pysycache-buttons-wolf pysycache-click-dinosaurs pysycache-click-sea pysycache-dblclick-appleandpear pysycache-dblclick-butterfly pysycache-i18n pysycache-images pysycache-move-animals pysycache-move-food pysycache-move-plants pysycache-move-sky pysycache-move-sports pysycache-puzzle-cartoons pysycache-puzzle-photos pysycache-sounds python-pykaraoke python-renpy qgo qonk qstat qtads quadrapassel quake quake-server quake2 quake2-server quake3 quake3-data quake3-server quake4 quake4-server quakespasm quarry qxw rafkill rafkill-data raincat raincat-data randtype rbdoom3bfg redeclipse redeclipse-common redeclipse-data redeclipse-server reminiscence renpy renpy-demo renpy-thequestion residualvm residualvm-data ri-li ri-li-data ricochet rlvm robocode robotfindskitten rockdodger rocksndiamonds rolldice rott rrootage rrootage-data rtcw rtcw-common rtcw-server runescape salliere sandboxgamemaker sauerbraten sauerbraten-server scid scid-data scid-rating-data scid-spell-data scorched3d scorched3d-data scottfree scummvm scummvm-data scummvm-tools sdl-ball sdl-ball-data seahorse-adventures searchandrescue searchandrescue-common searchandrescue-data sgt-launcher sgt-puzzles shogivar shogivar-data simutrans simutrans-data simutrans-makeobj simutrans-pak128.britain simutrans-pak64 singularity singularity-music sjaakii sjeng sl slashem slashem-common slashem-gtk slashem-sdl slashem-x11 slimevolley slimevolley-data slingshot sludge-engine sm snake4 snowballz solarwolf sopwith spacearyarya spacezero speedpad spellcast sponc spout spring spring-common spring-javaai spring-maps-kernelpanic spring-mods-kernelpanic springlobby starfighter starfighter-data starvoyager starvoyager-data stax steam steam-devices steam-installer steamcmd stockfish stormbaancoureur stormbaancoureur-data sudoku supertransball2 supertransball2-data supertux supertux-data supertuxkart supertuxkart-data swell-foop tagua tagua-data tali tanglet tanglet-data tatan tdfsb tecnoballz tecnoballz-data teeworlds teeworlds-data teeworlds-server tenace tenmado tennix tetrinet-client tetrinet-server tetrinetx tetzle tf tf5 tictactoe-ng tint tintin++ tinymux titanion titanion-data toga2 tomatoes tomatoes-data tome toppler torcs torcs-data torus-trooper torus-trooper-data tourney-manager trackballs trackballs-data transcend treil trigger-rally trigger-rally-data triplane triplea trophy trophy-data trophy-dbg tumiki-fighters tumiki-fighters-data tuxfootball tuxmath tuxmath-data tuxpuck tuxtype tuxtype-data tworld tworld-data typespeed uci2wb ufoai ufoai-common ufoai-data ufoai-maps ufoai-misc ufoai-music ufoai-server ufoai-sound ufoai-textures uhexen2 uhexen2-common uligo unknown-horizons uqm uqm-content uqm-music uqm-russian uqm-voice val-and-rick val-and-rick-data vbaexpress vcmi vectoroids viruskiller visualboyadvance vodovod vor warmux warmux-data warmux-servers warzone2100 warzone2100-data warzone2100-music werewolf wesnoth wesnoth-1.12 wesnoth-1.12-aoi wesnoth-1.12-core wesnoth-1.12-data wesnoth-1.12-did wesnoth-1.12-dm wesnoth-1.12-dw wesnoth-1.12-ei wesnoth-1.12-httt wesnoth-1.12-l wesnoth-1.12-low wesnoth-1.12-music wesnoth-1.12-nr wesnoth-1.12-server wesnoth-1.12-sof wesnoth-1.12-sotbe wesnoth-1.12-thot wesnoth-1.12-tools wesnoth-1.12-trow wesnoth-1.12-tsg wesnoth-1.12-ttb wesnoth-1.12-utbs wesnoth-core wesnoth-music wfut whichwayisup widelands widelands-data wing wing-data wizznic wizznic-data wmpuzzle wolf4sdl wordplay wordwarvi wordwarvi-sound xabacus xabacus xball xbill xblast-tnt xblast-tnt-images xblast-tnt-levels xblast-tnt-models xblast-tnt-musics xblast-tnt-sounds xboard xbomb xbubble xbubble-data xchain xcowsay xdemineur xdesktopwaves xevil xfireworks xfishtank xflip xfrisk xgalaga xgalaga++ xgammon xinv3d xjig xjokes xjump xletters xmabacus xmahjongg xmille xmoto xmoto-data xmountains xmpuzzles xonix xpat2 xpenguins xphoon xpilot-extra xpilot-ng xpilot-ng-client-sdl xpilot-ng-client-x11 xpilot-ng-common xpilot-ng-server xpilot-ng-utils xpuzzles xqf xracer xracer-tools xscavenger xscorch xscreensaver-screensaver-dizzy xshisen xshogi xskat xsok xsol xsoldier xstarfish xsystem35 xteddy xtron xvier xwelltris xye xye-data xzip yahtzeesharp yamagi-quake2 yamagi-quake2-core zangband zangband-data zatacka zaz zaz-data zec zivot zoom-player gameconqueror
            #hamradio
            sudo apt-get purge -y acfax aldo ampr-ripd antennavis aprsdigi aprx ax25-apps ax25-tools ax25-xtools ax25mail-utils axmail baycomepp baycomusb chirp comptext comptty cqrlog cubicsdr cutesdr cw cwcp cwdaemon d-rats dablin direwolf ebook2cw ebook2cwgui fbb fccexam flamp fldigi flmsg flrig flwrap freedv glfer gnss-sdr gnuais gnuaisgui gpredict gqrx-sdr grig gsmc hamexam hamfax icom inspectrum klog libecholib1.3 libfap6 libhamlib-utils limesuite linpac linpsk lysdr morse morse-x morse2ascii multimon nec2c owx p10cfgd predict predict-gsat psk31lx pydxcluster pyqso qrq qsstv qtel qtel-icons quisk remotetrx soapyosmo-common0.6 soapyremote-server soapysdr-module-airspy soapysdr-module-all soapysdr-module-audio soapysdr-module-bladerf soapysdr-module-hackrf soapysdr-module-lms7 soapysdr-module-mirisdr soapysdr-module-osmosdr soapysdr-module-redpitaya soapysdr-module-remote soapysdr-module-rfspace soapysdr-module-rtlsdr soapysdr-module-uhd soapysdr-tools soapysdr0.6-module-airspy soapysdr0.6-module-all soapysdr0.6-module-audio soapysdr0.6-module-bladerf soapysdr0.6-module-hackrf soapysdr0.6-module-lms7 soapysdr0.6-module-mirisdr soapysdr0.6-module-osmosdr soapysdr0.6-module-redpitaya soapysdr0.6-module-remote soapysdr0.6-module-rfspace soapysdr0.6-module-rtlsdr soapysdr0.6-module-uhd soundmodem splat svxlink-calibration-tools svxlink-gpio svxlink-server svxreflector tk2 tk5 tlf trustedqsl tucnak twclock twpsk uhd-soapysdr uronode wsjtx wwl xastir xcwcp xdemorse xdx xlog xlog-data xnec2c xnecview yagiuda z8530-utils2
            #video
            sudo apt-get purge -y akqml bino browser-plugin-gnash browser-plugin-vlc cclive crtmpserver crtmpserver-apps crtmpserver-dev crtmpserver-libs deepin-movie dtv-scan-tables dumphd dvblast dvbstreamer dvdrip-utils ffmpeg flowblade flvmeta freetuxtv frei0r-plugins get-flash-videos gmlive gnash-common-opengl gnash-ext-fileio gnash-ext-lirc gnash-ext-mysql gnash-opengl gnome-dvb-client gnome-dvb-daemon gnome-mpv gnome-twitch gnome-twitch-player-backend-gstreamer-cairo gnome-twitch-player-backend-gstreamer-clutter gnome-twitch-player-backend-gstreamer-opengl gnome-twitch-player-backend-mpv-opengl grilo-plugins-dvb-daemon growisofs gst123 gstreamer1.0-crystalhd h264enc hdmi2usb-fx2-firmware i965-va-driver i965-va-driver-shaders imagination imagination-common kazam klash-opengl kodi kodi-bin kodi-data kodi-eventclients-common kodi-eventclients-kodi-send kodi-eventclients-ps3 kodi-eventclients-wiiremote kodi-pvr-hts kodi-repository-kodi kylin-video libaacs0 libde265-examples libdvbcsa1 libffmpegthumbnailer4v5 libheif-examples libqtav1 libqtavwidgets1 libtotem0 libvlc-bin libxine2-xvdr lives-plugins livestreamer m2vrequantiser mediathekview mencoder minitube mjpegtools-gtk mplayer mplayer-gui mpv multicat nageru nomnom nordlicht obs-plugins obs-studio oggvideotools ogmrip-dirac ogmrip-oggz ogmrip-plugins openalpr openalpr-daemon openshot openshot-qt photofilmstrip qml-module-qtav qstopmotion qtav-players ser-player shotdetect simplescreenrecorder smplayer-l10n smtube sreview-common sreview-detect sreview-encoder sreview-master sreview-web streamlink subliminal-nautilus swfdec-gnome swfdec-mozilla tablet-encode transcode transmageddon tsdecrypt tvnamer va-driver-all vdpau-driver-all vdr-plugin-dvbhddevice vdr-plugin-dvbsddevice vdr-plugin-epgsync vdr-plugin-osdteletext vdr-plugin-satip vdr-plugin-skinenigmang vdr-plugin-softhddevice vdr-plugin-svdrpext vdr-plugin-svdrpext vdr-plugin-svdrposd vdr-plugin-vnsiserver vlc-bin vlc-plugin-access-extra vlc-plugin-base vlc-plugin-fluidsynth vlc-plugin-notify vlc-plugin-qt vlc-plugin-samba vlc-plugin-skins2 vlc-plugin-svg vlc-plugin-video-output vlc-plugin-video-splitter vlc-plugin-visualization vlc-plugin-vlsub vlc-plugin-zvbi voctomix voctomix-core voctomix-gui voctomix-outcasts vokoscreen webcamoid webcamoid-data webcamoid-plugins winff-data winff-gtk2 winff-qt x265 xbmc-pvr-argustv xbmc-pvr-dvbviewer xbmc-pvr-iptvsimple xbmc-pvr-mediaportal-tvserver xbmc-pvr-mythtv-cmyth xbmc-pvr-nextpvr xbmc-pvr-njoy xbmc-pvr-tvheadend-hts xbmc-pvr-vdr-vnsi xbmc-pvr-vuplus xbmc-pvr-wmc xvidenc totem*
            #https://www.ubuntupit.com/an-ultimate-list-of-ethical-hacking-and-penetration-testing-tools-for-kali-linux/
            #hacking
            sudo apt-get purge -y wireshark* *nmap* *medusa* john* *sqlmap* hydra* zenmap ophcrack* tcpdump* kismet* snort* fwsnort *nessus* netcat* aircrack-ng nikto wifite yersinia hashcat* *macchanger* pixiewps bbqsql proxychains* whatweb dirb traceroute *httrack* *openvas* 4g8 acccheck airgraph-ng bittorrent* bittornado* bluemon btscanner buildtorrent brutespray dsniff ettercap* hunt nast netsniff-ng python-scapy sipgrep sniffit tcpick tcpreplay tcpslice tcptrace tcptraceroute tcpxtract irpas mdk3 reaver slowhttptest ssldump sslstrip thc-ipv6 bro* darkstat dnstop flowscan nfstrace* nstreams ntopng* ostinato softflowd tshark 
            #unwanted services
            sudo apt-get purge -y apache2* cheese* *mahjongg* rhythmbox* minetest* samba* python-samba *telnet* cups* postgresql* musescore* openbsd-inetd inetutils-inetd reconf-inetd update-inetd *xinetd* nis rsh* talk talkd ldap-* alljoyn* *bluetooth*
            sudo apt-get install -y clamav clamav-daemon rkhunter auditd aide aide-common unattended-upgrades thunderbird tree apparmor apparmor-utils apparmor-profiles ntp tcpd iptables rsyslog sshguard
            sudo apt-get upgrade -y
            sudo apt-get autoremove -y
            sudo apt-get autoclean -y
            
            cd //usr/local/src
            sudo wget http://www.rfxn.com/downloads/maldetect-current.tar.gz
            sudo tar -xzf maldetect-current.tar.gz
            cd maldetect-*
            sudo sh ./install.sh
            break;;
        [Nn]* )
            echo "Skipped."
            break;;
        * )
            echo "Please answer y or n.";;
    esac
done
# system config
#uninstall potentially unwanted filesystems
rmmod cramfs
rmmod freevxfs
rmmod jffs2
rmmod hfs
rmmod hfsplus
rmmod udf

#nor this
systemctl is-enabled autofs

#intrusion detection enabled
aideinit

#configure common-auth
#add a check for if this is already in here
sudo chmod 702 //etc/pam.d/common-auth
echo "auth required pam_tally2.so file=/var/log/tallylog deny=5 even_deny_root\ unlock_time=900" >> //etc/pam.d/common-auth
sudo chmod 700 //etc/pam.d/common-auth

#enable auditing
sudo auditctl -e 1

#configure sysctl.conf
#add presence checks for all of these
sudo chmod 702 //etc/sysctl.conf
#ip spoofing protection
echo "net.ipv4.conf.default.rp_filter = 1" >> //etc/sysctl.conf
echo "net.ipv4.conf.all.rp_filter = 1" >> //etc/sysctl.conf
#block syn attacks
echo "net.ipv4.tcp_syncookies = 1" >> //etc/sysctl.conf
echo "net.ipv4.tcp_max_syn_backlog = 2048" >> //etc/sysctl.conf
echo "net.ipv4.tcp_synack_retries = 2" >> //etc/sysctl.conf
echo "net.ipv4.tcp_syn_retries = 5" >> //etc/sysctl.conf
#control ip packet forwarding
echo "net.ipv4.ip_forward = 0" >> //etc/sysctl.conf
#ignore icmp redirects
echo "net.ipv4.conf.all.accept_redirects = 0" >> //etc/sysctl.conf
echo "net.ipv6.conf.all.accept_redirects = 0" >> //etc/sysctl.conf
echo "net.ipv4.conf.default.accept_redirects = 0" >> //etc/sysctl.conf
echo "net.ipv6.conf.default.accept_redirects = 0" >> //etc/sysctl.conf
#ignore send redirects
echo "net.ipv4.conf.all.send_redirects = 0" >> //etc/sysctl.conf
echo "net.ipv4.conf.default.send_redirects = 0" >> //etc/sysctl.conf
#disable source packet routing
echo "net.ipv4.conf.all.accept_source_route = 0" >> //etc/sysctl.conf
echo "net.ipv6.conf.all.accept_source_route = 0" >> //etc/sysctl.conf
echo "net.ipv4.conf.default.accept_source_route = 0" >> //etc/sysctl.conf
echo "net.ipv6.conf.default.accept_source_route = 0" >> //etc/sysctl.conf
#log martians
echo "net.ipv4.conf.all.log_martians = 1" >> //etc/sysctl.conf
echo "net.ipv4.icmp_ignore_bogus_error_responses = 1" >> //etc/sysctl.conf
#ignore icmp broadcast requests
echo "net.ipv4.icmp_echo_ignore_broadcasts = 1" >> //etc/sysctl.conf
#ignore directed pings
echo "net.ipv4.icmp_echo_ignore_all = 1" >> //etc/sysctl.conf
echo "kernel.exec-shield = 1" >> //etc/sysctl.conf
echo "kernel.randomize_va_space = 1" >> //etc/sysctl.conf
#disable ipv6 :(
echo "net.ipv6.conf.all.disable_ipv6 = 1" >> //etc/sysctl.conf
echo "net.ipv6.conf.default.disable_ipv6 = 1" >> //etc/sysctl.conf
echo "net.ipv6.conf.lo.disable_ipv6 = 1" >> //etc/sysctl.conf
#deny redirects
echo "net.ipv4.conf.all.secure_redirects = 0" >> //etc/sysctl.conf
#log packets with impossible addresses to kernel log
echo "net.ipv4.conf.default.secure_redirects = 0" >> //etc/sysctl.conf
#ipv6 configurations
echo "net.ipv6.conf.default.router_solicitations = 0" >> //etc/sysctl.conf
echo "net.ipv6.conf.default.accept_ra_rtr_pref = 0" >> //etc/sysctl.conf
echo "net.ipv6.conf.default.accept_ra_pinfo = 0" >> //etc/sysctl.conf
echo "net.ipv6.conf.default.accept_ra_defrtr = 0" >> //etc/sysctl.conf
echo "net.ipv6.conf.default.autoconf = 0" >> //etc/sysctl.conf
echo "net.ipv6.conf.default.dad_transmits = 0" >> //etc/sysctl.conf
echo "net.ipv6.conf.default.max_addresses = 1" >> //etc/sysctl.conf
echo "net.ipv4.conf.all.send redirects = 0" >> //etc/sysctl.conf
echo "net.ipv4.conf.all.accept redirects = 0" >> //etc/sysctl.conf
echo "net.ipv4.conf.all.secure redirects = 0" >> //etc/sysctl.conf
echo "net.ipv4.conf.all.log martians = 1" >> //etc/sysctl.conf
echo "net.ipv4.conf.all.rp filter = 1" >> //etc/sysctl.conf
echo "net.ipv6.conf.all.accept ra = 0" >> //etc/sysctl.conf
echo "net.ipv6.conf.default.accept_ra = 0" >> //etc/sysctl.conf
echo "net.ipv6.conf.all.accept redirects = 0" >> //etc/sysctl.conf
echo "kernel.randomize_va_space = 2" >> //etc/sysctl.conf
#panic when out of memory
echo "vm.panic_on_oom = 1" >> //etc/sysctl.conf
#reboot system 10 seconds after panic
echo "kernel.panic = 10" >> //etc/sysctl.conf
#apply new sysctl.conf settings
sudo chmod 700 //etc/sysctl.conf
sudo sysctl -p
#do the thing
sudo sysctl -w net.ipv4.ip forward=0
sudo sysctl -w net.ipv4.route.flush=1
sudo sysctl -w net.ipv4.conf.all.send_redirects=0
sudo sysctl -w net.ipv4.conf.default.send redirects=0
sudo sysctl -w net.ipv4.route.flush=1
sudo sysctl -w net.ipv4.conf.all.accept_source_route=0
sudo sysctl -w net.ipv4.conf.default.accept source route=0
sudo sysctl -w net.ipv4.route.flush=1
sudo sysctl -w net.ipv4.conf.all.accept_redirects=0
sudo sysctl -w net.ipv4.conf.default.accept redirects=0
sudo sysctl -w net.ipv4.route.flush=1
sudo sysctl -w net.ipv4.conf.all.secure_redirects=0
sudo sysctl -w net.ipv4.conf.default.secure_redirects=0
sudo sysctl -w net.ipv4.route.flush=1
sudo sysctl -w net.ipv4.conf.all.log_martians=1
sudo sysctl -w net.ipv4.conf.default.log martians=1
sudo sysctl -w net.ipv4.route.flush=1
sudo sysctl -w net.ipv4.icmp echo ignore broadcasts=1
sudo sysctl -w net.ipv4.route.flush=1
sudo sysctl -w net.ipv4.icmp_ignore_bogus_error_responses=1
sudo sysctl -w net.ipv4.route.flush=1
sudo sysctl -w net.ipv4.conf.all.rp_filter=1
sudo sysctl -w net.ipv4.conf.default.rp filter=1
sudo sysctl -w net.ipv4.route.flush=1
sudo sysctl -w net.ipv4.tcp syncookies=1
sudo sysctl -w net.ipv4.route.flush=1
sudo sysctl -w net.ipv6.conf.all.accept_ra=0
sudo sysctl -w net.ipv6.conf.default.accept ra=0
sudo sysctl -w net.ipv6.route.flush=1
sudo sysctl -w net.ipv6.conf.all.accept_redirects=0
sudo sysctl -w net.ipv6.conf.default.accept redirects=0
sudo sysctl -w net.ipv6.route.flush=1
sudo sysctl -w kernel.randomize_va_space=2
systemctl disable avahi-daemon
systemctl disable cups
systemctl disable isc-dhcp-server
systemctl disable isc-dhcp-server6
systemctl disable slapd
systemctl disable nfs-server
systemctl disable rpcbind
systemctl disable bind9
systemctl disable vsftpd
systemctl disable apache2
systemctl disable dovecot
systemctl disable smbd
systemctl disable squid
systemctl disable snmpd
systemctl disable rsync
systemctl disable nis

#ip spoofing
sudo chmod 702 //etc/host.conf
echo "order bind,hosts" >> //etc/host.conf
echo "nospoof on" >> //etc/host.conf
sudo chmod 700 //etc/host.conf

#restrict core dumps
sudo chmod 702 //etc/security/limits.conf
echo "* hard core" >> //etc/security/limits.conf
sudo chmod 700 //etc/security/limits.conf
sudo chmod 702 //etc/sysctl.conf
echo "fs.suid_dumpable = 0" >> //etc/sysctl.conf
sudo chmod 700 //etc/sysctl.conf
sudo sysctl -w fs.suid_dumpable=0

#config motd
sudo chmod 777 //etc/motd
echo "This system is for authorized users only. Individual use of this system and/or network without authority, or in excess of your authority, is strictly prohibited." > //etc/motd
sudo chmod 700 //etc/motd
sudo chmod 777 //etc/issue
echo "This system is for the use of authorized users only.  Individuals using this computer system without authority, or in excess of their authority, are subject to having all of their activities on this system monitored and recorded by system personnel.  In the course of monitoring individuals improperly using this system, or in the course of system maintenance, the activities of authorized users may also be monitored.  Anyone using this system expressly consents to such monitoring and is advised that if such monitoring reveals possible evidence of criminal activity, system personnel may provide the evidence of such monitoring to law enforcement officials." > //etc/issue
sudo chmod 700 //etc/issue
sudo chmod 777 //etc/issue.net
echo "This system is for the use of authorized users only.  Individuals using this computer system without authority, or in excess of their authority, are subject to having all of their activities on this system monitored and recorded by system personnel.  In the course of monitoring individuals improperly using this system, or in the course of system maintenance, the activities of authorized users may also be monitored.  Anyone using this system expressly consents to such monitoring and is advised that if such monitoring reveals possible evidence of criminal activity, system personnel may provide the evidence of such monitoring to law enforcement officials." > //etc/issue.net
sudo chmod 700 //etc/issue.net
touch //etc/dconf/profile/gdm
sudo chmod 777 //etc/dconf/profile/gdm
echo "user-db:user" >> //etc/dconf/profile/gdm
echo "system-db:gdm" >> //etc/dconf/profile/gdm
echo "file-db:/usr/share/gdm/greeter-dconf/defaults" >> //etc/dconf/profile/gdm
sudo chmod 700 //etc/dconf/profile/gdm

#Configure ntp
sudo chmod 777 //etc/ntp.conf
echo "restrict -4 default kod nomodify notrap nopeer noquery" >> //etc/ntp.conf
echo "restrict -6 default kod nomodify notrap nopeer noquery" >> //etc/ntp.conf
sudo chmod 700 //etc/ntp.conf

#Config hosts.deny
sudo chmod 777 //etc/hosts.deny
echo "ALL: ALL" >> //etc/hosts.deny
sudo chmod 700 //etc/hosts.deny

#Disable DCCP
sudo chmod 777 //etc/modprobe.d/CIS.conf
echo "install dccp /bin/true" >> //etc/modprobe.d/CIS.conf
echo "install sctp /bin/true" >> //etc/modprobe.d/CIS.conf
echo "install rds /bin/true" >> //etc/modprobe.d/CIS.conf
echo "install tipc /bin/true" >> //etc/modprobe.d/CIS.conf
sudo chmod 700 //etc/modprobe.d/CIS.conf

#auditing
sudo chmod 777 //etc/audit/auditd.conf
echo "max_log_file = 16384" >> //etc/audit/auditd.conf
echo "space_left_action = email" >> //etc/audit/auditd.conf
echo "action mail acct = root" >> //etc/audit/auditd.conf
echo "admin_space_left_action = halt" >> //etc/audit/auditd.conf
echo "max_log_file_action = keep_logs" >> //etc/audit/auditd.conf
sudo chmod 700 //etc/audit/auditd.conf
systemctl reload auditd
sudo chmod 777 //etc/audit/audit.rules
echo "-a always,exit -F arch=b64 -S adjtimex -S settimeofday -k time-change" >> //etc/audit/audit.rules
echo "-a always,exit -F arch=b32 -S adjtimex -S settimeofday -S stime -k time- change" >> //etc/audit/audit.rules
echo "-a always,exit -F arch=b64 -S clock_settime -k time-change" >> //etc/audit/audit.rules
echo "-a always,exit -F arch=b32 -S clock_settime -k time-change -w /etc/localtime -p wa -k time-change" >> //etc/audit/audit.rules
echo "-w /etc/group -p wa -k identity" >> //etc/audit/audit.rules
echo "-w /etc/passwd -p wa -k identity" >> //etc/audit/audit.rules
echo "-w /etc/gshadow -p wa -k identity" >> //etc/audit/audit.rules
echo "-w /etc/shadow -p wa -k identity" >> //etc/audit/audit.rules
echo "-w /etc/security/opasswd -p wa -k identity" >> //etc/audit/audit.rules
echo "-a always,exit -F arch=b64 -S sethostname -S setdomainname -k system-locale" >> //etc/audit/audit.rules
echo "-a always,exit -F arch=b32 -S sethostname -S setdomainname -k system-locale" >> //etc/audit/audit.rules
echo "-w /etc/issue -p wa -k system-locale" >> //etc/audit/audit.rules
echo "-w /etc/issue.net -p wa -k system-locale" >> //etc/audit/audit.rules
echo "-w /etc/hosts -p wa -k system-locale" >> //etc/audit/audit.rules
echo "-w /etc/sysconfig/network -p wa -k system-locale" >> //etc/audit/audit.rules
echo "-w /etc/apparmor/ -p wa -k MAC-policy" >> //etc/audit/audit.rules
echo "-w /etc/apparmor.d/ -p wa -k MAC-policy" >> //etc/audit/audit.rules
echo "-w /var/log/faillog -p wa -k logins" >> //etc/audit/audit.rules
echo "-w /var/log/lastlog -p wa -k logins" >> //etc/audit/audit.rules
echo "-w /var/log/tallylog -p wa -k logins" >> //etc/audit/audit.rules
echo "-w /var/run/utmp -p wa -k session" >> //etc/audit/audit.rules
echo "-w /var/log/wtmp -p wa -k logins" >> //etc/audit/audit.rules
echo "-w /var/log/btmp -p wa -k logins" >> //etc/audit/audit.rules
echo "-a always,exit -F arch=b64 -S chmod -S fchmod -S fchmodat -F auid>=1000 -F auid!=4294967295 -k perm_mod" >> //etc/audit/audit.rules
echo "-a always,exit -F arch=b32 -S chmod -S fchmod -S fchmodat -F auid>=1000 -F auid!=4294967295 -k perm_mod" >> //etc/audit/audit.rules
echo "-a always,exit -F arch=b64 -S chown -S fchown -S fchownat -S lchown -F auid>=1000 -F auid!=4294967295 -k perm_mod" >> //etc/audit/audit.rules
echo "-a always,exit -F arch=b32 -S chown -S fchown -S fchownat -S lchown -F auid>=1000 -F auid!=4294967295 -k perm_mod" >> //etc/audit/audit.rules
echo "-a always,exit -F arch=b64 -S setxattr -S lsetxattr -S fsetxattr -S removexattr -S lremovexattr -S fremovexattr -F auid>=1000 -F auid!=4294967295 -k perm_mod" >> //etc/audit/audit.rules
echo "-a always,exit -F arch=b32 -S setxattr -S lsetxattr -S fsetxattr -S removexattr -S lremovexattr -S fremovexattr -F auid>=1000 -F auid!=4294967295 -k perm_mod" >> //etc/audit/audit.rules
echo "-a always,exit -F arch=b64 -S creat -S open -S openat -S truncate -S ftruncate -F exit=-EACCES -F auid>=1000 -F auid!=4294967295 -k access" >> //etc/audit/audit.rules
echo "-a always,exit -F arch=b32 -S creat -S open -S openat -S truncate -S ftruncate -F exit=-EACCES -F auid>=1000 -F auid!=4294967295 -k access" >> //etc/audit/audit.rules
echo "-a always,exit -F arch=b64 -S creat -S open -S openat -S truncate -S ftruncate -F exit=-EPERM -F auid>=1000 -F auid!=4294967295 -k access" >> //etc/audit/audit.rules
echo "-a always,exit -F arch=b32 -S creat -S open -S openat -S truncate -S ftruncate -F exit=-EPERM -F auid>=1000 -F auid!=4294967295 -k access" >> //etc/audit/audit.rules
echo "-a always,exit -F arch=b64 -S mount -F auid>=1000 -F auid!=4294967295 -k mounts" >> //etc/audit/audit.rules
echo "-a always,exit -F arch=b32 -S mount -F auid>=1000 -F auid!=4294967295 -k mounts" >> //etc/audit/audit.rules
echo "-a always,exit -F arch=b64 -S unlink -S unlinkat -S rename -S renameat -F auid>=1000 -F auid!=4294967295 -k delete" >> //etc/audit/audit.rules
echo "-a always,exit -F arch=b32 -S unlink -S unlinkat -S rename -S renameat -F auid>=1000 -F auid!=4294967295 -k delete" >> //etc/audit/audit.rules
echo "-w /etc/sudoers -p wa -k scope" >> //etc/audit/audit.rules
echo "-w /etc/sudoers.d/ -p wa -k scope" >> //etc/audit/audit.rules
echo "-w /var/log/sudo.log -p wa -k actions" >> //etc/audit/audit.rules
echo "-w /sbin/insmod -p x -k modules" >> //etc/audit/audit.rules
echo "-w /sbin/rmmod -p x -k modules" >> //etc/audit/audit.rules
echo "-w /sbin/modprobe -p x -k modules" >> //etc/audit/audit.rules
echo "-a always,exit -F arch=b64 -S init_module -S delete_module -k modules" >> //etc/audit/audit.rules
sudo chmod 700 //etc/audit/auditd.conf
sudo chmod 777 //etc/audit/.rules
echo "-e 2" >> //etc/audit/.rules
sudo chmod 700 //etc/audit/.rules

#rsyslog
systemctl enable rsyslog
sudo chmod 777 //etc/rsyslog.conf
echo "$FileCreateMode 0640" >> //etc/rsyslog.conf
sudo chmod 700 //etc/rsyslog.conf
sudo chmod 777 //etc/rsyslog.d/*.conf
echo "$FileCreateMode 0640" >> //etc/rsyslog.d/*.conf
sudo chmod 700 //etc/rsyslog.d/*.conf
sudo chmod -R g-wx,o-rwx //var/log/*

systemctl enable cron

#disable IPv6
sudo chmod 777 //etc/default/grub
echo "GRUB_CMDLINE_LINUX="ipv6.disable=1"" >> //etc/default/grub
echo "GRUB_CMDLINE_LINUX="audit=1"" >> //etc/default/grub
sudo chmod 700 //etc/default/grub
update-grub

#user stuff
sudo useradd -D -f 30
sudo usermod -g 0 root
sudo chmod 777 //etc/bash.bashrc
echo "umask 027" >> //etc/bash.bashrc
sudo chmod 700 //etc/bash.bashrc
sudo chmod 777 //etc/profile
echo "umask027" >> //etc/profile
echo "TMOUT=600" >> //etc/profile
sudo chmod 700 //etc/profile
sudo chmod 777 //etc/profile.d/*.sh
echo "umask 027" >> //etc/profile.d/*.sh
sudo chmod 700 //etc/profile.d/*.sh
sudo chmod 777 //etc/bashrc
echo "TMOUT=600" >> //etc/bashrc
sudo chmod 700 //etc/bashrc
# Display cleanup completion message
echo "Cleanup completed."

# Display completion message
echo "Security configuration completed."

# Display script completion message
echo "Script execution completed."
