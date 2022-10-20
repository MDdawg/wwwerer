#!/bin/bash
declare -a user_array=($(cut -d ":" -f1 /etc/passwd | sort))


userLength=${#user_array[@]}


for (( i=0;i<$userLength;i++))
do
    clear
    echo "Are you sure you want to delete ${user_array[i]}?"
    select yn in "y" "n"; do
         case $yn in [Yy] )  
             # userdel ${user_array[${i}]}
             echo "test"
             
         break;;
             [Nn] ) echo "test no $i"
             clear
        echo "add or remove admin from ${user_array[i]}?"
        select yn in "y" "n"; do
            case $yn in [Yy] )
                echo "removed"
                break;;
            [Nn] ) echo "removed but no"
                break;;
            esac
        done
             break;;
        esac
    done
echo "done"


done
apt update && upgrade
echo "enable ufw?"
    select yn in "y" "n"; do
         case $yn in [Yy] )  
             systemctl enable ufw
             
         break;;
             [Nn] ) echo "no ssh "
             clear
             esac
         done
clear
echo "enable ssh?"
    select yn in "y" "n"; do
         case $yn in [Yy] )  
             ufw allow 22/tcp
             
         break;;
             [Nn] ) echo "no ssh"
             clear
             esac
         done
clear

echo "Delete files? y/n "
        select yn in "y" "n"; do
            case $yn in [Yy] )
                find / -name '*.mp3' -type f -delete
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
                find /home -name '*.jpeg' -type f -delete
            
            break;;
             [Nn] ) echo "Process Aborted "
             clear
             esac
        done 

    sleep 3
    
    echo "Done "
    
clear
