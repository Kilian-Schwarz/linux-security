#!/bin/bash
echo "Linux Security Script - by Kilian Schwarz  ---  v0.1"


# Laden der Konfigurationsdatei
source ./security.conf

# User confirmation prompt
echo "This script will perform the following operations:"

# Zähle die aktivierten Module und zeige die entsprechenden Meldungen an
counter=1
if [ "$ENABLE_UFW" = "yes" ]; then
    echo "$counter. Configure UFW firewall."
    ((counter++))
fi
if [ "$ENABLE_ADMINUSER" = "yes" ]; then
    echo "$counter. Create and configure a new admin user."
    ((counter++))
fi
if [ "$ENABLE_PASSWORDSECURITY" = "yes" ]; then
    echo "$counter. Set up password security."
    ((counter++))
fi
if [ "$ENABLE_SSHKEYS" = "yes" ]; then
    echo "$counter. Insert SSH keys."
    ((counter++))
fi
if [ "$ENABLE_SSHCONFIG" = "yes" ]; then
    echo "$counter. Configure SSH security settings."
    ((counter++))
fi
if [ "$ENABLE_FAIL2BAN" = "yes" ]; then
    echo "$counter. Configure Fail2Ban for dynamic IP blocking."
    ((counter++))
fi
if [ "$ENABLE_CLAMAV" = "yes" ]; then
    echo "$counter. Activate ClamAV antivirus."
    ((counter++))
fi
if [ "$ENABLE_AIDE" = "yes" ]; then
    echo "$counter. Activate AIDE for file integrity monitoring."
    ((counter++))
fi
if [ "$ENABLE_RKHUNTER" = "yes" ]; then
    echo "$counter. Configure rkhunter for rootkit detection."
    ((counter++))
fi
if [ "$ENABLE_AUTOUPDATE" = "yes" ]; then
    echo "$counter. Install and configure an autoupdater."
    ((counter++))
fi
if [ "$ENABLE_POSTFIX" = "yes" ]; then
    echo "$counter. Set a secure banner for Postfix."
    ((counter++))
fi
if [ "$ENABLE_AUDIT" = "yes" ]; then
    echo "$counter. Enable auditing tools and services."
    ((counter++))
fi
if [ "$ENABLE_OTHERSECURE" = "yes" ]; then
    echo "$counter. Apply other security configurations."
    ((counter++))
fi
if [ "$ENABLE_GRUB" = "yes" ]; then
    echo "$counter. Set GRUB bootloader password."
    ((counter++))
fi
if [ "$ENABLE_BANNER" = "yes" ]; then
    echo "$counter. Configure login banner."
    ((counter++))
fi
echo "Please ensure that all values in the security.conf file are correct."

read -p "Are you sure you want to proceed with these changes? (yes/no): " confirm
if [ "$confirm" != "yes" ]; then
    echo "Operation aborted by user."
    exit 0
fi

if [ "$(id -u)" -ne 0 ]; then
    echo "Dieses Skript muss als Root ausgeführt werden."
    exit 1
fi

start=$(date +%s%N)

# Disable job control messages
set +m

export DEBIAN_FRONTEND=noninteractive
trap 'echo -e "\nProcess interrupted"; exit' INT

# Check if the security configuration file exists
if [ ! -f ./security.conf ]; then
    echo "Die Konfigurationsdatei security.conf wurde nicht gefunden."
    exit 1
fi
# Überprüfen, ob die Variablen für UFW-Regeln gesetzt sind
if [ -z "$SECURITY_UFWSSH_IPS" ]; then
    echo "UFW_RULES Variablen fehlen in der Konfigurationsdatei."
    exit 1
fi

# Überprüfen, ob notwendige Variablen in der Konfigurationsdatei gesetzt sind
if [ -z "$SECURITY_UFWSSH_IPS" ] || [ -z "$SECURITY_SSH_PORT" ] || [ -z "$SECURITY_USERNAME_ADMINUSER" ] || [ -z "$SECURITY_SSH_SSH_ADMINUSER_KEYS" ] || [ -z "$SECURITY_SSH_ADMIN_KEYS" ] || [ -z "$SECURITY_TIMEZONE" ]; then
    echo "Eine oder mehrere notwendige Variablen fehlen in der Konfigurationsdatei."
    exit 1
fi

# Check if module activation variables are set
if [ -z "$ENABLE_ADMINUSER" ] || [ -z "$ENABLE_PASSWORDSECURITY" ] || [ -z "$ENABLE_SSHKEYS" ] || [ -z "$ENABLE_SSHCONFIG" ] || [ -z "$ENABLE_FAIL2BAN" ] || [ -z "$ENABLE_CLAMAV" ] || [ -z "$ENABLE_AIDE" ] || [ -z "$ENABLE_RKHUNTER" ] || [ -z "$ENABLE_AUTOUPDATE" ] || [ -z "$ENABLE_POSTFIX" ] || [ -z "$ENABLE_AUDIT" ] || [ -z "$ENABLE_OTHERSECURE" ] || [ -z "$ENABLE_GRUB" ]; then
    echo "Eine oder mehrere Aktivierungsvariablen fehlen in der Konfigurationsdatei."
    exit 1
fi



# Extract variables from the configuration file
IFS=',' read -r -a UFWSSH_IPS <<< "$SECURITY_UFWSSH_IPS"
SSH_PORT="$SECURITY_SSH_PORT"
USERNAME_ADMINUSER="$SECURITY_USERNAME_ADMINUSER"
TIMEZONE="$SECURITY_TIMEZONE"

# Function to parse associative array from string
parse_ssh_keys() {
    declare -A result
    local array_string="$1"
    array_string="${array_string//[()]/}"  # Remove parentheses
    IFS=', ' read -ra items <<< "$array_string"
    for item in "${items[@]}"; do
        key="${item%%=*}"
        value="${item#*=}"
        key="${key//\"}"
        value="${value//\"}"
        result["$key"]="$value"
    done
    echo "$(declare -p result)"
}

# Convert the SSH keys from string to associative arrays
eval "$(parse_ssh_keys "$SECURITY_SSH_SSH_ADMINUSER_KEYS")"
declare -A SSH_SSH_ADMINUSER_KEYS="${result[@]}"

eval "$(parse_ssh_keys "$SECURITY_SSH_ADMIN_KEYS")"
declare -A SSH_ADMIN_KEYS="${result[@]}"

# Check if the extracted variables are valid
if [ ${#UFWSSH_IPS[@]} -eq 0 ] || [ -z "$SSH_PORT" ] || [ -z "$USERNAME_ADMINUSER" ] || [ ${#SSH_SSH_ADMINUSER_KEYS[@]} -eq 0 ] || [ ${#SSH_ADMIN_KEYS[@]} -eq 0 ] || [ -z "$TIMEZONE" ]; then
    echo "Eine oder mehrere notwendige Variablen aus der Konfigurationsdatei sind ungültig."
    exit 1
fi

#-------------------------------------------------------------------------------------
# ----------------------------------- VARIABLEN --------------------------------------
#-------------------------------------------------------------------------------------
# Example Packages Array
PASSWORD_ADMINUSER=$(tr -dc A-Za-z0-9 </dev/urandom | head -c 42 ; echo '')
PACKAGES=(curl ufw libpam-passwdqc fail2ban sysstat acct debsums apt-show-versions auditd build-essential libpcap-dev libpcre3-dev libdumbnet-dev bison flex zlib1g-dev liblzma-dev openssl libssl-dev cmake libhwloc-dev pkg-config luajit libluajit-5.1-dev libpcap-dev libdumbnet-dev libunwind-dev liblzma-dev zlib1g-dev libssl-dev libnghttp2-dev cron aide clamav clamav-daemon rkhunter )
# These variables are now read from the security.conf file
# UFWSSH_IPS are now read from the security.conf file
# SSH_PORT is now read from the security.conf file
# USERNAME_ADMINUSER is now read from the security.conf file


#-------------------------------------------------------------------------------------
# ------------------------------ DEFINATE FUNCTIONS ----------------------------------
#-------------------------------------------------------------------------------------


# Function for loading animation
loading_animation() {
    local action=$1
    local pid=$2
    local delay=0.1
    local spinstr='⠋⠙⠹⠸⠼⠴⠦⠧⠇'
    local start1=$(date +%s) # Start time for calculating the duration

    while kill -0 $pid 2>/dev/null; do
        for ((i=0; i<${#spinstr}; i++)); do
            local char="${spinstr:$i:1}"
            local end1=$(date +%s)
            local duration1=$((end1 - start1))
            local minutes1=$((duration1 / 60))
            local seconds1=$((duration1 % 60))

            printf "\r[\e[36m%s\e[0m] | %2dmin %2dsec | %s... " "$char" "$minutes1" "$seconds1" "$action"
            sleep $delay
        done
    done
}

# Function to display success or error with animation
execute_with_status() {
    start1=$(date +%s)
    local action=$1
    shift

    # Execute the command and explicitly suppress Bash job control messages
    ("$@" >/dev/null 2>&1) &
    local pid=$!

    loading_animation "$action" $pid
    wait $pid
    local status=$?
    end1=$(date +%s)
    duration1=$((end1 - start1))
    minutes1=$((duration1 / 60))
    seconds1=$((duration1 % 60))
    if [ $status -eq 0 ]; then
        printf "\r[\e[32m✔\e[0m] | %2dmin %2dsec | %s\n" "$minutes1" "$seconds1" "$action           "
    else
        printf "\r[\e[31m✖\e[0m] | %2dmin %2dsec | %s\n" "$minutes1" "$seconds1" "$action failed.          "
    fi
    # Remove any remains of the animation
    echo -ne "\r\033[K"
}

passwordsecurity() {
    if ! grep -q "rounds=5000" /etc/pam.d/common-password; then
        sed -i '/pam_unix.so/ s/$/ rounds=5000/' /etc/pam.d/common-password
        echo "Runden für Passwort-Hashing hinzugefügt."
    else
        echo "Passwort-Hashing-Runden bereits konfiguriert."
    fi
    for user in $(awk -F':' '{
        if ($2 !~ /^(!|\*|\*LK\*|!!)$/ && $1 !~ /^(root|halt|sync|shutdown)$/)
            print $1
    }' /etc/shadow); do
        echo "Markiere Passwort von $user als abgelaufen."
        passwd --expire "$user"
    done
}

restartpolicy() {
    CONF_FILE="/etc/needrestart/needrestart.conf"

    # Check if the configuration file exists
    if [ -f "$CONF_FILE" ]; then
        # Search and replace the line defining $nrconf{restart} to enable automatic restarts
        sudo sed -i 's/^#\$nrconf\{restart\} =.*/\$nrconf\{restart\} = '\''a'\'';/' "$CONF_FILE"
        echo "needrestart configuration updated to enable automatic restarts."
    else
        echo "needrestart configuration file not found: $CONF_FILE"
    fi

}


# Function to create and configure user
config_ADMINUSER() {
    sudo useradd $USERNAME_ADMINUSER -m -s /bin/bash
    echo "$USERNAME_ADMINUSER:$PASSWORD_ADMINUSER" | sudo chpasswd
    sudo usermod -aG sudo $USERNAME_ADMINUSER
}

# Function to add SSH keys
add_sshkeys() {
    # Add SSH keys for ADMINUSER
    ADMINUSER_home="/home/$USERNAME_ADMINUSER"
    sudo mkdir -p "$ADMINUSER_home/.ssh"
    sudo touch "$ADMINUSER_home/.ssh/authorized_keys"

    # Iterate over each key and add it as a new line
    IFS=',' read -ra ADMINUSER_KEYS <<< "$SECURITY_SSH_SSH_ADMINUSER_KEYS"
    for key in "${ADMINUSER_KEYS[@]}"; do
        echo "$key" | sudo tee -a "$ADMINUSER_home/.ssh/authorized_keys" > /dev/null
    done

    sudo chmod 700 "$ADMINUSER_home/.ssh"
    sudo chmod 600 "$ADMINUSER_home/.ssh/authorized_keys"
    sudo chown -R $USERNAME_ADMINUSER:$USERNAME_ADMINUSER "$ADMINUSER_home"

    # General Public Keys for all users
    for user_home in /home/*; do
        if [ -d "$user_home" ] && [ "$(basename "$user_home")" != "$USERNAME_ADMINUSER" ]; then
            sudo mkdir -p "$user_home/.ssh"
            sudo touch "$user_home/.ssh/authorized_keys"
            IFS=',' read -ra GENERAL_KEYS <<< "$SECURITY_SSH_ADMIN_KEYS"
            for key in "${GENERAL_KEYS[@]}"; do
                echo "$key" | sudo tee -a "$user_home/.ssh/authorized_keys" > /dev/null
            done
            sudo chmod 700 "$user_home/.ssh"
            sudo chmod 600 "$user_home/.ssh/authorized_keys"
            sudo chown $(basename "$user_home"):$(basename "$user_home") "$user_home/.ssh" -R
        fi
    done
}

# Function to clean sshd_config.d directory
clean_sshd_config_d() {
    if [ -d /etc/ssh/sshd_config.d ]; then
        sudo tar -czf /etc/ssh/sshd_config.d_backup_$(date +%F_%T).tar.gz /etc/ssh/sshd_config.d/*
        sudo rm -f /etc/ssh/sshd_config.d/*
        echo "Backup of /etc/ssh/sshd_config.d created and all configuration files removed."
    fi
}

config_ssh() {
    # Clean the sshd_config.d directory
    clean_sshd_config_d

    # Backup the original sshd_config
    sudo cp /etc/ssh/sshd_config /etc/ssh/sshd_config.bak

    # Disable password authentication and enforce key-based authentication
    sudo sed -i 's/^PasswordAuthentication yes/PasswordAuthentication no/' /etc/ssh/sshd_config
    sudo sed -i 's/^#PasswordAuthentication yes/PasswordAuthentication no/' /etc/ssh/sshd_config
    sudo sed -i 's/^ChallengeResponseAuthentication yes/ChallengeResponseAuthentication no/' /etc/ssh/sshd_config
    sudo sed -i 's/^#ChallengeResponseAuthentication yes/ChallengeResponseAuthentication no/' /etc/ssh/sshd_config
    sudo sed -i 's/^UsePAM yes/UsePAM no/' /etc/ssh/sshd_config
    sudo sed -i 's/^#UsePAM yes/UsePAM no/' /etc/ssh/sshd_config

    # Ensure PubkeyAuthentication is enabled
    sudo sed -i 's/^#PubkeyAuthentication yes/PubkeyAuthentication yes/' /etc/ssh/sshd_config
    sudo sed -i 's/^PubkeyAuthentication no/PubkeyAuthentication yes/' /etc/ssh/sshd_config

    # Additional security settings
    sudo sed -i 's/^PermitRootLogin.*/PermitRootLogin no/' /etc/ssh/sshd_config # Disable root SSH login
    sudo sed -i 's/^#PermitRootLogin.*/PermitRootLogin no/' /etc/ssh/sshd_config # Disable root SSH login

    sudo sed -i '/^MaxAuthTries/c\MaxAuthTries 3' /etc/ssh/sshd_config
    sudo sed -i '/^MaxSessions/c\MaxSessions 2' /etc/ssh/sshd_config
    sudo sed -i "/^#Port /c\Port $SSH_PORT" /etc/ssh/sshd_config

    sudo sed -i 's/^AllowTcpForwarding yes/AllowTcpForwarding no/' /etc/ssh/sshd_config
    sudo sed -i 's/^ClientAliveCountMax 3/ClientAliveCountMax 2/' /etc/ssh/sshd_config
    sudo sed -i 's/^LogLevel INFO/LogLevel VERBOSE/' /etc/ssh/sshd_config
    sudo sed -i 's/^MaxAuthTries 6/MaxAuthTries 3/' /etc/ssh/sshd_config
    sudo sed -i 's/^MaxSessions 10/MaxSessions 2/' /etc/ssh/sshd_config
    sudo sed -i 's/^TCPKeepAlive yes/TCPKeepAlive no/' /etc/ssh/sshd_config
    sudo sed -i 's/^X11Forwarding yes/X11Forwarding no/' /etc/ssh/sshd_config
    sudo sed -i 's/^AllowAgentForwarding yes/AllowAgentForwarding no/' /etc/ssh/sshd_config

    sudo sed -i 's/^#AllowTcpForwarding yes/AllowTcpForwarding no/' /etc/ssh/sshd_config
    sudo sed -i 's/^#ClientAliveCountMax 3/ClientAliveCountMax 2/' /etc/ssh/sshd_config
    sudo sed -i 's/^#LogLevel INFO/LogLevel VERBOSE/' /etc/ssh/sshd_config
    sudo sed -i 's/^#MaxAuthTries 6/MaxAuthTries 3/' /etc/ssh/sshd_config
    sudo sed -i 's/^#MaxSessions 10/MaxSessions 2/' /etc/ssh/sshd_config
    sudo sed -i 's/^#TCPKeepAlive yes/TCPKeepAlive no/' /etc/ssh/sshd_config
    sudo sed -i 's/^#X11Forwarding yes/X11Forwarding no/' /etc/ssh/sshd_config
    sudo sed -i 's/^#AllowAgentForwarding yes/AllowAgentForwarding no/' /etc/ssh/sshd_config
    sudo sed -i 's/^#Banner none/Banner \/etc\/issue.net/' /etc/ssh/sshd_config

    # Restart SSH service to apply changes
    sudo systemctl restart ssh
    echo "Password authentication has been successfully disabled."
}

# Configure Fail2Ban for dynamic IP blocking
fail2ban_config() {
    sudo cp /etc/fail2ban/jail.conf /etc/fail2ban/jail.local
    echo -e "[ssh]\nenabled = true\nport = ssh\nfilter = sshd\nlogpath = /var/log/auth.log\nmaxretry = 3\nbantime = 60" >> /etc/fail2ban/jail.local
    sudo sed -i 's/bantime = 600/bantime = 60\nfindtime = 60/' /etc/fail2ban/jail.local
    sudo service fail2ban restart
}

# ClaimAV Configuration
claimav_configuration() {
    sudo freshclam
    sudo systemctl restart clamav-freshclam
    sudo systemctl enable clamav-freshclam
    sudo systemctl start clamav-daemon
    sudo systemctl enable clamav-daemon
}

#aide Configuration
adide_configuration() {
    AIDE_CONF="/etc/aide/aide.conf"
    DATABASE="/var/lib/aide/aide.db"
    DATABASE_NEW="/var/lib/aide/aide.db.new"

    # Überprüfen, ob die 'database_out'- und 'database_in'-Optionen in der AIDE-Konfigurationsdatei vorhanden sind
    if ! grep -q 'database_out=file:/var/lib/aide/aide.db.new' "$AIDE_CONF"; then
        echo 'database_out=file:/var/lib/aide/aide.db.new' >> "$AIDE_CONF"
    fi

    if ! grep -q 'database_in=file:/var/lib/aide/aide.db' "$AIDE_CONF"; then
        echo 'database_in=file:/var/lib/aide/aide.db' >> "$AIDE_CONF"
    fi

    # Aktualisiert die Hash-Algorithmus-Konfiguration
    sed -i 's/^Hash=.*/Hash=SHA256/' /etc/aide/aide.conf

    # AIDE-Datenbank initialisieren
    echo "Initialisiere AIDE-Datenbank..."
    aide --config="$AIDE_CONF" --init

    # Überprüfen, ob die AIDE-Datenbankdatei erfolgreich erstellt wurde
    if [ -f "$DATABASE_NEW" ]; then
        # Ersetzt die bestehende AIDE-Datenbank durch die neu initialisierte Version
        mv "$DATABASE_NEW" "$DATABASE"
        echo "AIDE-Datenbank wurde erfolgreich initialisiert und ist bereit für den Einsatz."
    else
        echo "Fehler: AIDE Datenbankdatei konnte nicht erstellt werden. Bitte überprüfen Sie die AIDE-Konfiguration und Fehlermeldungen."
        exit 1
    fi

}

# Rootkit detection with rkhunter
rkhunter_configuration() {
    sudo rkhunter --update
    sudo rkhunter --propupd # Update the database with the properties of system files
}

# Autoupdate script
autoupdater_config() {
    mkdir -p /opt/scripts-ks
    echo "apt-get update && apt-get upgrade -y" > "/opt/scripts-ks/autoupdate.sh"
    echo "date '+%H:%M:%S   %d/%m/%y'  >> /opt/scripts-ks/autoupdate_t.log" >> "/opt/scripts-ks/autoupdate.sh"
    chmod +x "/opt/scripts-ks/autoupdate.sh"
    echo "0 1 * * * root /opt/scripts-ks/autoupdate.sh > /opt/scripts-ks/autoupdate.log" >> /etc/crontab
}

# Set Postfix SMTP Banner
postconf_secure() {
    postconf -e 'smtpd_banner = $myhostname ESMTP'
    service postfix reload
}

# Enable Secure Config Auditd, acct and sysstat
enable_audit() {
    systemctl enable acct
    systemctl start acct
    apt-get install -y sysstat
    sed -i '/^ENABLED="false"/c\ENABLED="true"' /etc/default/sysstat
    service sysstat start
    apt-get install -y auditd
    systemctl enable auditd
    systemctl start auditd
}

other_secure_options() {

    # Sicherheitsvorkehrungen
    set -euo pipefail

    # 1. Core Dumps deaktivieren
    echo "* hard core 0" >> /etc/security/limits.conf

    # Configure password hashing rounds in /etc/login.defs
    sed -i 's/^PASS_MAX_DAYS.*/PASS_MAX_DAYS   99999/' /etc/login.defs
    sed -i 's/^PASS_MIN_DAYS.*/PASS_MIN_DAYS   0/' /etc/login.defs
    sed -i 's/^PASS_WARN_AGE.*/PASS_WARN_AGE   90/' /etc/login.defs
    echo "SHA_CRYPT_MIN_ROUNDS 5000" >> /etc/login.defs
    echo "SHA_CRYPT_MAX_ROUNDS 50000" >> /etc/login.defs#
    # Set default umask in /etc/login.defs to 027
    sed -i 's/^UMASK.*/UMASK           027/' /etc/login.defs
    # Disable USB storage
    echo "install usb-storage /bin/true" >> /etc/modprobe.d/blacklist.conf
    # Disable the 'VRFY' command in Postfix
    postconf -e disable_vrfy_command=yes
    # Disable unnecessary protocols
    for protocol in dccp sctp rds tipc; do
        echo "install $protocol /bin/true" >> /etc/modprobe.d/blacklist-$protocol.conf
    done
    # Add legal banners
    echo "Unauthorized access is prohibited." > /etc/issue
    echo "Unauthorized access is prohibited." > /etc/issue.net
    # Harden compilers
    chmod 700 /usr/bin/gcc
    chmod 700 /usr/bin/g++
}

set_grub_password() {
    # Erzeugen eines verschlüsselten Passworts
    ENCRYPTED_PASS=$(echo -e "${GRUB_PASSWORD}\n${GRUB_PASSWORD}" | grub-mkpasswd-pbkdf2 | grep -o 'grub.pbkdf2.*')

    # Sicherung der aktuellen GRUB-Konfigurationsdatei
    cp /etc/grub.d/40_custom /etc/grub.d/40_custom.backup

    # Hinzufügen des verschlüsselten Passworts zur GRUB-Konfiguration
    echo "set superusers=\"root\"" >> /etc/grub.d/40_custom
    echo "password_pbkdf2 root ${ENCRYPTED_PASS}" >> /etc/grub.d/40_custom

    # Aktualisieren der GRUB-Konfiguration
    update-grub

    echo "Das GRUB-Bootloader-Passwort wurde gesetzt."
}

# Function to set timezone
set_timezone() {
    sudo timedatectl set-timezone "$TIMEZONE"
}


# Funktion zur Anwendung der UFW-Regeln
apply_ufw_rules() {
    if [ -n "$UFW_RULES" ]; then
        IFS=' ' read -ra RULES <<< "$UFW_RULES"
        for rule in "${RULES[@]}"; do
            IFS=':' read -r ip port protocol <<< "$rule"
            if [ "$ip" == "0.0.0.0" ]; then
                # Wenn die IP 0.0.0.0 ist, den Port freigeben
                ufw allow "$port"
            elif [ -z "$protocol" ]; then
                # Wenn kein Protokoll angegeben ist, sowohl TCP als auch UDP freigeben
                ufw allow from "$ip" to any port "$port"
            else
                ufw allow from "$ip" to any port "$port" proto "$protocol"
            fi
        done
    else
        echo "Keine UFW Regeln definiert."
    fi
}

# Beispiel-Konfigurationssektion für UFW
config_ufw() {
    ufw --force reset
    ufw default deny incoming
    ufw default allow outgoing

    for ip in "${UFWSSH_IPS[@]}"; do
        ufw allow from $ip to any port $SSH_PORT proto tcp
    done
    
    # Anwenden der zusätzlichen UFW-Regeln
    apply_ufw_rules
    
    ufw --force enable
}


# Function to configure the login banner
config_banner() {
    # Create the custom ASCII art banner script
    cat << 'EOF' > /etc/profile.d/mymotd.sh
#!/bin/bash
YELLOW=$(tput setaf 3)
RESET=$(tput sgr0)
BOLD=$(tput bold)

# Function to print a formatted line
print_line() {
    printf " %-45s : %-50s \n" "$1" "$2"
}

# Function to get the last 5 logged in users
get_last_logins() {
    last -n 5 -a | head -n 5 | awk '{$2=$3=""; print $0}'
}

echo "--------------------------------------------------------------"
print_line "${BOLD}${YELLOW}Hostname (FQDN)${RESET}" "$(hostname -f)"
print_line "${BOLD}${YELLOW}Date and Time${RESET}" "$(date)"
print_line "${BOLD}${YELLOW}OS${RESET}" "$(lsb_release -d | awk -F'\t' '{print $2}')"
print_line "${BOLD}${YELLOW}Kernel${RESET}" "$(uname -r)"
print_line "${BOLD}${YELLOW}Uptime${RESET}" "$(uptime -p | sed 's/up //')"
print_line "${BOLD}${YELLOW}Packages${RESET}" "$(dpkg -l | wc -l)"
print_line "${BOLD}${YELLOW}Shell${RESET}" "$SHELL"
print_line "${BOLD}${YELLOW}Terminal${RESET}" "$(tty)"
print_line "${BOLD}${YELLOW}Last Boot${RESET}" "$(who -b | awk '{print $3, $4}')"
echo "--------------------------------------------------------------"
print_line "${BOLD}${YELLOW}CPU${RESET}" "$(grep -m 1 'model name' /proc/cpuinfo | cut -d ':' -f 2 | xargs)"
print_line "${BOLD}${YELLOW}GPU${RESET}" "$(lspci | grep -i 'vga' | cut -d ':' -f 3 | xargs)"
print_line "${BOLD}${YELLOW}Memory${RESET}" "$(free -h | grep Mem | awk '{print $3 "/" $2}')"
print_line "${BOLD}${YELLOW}Disk (/)${RESET}" "$(df -h / | awk 'NR==2 {print $3 "/" $2 " (" $5 ")"}')"
print_line "${BOLD}${YELLOW}Swap${RESET}" "$(free -h | grep Swap | awk '{print $3 "/" $2}')"
print_line "${BOLD}${YELLOW}Load Average (1, 5, 15 min)${RESET}" "$(uptime | awk -F'load average:' '{print $2}' | xargs)"
echo "--------------------------------------------------------------"
print_line "${BOLD}${YELLOW}Processes${RESET}" "$(ps ax | wc -l | tr -d ' ')"
print_line "${BOLD}${YELLOW}Logged-in Users${RESET}" "$(who | awk '{print $1}' | sort | uniq | xargs)"
print_line "${BOLD}${YELLOW}IP Addresses${RESET}" "$(hostname -I | xargs)"
if [ -f /usr/lib/update-notifier/apt-check ]; then
    print_line "${BOLD}${YELLOW}Updates${RESET}" "$(/usr/lib/update-notifier/apt-check --human-readable | head -1)"
else
    print_line "${BOLD}${YELLOW}Updates${RESET}" "No update notifier found"
fi
print_line "${BOLD}${YELLOW}Restart Required${RESET}" "$(if [ -f /var/run/reboot-required ]; then echo 'Yes'; else echo 'No'; fi)"
echo "--------------------------------------------------------------"
echo " ${BOLD}${YELLOW}Last 5 Login Activities${RESET}"
get_last_logins | while read -r line; do echo " $line"; done
echo "--------------------------------------------------------------"
EOF

    chmod +x /etc/profile.d/mymotd.sh
}
config_banner


#-------------------------------------------------------------------------------------
# ------------------------------ Paketinstallation -----------------------------------
#-------------------------------------------------------------------------------------

execute_with_status "Updating package lists" sudo apt-get update -y

# Definiere Paketgruppen für jedes Modul
UFW_PACKAGES=(ufw)
ADMINUSER_PACKAGES=()
PASSWORDSECURITY_PACKAGES=(libpam-passwdqc)
SSHKEYS_PACKAGES=()
SSHCONFIG_PACKAGES=()
FAIL2BAN_PACKAGES=(fail2ban)
CLAMAV_PACKAGES=(clamav clamav-daemon)
AIDE_PACKAGES=(aide)
RKHUNTER_PACKAGES=(rkhunter)
AUTOUPDATE_PACKAGES=(cron)
POSTFIX_PACKAGES=(postfix)
AUDIT_PACKAGES=(auditd sysstat acct)
OTHERSECURE_PACKAGES=(debsums apt-show-versions build-essential libpcap-dev libpcre3-dev libdumbnet-dev bison flex zlib1g-dev liblzma-dev openssl libssl-dev cmake libhwloc-dev pkg-config luajit libluajit-5.1-dev libpcap-dev libdumbnet-dev libunwind-dev liblzma-dev zlib1g-dev libssl-dev libnghttp2-dev)
GRUB_PACKAGES=()
BANNER_PACKAGES=()

# Funktion zur Installation der Pakete einer Paketgruppe
install_packages() {
    local packages=("$@")
    for package in "${packages[@]}"; do
        package_installation() {
            export DEBIAN_FRONTEND=noninteractive
            echo "postfix postfix/main_mailer_type select Internet Site" | sudo debconf-set-selections
            echo "postfix postfix/mailname string your.domain.com" | sudo debconf-set-selections
            sudo apt-get install -y $package
        }
        execute_with_status "Installing $package" package_installation
    done
}

# Installiere Pakete basierend auf den aktivierten Modulen
if [ "$ENABLE_UFW" = "yes" ]; then
    install_packages "${UFW_PACKAGES[@]}"
fi

if [ "$ENABLE_ADMINUSER" = "yes" ]; then
    install_packages "${ADMINUSER_PACKAGES[@]}"
fi

if [ "$ENABLE_PASSWORDSECURITY" = "yes" ]; then
    install_packages "${PASSWORDSECURITY_PACKAGES[@]}"
fi

if [ "$ENABLE_SSHKEYS" = "yes" ]; then
    install_packages "${SSHKEYS_PACKAGES[@]}"
fi

if [ "$ENABLE_SSHCONFIG" = "yes" ]; then
    install_packages "${SSHCONFIG_PACKAGES[@]}"
fi

if [ "$ENABLE_FAIL2BAN" = "yes" ]; then
    install_packages "${FAIL2BAN_PACKAGES[@]}"
fi

if [ "$ENABLE_CLAMAV" = "yes" ]; then
    install_packages "${CLAMAV_PACKAGES[@]}"
fi

if [ "$ENABLE_AIDE" = "yes" ]; then
    install_packages "${AIDE_PACKAGES[@]}"
fi

if [ "$ENABLE_RKHUNTER" = "yes" ]; then
    install_packages "${RKHUNTER_PACKAGES[@]}"
fi

if [ "$ENABLE_AUTOUPDATE" = "yes" ]; then
    install_packages "${AUTOUPDATE_PACKAGES[@]}"
fi

if [ "$ENABLE_POSTFIX" = "yes" ]; then
    install_packages "${POSTFIX_PACKAGES[@]}"
fi

if [ "$ENABLE_AUDIT" = "yes" ]; then
    install_packages "${AUDIT_PACKAGES[@]}"
fi

if [ "$ENABLE_OTHERSECURE" = "yes" ]; then
    install_packages "${OTHERSECURE_PACKAGES[@]}"
fi

if [ "$ENABLE_GRUB" = "yes" ]; then
    install_packages "${GRUB_PACKAGES[@]}"
fi

if [ "$ENABLE_BANNER" = "yes" ]; then
    install_packages "${BANNER_PACKAGES[@]}"
fi



#-------------------------------------------------------------------------------------
# --------------------------------------- MAIN ---------------------------------------
#-------------------------------------------------------------------------------------


## Install packages (example packages)
#for package in "${PACKAGES[@]}"; do
#
#    package_installation() {
#        export DEBIAN_FRONTEND=noninteractive
#        echo "postfix postfix/main_mailer_type select Internet Site" | sudo debconf-set-selections
#        echo "postfix postfix/mailname string your.domain.com" | sudo debconf-set-selections
#        sudo apt-get install -y $package
#    }
#    
#    execute_with_status "Installing $package" package_installation
#
#done

if [ "$ENABLE_UFW" = "yes" ]; then
    execute_with_status "Configure UFW" config_ufw
fi

if [ "$ENABLE_ADMINUSER" = "yes" ]; then
    execute_with_status "Create and configure user 'ADMINUSER'" config_ADMINUSER
fi

if [ "$ENABLE_PASSWORDSECURITY" = "yes" ]; then
    execute_with_status "Setup Password Security" passwordsecurity
fi

if [ "$ENABLE_SSHKEYS" = "yes" ]; then
    execute_with_status "Insert SSH Keys" add_sshkeys
fi

if [ "$ENABLE_SSHCONFIG" = "yes" ]; then
    execute_with_status "Configure SSH Security" config_ssh
fi

if [ "$ENABLE_FAIL2BAN" = "yes" ]; then
    execute_with_status "Configure Fail2Ban for dynamic IP blocking" fail2ban_config
fi

if [ "$ENABLE_CLAMAV" = "yes" ]; then
    execute_with_status "Activate ClaimAV" claimav_configuration
fi

if [ "$ENABLE_AIDE" = "yes" ]; then
    execute_with_status "Activate Aide (May take a few minutes)" adide_configuration
fi

if [ "$ENABLE_RKHUNTER" = "yes" ]; then
    execute_with_status "Configure rkhunter" rkhunter_configuration
fi

if [ "$ENABLE_AUTOUPDATE" = "yes" ]; then
    execute_with_status "Install and Configure Autoupdater" autoupdater_config
fi

if [ "$ENABLE_POSTFIX" = "yes" ]; then
    execute_with_status "SMTP Secure Banner" postconf_secure
fi

if [ "$ENABLE_AUDIT" = "yes" ]; then
    execute_with_status "Enable Secure Config Auditd, acct and sysstat" enable_audit
fi

if [ "$ENABLE_OTHERSECURE" = "yes" ]; then
    execute_with_status "Enable other Secure Options" other_secure_options
fi

if [ "$ENABLE_GRUB" = "yes" ]; then
    execute_with_status "Set GRUB Password" set_grub_password
fi

if [ "$ENABLE_BANNER" = "yes" ]; then
    execute_with_status "Configure login banner" config_banner
fi






if [ "$ENABLE_RKHUNTER" = "yes" ]; then
    echo "rkhunter Checkup (may take a few minutes)"
    sudo rkhunter -c --enable all --disable none --rwo
fi





#-------------------------------------------------------------------------------------
# ------------------------------------ END OUTPUT ------------------------------------
#-------------------------------------------------------------------------------------

# Retrieve server information
SERVER_NAME=$(hostname)
SERVER_IP=$(hostname -I | awk '{print $1}')
ssh_port=$(grep -Po '(?<=^Port\s)\d+' /etc/ssh/sshd_config)

end=$(date +%s%N)
duration_ns=$((end - start))
# Convert to seconds for total duration
duration_s=$((duration_ns / 1000000000))

# Extract minutes, seconds, and milliseconds
minutes=$((duration_s / 60))
seconds=$((duration_s % 60))
milliseconds=$(((duration_ns / 1000000) % 1000))

# Re-enable job control messages
set -m
# Issue red warning
echo -e "\n\n\e[31mWARNING: It is recommended to restart the server once.\e[0m\n\n"
echo -e "\e[33mWARNING: Save the output.\e[0m\n"
printf "|%-31s|%-52s|\n" "-------------------------------" "--------------------------------------------------------------"
printf "| %-29s | %-60s |\n" "Execution Duration" "$minutes min $seconds sec $milliseconds ms"
printf "| %-29s | %-60s |\n" "Server Name" "$SERVER_NAME"
printf "| %-29s | %-60s |\n" "Server IP Address" "$SERVER_IP"
if [ "$ENABLE_ADMINUSER" = "yes" ]; then
    printf "| %-29s | %-60s |\n" "Password for $USERNAME_ADMINUSER" "$PASSWORD_ADMINUSER"
fi
if [ "$ENABLE_GRUB" = "yes" ]; then
    printf "| %-29s | %-60s |\n" "GRUB Password" "$GRUB_PASSWORD"
fi
if [ "$ENABLE_SSHCONFIG" = "yes" ]; then
    printf "| %-29s | %-60s |\n" "SSH Port" "$ssh_port"
    # Überprüfen, ob das Array Elemente enthält
    if [ ${#UFWSSH_IPS[@]} -gt 0 ]; then
    # Ausgabe der Kopfzeile nur einmal
    printf "| %-29s | %-60s |\n" "SSH allowed from" "${UFWSSH_IPS[0]}"
    
    # Starte die Schleife mit dem zweiten Element, da das erste bereits ausgegeben wurde
    for i in "${UFWSSH_IPS[@]:1}"; do
        printf "| %-29s | %-60s |\n" "" "$i"
    done
    else
    echo "Keine IP-Adressen definiert."
    fi
fi



printf "|%-31s|%-52s|\n" "-------------------------------" "--------------------------------------------------------------"
