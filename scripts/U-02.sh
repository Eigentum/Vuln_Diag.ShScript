#! /bin/bash

source ../config/settings.conf
echo "[INFO] Start Vulnerabilities by U-02..."
check_pw_complexity() {
    local vulnerabilities=0

    case "$OS" in
        "Ubuntu" | "Debian")
            CONFIG_FILE="etc/security/pwquality.conf"
            ;;
        "CentOS" | "Fedora")
            if [ -f /etc/pam.d/system-auth ]; then
                CONFIG_FILE="/etc/pam.d/system-auth"
            elif [ -f /etc/security/pwquality.conf ]; then
                CONFIG_FILE="etc/security/pwquality.conf"
            else
                echo "There is no Config File."
                exit 1
            fi
            ;;
        "AIX")
            CONFIG_FILE="/etc/security/user"
            ;;
        "HP-UX")
            CONFIG_FILE="/etc/default/security"
            ;;
        "SunOS")
            CONFIG_FILE="/etc/default/passwd"
            ;;
        *)
            echo "Unknown OS : $OS"
            exit 1;
            ;;
    esac

    if [ -f $CONFIG_FILE ]; then
        case $OS in
            "SunOS")
                HISTORY=$(grep "^HISTORY" $CONFIG_FILE | awk -F= '{print $2}')
                MINDIFF=$(grep "^MINDIFF" $CONFIG_FILE | awk -F= '{print $2}')
                MINALPHA=$(grep "^MINALPHA" $CONFIG_FILE | awk -F= '{print $2}')
                MINNONALPHA=$(grep "^MINNONALPHA" $CONFIG_FILE | awk -F= '{print $2}')
                MINUPPER=$(grep "^MINUPPER" $CONFIG_FILE | awk -F= '{print $2}')
                MINLOWER=$(grep "^MINLOWER" $CONFIG_FILE | awk -F= '{print $2}')
                MAXREPEATS=$(grep "^MAXREPEATS" $CONFIG_FILE | awk -F= '{print $2}')
                MINSPECIAL=$(grep "^MINSPECIAL" $CONFIG_FILE | awk -F= '{print $2}')
                MINDIGIT=$(grep "^MINDIGIT" $CONFIG_FILE | awk -F= '{print $2}')
                NAMECHECK=$(grep "^NAMECHECK" $CONFIG_FILE | awk -F= '{print $2}')
                MINLENGTH=$(grep "^PASSLENGTH" $CONFIG_FILE | awk -F= '{print $2}')
                ;;
            "Ubuntu" | "Debian" | "CentOS" | "Fedora")
                MINLENGTH=$(grep "^minlen" $CONFIG_FILE | awk -F= '{print $2}')
                UCREDIT=$(grep "^ucredit" $CONFIG_FILE | awk -F= '{print $2}')
                LCREDIT=$(grep "^lcredit" $CONFIG_FILE | awk -F= '{print $2}')
                DCREDIT=$(grep "^dcredit" $CONFIG_FILE | awk -F= '{print $2}')
                OCREDIT=$(grep "^ocredit" $CONFIG_FILE | awk -F= '{print $2}')
                ;;
            "AIX")
                HISTEXPIRE=$(grep "^histexpire" $CONFIG_FILE | awk -F= '{print $2}')
                HISTSIZE=$(grep "^histsize" $CONFIG_FILE | awk -F= '{print $2}')
                MAXREPEATS=$(grep "^maxrepeats" $CONFIG_FILE | awk -F= '{print $2}')
                MINLENGTH=$(grep "^minlen" $CONFIG_FILE | awk -F= '{print $2}')
                MINALPHA=$(grep "^minalpha" $CONFIG_FILE | awk '{print $2}')
                MINOTHER=$(grep "^minother" $CONFIG_FILE | awk '{print $2}')
                MINDIFF=$(grep "^mindiff" $CONFIG_FILE | awk '{print $2}')
                ;;
            "HP-UX")
                MINLENGTH=$(grep "^MIN_PASSWORD_LENGTH" "$CONFIG_FILE" | awk -F= '{print $2}')
                MINUPPER=$(grep "^PASSWORD_MIN_UPPER_CASE_CHARS" $CONFIG_FILE | awk -F= '{print $2}')
                MINLOWER=$(grep "^PASSWORD_MIN_LOWER_CASE" "$CONFIG_FILE" | awk -F= '{print $2}')
                MINDIGIT=$(grep "^PASSWORD_MIN_DIGIT" "$CONFIG_FILE" | awk -F= '{print $2}')
                MINSPECIAL=$(grep "^PASSWORD_MIN_SPECIAL" "$CONFIG_FILE" | awk -F= '{print $2}')
                ;;
        esac

    if [[ "$MINLENGTH" -lt 8 ]]; then
        echo "- Cause: Password minimum length is less than 8 characters." >> "$LOG_FILE"
        vulnerabilities=1
    fi

    case "$OS" in
        "AIX")
            if [[ "$MINALPHA" -lt 1 ]]; then
                echo "- Cause: No alphabetic characters included." >> "$LOG_FILE"
                vulnerabilities=1
            fi
            if [[ "$MINOTHER" -lt 1 ]]; then
                echo "- Cause: No numeric or special characters included." >> "$LOG_FILE"
                vulnerabilities=1
            fi
            ;;
        "HP-UX")
            if [[ "$MINLOWER" -lt 1 ]]; then
                echo "- Cause: No lowercase characters included." >> "$LOG_FILE"
                vulnerabilities=1
                fi
            if [[ "$MINDIGIT" -lt 1 ]]; then
                echo "- Cause: No digits included." >> "$LOG_FILE"
                vulnerabilities=1
            fi
            if [[ "$MINSPECIAL" -lt 1 ]]; then
                echo "- Cause: No special characters included." >> "$LOG_FILE"
                vulnerabilities=1
            fi
            ;;
        "SunOS")
            if [[ "$MINALPHA" -lt 1 ]]; then
                echo "- Cause: No alphabetic characters included." >> "$LOG_FILE"
                vulnerabilities=1
            fi
            if [[ "$MINNONALPHA" -lt 1 ]]; then
                echo "- Cause: No numeric or special characters included." >> "$LOG_FILE"
                vulnerabilities=1
            fi
            ;;
        "Ubuntu" | "CentOS")
            if [[ "$UCREDIT" -eq 0 ]]; then
                echo "- Cause: No uppercase characters included." >> "$LOG_FILE"
                vulnerabilities=1
            fi
            if [[ "$LCREDIT" -eq 0 ]]; then
                echo "- Cause: No lowercase characters included." >> "$LOG_FILE"
                vulnerabilities=1
            fi
            if [[ "$DCREDIT" -eq 0 ]]; then
                echo "- Cause: No digits included." >> "$LOG_FILE"
                vulnerabilities=1
            fi
            if [[ "$OCREDIT" -eq 0 ]]; then
                echo "- Cause: No special characters included." >> "$LOG_FILE"
                vulnerabilities=1
            fi
            ;;
        esac
        
        if [ "$vulnerabilities" -eq 1 ]; then
            echo "[U-02] Password complexity settings - Vulnerable" >> "$LOG_FILE"
        else
            echo "[U-02] Password complexity settings - Safe" >> "$LOG_FILE"
        fi
    else
        echo "Password configuration file not found: $CONFIG_FILE"
        exit 1
    fi
}

check_password_complexity