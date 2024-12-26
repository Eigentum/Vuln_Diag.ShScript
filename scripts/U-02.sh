#! /bin/bash

source ../config/settings.conf

check_pw_complexity() {
    local vulnerabilities=0

    case "$OS" in
        "Ubuntu" | "Debian")
            CONFIG_FILE="$PASSWORD_CONFIG_FILE"
            ;;
        "CentOS" | "Fedora")
            CONFIG_FILE="$PASSWORD_CONFIG_FILE"
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

    if [-f "$CONFIG_FILE"]; then
        case $OS in
            "SunOS")
                MIN_LENGTH=$(grep "PASSLENGTH" "$CONFIG_FILE" | awk -F= '{print $2}')
                MIN_ALPHA=$(grep "MINALPHA" "$CONFIG_FILE" | awk -F= '{print $2}')
                MIN_NON_ALPHA=$(grep "MINNONALPHA" "$CONFIG_FILE" | awk -F= '{print $2}')
                ;;
            "Ubuntu" | "Debian" | "CentOS" | "Fedora")
                MIN_LENGTH=$(grep "minlen" "$CONFIG_FILE" | awk -F= '{print $2}')
                UCREDIT=$(grep "ucredit" "$CONFIG_FILE" | awk -F= '{print $2}')
                LCREDIT=$(grep "lcredit" "$CONFIG_FILE" | awk -F= '{print $2}')
                DCREDIT=$(grep "dcredit" "$CONFIG_FILE" | awk -F= '{print $2}')
                OCREDIT=$(grep "ocredit" "$CONFIG_FILE" | awk -F= '{print $2}')
                ;;
            "AIX")
                MIN_LENGTH=$(grep "minlen" "$CONFIG_FILE" | awk -F= '{print $2}')
                MIN_ALPHA=$(grep "minalpha" "$CONFIG_FILE" | awk '{print $2}')
                MIN_OTHER=$(grep "minother" "$CONFIG_FILE" | awk '{print $2}')
                ;;
            "HP-UX")
                MIN_LENGTH=$(grep "MIN_PASSWORD_LENGTH" "$CONFIG_FILE" | awk -F= '{print $2}')
                MIN_LOWER=$(grep "PASSWORD_MIN_LOWER_CASE" "$CONFIG_FILE" | awk -F= '{print $2}')
                MIN_DIGIT=$(grep "PASSWORD_MIN_DIGIT" "$CONFIG_FILE" | awk -F= '{print $2}')
                MIN_SPECIAL=$(grep "PASSWORD_MIN_SPECIAL" "$CONFIG_FILE" | awk -F= '{print $2}')
                ;;
        esac

    if [[ "$MIN_LENGTH" -lt 8 ]]; then
        echo "- Cause: Password minimum length is less than 8 characters." >> "$LOG_FILE"
        vulnerabilities=1
    fi

    case "$OS" in
        "AIX")
            if [[ "$MIN_ALPHA" -lt 1 ]]; then
                echo "- Cause: No alphabetic characters included." >> "$LOG_FILE"
                vulnerabilities=1
            fi
            if [[ "$MIN_OTHER" -lt 1 ]]; then
                echo "- Cause: No numeric or special characters included." >> "$LOG_FILE"
                vulnerabilities=1
            fi
            ;;
        "HP-UX")
            if [[ "$MIN_LOWER" -lt 1 ]]; then
                echo "- Cause: No lowercase characters included." >> "$LOG_FILE"
                vulnerabilities=1
                fi
            if [[ "$MIN_DIGIT" -lt 1 ]]; then
                echo "- Cause: No digits included." >> "$LOG_FILE"
                vulnerabilities=1
            fi
            if [[ "$MIN_SPECIAL" -lt 1 ]]; then
                echo "- Cause: No special characters included." >> "$LOG_FILE"
                vulnerabilities=1
            fi
            ;;
        "SunOS")
            if [[ "$MIN_ALPHA" -lt 1 ]]; then
                echo "- Cause: No alphabetic characters included." >> "$LOG_FILE"
                vulnerabilities=1
            fi
            if [[ "$MIN_NON_ALPHA" -lt 1 ]]; then
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