#!/bin/bash

OS=$(uname -s)
check_password_file_protection() {
    local vulnerabilities=0

    case "$OS" in
        "Linux" | "SunOS" | "AIX")
            PASSWD_FILE="/etc/passwd"
            SHADOW_FILE="/etc/shadow"
            ;;
        "HP-UX")
            PASSWD_FILE="/etc/security/passwd"
            SHADOW_FILE="/etc/security/passwd"
            ;;
        *)
            echo "Unsupported operating system: $OS"
            exit 1
            ;;
    esac

    
    if [ -f "$PASSWD_FILE" ]; then
        echo "Checking password protection in: $PASSWD_FILE"
        
        if grep "^root" "$PASSWD_FILE" | awk -F":" '$2 == "x" {exit 0} END {exit 1}'; then
            echo "[PASSWD] Passwords are encrypted and stored in $SHADOW_FILE."
        else
            echo "[PASSWD] WARNING: Plain text passwords found in $PASSWD_FILE!"
            vulnerabilities=1
        fi
    else
        echo "Password file not found: $PASSWD_FILE"
        exit 1
    fi

    if [ -f "$SHADOW_FILE" ]; then
        SHADOW_PERMISSIONS=$(awk -F: '$2 ~ /^\$/ {print $1 "has and encrypted password"} $2 == "" {print $1 "has no password"} $2 ~/^[!*]/ {print $1 "is locked"}' "$SHADOW_FILE") // 여기 고쳐야함!!!
        if [[ "$SHADOW_PERMISSIONS" -eq 400 || "$SHADOW_PERMISSIONS" -eq 600 ]]; then
            echo "[SHADOW] Shadow file permissions are properly set."
        else
            echo "[SHADOW] WARNING: Shadow file permissions are insecure!"
            vulnerabilities=1
        fi
    else
        echo "Shadow file not found: $SHADOW_FILE"
        exit 1
    fi

    if [ "$vulnerabilities" -eq 1 ]; then
        echo "[U-04] Password file protection - Vulnerable"
    else
        echo "[U-04] Password file protection - Safe"
    fi
}

check_password_file_protection
