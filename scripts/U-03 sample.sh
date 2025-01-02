#!/bin/bash

source ../config/settings.conf

check_account_lockout() {
    local vulnerabilities=0
    OS=$(uname -s)
    
    case "$OS" in
        "Linux")
            CONFIG_FILE="/etc/pam.d/system-auth"
            ;;
        "AIX")
            CONFIG_FILE="/etc/security/user"
            ;;
        "HP-UX")
            CONFIG_FILE="/tcb/files/auth/system/default"
            ;;
        "SunOS")
            CONFIG_FILE="/etc/default/login"
            POLICY_FILE="/etc/security/policy.conf"
            ;;
        *)
            echo "Unsupported operating system: $OS"
            exit 1
            ;;
    esac

    if [ -f "$CONFIG_FILE" ]; then
        echo "Checking account lockout settings in: $CONFIG_FILE"

        case "$OS" in
            "Linux")
                DENY_SETTING=$(grep -E "deny=[0-9]+" $CONFIG_FILE | awk -F= '{print $2}')
                if [[ "$DENY_SETTING" -gt 10 || -z $DENY_SETTING ]]; then
                    echo "- Cause: Account lockout threshold exceeds 10 attempts or is not set." >> "$LOG_FILE"
                    vulnerabilities=1
                fi
                ;;
            "AIX")
                LOGIN_RETRIES=$(grep "loginretries" $CONFIG_FILE | awk -F" " '{print $3}')
                if [[ $LOGIN_RETRIES -gt 10 || -z $LOGIN_RETRIES ]]; then
                    echo "- Cause: Account lockout threshold exceeds 10 attempts or is not set." >> "$LOG_FILE"
                    vulnerabilities=1
                fi
                ;;
            "HP-UX")
                MAX_TRIES=$(grep "u_maxtries" $CONFIG_FILE | awk -F# '{print $2}')
                if [[ $MAX_TRIES -gt 10 || -z $MAX_TRIES ]]; then
                    echo "- Cause: Account lockout threshold exceeds 10 attempts or is not set." >> "$LOG_FILE"
                    vulnerabilities=1
                fi
                ;;
            "SunOS")
                RETRIES=$(grep "RETRIES" $CONFIG_FILE | awk -F= '{print $2}')
                if [[ $RETRIES -gt 10 || -z $RETRIES ]]; then
                    echo "- Cause: Account lockout threshold exceeds 10 attempts or is not set." >> "$LOG_FILE"
                    vulnerabilities=1
                fi
                if [ -f $POLICY_FILE ]; then
                    LOCK_AFTER_RETRIES=$(grep "LOCK_AFTER_RETRIES" "$POLICY_FILE" | awk -F= '{print $2}')
                    if [[ $LOCK_AFTER_RETRIES != "YES" ]]; then
                        echo "- Cause: Account lockout policy is not enabled." >> "$LOG_FILE"
                        vulnerabilities=1
                    fi
                fi
                ;;
        esac

        if [ $vulnerabilities -eq 1 ]; then
            echo "[U-03] Account lockout settings - Vulnerable" >> "$LOG_FILE"
        else
            echo "[U-03] Account lockout settings - Safe" >> "$LOG_FILE"
        fi,
    else
        echo "Configuration file not found: $CONFIG_FILE"
        exit 1
    fi
}

check_account_lockout
