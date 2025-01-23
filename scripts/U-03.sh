#!/bin/bash

OS=$(uname -s)

vulnerabilities=0

case $OS in
    SunOS)
        CONFIG_FILE="/etc/default/login"
        POLICY_FILE="/etc/security/policy.conf"
    ;;
    LINUX)
        if [[ -f /etc/pam.d/system-auth ]]; then
            CONFIG_FILE="/etc/pam.d/system-auth"
        elif [[ ! -f /etc/pam.d/system-auth ]]; then
            echo "There is no Config File.. consider other Distribution"
        fi
        if [[ -f /lib/security/pam_tally.so ]]; then
            echo "[WARNING] There is no Module 'pam_tally.so'.. try install module before setting."
        fi 
    ;;
    AIX)
        CONFIG_FILE="/etc/security/user"
    ;;
    HP-UX)
        if [[ -f /tcb/files/auth/system/default ]]; then
            CONFIG_FILE="/tcb/files/auth/system/default"
            RETRIES=$(grep "^u_maxtries" /tcb/files/auth/system/default | awk -F'#' '{print $2}')
        elif [[ -f /etc/default/security ]]; then
            CONFIG_FILE="/etc/default/security"
            RETRIES=$(grep "^AUTH_MAXTRIES" /etc/default/security | awk -F= '{print $2}')
        fi
    ;;
    *)
        echo "[ERROR] Unknown OS... : $OS"
        exit 1
    ;;
esac

case $OS in
    SunOS)
        RETRIES=$(grep "^RETRIES" "$CONFIG_FILE" | awk -F= '{print $2}')
        if [[ $RETRIES -gt 10 || -z $RETRIES ]]; then
            echo "[CAUTION] Account Lockout threshold exceeds 10 attempts or is not set."
            vulnerabilities=1
        fi
        if [ -f "$POLICY_FILE" ]; then
            LOCK_AFTER_RETRIES=$(grep "^LOCK_AFTER_RETRIES" /etc/security/policy.conf | awk -F= '{print $2}')
            if [[ $LOCK_AFTER_RETRIES -ne "YES" ]]; then
                echo "[CAUTION] Account lockout policy is not enabled."
            fi
        fi
        ;;
    LINUX)
        DENY_SETTING=$(grep -E "^deny=[0-9]+" "$CONFIG_FILE" | awk -F= '{print $2}')
        if [[ $DENY_SETTING -gt 10 || -z $DENY_SETTING ]]; then
            echo "[CAUTION] Account Lockout threshold exceeds 10 attempts or is not set."
            vulnerabilities=1
        fi
        ;;
    AIX)
        RETRIES=$(grep -E "loginretries = [0-9]+" "$CONFIG_FILE" | awk -F= '{print $2}')
        if [[ $RETRIES -gt 10 || -z $RETRIES ]]; then
            echo "[CAUTION] Account Lockout threshold exceeds 10 attempts or is not set."
            vulnerabilities=1
        fi
        ;;
    HP-UX)
        RETRIES=$(grep -E "u_maxtries#[0-9]+" "$CONFIG_FILE" | awk -F"#" '{print $2}')
        if [[ $RETRIES -gt 10 || -z $RETRIES ]]; then
            echo "[CAUTION] Account Lockout threshold exceeds 10 attempts or is not set."
            vulnerabilities=1
        fi
        ;;
esac


    