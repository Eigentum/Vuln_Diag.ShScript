#!/bin/bash

source ../config/settings.conf

vulnerabilities=0

case $OS in
    SunOS)
        CONFIG_FILE="/etc/default/login"
        POLICY_FILE="/etc/security/policy.conf"
        ;;
    CentOS|Fedora|Red Hat)
        if [[ -f /etc/pam.d/system-auth ]]; then
            CONFIG_FILE="/etc/pam.d/system-auth"
        fi
        ;;
    Debian|Ubuntu)
        if [[ -f /etc/pam.d/common-auth ]]; then
            CONFIG_FILE="/etc/pam.d/common-auth"
        else
            echo "[ERROR] There is no 'common-auth' file..."
            exit 1
        fi
        if [[ -f /etc/pam.d/common-account ]]; then
            ACCOUNT_FILE="/etc/pam.d/common-account"
        else
            echo "[ERROR] There is no 'common-account' file..."
        fi
        ;;
    AIX)
        CONFIG_FILE="/etc/security/user"
        ;;
    HP-UX)
        CONFIG_FILE="/tcb/files/auth/system/default"
        ;;
    *)
        echo "[ERROR] Unknown OS... : $OS"
        exit 1
        ;;
esac

if [ -f "$CONSOLE_FILE" ]; then
    echo "Check account lockout settings in : $CONFIG_FILE"

    case $OS in
        SunOS)
            RETRIES=$(grep "RETRIES" $CONFIG_FILE | awk -F= '{print $2}')
            if [[ $RETRIES -gt 10 || -z $RETRIES ]]; then
                echo "[CAUTION] Account Lockout threshold exceeds 10 attempts or is not set."
                vulnerabilities=1
            fi
            if [ -f $POLICY_FILE ]; then
                LOCK_AFTER_RETRIES=$(grep "LOCK_AFTER_RETRIES" /etc/security/policy.conf | awk -F= '{print $2}')
                if [[ $LOCK_AFTER_RETRIES -ne "YES" ]]; then
                    echo "[CAUTION] Account lockout policy is not enabled."
                fi
            fi
            ;;
        CentOS|Fedora|Red Hat)
            Deny_SETTING=$(grep -E "deny=[0-9]+" $CONFIG_FILE | awk -F= '{print $2}')
            if [[ $DENY_SETTING -gt 10 || -z $DENY_SETTING ]]; then
                echo "[CAUTION] Account Lockout threshold exceeds 10 attempts or is not set."
                vulnerabilities=1
            fi
            ;;
        Debian|Ubuntu)
        Auth_SETTING=$(grep "pam_tally)
        if [[ -z ]]
            Deny_SETTING=$(grep )