#!/bin/bash
telnet_vuln=0
ssh_vuln=0
OS=$(uname -s)

case "$OS" in
    Linux*)
    if [ -f /etc/pam.d/login ]; then
        if ! grep -q "pam_securetty.so" /etc/pam.d/login; then
            echo "[WARNING_Telnet] 'pam_securetty.so' does not Enabled (/etc/pam.d/login)."
            telnet_vuln=1
        else
            echo "[SAFE_Telnet] Included 'pam_securetty.so'"
        fi
    else
        echo "Path does not exist '/etc/pam.d/login'."
    fi

    if [ -f /etc/securetty ]; then
        if grep -q "pts/" /etc/securetty; then
            echo "[WARNING_Telnet] 'pts/' included in /etc/securetty" 
            telnet_vuln=1
        else
            echo "[SAFE_Telnet] 'pts/' does not included in /etc/securetty"
        fi
    else
        echo "Path does not exist '/etc/securetty'."
    fi

    if [ -f /etc/ssh/sshd_config ]; then
        if grep -q "^PermitRootLogin yes" /etc/ssh/sshd_config; then
            echo "[WARNING_SSH] Allowed 'PermitRootLogin'."
            ssh_vuln=1
        else
            echo "[SAFE_SSH] PermitRootLogin Denied."
        fi
    else 
        echo "Path does not exist '/etc/ssh/sshd_config'."
    fi
    ;;
    SunOS)
    if [ -f /etc/default/login ]; then
        if grep -q "^CONSOLE=/dev/console" /etc/default/login; then
            echo "[SAFE_Telnet] 'CONSOLE=/dev/console' is set."
        else
            echo "[WARNING_Telnet] 'CONSOLE=/dev/console' is not set."
            telnet_vuln=1
        fi
    else
        echo "Path does not exist '/etc/default/login'."
    fi

    if [ -f /etc/ssh/sshd_config ]; then
        if grep -q "^PermitRootLogin yes" /etc/ssh/sshd_config; then
            echo "[WARNING_SSH] Allowed 'PermitRootLogin'."
            ssh_vuln=1
        else
            echo "[SAFE_SSH] PermitRootLogin Denied."
        fi
    else 
        echo "Path does not exist '/etc/ssh/sshd_config'."
    fi
    ;;
    AIX) 
    if [ -f /etc/security/user ]; then
        if grep -q "rlogin = true" /etc/security/user; then
            echo "[WARNING_Telnet] 'rlogin' configuration of root account enabled."
            telnet_vuln=1
        else
            echo "[SAFE_Telnet]  'rlogin' configuration of root account disabled."
        fi
    else 
        echo "Path does not exist '/etc/security/user'."
    fi

    if [ -f /etc/ssh/sshd_config ]; then
        if grep -q "^PermitRootLogin yes" /etc/ssh/sshd_config; then
            echo "[WARNING_SSH] Allowed 'PermitRootLogin'."
            ssh_vuln=1
        elif ! grep -q "^PermitRootLogin" /etc/ssh/sshd_config; then
            echo "[WARNING_SSH] Vulnerable setting. change setting to 'no'"
            ssh_vuln=1
        else
            echo "[SAFE_SSH] PermitRootLogin Denied."
        fi
    else 
        echo "Path does not exist '/etc/ssh/sshd_config'."
    fi
    ;;
    HP-UX)
    if [ -f /etc/securetty ]; then
        if grep -q "^[^#]*console$" /etc/securetty; then
            echo "[SAFE_Telnet] 'console' set in /etc/securetty"
        else 
            echo "[WARNING_Telnet] need set 'console' in /etc/securetty"
            telnet_vuln=1
        fi
    else 
        echo "Path does not exist '/etc/securetty'."
    fi

    if [ -f /etc/ssh/sshd_config ]; then
        if grep -q "^PermitRootLogin yes" /etc/ssh/sshd_config; then
            echo "[WARNING_SSH] Allowed 'PermitRootLogin'."
            ssh_vuln=1
        elif ! grep -q "^PermitRootLogin" /etc/ssh/sshd_config; then
            echo "[WARNING_SSH] Vulnerable setting. change setting to 'no'."
            ssh_vuln=1
        else
            echo "[SAFE_SSH] PermitRootLogin Denied."
        fi
    else
        echo "Path does not exist '/etc/ssh/sshd_config'."
    fi
    ;;
esac

echo "Telnet Vulnerability Flag: $telnet_vuln"
echo "SSH Vulnerability Flag: $ssh_vuln"

if [ "$telnet_vuln" -eq 0 ] && [ "$ssh_vuln" -eq 0 ]; then
    echo "[RESULT] U-01 Result: SAFE."
else
    echo "[RESULT] U-01 Result: Found Vulnerability."
fi
