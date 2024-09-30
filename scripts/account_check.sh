#!/bin/bash
# load config file..
source ../config/settings.conf

check_accounts() {
	check_root_remote_login			# U-01
	check_password_complexity		# U-02
	check_account_lock_threshold		# U-03
	check_password_file_protection		# U-04
	check_non_root_uid_zero			# U-44
	check_su_command_restriction		# U-45
	check_password_min_length		# U-46
	check_password_max_age			# U-47
	check_password_min_age			# U-48
	check_remove_unnecessary_accounts	# U-49
	check_admin_group_min_accounts		# U-50
	check_no_gid_without_account		# U-51
	check_no_duplicate_uid			# U-52
	check_user_shell			# U-53
	check_session_timeout			# U-54
}

# !!! Var list
# $OS
# $OS_VERSION
# $LOG_FILE
# $PASSWORD_CONFIG_FILE
# $SSH_CONFIG_FILE
# $PAM_SU_FILE
# $SHADOW_FILE
# $PROFILE_FILE
 

# U-01
check_root_remote_login() {
	if grep -q "PermitRootLogin no" $SSH_CONFIG_FILE; then
		echo "U-01: Root Account remote access Restriction - Good" | tee -a $LOG_FILE
	else
		echo "U-01: Root Account remote access Restriction - Weak" | tee -a $LOG_FILE
	fi
}

# U-02
check_password_complexity() {
	if grep -q "minlen=8" $PASSWORD_CONFIG_FILE; then
		echo "U-02: Password complexity settings - Good" | tee -a $LOG_FILE
	else
		echo "U-02: Password complexity settings - Weak" | tee -a $LOG_FILE
	fi
}

# U-03
check_account_lock_threshold() {
	if grep -q "deny=5" $PASSWORD_CONFIG_FILE; then
		echo "U-03: Account lockout threshold settings - Good" | tee -a $LOG_FILE
	else
		echo "U-03: Account lockout threshold settings - Weak" | tee -a $LOG_FILE
	fi
}

# U-04
check_password_file_protection() {
	if [ $(stat -c "%a" /etc/shadow) -eq 640 ]; then
		echo "U-04 Password File Protection - Good" | tee -a $LOG_FILE
	else
		echo "U-04 Password File Protection - Weak" | tee -a $LOG_FILE
	fi
}

# U-44
check_non_root_uid_zero() {
	if awk -F: '($3 == 0 && $1 != "root") {print $1}' /etc/passwd; then

