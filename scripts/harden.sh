#!/usr/bin/env bash

echo -e "\e[32m################## HARDEN ##################\e[0m"

# Amazon Linux 2 CIS Benchmark Hardening
# see docs/CIS_Amazon_Linux_2_Benchmark_v1.0.0.pdf for specifics on each topic

# replace these with your own legalese and company name
BANNER="\nThis computer system is private property. It is for authorized use only. Users have no personal privacy rights in any \nmaterials they place, view, access, or transmit on this system. Any or all uses of this system and all files on this \nsystem may be intercepted, monitored, recorded, copied, audited, inspected, and disclosed to authorized company or law \nenforcement personnel. Unauthorized or improper use of this system may result in administrative disciplinary action, \ncivil charges, criminal penalties, and/or other sanctions as allowed by law. By continuing to use this system you \nindicate your awareness of and consent to these terms and conditions of use.\n"
MOTD=" _____ _____ _____ _____ \n|     |  _  |  |  | __  |\n|  |  |   __|  |  | __ -|\n|_____|__|  |_____|_____|\n"

# 1.1.1.1  Ensure mounting of cramfs is disabled
echo "install cramfs /bin/true" > /etc/modprobe.d/CIS-1.1.1.1.conf

# 1.1.1.2  Ensure mounting of hfs is disabled
echo "install hfs /bin/true" > /etc/modprobe.d/CIS-1.1.1.2.conf

# 1.1.1.3  Ensure mounting of hfsplus is disabled
echo "install hfsplus /bin/true" > /etc/modprobe.d/CIS-1.1.1.3.conf

# 1.1.1.4  Ensure mounting of squashfs is disabled
echo "install squashfs /bin/true" > /etc/modprobe.d/CIS-1.1.1.4.conf

# 1.1.1.5  Ensure mounting of udf is disabled
echo "install udf /bin/true" > /etc/modprobe.d/CIS-1.1.1.5.conf

# See partition.sh for the following...
# 1.1.2    Ensure separate partition exists for /tmp
# 1.1.3    Ensure nodev option set on /tmp
# 1.1.4    Ensure nosuid option set on /tmp
# 1.1.5    Ensure noexec option set on /tmp
# 1.1.6    Ensure separate partition exists for /var
# 1.1.7    Ensure separate partition exists for /var/tmp
# 1.1.8    Ensure nodev option set on /var/tmp
# 1.1.9    Ensure nosuid option set on /var/tmp
# 1.1.10   Ensure noexec option set on /var/tmp
# 1.1.11   Ensure separate partition exists for /var/log
# 1.1.12   Ensure separate partition exists for /var/log/audit
# 1.1.13   Ensure separate partition exists for /home
# 1.1.14   Ensure nodev option set on /home
# 1.1.17   Ensure noexec option set on /dev/shm

# 1.3.1    Ensure AIDE is installed
yum install aide -y
aide --init
mv /var/lib/aide/aide.db.new.gz /var/lib/aide/aide.db.gz

# 1.3.2    Ensure filesystem integrity is regularly checked
echo "0 5 * * * /usr/sbin/aide --check" > /etc/cron.d/aide

# 1.4.1    Ensure permissions on bootloader config are configured
chown root:root /boot/grub2/grub.cfg
chmod og-rwx /boot/grub2/grub.cfg

# 1.4.2    Ensure authentication required for single user mode
# NOTE this creates a random password that is not retrievable
GRUBPASS=$(openssl rand -base64 32)
sudo script -q -c 'grub2-setpassword' > /dev/null << EOF
$GRUBPASS
$GRUBPASS
EOF

# 1.5.1    Ensure core dumps are restricted
echo "* hard core 0" > /etc/security/limits.d/CIS-1.5.1.conf
echo "fs.suid_dumpable = 0" > /etc/sysctl.d/CIS-1.5.1.conf
sysctl -w fs.suid_dumpable=0

# 1.5.3    Ensure address space layout randomisation (ASLR) is enabled
echo "kernel.randomize_va_space = 2" > /etc/sysctl.d/CIS-1.5.3.conf
sysctl -w kernel.randomize_va_space=2

# 1.6.1.2  Ensure the SELinux state is enforcing
sed -i 's/^SELINUX=.*/SELINUX=enforcing/' /etc/selinux/config

# 1.6.1.3  Ensure SELinux policy is configured
sed -i 's/^SELINUXTYPE=.*/SELINUXTYPE=targeted/' /etc/selinux/config

# 1.7.1.1  Ensure message of the day is configured properly
echo -e "cat << EOF\n$MOTD\nEOF" > /etc/update-motd.d/30-banner
systemctl --quiet restart update-motd

# 1.7.1.2  Ensure local login warning banner is configured properly
echo -e $BANNER > /etc/issue

# 1.7.1.3  Ensure remote login warning banner is configured properly
echo -e $BANNER > /etc/issue.net

# 1.7.1.4  Ensure permissions on /etc/motd are configured
chown root:root /etc/motd
chmod 644 /etc/motd

# 2.1.1.3  Ensure chrony is configured
sed -i 's/^OPTIONS=.*/OPTIONS="-u chrony"/' /etc/sysconfig/chronyd

# 2.1.7    Ensure NFS and RPC are not enabled
# NOTE NFS would be required if using Amazon EFS
# systemctl disable nfs
systemctl disable nfs-server
systemctl disable rpcbind

# 3.1.1    Ensure IP forwarding is disabled
echo -e "net.ipv4.ip_forward = 0\nnet.ipv6.conf.all.forwarding = 0" > /etc/sysctl.d/CIS-3.1.1.conf
sysctl -w net.ipv4.ip_forward=0
sysctl -w net.ipv4.route.flush=1
sysctl -w net.ipv6.conf.all.forwarding=0
sysctl -w net.ipv6.route.flush=1

# 3.1.2    Ensure packet redirect sending is not allowed
echo -e "net.ipv4.conf.all.send_redirects = 0\nnet.ipv4.conf.default.send_redirects = 0" > /etc/sysctl.d/CIS-3.1.2.conf
sysctl -w net.ipv4.conf.all.send_redirects=0
sysctl -w net.ipv4.conf.default.send_redirects=0
sysctl -w net.ipv4.route.flush=1

# 3.2.1    Ensure source routed packets are not accepted
echo -e "net.ipv4.conf.all.accept_source_route = 0\nnet.ipv4.conf.default.accept_source_route = 0\nnet.ipv6.conf.all.accept_source_route = 0\nnet.ipv6.conf.default.accept_source_route = 0" > /etc/sysctl.d/CIS-3.2.1.conf
sysctl -w net.ipv4.conf.all.accept_source_route=0
sysctl -w net.ipv4.conf.default.accept_source_route=0
sysctl -w net.ipv4.route.flush=1
sysctl -w net.ipv6.conf.all.accept_source_route=0
sysctl -w net.ipv6.conf.default.accept_source_route=0
sysctl -w net.ipv6.route.flush=1

# 3.2.2    Ensure ICMP redirects are not accepted
echo -e "net.ipv4.conf.all.accept_redirects = 0\nnet.ipv4.conf.default.accept_redirects = 0\nnet.ipv6.conf.all.accept_redirects = 0\nnet.ipv6.conf.default.accept_redirects = 0" > /etc/sysctl.d/CIS-3.2.2.conf
sysctl -w net.ipv4.conf.all.accept_redirects=0
sysctl -w net.ipv4.conf.default.accept_redirects=0
sysctl -w net.ipv4.route.flush=1
sysctl -w net.ipv6.conf.all.accept_redirects=0
sysctl -w net.ipv6.conf.default.accept_redirects=0
sysctl -w net.ipv6.route.flush=1

# 3.2.3    Ensure secure ICMP redirects are not accepted
echo -e "net.ipv4.conf.all.secure_redirects = 0\nnet.ipv4.conf.default.secure_redirects = 0" > /etc/sysctl.d/CIS-3.2.3.conf
sysctl -w net.ipv4.conf.all.secure_redirects=0
sysctl -w net.ipv4.conf.default.secure_redirects=0
sysctl -w net.ipv4.route.flush=1

# 3.2.4    Ensure suspicious packages are logged
echo -e "net.ipv4.conf.all.log_martians = 1\nnet.ipv4.conf.default.log_martians = 1" > /etc/sysctl.d/CIS-3.2.4.conf
sysctl -w net.ipv4.conf.all.log_martians=1
sysctl -w net.ipv4.conf.default.log_martians=1
sysctl -w net.ipv4.route.flush=1

# 3.2.5    Ensure broadcast ICMP requests are ignored
echo -e "net.ipv4.icmp_echo_ignore_broadcasts = 1" > /etc/sysctl.d/CIS-3.2.5.conf
sysctl -w net.ipv4.icmp_echo_ignore_broadcasts=1
sysctl -w net.ipv4.route.flush=1

# 3.2.6    Ensure bogus ICMP responses are ignored
echo -e "net.ipv4.icmp_ignore_bogus_error_responses = 1" > /etc/sysctl.d/CIS-3.2.6.conf
sysctl -w net.ipv4.icmp_ignore_bogus_error_responses=1
sysctl -w net.ipv4.route.flush=1

# 3.2.7    Ensure Reverse Path Filtering is enabled
echo -e "net.ipv4.conf.all.rp_filter = 1\nnet.ipv4.conf.default.rp_filter = 1" > /etc/sysctl.d/CIS-3.2.7.conf
sysctl -w net.ipv4.conf.all.rp_filter=1
sysctl -w net.ipv4.conf.default.rp_filter=1
sysctl -w net.ipv4.route.flush=1

# 3.2.8    Ensure TCP SYN Cookies is enabled
echo -e "net.ipv4.tcp_syncookies = 1" > /etc/sysctl.d/CIS-3.2.8.conf
sysctl -w net.ipv4.tcp_syncookies=1
sysctl -w net.ipv4.route.flush=1

# 3.2.9    Ensure IPv6 router advertisements are not accepted
echo -e "net.ipv6.conf.all.accept_ra = 0\nnet.ipv6.conf.default.accept_ra = 0" > /etc/sysctl.d/CIS-3.2.9.conf
sysctl -w net.ipv6.conf.all.accept_ra=0
sysctl -w net.ipv6.conf.default.accept_ra=0
sysctl -w net.ipv6.route.flush=1

# 3.3.2    Ensure /etc/hosts.allow is configured
# TODO this should be restricted to only allowed IP addresses which is difficult to safely automate here
echo -e "\e[31mTODO - CIS 3.3.2 - Ensure /etc/hosts.allow is configured\e[0m"
echo "ALL: ALL" > /etc/hosts.allow

# 3.3.3    Ensure /etc/hosts.deny is configured
echo "ALL: ALL" > /etc/hosts.deny

# 3.3.4    Ensure permissions on /etc/hosts.allow are configured
chown root:root /etc/hosts.allow
chmod 644 /etc/hosts.allow

# 3.3.5    Ensure permissions on /etc/hosts.deny are configured
chown root:root /etc/hosts.deny
chmod 644 /etc/hosts.deny

# 3.4.1    Ensure DCCP is disabled
echo "install dccp /bin/true" > /etc/modprobe.d/CIS-3.4.1.conf

# 3.4.2    Ensure SCTP is disabled
echo "install sctp /bin/true" > /etc/modprobe.d/CIS-3.4.2.conf

# 3.4.3    Ensure RDS is disabled
echo "install rds /bin/true" > /etc/modprobe.d/CIS-3.4.3.conf

# 3.4.4    Ensure TIPC is disabled
echo "install tipc /bin/true" > /etc/modprobe.d/CIS-3.4.4.conf

# 3.5.3    Ensure iptables is installed
# NOTE this is done out of order to ensure rules are applied correctly below
yum install iptables-services -y
systemctl enable iptables.service

# 3.5.1.1  Ensure default deny firewall policy
iptables -P INPUT DROP
iptables -P OUTPUT DROP
iptables -P FORWARD DROP
iptables-save > /etc/sysconfig/iptables

# 3.5.1.2  Ensure loopback traffic is configured
iptables -A INPUT -i lo -j ACCEPT
iptables -A OUTPUT -o lo -j ACCEPT
iptables -A INPUT -s 127.0.0.0/8 -j DROP
iptables-save > /etc/sysconfig/iptables

# 3.5.1.3  Ensure outbound and established connections are configured
iptables -A OUTPUT -p tcp -m state --state NEW,ESTABLISHED -j ACCEPT
iptables -A OUTPUT -p udp -m state --state NEW,ESTABLISHED -j ACCEPT
iptables -A OUTPUT -p icmp -m state --state NEW,ESTABLISHED -j ACCEPT
iptables -A INPUT -p tcp -m state --state ESTABLISHED -j ACCEPT
iptables -A INPUT -p udp -m state --state ESTABLISHED -j ACCEPT
iptables -A INPUT -p icmp -m state --state ESTABLISHED -j ACCEPT
iptables-save > /etc/sysconfig/iptables

# 3.5.1.4 Ensure firewall rules exist for all open ports
# NOTE this only allows SSH by default but would have to be expanded based on role
iptables -A INPUT -p tcp --dport 22 -m state --state NEW -j ACCEPT
iptables-save > /etc/sysconfig/iptables

# 3.6      Disable IPv6
sed -i 's/shell=0"$/shell=0 ipv6.disable=1"/' /etc/default/grub
grub2-mkconfig > /boot/grub2/grub.cfg

# 4.1.1.2  Ensure system is disabled when audit logs are full
sed -i 's/^space_left_action.*/space_left_action = email/' /etc/audit/auditd.conf
sed -i 's/^action_mail_acct.*/action_mail_acct = root/' /etc/audit/auditd.conf
sed -i 's/^admin_space_left_action.*/admin_space_left_action = halt/' /etc/audit/auditd.conf

# 4.1.1.3  Ensure audit logs are not automatically deleted
sed -i 's/^max_log_file_action.*/max_log_file_action = keep_logs/' /etc/audit/auditd.conf

# 4.1.3    Ensure auditing for processes that start prior to auditd is enabled
sed -i 's/disable=1"$/disable=1 audit=1"/' /etc/default/grub
grub2-mkconfig > /boot/grub2/grub.cfg

# 4.1.4    Ensure events that modify date and time information are collected
echo -e "-a always,exit -F arch=b64 -S adjtimex -S settimeofday -k time-change\n-a always,exit -F arch=b32 -S adjtimex -S settimeofday -S stime -k time-change\n-a always,exit -F arch=b64 -S clock_settime -k time-change\n-a always,exit -F arch=b32 -S clock_settime -k time-change\n-w /etc/localtime -p wa -k time-change" > /etc/audit/rules.d/CIS-4.1.04.rules

# 4.1.5    Ensure events that modify user/group information are collected
echo -e "-w /etc/group -p wa -k identity\n-w /etc/passwd -p wa -k identity\n-w /etc/gshadow -p wa -k identity\n-w /etc/shadow -p wa -k identity\n-w /etc/security/opasswd -p wa -k identity" > /etc/audit/rules.d/CIS-4.1.05.rules

# 4.1.6    Ensure events that modify the system's network environment are collected
echo -e "-a always,exit -F arch=b64 -S sethostname -S setdomainname -k system-locale\n-a always,exit -F arch=b32 -S sethostname -S setdomainname -k system-locale\n-w /etc/issue -p wa -k system-locale\n-w /etc/issue.net -p wa -k system-locale\n-w /etc/hosts -p wa -k system-locale\n-w /etc/sysconfig/network -p wa -k system-locale\n-w /etc/sysconfig/network-scripts/ -p wa -k system-locale" > /etc/audit/rules.d/CIS-4.1.06.rules

# 4.1.7    Ensure events that modify the system's Mandatory Access Controls are collected
echo -e "-w /etc/selinux/ -p wa -k MAC-policy\n-w /usr/share/selinux/ -p wa -k MAC-policy" > /etc/audit/rules.d/CIS-4.1.07.rules

# 4.1.8    Ensure login and logout events are collected
echo -e "-w /var/log/lastlog -p wa -k logins\n-w /var/run/faillock/ -p wa -k logins" > /etc/audit/rules.d/CIS-4.1.08.rules

# 4.1.9    Ensure session initiation information is collected
echo -e "-w /var/run/utmp -p wa -k session\n-w /var/log/wtmp -p wa -k logins\n-w /var/log/btmp -p wa -k logins" > /etc/audit/rules.d/CIS-4.1.09.rules

# 4.1.10   Ensure discretionary access control permission modification events are collected
echo -e "-a always,exit -F arch=b64 -S chmod -S fchmod -S fchmodat -F auid>=1000 -F auid!=4294967295 -k perm_mod\n-a always,exit -F arch=b32 -S chmod -S fchmod -S fchmodat -F auid>=1000 -F auid!=4294967295 -k perm_mod\n-a always,exit -F arch=b64 -S chown -S fchown -S fchownat -S lchown -F auid>=1000 -F auid!=4294967295 -k perm_mod\n-a always,exit -F arch=b32 -S chown -S fchown -S fchownat -S lchown -F auid>=1000 -F auid!=4294967295 -k perm_mod\n-a always,exit -F arch=b64 -S setxattr -S lsetxattr -S fsetxattr -S removexattr -S lremovexattr -S fremovexattr -F auid>=1000 -F auid!=4294967295 -k perm_mod\n-a always,exit -F arch=b32 -S setxattr -S lsetxattr -S fsetxattr -S removexattr -S lremovexattr -S fremovexattr -F auid>=1000 -F auid!=4294967295 -k perm_mod" > /etc/audit/rules.d/CIS-4.1.10.rules

# 4.1.11   Ensure unsuccessful unauthorised file access attempts are collected
echo -e "-a always,exit -F arch=b64 -S creat -S open -S openat -S truncate -S ftruncate -F exit=-EACCES -F auid>=1000 -F auid!=4294967295 -k access\n-a always,exit -F arch=b32 -S creat -S open -S openat -S truncate -S ftruncate -F exit=-EACCES -F auid>=1000 -F auid!=4294967295 -k access\n-a always,exit -F arch=b64 -S creat -S open -S openat -S truncate -S ftruncate -F exit=-EPERM -F auid>=1000 -F auid!=4294967295 -k access\n-a always,exit -F arch=b32 -S creat -S open -S openat -S truncate -S ftruncate -F exit=-EPERM -F auid>=1000 -F auid!=4294967295 -k access" > /etc/audit/rules.d/CIS-4.1.11.rules

# 4.1.13   Ensure successful filesystem mounts are collected
echo -e "-a always,exit -F arch=b64 -S mount -F auid>=1000 -F auid!=4294967295 -k mounts\n-a always,exit -F arch=b32 -S mount -F auid>=1000 -F auid!=4294967295 -k mounts" > /etc/audit/rules.d/CIS-4.1.13.rules

# 4.1.14   Ensure file deletion events by users are collected
echo -e "-a always,exit -F arch=b64 -S unlink -S unlinkat -S rename -S renameat -F auid>=1000 -F auid!=4294967295 -k delete\n-a always,exit -F arch=b32 -S unlink -S unlinkat -S rename -S renameat -F auid>=1000 -F auid!=4294967295 -k delete" > /etc/audit/rules.d/CIS-4.1.14.rules

# 4.1.15   Ensure changes to system administration scope (sudoers) is collected
echo -e "-w /etc/sudoers -p wa -k scope\n-w /etc/sudoers.d/ -p wa -k scope" > /etc/audit/rules.d/CIS-4.1.15.rules

# 4.1.16   Ensure system administrator actions (sudolog) are collected
echo -e "-w /var/log/sudo.log -p wa -k actions" > /etc/audit/rules.d/CIS-4.1.16.rules

# 4.1.17   Ensure kernel module loading and unloading is collected
echo -e "-w /sbin/insmod -p x -k modules\n-w /sbin/rmmod -p x -k modules\n-w /sbin/modprobe -p x -k modules\n-a always,exit -F arch=b64 -S init_module -S delete_module -k modules" > /etc/audit/rules.d/CIS-4.1.17.rules

# 4.1.18   Ensure the audit configuration is immutable
echo -e "-e 2" > /etc/audit/rules.d/CIS-4.1.18.rules

# 4.2.1.3  Ensure rsyslog default file permissions configured
echo "\$FileCreateMode 0640" > /etc/rsyslog.d/CIS-4.2.1.3.conf

# 4.2.1.4  Ensure rsyslog is configured to send logs to a remote host
# TODO this requires an external log server which is difficult to safely automate here
echo -e "\e[31mTODO - CIS 4.2.1.4 - Ensure rsyslog is configured to send logs to a remote host\e[0m"

# 4.2.4    Ensure permissions on log files are configured
find /var/log -type f -exec chmod g-wx,o-rwx {} +
echo -e "# CIS-4.2.4 ensure log permissions remain configured\n0 * * * * root find /var/log -type f -exec chmod g-wx,o-rwx {} +" > /etc/cron.d/CIS-4.2.4

# 5.1.2    Ensure permissions on /etc/crontab are configured
chown root:root /etc/crontab
chmod og-rwx /etc/crontab

# 5.1.3    Ensure permissions on /etc/cron.hourly are configured
chown root:root /etc/cron.hourly
chmod og-rwx /etc/cron.hourly

# 5.1.4    Ensure permissions on /etc/cron.daily are configured
chown root:root /etc/cron.daily
chmod og-rwx /etc/cron.daily

# 5.1.5    Ensure permissions on /etc/cron.weekly are configured
chown root:root /etc/cron.weekly
chmod og-rwx /etc/cron.weekly

# 5.1.6    Ensure permissions on /etc/cron.monthly are configured
chown root:root /etc/cron.monthly
chmod og-rwx /etc/cron.monthly

# 5.1.7    Ensure permissions on /etc/cron.d are configured
chown root:root /etc/cron.d
chmod og-rwx /etc/cron.d

# 5.1.8    Ensure at/cron is restricted to authorised users
rm -f /etc/cron.deny
rm -f /etc/at.deny
touch /etc/cron.allow
touch /etc/at.allow
chmod og-rwx /etc/cron.allow
chmod og-rwx /etc/at.allow
chown root:root /etc/cron.allow
chown root:root /etc/at.allow

# 5.2.4    Ensure SSH Protocol is set to 2
echo -e "\n# CIS-5.2.4\nProtocol 2" >> /etc/ssh/sshd_config

# 5.2.5    Ensure SSH LogLevel is appropriate
sed -i 's/^#*LogLevel.*/LogLevel VERBOSE/' /etc/ssh/sshd_config

# 5.2.6    Ensure SSH X11 forwarding is disabled
sed -i 's/^#*X11Forwarding.*/X11Forwarding no/' /etc/ssh/sshd_config

# 5.2.7    Ensure SSH MaxAuthTries is set to 4 or less
sed -i 's/^#*MaxAuthTries.*/MaxAuthTries 4/' /etc/ssh/sshd_config

# 5.2.8    Ensure SSH IgnoreRhosts is enabled
sed -i 's/^#*IgnoreRhosts.*/IgnoreRhosts yes/' /etc/ssh/sshd_config

# 5.2.9    Ensure SSH HostbasedAuthentication is disabled
sed -i 's/^#*HostbasedAuthentication.*/HostbasedAuthentication no/' /etc/ssh/sshd_config

# 5.2.10   Ensure SSH root login is disabled
sed -i 's/^#*PermitRootLogin.*/PermitRootLogin no/' /etc/ssh/sshd_config

# 5.2.11   Ensure SSH PermitEmptyPasswords is disabled
sed -i 's/^#*PermitEmptyPasswords.*/PermitEmptyPasswords no/' /etc/ssh/sshd_config

# 5.2.12   Ensure SSH PermitUserEnvironment is disabled
sed -i 's/^#*PermitUserEnvironment.*/PermitUserEnvironment no/' /etc/ssh/sshd_config

# 5.2.13   Ensure only strong ciphers are used
echo -e "\n# CIS-5.2.13\nCiphers aes128-ctr,aes192-ctr,aes256-ctr" >> /etc/ssh/sshd_config

# 5.2.14   Ensure only approved MAC algorithms are used
echo -e "\n# CIS-5.2.14\nMACs hmac-ripemd160,hmac-sha2-256,hmac-sha2-512,hmac-ripemd160@openssh.com" >> /etc/ssh/sshd_config

# 5.2.15   Ensure that strong Key Exchange algorithms are used
echo -e "\n# CIS-5.2.15\nKexAlgorithms diffie-hellman-group-exchange-sha256" >> /etc/ssh/sshd_config

# 5.2.16   Ensure SSH Idle Timeout Interval is configured
sed -i 's/^#*ClientAliveInterval.*/ClientAliveInterval 300/' /etc/ssh/sshd_config
sed -i 's/^#*ClientAliveCountMax.*/ClientAliveCountMax 0/' /etc/ssh/sshd_config

# 5.2.17   Ensure SSH LoginGraceTime is set to one minute or less
sed -i 's/^#*LoginGraceTime.*/LoginGraceTime 60/' /etc/ssh/sshd_config

# 5.2.18   Ensure SSH access is limited
echo -e "\n# CIS-5.2.18\nAllowUsers ec2-user\nAllowGroups wheel" >> /etc/ssh/sshd_config

# 5.2.19   Ensure SSH warning banner is configured
sed -i 's/^#*Banner.*/Banner \/etc\/issue.net/' /etc/ssh/sshd_config

# 5.3.1    Ensure password creation requirements are configured
sed -i 's/^[# ]*minlen.*/minlen = 14/' /etc/security/pwquality.conf
sed -i 's/^[# ]*dcredit.*/dcredit = -1/' /etc/security/pwquality.conf
sed -i 's/^[# ]*ucredit.*/ucredit = -1/' /etc/security/pwquality.conf
sed -i 's/^[# ]*ocredit.*/ocredit = -1/' /etc/security/pwquality.conf
sed -i 's/^[# ]*lcredit.*/lcredit = -1/' /etc/security/pwquality.conf

# 5.3.2    Ensure lockout for failed password attempts is configured
sed -i 's/auth\s*required\s*pam_env.so/auth        required      pam_faillock.so preauth audit silent deny=5 unlock_time=900/' /etc/pam.d/password-auth /etc/pam.d/system-auth
sed -i 's/auth\s*sufficient\s*pam_unix.so try_first_pass nullok/auth [success=1 default=bad] pam_unix.so\nauth [default=die] pam_faillock.so authfail audit deny=5 unlock_time=900\nauth        sufficient    pam_faillock.so authsucc audit deny=5 unlock_time=900/' /etc/pam.d/password-auth /etc/pam.d/system-auth

# 5.3.3    Ensure password reuse is limited
sed -i 's/sha512 shadow$/sha512 shadow remember=5/' /etc/pam.d/password-auth /etc/pam.d/system-auth

# 5.4.1.1  Ensure password expiration is 365 days or less
sed -i 's/^PASS_MAX_DAYS.*/PASS_MAX_DAYS 365/' /etc/login.defs

# 5.4.1.2  Ensure minimum days between password changes is 7 or more
sed -i 's/^PASS_MIN_DAYS.*/PASS_MIN_DAYS 7/' /etc/login.defs

# 5.4.1.4  Ensure inactive password lock is 30 days or less
useradd -D -f 30

# 5.4.4    Ensure default user umask is 027 or more restrictive
sed -i 's/umask [0-7][0-7][0-7]/umask 027/' /etc/bashrc /etc/profile /etc/profile.d/*.sh

# 5.4.5    Ensure default user shell timeout is 900 seconds or less
echo "export TMOUT=900" > /etc/profile.d/CIS-5.4.5.sh

# 5.6      Ensure access to the su command is restricted
sed -i 's/^#\(auth\s*required\s*pam_wheel.so\s*use_uid\)/\1/' /etc/pam.d/su

# 6.1.1    Audit system file permissions
# TODO this is pretty involved and difficult to safely automate here
echo -e "\e[31mTODO - CIS 6.1.1 - Audit system file permissions\e[0m"


echo "Harden script completed on `date`" >> /var/log/packer.log