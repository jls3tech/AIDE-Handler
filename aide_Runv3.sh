#!/bin/bash

#######
# AIDE Handler v3
# 03/01/2017
# TechJLS3
# Rotates AIDE databases, Parses AIDE logs for easier Splunk ingestion
# Use: Install AIDE "yum install aide" then set up a cron job to run this script.
#######

#Variables
today_date=$(date +%F)
Day_of_week=$(date +%a)
AIDE_File_Name="AIDE_Log_$today_date.txt"
AIDE_Splunk_Log="AIDE_Log_$today_date.csv"
AIDE_Log_Dir="/var/log/aide/"

#Functions
function parse {
#For Splunk, comment out if needed. Execute file Parsing and saving file as CSV.
if [ "$1" != "DOW" ]; then
	echo "State,Path" > /var/log/aide/$AIDE_Splunk_Log
	cat /var/log/aide/$AIDE_File_Name | grep 'changed\|added\|removed'|sed -r 's/://g'|sed -r 's/ /,/g' >> /var/log/aide/$AIDE_Splunk_Log
else
	AIDE_Splunk_Log="AIDE_Log_Baseline_$today_date.csv"
	AIDE_File_Name="AIDE_Log_Baseline_$today_date.txt"
	echo "State,Path" > /var/log/aide/$AIDE_Splunk_Log
	cat /var/log/aide/$AIDE_File_Name | grep 'changed\|added\|removed'|sed -r 's/://g'|sed -r 's/ /,/g' >> /var/log/aide/$AIDE_Splunk_Log
fi
}

function writeConf {
echo '# Example configuration file for AIDE.

@@define DBDIR /var/lib/aide
@@define LOGDIR /var/log/aide

# The location of the database to be read.
database=file:@@{DBDIR}/aide.db.gz

# The location of the database to be written.
#database_out=sql:host:port:database:login_name:passwd:table
#database_out=file:aide.db.new
database_out=file:@@{DBDIR}/aide.db.new.gz

# Whether to gzip the output to database.
gzip_dbout=yes

# Default.
verbose=5

report_url=file:@@{LOGDIR}/aide.log
report_url=stdout
#report_url=stderr
#NOT IMPLEMENTED report_url=mailto:root@foo.com
#NOT IMPLEMENTED report_url=syslog:LOG_AUTH

# These are the default rules.
#
#p:      permissions
#i:      inode:
#n:      number of links
#u:      user
#g:      group
#s:      size
#b:      block count
#m:      mtime
#a:      atime
#c:      ctime
#S:      check for growing size
#acl:           Access Control Lists
#selinux        SELinux security context
#xattrs:        Extended file attributes
#md5:    md5 checksum
#sha1:   sha1 checksum
#sha256:        sha256 checksum
#sha512:        sha512 checksum
#rmd160: rmd160 checksum
#tiger:  tiger checksum
#haval:  haval checksum (MHASH only)
#gost:   gost checksum (MHASH only)
#crc32:  crc32 checksum (MHASH only)
#whirlpool:     whirlpool checksum (MHASH only)

FIPSR = p+i+n+u+g+s+m+c+acl+selinux+xattrs+sha256

#R:             p+i+n+u+g+s+m+c+acl+selinux+xattrs+md5
#L:             p+i+n+u+g+acl+selinux+xattrs
#E:             Empty group
#>:             Growing logfile p+u+g+i+n+S+acl+selinux+xattrs

# You can create custom rules like this.
# With MHASH...
# ALLXTRAHASHES = sha1+rmd160+sha256+sha512+whirlpool+tiger+haval+gost+crc32
ALLXTRAHASHES = sha1+rmd160+sha256+sha512+tiger

# Everything but access time (Ie. all changes)
EVERYTHING = R+ALLXTRAHASHES

# Sane, with one good hash.
# NORMAL = sha256
NORMAL = sha256+p

# For directories, dont bother doing hashes.
#DIR = p+i+n+u+g+acl+selinux+xattrs

# Access control only.
PERMS = p+u+g+acl+selinux+xattrs

# Access + inode changes + file type.
# STATIC = p+u+g+acl+selinux+xattrs+i+n+b+c+ftype

# Logfiles only check access w/o xattrs.
LOG = p

# Content + file type.
# CONTENT = sha256+ftype

# Extended content + file type + access.
# CONTENT_EX = sha256+ftype+p+u+g+n+acl+selinux+xattrs

# Some files get updated automatically, so the inode/ctime/mtime change
# but we want to know when the data inside them changes.
# DATAONLY =  p+n+u+g+s+acl+selinux+xattrs+sha256

# Next decide what directories/files you want in the database. Aide
# uses a first match system. Put file specific instructions before generic
# matches. e.g. Put file matches before directories.

/boot/   NORMAL
/bin/    NORMAL
/sbin/   NORMAL
/lib/    NORMAL
/lib64/  NORMAL
/opt/    NORMAL
/home/    NORMAL

# Admins dot files constantly change, just check perms.
/root/ NORMAL
!/root/\..* NORMAL
# Otherwise get all of /root.
#/root/   CONTENT_EX

# These are too volatile.
!/usr/src/ NORMAL
!/usr/tmp/ NORMAL
# Otherwise get all of /usr.
/usr/    NORMAL

# Check only permissions, user, group, seliunx for /etc, but
# cover some important files closely.
#!/etc/mtab$

# Ignore backup files
#!/etc/.*~

# trusted databases
/etc/hosts$ NORMAL
/etc/host.conf$ NORMAL
/etc/hostname$ NORMAL
/etc/issue$ NORMAL
/etc/issue.net$ NORMAL
/etc/protocols$ NORMAL
/etc/services$ NORMAL
/etc/localtime$ NORMAL
/etc/alternatives/ NORMAL
/etc/mime.types$ NORMAL
/etc/terminfo/ NORMAL
/etc/exports$  NORMAL
/etc/fstab$    NORMAL
/etc/passwd$   NORMAL
/etc/group$    NORMAL
/etc/gshadow$  NORMAL
/etc/shadow$   NORMAL
/etc/security/opasswd$   NORMAL
/etc/skel/ NORMAL

# networking
/etc/hosts.allow$   NORMAL
/etc/hosts.deny$    NORMAL
/etc/firewalld/ NORMAL
/etc/NetworkManager/ NORMAL
/etc/networks$ NORMAL
/etc/dhcp/ NORMAL
/etc/wpa_supplicant/ NORMAL
/etc/resolv.conf$ NORMAL
/etc/nscd.conf$ NORMAL

# logins and accounts
/etc/login.defs$ NORMAL
/etc/libuser.conf$ NORMAL
/var/log/faillog$ NORMAL
/var/log/lastlog$ NORMAL
/var/run/faillock/ NORMAL
/etc/pam.d/ NORMAL
/etc/security$ NORMAL
/etc/securetty$ NORMAL
/etc/polkit-1/ NORMAL
/etc/sudo.conf$ NORMAL
/etc/sudoers$ NORMAL
/etc/sudoers.d/ NORMAL

# Shell/X starting files
/etc/profile$ NORMAL
/etc/profile.d/ NORMAL
/etc/bashrc$ NORMAL
/etc/bash_completion.d/ NORMAL
/etc/zprofile$ NORMAL
/etc/zshrc$ NORMAL
/etc/zlogin$ NORMAL
/etc/zlogout$ NORMAL
/etc/X11/ NORMAL
/etc/shells$ NORMAL

# Pkg manager
/etc/yum.conf$ NORMAL
/etc/yumex.conf$ NORMAL
/etc/yumex.profiles.conf$ NORMAL
/etc/yum/ NORMAL
/etc/yum.repos.d/ NORMAL

# This gets new/removes-old filenames daily.
!/var/log/sa/
# As we are checking it, weve truncated yesterdays size to zero.
!/var/log/aide.log

# auditing
# AIDE produces an audit record, so this becomes perpetual motion.
# /var/log/audit/ PERMS+ANF+ARF
/etc/audit/ NORMAL
/etc/audisp/ NORMAL
/etc/libaudit.conf$ NORMAL
/etc/aide.conf$  NORMAL

# System logs
/etc/rsyslog.conf$ NORMAL
/etc/rsyslog.d/ NORMAL
/etc/logrotate.conf$ NORMAL
/etc/logrotate.d/ NORMAL
/var/log/ LOG
/var/run/utmp$ LOG

# secrets
/etc/pkcs11/ NORMAL
/etc/pki/ NORMAL
/etc/ssl/ NORMAL
/etc/certmonger/ NORMAL

# init system
/etc/systemd/ NORMAL
/etc/sysconfig/ NORMAL
/etc/rc.d/ NORMAL
/etc/tmpfiles.d/ NORMAL
/etc/machine-id$ NORMAL

# boot config
/etc/grub.d/ NORMAL
/etc/grub2.cfg$ NORMAL
/etc/dracut.conf$ NORMAL
/etc/dracut.conf.d/ NORMAL

# glibc linker
/etc/ld.so.cache$ NORMAL
/etc/ld.so.conf$ NORMAL
/etc/ld.so.conf.d/ NORMAL

# kernel config
/etc/sysctl.conf$ NORMAL
/etc/sysctl.d/ NORMAL
/etc/modprobe.d/ NORMAL
/etc/modules-load.d/ NORMAL
/etc/depmod.d/ NORMAL
/etc/udev/ NORMAL
/etc/crypttab$ NORMAL

#### Daemons ####

# cron jobs
/var/spool/at/ NORMAL
/etc/at.allow$ NORMAL
/etc/at.deny$ NORMAL
/etc/cron.allow$ NORMAL
/etc/cron.deny$ NORMAL
/etc/cron.d/ NORMAL
/etc/cron.daily/ NORMAL
/etc/cron.hourly/ NORMAL
/etc/cron.monthly/ NORMAL
/etc/cron.weekly/ NORMAL
/etc/crontab$ NORMAL
/var/spool/cron/root/ NORMAL
/etc/anacrontab$ NORMAL

# time keeping
/etc/ntp.conf$ NORMAL
/etc/ntp/ NORMAL
/etc/chrony.conf$ NORMAL
/etc/chrony.keys$ NORMAL

# mail
/etc/aliases$ NORMAL
/etc/aliases.db$ NORMAL
/etc/postfix/ NORMAL
/etc/mail.rc$ NORMAL
/etc/mailcap$ NORMAL

# ssh
/etc/ssh/sshd_config$ NORMAL
/etc/ssh/ssh_config$ NORMAL

# stunnel
/etc/stunnel/ NORMAL

# ftp
/etc/vsftpd.conf$ NORMAL
/etc/vsftpd/ NORMAL

# printing
/etc/cups/ NORMAL
/etc/cupshelpers/ NORMAL
/etc/avahi/ NORMAL

# web server
/etc/httpd/ NORMAL

# dns
/etc/named/ NORMAL
/etc/named.conf$ NORMAL
/etc/named.iscdlv.key$ NORMAL
/etc/named.rfc1912.zones$ NORMAL
/etc/named.root.key$ NORMAL

# xinetd
/etc/xinetd.d/ NORMAL

# Now everything else in /etc.
/etc/    PERMS

# With AIDEs default verbosity level of 5, these would give lots of
# warnings upon tree traversal. It might change with future version.
#
#=/lost\+found    DIR
#=/home           DIR

# Ditto /var/log/sa/ same reason...
!/var/log/httpd/
' > /etc/aide.conf
echo "Updated Conf file" >> /var/log/aide/aide.log
}

#Checks to ensure AIDE is present on the system
if [ ! -f "/usr/sbin/aide" ]; then
	yum -y install aide > /dev/null 2>&1
	if [ -f "/usr/sbin/aide" ]; then
		echo "AIDE INSTALLED, Needs updated conf" >> /var/log/aide/aide.log
		writeConf
		/usr/sbin/aide --init --config=/etc/aide.conf > /dev/null 2>&1
		cp /var/lib/aide/aide.db.new.gz /var/lib/aide/aide.db.gz
	else
		echo "AIDE NOT PRESENT on system" >> /var/log/aide/aide.log
		exit 1
	fi	
fi

#Check for Var log location for AIDE Logs otherwise make it.
if [ ! -d "$AIDE_Log_Dir" ]; then
	mkdir "$AIDE_Log_Dir"
fi

#Compare SHA256 of Conf
SHAComp=$(sha256sum /etc/aide.conf|egrep -o '[a-fA-F0-9]{64}')
if [ "$SHAComp" != "353073d3530a9bc25dabe285cf954414f68b2aa23b8b96846fd1d779a5f6f699" ]; then
	writeConf
fi

#Run AIDE Check and Save Results in a Dated File

/usr/sbin/aide --check --config=/etc/aide.conf > /var/log/aide/$AIDE_File_Name
parse

#Backup current database as a dated DB
cp /var/lib/aide/aide.db.gz /var/lib/aide/aide.db.$today_date.gz
rm -f /var/lib/aide/aide.db.gz

#Weekly baseline comparison. Comment out if not needed.
#Check if today is day of choice if so, reload baseline DB
if [ "$Day_of_week" = "Wed" ]; then
	AIDE_File_Name="AIDE_Log_Baseline_$today_date.txt"
	#Checks for the baseline DB if there compare, if not writes to file.	
	if [ -f /var/lib/aide/aide.db.Baseline.gz ]; then
		cp /var/lib/aide/aide.db.Baseline.gz /var/lib/aide/aide.db.gz
		/usr/sbin/aide --check --config=/etc/aide.conf > /var/log/aide/$AIDE_File_Name
		parse DOW	
	else
		echo "No defined Baseline DB" > /var/log/aide/$AIDE_File_Name
	fi
fi

#Generate new database based on current system settings
/usr/sbin/aide --init --config=/etc/aide.conf > /dev/null 2>&1
cp /var/lib/aide/aide.db.new.gz /var/lib/aide/aide.db.gz
rm -f /var/lib/aide/aide.db.new.gz

#Delete old Backup DBs after 90 days.
find /var/lib/aide/ -type f -name "*.gz" -mtime +90|grep -v Baseline|xargs rm -rf;

#Remove txt file
find /var/log/aide/ -type f -name "*.txt" -mtime +30|xargs rm -rf;

#Remove CSV files after 90 days
find /var/log/aide/ -type f -name "*.csv" -mtime +30|xargs rm -rf;
