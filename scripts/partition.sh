#!/usr/bin/env bash

echo -e "\e[32m################## PARTITION ##################\e[0m"

# Creates CIS compliant partitions
# See https://techgirlkb.guru/2019/08/how-to-create-cis-compliant-partitions-on-aws/

lsblk

VOL=xvdf

# create the partitions
mkfs -t ext4 /dev/${VOL}
parted --script /dev/${VOL} mklabel gpt
parted --script --align=opt /dev/${VOL} mkpart vartmp ext4 2MB 5% 
parted --script --align=opt /dev/${VOL} mkpart swap linux-swap 5% 10% 
parted --script --align=opt /dev/${VOL} mkpart home ext4 10% 15% 
parted --script --align=opt /dev/${VOL} mkpart usr ext4 15% 45% 
parted --script --align=opt /dev/${VOL} mkpart varlogaudit ext4 45% 55% 
parted --script --align=opt /dev/${VOL} mkpart varlog ext4 55% 65% 
parted --script --align=opt /dev/${VOL} mkpart var ext4 65% 100% 
parted --script /dev/${VOL} unit GiB
for I in 1 3 4 5 6 7; do mkfs.ext4 /dev/${VOL}${I}; done

# mount them to temporary locations
mkswap /dev/${VOL}2
mkdir -p /mnt/vartmp /mnt/home /mnt/usr /mnt/varlogaudit /mnt/varlog /mnt/var
mount /dev/${VOL}1 /mnt/vartmp
mount /dev/${VOL}3 /mnt/home
mount /dev/${VOL}4 /mnt/usr
mount /dev/${VOL}5 /mnt/varlogaudit
mount /dev/${VOL}6 /mnt/varlog
mount /dev/${VOL}7 /mnt/var

# rsync existing contents into new partitions
# see cleanup.sh for the later removal of the source files
rsync -a /var/tmp/ /mnt/vartmp/ 
rsync -a /home/ /mnt/home/ 
rsync -a /usr/ /mnt/usr/ 
rsync -a /var/log/audit/ /mnt/varlogaudit/ 
rsync -a --exclude=audit /var/log/ /mnt/varlog/ 
rsync -a --exclude=log --exclude=tmp /var/ /mnt/var/

# set folder permissions
mkdir /mnt/var/log 
mkdir /mnt/var/tmp
mkdir /mnt/var/log/audit 
mkdir /mnt/varlog/audit 
chmod 755 /mnt/var/log
chmod 755 /mnt/var/tmp 
chmod 755 /mnt/var/log/audit 
chmod 755 /mnt/varlog/audit

# setup tmp mount
systemctl unmask tmp.mount 
systemctl enable tmp.mount 
sed -i 's/^Options=.*/Options=mode=1777,strictatime,noexec,nodev,nosuid/' /etc/systemd/system/local-fs.target.wants/tmp.mount

# function to get the UUID for a given partition
get_uuid() {
    blkid | grep '"'$1'"' | awk '{ print $2 }' | tr -d '"'
} 

# add /etc/fstab lines for all of the new partition mounts
echo $(get_uuid home) /home ext4 defaults,noatime,acl,user_xattr,nodev,nosuid 0 2 >> /etc/fstab
echo $(get_uuid usr) /usr ext4 defaults,noatime,nodev,errors=remount-ro 0 2 >> /etc/fstab
echo $(get_uuid varlogaudit) /var/log/audit ext4 defaults,noatime,nodev,nosuid 0 2 >> /etc/fstab
echo $(get_uuid varlog) /var/log ext4 defaults,noatime,nodev,nosuid 0 2 >> /etc/fstab
echo $(get_uuid var) /var ext4 defaults,noatime,nodev,nosuid 0 2 >> /etc/fstab
echo $(get_uuid swap) swap swap defaults 0 0 >> /etc/fstab
echo $(get_uuid vartmp) /var/tmp ext4 defaults,noatime,nodev,nosuid,noexec 0 0 >> /etc/fstab
echo tmpfs /dev/shm tmpfs defaults,nodev,nosuid,noexec 0 0 >> /etc/fstab
echo tmpfs /tmp tmpfs defaults,noatime,nodev,noexec,nosuid,size=256m 0 0 >> /etc/fstab

echo "Provision script completed on `date`" >> /var/log/packer.log

# reboot so fstab mounts are used going forward
echo "# RESTARTING TO APPLY PARTITIONS #"
touch /.autorelabel;reboot