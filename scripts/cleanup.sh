#!/usr/bin/env bash

echo -e "\e[32m################## CLEANUP ##################\e[0m"

# Cleans up files that are now hidden by new partition mounts

# bind mount to get access to underlying files
mount --bind / /mnt/home

# remove the "hidden" files
rm -fR /mnt/home/home/*
rm -fR /mnt/home/usr/*
rm -fR /mnt/home/var/*

# remove temp mount points
umount /mnt/home
rm -fR /mnt/*

yum clean all -y

echo "Cleanup script completed on `date`" >> /var/log/packer.log