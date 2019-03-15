# backupvm2
kvm incremental backup

create a bash script for single instance(backup_single.sh)

#!/bin/bash

# KVM ip address
HOST="$1"
# Domain/VM name
DOMAIN="$2"
EXCLUDED_DISKS=(test.qcow2 test1.qcow2)
LOG_LEVEL=INFO
# Destination pool which vm backup take places
POOL="fkm"
BACKUP_EXEC_PATH="/root/backupvmv2"
BACKUP_EXEC="/root/backupvmv2/backupvmv2.py"
BACKUP_VENV="/root/backupvmv2/venv/bin/activate"
# SASL for libvirt
USERNAME=admin
PASSWORD=pass


python3 $BACKUP_EXEC $HOST $DOMAIN $POOL -u $USERNAME -p $PASSWORD -e ${EXCLUDED_DISKS[*]} -v $LOG_LEVEL


--------
create script for batch (backupjob.sh)

#!/bin/bash

EXCLUDED_DOMS=(test xyz)
EXCLUDED_DISKS=(sftp-2.qcow2 sftp-1.qcow2)
LOG_LEVEL=INFO
SRC_HOSTS=(vm-kvm01 vm-kvm02 vm-kvm03 vm-kvm04 vm-kvm05 vm-kvm06 vm-kvm07 vm-kvm08 vm-kvm09 vm-kvm104)
POOL="fkm"
BACKUP_EXEC_PATH="/root/backupvmv2"
BACKUP_EXEC="/root/backupvmv2/backupvmv2.py"
BACKUP_VENV="/root/backupvmv2/venv/bin/activate"
# SASL Username passwd
USERNAME=admin
PASSWORD=passw


echo ${SRC_HOSTS[@]}
source $BACKUP_VENV

for h in ${SRC_HOSTS[@]}
do
   echo --------------- $i ----------------
   DOMS=$(virsh -c $h list --name)
   echo $DOMS
   for d in ${DOMS[@]}
   do
       if !( echo "${EXCLUDED_DOMS[*]}" | fgrep -qi "$d" )
       then
          echo "Islem sirasi: " $d - $h
          python3 $BACKUP_EXEC $h $d $POOL -u $USERNAME -p $PASSWORD -e ${EXCLUDED_DISKS[*]} -v $LOG_LEVEL
       fi

   done
done



Crontab
45 0 * * 1-7 /root/backupjob.sh > /root/backupjob-`date +\%Y\%m\%d_\%H\%M\%S`.log 2>&1
