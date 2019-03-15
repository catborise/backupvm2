# backupvm2
Linux KVM incremental backup/replication.

Create a pool(eg. backup, fkm) for all KVM hosts. Start pool.

Prepare access for kvm hosts - create aliases
```
cat << EOF > .config/libvirt/libvirt.conf


uri_aliases = [
   "vm-kvm09=qemu+ssh://10.20.30.113/system",
   "vm-kvm08=qemu+ssh://10.20.30.112/system",
   "vm-kvm07=qemu+ssh://10.20.30.111/system",
   "vm-kvm06=qemu+ssh://10.20.30.110/system",
   "vm-kvm05=qemu+ssh://10.20.30.109/system",
   "vm-kvm04=qemu+ssh://10.20.30.108/system",
   "vm-kvm03=qemu+ssh://10.20.30.107/system",
   "vm-kvm02=qemu+ssh://10.20.30.106/system",
   "vm-kvm01=qemu+ssh://10.20.30.105/system",
 ]
EOF
```

create a bash script for single instance(backup_single.sh)
```
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
# SASL/SSH for libvirt (depend on aliases)
USERNAME=admin
PASSWORD=pass


python3 $BACKUP_EXEC $HOST $DOMAIN $POOL -u $USERNAME -p $PASSWORD -e ${EXCLUDED_DISKS[*]} -v $LOG_LEVEL
```

--------
create script for batch (backupjob.sh)
```
#!/bin/bash

EXCLUDED_DOMS=(test xyz)
EXCLUDED_DISKS=(sftp-2.qcow2 sftp-1.qcow2)
LOG_LEVEL=INFO
SRC_HOSTS=(vm-kvm01 vm-kvm02 vm-kvm03 vm-kvm04 vm-kvm05 vm-kvm06 vm-kvm07 vm-kvm08 vm-kvm09 vm-kvm104)
POOL="fkm"
BACKUP_EXEC_PATH="/root/backupvmv2"
BACKUP_EXEC="/root/backupvmv2/backupvmv2.py"
BACKUP_VENV="/root/backupvmv2/venv/bin/activate"
# SASL/SSH Username passwd (depend on aliases)
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
```


Crontab
```
45 0 * * 1-7 /root/backupjob.sh > /root/backupjob-`date +\%Y\%m\%d_\%H\%M\%S`.log 2>&1
```
