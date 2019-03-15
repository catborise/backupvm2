
import sys, os, logging
import argparse, getpass
from vrtManager.LogFacility import Log
from datetime import datetime
from libvirt import libvirtError
from vrtManager import util
from vrtManager import connection
from vrtManager.instance import wvmInstance
from vrtManager.storage import wvmStorage



class Password(argparse.Action):
    def __call__(self, parser, namespace, values, option_string):
        if values is None:
            values = getpass.getpass()

        setattr(namespace, self.dest, values)


def start_backup(inst: wvmInstance, pool: wvmStorage, excluded_disk_list: list, force_full=False, compress=False, merge=True):
    pool.refresh()
    image_info_list = util.prepare_img_info_list(inst, pool, excluded_disk_list)

    log.debug("Backup candidates of disks : {}".format(image_info_list or "Not Found"))

    for image_info in image_info_list:
        try:
            if force_full:
                inst.backup_disk(image_info, "full", pool, compress)  # forcefully do full backup
            elif pool.is_vol_exist(image_info["base"]):
                if inst.get_dirty_bitmap(image_info) is None:  # full backup alinmis fakat dirty block halihazirda yok
                    inst.backup_disk(image_info, "full", pool, compress)
                else:  # full backup alinmis ve dirty block var
                    inc_info = util.prepare_inc_info(image_info)
                    inst.backup_disk(inc_info, "inc", pool, compress, merge)
            elif os.path.exists(image_info["base"]) and not os.path.isdir(image_info["base"]):
                if inst.get_dirty_bitmap(image_info) is None:  # full backup alinmis fakat dirty block halihazirda yok
                    inst.backup_disk(image_info, "full", pool, compress)
                else:  # full backup is done and dirty block is exist
                    inc_info = util.prepare_inc_info(image_info)
                    inst.backup_disk(inc_info, "inc", pool, compress, merge)
            else:
                inst.backup_disk(image_info, "full", pool, compress)  # base imaj yok full alinmasi gerek
        except libvirtError as le:
            log.error("Backup operation failed: %s" % le.get_error_message())
            log.error("Created image is deleting...")
            pool.delete_volume_with_info(image_info)
            return 1

    inst.backup_xml(pool)


def main(argv):
    parser = argparse.ArgumentParser("Backup KVM domain to destination pool Full or incrementally")

    parser.add_argument("host", help="DNS name or ip address of KVM host")
    parser.add_argument("domain", help="Domain name")
    parser.add_argument("pool", help="Destination Pool Name")
    parser.add_argument('-u', '--username', dest='username', required=True, help="Username for libvirt connection.")
    parser.add_argument('-p', action=Password, nargs='?', dest='password', help='Enter your password for libvirt connection')
    parser.add_argument('-f', '--force', dest='force', action="store_true", help="Force to make a full backup. Else it decides backup type")
    parser.add_argument('-m', '--not-merge', dest="merge", action="store_false", help="Destination Pool Name")
    parser.add_argument('-t', '--conntype', dest='conntype', default='TCP', choices=['SSH', 'TCP', 'TLS'], type=str, help="Connection type of libvirt")
    parser.add_argument('-c', '--compress', dest='compress', action="store_true", help="Compress Disk Images of Domain")
    parser.add_argument('-e', '--exclude', dest='exclude', nargs="+", type=str, help="Exclude specified disks of domain. ex: -e abc.qcow2 bcd.qcow2")
    parser.add_argument('-v', '--verbose', dest='verbose', default='INFO',
                        choices=['DEBUG', 'INFO', 'WARNING', 'ERROR', 'CRITICAL'], type=str, help="Log level of application")
    args = parser.parse_args()

    if not (os.path.exists("log") and os.path.isdir("log")):
        os.mkdir("log")

    Log(args.verbose, args.domain)
    global log
    log = logging.getLogger("BackupLogs")

    try:
        conn_type = getattr(connection,"CONN_"+args.conntype)
        pool = wvmStorage(args.host, args.username, args.password, conn_type, args.pool)
        inst = wvmInstance(args.host, args.username, args.password, conn_type, args.domain)

        log.info("Dom UUID: {}".format(inst.get_uuid()))
        log.info("Dom Disk Device: {}".format(inst.get_disk_device()))
        log.info("Pool Name: {}, {} ".format(pool.get_name(), pool.get_pretty_capacity()))
        log.info("Excluded Disks: {}".format(args.exclude))

        start = datetime.now()
        start_backup(inst, pool, args.exclude, args.force, args.compress, args.merge)

        log.info("Backup of {} Completion Time: {} sec. ".format(args.domain, str(datetime.now() - start)))

    except libvirtError as err:
        log.error(err.get_error_message())
        exit(1)


if __name__ == '__main__':
    sys.exit(main(sys.argv))
