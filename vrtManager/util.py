#
# Copyright (C) 2013 Webvirtmgr.
#
import random
import lxml.etree as etree
import libvirt
import json, logging, os, subprocess, shlex
from libvirt_qemu import qemuMonitorCommand
from time import sleep
from sys import stdout
from datetime import datetime
import re




def is_kvm_available(domain_xml):
    kvm_domains = get_xml_path(domain_xml, "//domain/@type='kvm'")
    if kvm_domains > 0:
        return True
    else:
        return False


def randomMAC():
    """Generate a random MAC address."""
    # qemu MAC
    oui = [0x52, 0x54, 0x00]

    mac = oui + [random.randint(0x00, 0xff),
                 random.randint(0x00, 0xff),
                 random.randint(0x00, 0xff)]
    return ':'.join(map(lambda x: "%02x" % x, mac))


def randomUUID():
    """Generate a random UUID."""

    u = [random.randint(0, 255) for dummy in range(0, 16)]
    return "-".join(["%02x" * 4, "%02x" * 2, "%02x" * 2, "%02x" * 2, "%02x" * 6]) % tuple(u)


def get_max_vcpus(conn, type=None):
    """@param conn: libvirt connection to poll for max possible vcpus
       @type type: optional guest type (kvm, etc.)"""
    if type is None:
        type = conn.getType()
    try:
        m = conn.getMaxVcpus(type.lower())
    except libvirt.libvirtError:
        m = 32
    return m


def xml_escape(str):
    """Replaces chars ' " < > & with xml safe counterparts"""
    if str is None:
        return None

    str = str.replace("&", "&amp;")
    str = str.replace("'", "&apos;")
    str = str.replace("\"", "&quot;")
    str = str.replace("<", "&lt;")
    str = str.replace(">", "&gt;")
    return str


def compareMAC(p, q):
    """Compare two MAC addresses"""
    pa = p.split(":")
    qa = q.split(":")

    if len(pa) != len(qa):
        if p > q:
            return 1
        else:
            return -1

    for i in range(len(pa)):
        n = int(pa[i], 0x10) - int(qa[i], 0x10)
        if n > 0:
            return 1
        elif n < 0:
            return -1
    return 0


def get_xml_path(xml, path=None, func=None):
    """
    Return the content from the passed xml xpath, or return the result
    of a passed function (receives xpathContext as its only arg)
    """
    #doc = None
    #ctx = None
    #result = None

    #try:
    doc = etree.fromstring(xml)

    #ctx = doc.xpathNewContext()

    if path:
        #ret = ctx.xpathEval(path)
        ret = doc.xpath(path)

        if ret is not None:
            if type(ret) == list:
                if len(ret) >= 1:
                    result = ret[0].text
            else:
                result = ret

    elif func:
        result = func(doc)

    else:
        raise ValueError("'path' or 'func' is required.")


    #finally:
    #    if doc:
    #        doc.freeDoc()
    #    if ctx:
    #        ctx.xpathFreeContext()
    return result


def pretty_mem(val):
    val = int(val)
    if val > (10 * 1024 * 1024):
        return "%2.2f GB" % (val / (1024.0 * 1024.0))
    else:
        return "%2.0f MB" % (val / 1024.0)


def pretty_bytes(val):
    val = int(val)
    if val > (1024 * 1024 * 1024):
        return "%2.2f GB" % (val / (1024.0 * 1024.0 * 1024.0))
    else:
        return "%2.2f MB" % (val / (1024.0 * 1024.0))


def exec_monitor_command(inst, execute_str: str):
    query_results = json.loads(qemuMonitorCommand(inst, execute_str, 0))
    #if len(query_results['return']) == 0:
    #    return None
    return query_results


def block_job_progress(dom):
    while True:
        info = json.loads(qemuMonitorCommand(dom, '{"execute":"query-block-jobs"}', 0))
        if len(info['return']) == 0:
            break

        bar_length = 50
        for i in info['return']:
            start = i['offset']
            end = i['len']
            percent = float(start) / float(end)
            hashes = '#' * int(round(percent * bar_length))
            spaces = '-' * (bar_length - len(hashes))
            stdout.write(
                "\r[{0}] {1}/{2} ({3}%)".format(
                    hashes + spaces,
                    start,
                    end,
                    int(round(percent * 100))
                )
            )
            stdout.flush()
            sleep(2)
        start = end
        percent = float(start) / float(end)
        hashes = '#' * int(round(percent * bar_length))
        spaces = '-' * (bar_length - len(hashes))
        stdout.write(
            "\r[{0}] {1}/{2} ({3}%)".format(
                hashes + spaces,
                start,
                end,
                int(round(percent * 100))
            )
        )
        stdout.flush()
    stdout.write("!\n")


def prepare_block_inc_drive_backup_str(image_info: dict, compress=False):
    type_str = dict()
    type_str["execute"] = "drive-backup"
    type_str["arguments"] = {
        "device": image_info["node"],
        "bitmap": image_info["bitmap"],
        "target": image_info["target"],
        "format": "qcow2",
        "sync": "incremental",
        "mode": "existing",
        "compress": compress
    }
    return json.dumps(type_str)


def prepare_block_bitmap_add_str(image_info, compress=False, persistent=True):
    type_str = dict()

    type_str["execute"] = "transaction"
    type_str["arguments"] = {
        "actions":
            [{
                "type": "block-dirty-bitmap-add",
                "data": {
                    "node": image_info["node"],
                    "name": image_info["bitmap"],
                    "autoload": True,
                    "persistent": persistent # since 2.10
                }
            },
                {
                    "type": "drive-backup",
                    "data": {
                        "device": image_info["node"],
                        "target": image_info["target"],
                        "format": "qcow2",
                        "sync": "full",
                        "compress": compress
                    }
                }]
    }

    return json.dumps(type_str)


def prepare_block_bitmap_remove_str(image_info: dict):
    cmd_str = dict()

    cmd_str["execute"] = "block-dirty-bitmap-remove"
    cmd_str["arguments"] = {
        "node": image_info["node"],
        "name": image_info["bitmap"]
    }

    return json.dumps(cmd_str)


def prepare_img_info_list(inst, pool, excluded_disk_list=list()):
    image_info_list = list()

    for idx, file in enumerate(inst.get_block_device()):
        if file["fullname"] in (excluded_disk_list or list()):
            continue

        image_info = dict()
        image_info['name'] = file["fullname"]
        image_info['node'] = file["device"]
        image_info['target'] = pool.get_target_path() + "/" + image_info["name"]
        image_info['base'] = image_info["target"]
        #image_info['bitmap'] = image_info["name"] # make bitmap name like filename usually others does bitmapX
        image_info['bitmap'] = "bitmap" + str(idx)
        image_info['file'] = file['file']

        image_info_list.append(image_info)

    return image_info_list


def prepare_inc_info(image_info: dict):
    suffix = datetime.now().strftime("%Y%m%d_%H%M%S")
    image_info["suffix"] = suffix
    image_info["name"] += "_" + image_info["suffix"]
    image_info["target"] += "_" + image_info["suffix"]
    return image_info


def check_active_progress(dom):
    info = json.loads(qemuMonitorCommand(dom, '{"execute":"query-block-jobs"}', 0))
    if len(info['return']) == 0:
        return False
    return True


class DiskImageHelper(object):
    @staticmethod
    def get_backing_file(file: str):
        """ Gets backing file for disk image """
        get_backing_file_cmd = "qemu-img info %s" % file
        logging.warning("Executing: '%s'" % get_backing_file_cmd)
        out = subprocess.check_output(shlex.split(get_backing_file_cmd))
        lines = out.decode('utf-8').split('\n')
        for line in lines:
            if re.search("backing file:", line):
                return line.strip().split()[2]
        return None

    @staticmethod
    def get_img_size(file: str):
        """ Gets disk image size info """
        get_info_cmd = "qemu-img info %s" % file
        logging.warning("Executing: '%s'" % get_info_cmd)
        out = subprocess.check_output(shlex.split(get_info_cmd))
        lines = out.decode('utf-8').split('\n')
        for line in lines:
            if re.search("disk size:", line):
                return line.strip().split()[2]
        return None

    @staticmethod
    def get_backing_files_tree(file: str):
        """ Gets all backing files (snapshot tree) for disk image """
        backing_files = []
        backing_file = DiskImageHelper.get_backing_file(file)
        while backing_file is not None:
            backing_files.append(backing_file)
            backing_file = DiskImageHelper.get_backing_file(backing_file)
        return backing_files

    @staticmethod
    def delete_committed_file_tree(file: str):
        """ Keeps only base backing file deletes others """
        backing_file = DiskImageHelper.get_backing_file(file)
        if backing_file is not None:
            DiskImageHelper.delete_file(file)
            DiskImageHelper.delete_backing_files_tree(backing_file)
            logging.warning("Deleted %s" % file)
            return

    @staticmethod
    def set_backing_file(backing_file: str, file: str):
        """ Sets backing file for disk image """
        set_backing_file_cmd = "qemu-img rebase -u -b %s %s" % (backing_file, file)
        logging.warning("Executing: '%s'" % set_backing_file_cmd)
        subprocess.check_output(shlex.split(set_backing_file_cmd))

    @staticmethod
    def compare_files(file1: str, file2: str):
        """ compares disk file """
        comparing_file_cmd = "qemu-img compare %s %s" % (file1, file2)
        logging.warning("Comparing: '%s'" % comparing_file_cmd)
        subprocess.check_output(shlex.split(comparing_file_cmd))

    @staticmethod
    def delete_file(file: str):
        """ Delete backing file for disk image """
        try:
            os.remove(file)
            logging.warning("Deleted: '%s'" % file)
        except OSError as e:
            logging.error("Error: %s - %s." % (e.filename, e.strerror))

    @staticmethod
    def delete_backing_files_tree(file: str):
        """ Removes all backing files (snapshot tree) for disk image """
        backing_files = DiskImageHelper.get_backing_files_tree(file)
        for backing_file in backing_files:
            DiskImageHelper.delete_file(backing_file)
        logging.warning("Deleted all backing tree: '%s'" % file)

    @staticmethod
    def commit_all(file: str):
        """ commit to flat the file  """
        commit_all_file_cmd = "qemu-img commit %s" % (file)
        logging.warning("Executing: '%s'" % commit_all_file_cmd)
        subprocess.check_output(shlex.split(commit_all_file_cmd))

    @staticmethod
    def commit_backing_file(backing_file: str, file: str):
        """ commit top image to base """
        commit_backing_file_cmd = "qemu-img commit -b %s %s" % (backing_file, file)
        logging.warning("Executing: '%s'" % commit_backing_file_cmd)
        subprocess.check_output(shlex.split(commit_backing_file_cmd))