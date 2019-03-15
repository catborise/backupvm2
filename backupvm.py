import sys, os, json
import libvirt
from xml.etree import ElementTree as ET
from libvirt_qemu import qemuMonitorCommand
from time import time, sleep
from datetime import datetime
import Retention
import logging, subprocess, shlex, re


class Connection(object):

    def __init__(self, uri, sasl_user, sasl_pass):
        self.uri = uri
        self.sasl_user = sasl_user
        self.sasl_pass = sasl_pass

    def connect(self):
        auth = [[libvirt.VIR_CRED_AUTHNAME, libvirt.VIR_CRED_PASSPHRASE], self.request_cred, None]
        conn = libvirt.openAuth(self.uri, auth, 0)

        if conn == None:
            print("cannot connect")
            return 0
        return conn

    def request_cred(self, credentials, user_data):
        for credential in credentials:
            if credential[0] == libvirt.VIR_CRED_AUTHNAME:
                credential[4] = self.sasl_user
            elif credential[0] == libvirt.VIR_CRED_PASSPHRASE:
                credential[4] = self.sasl_pass
        return 0

    def close(self):
        self.close()


class Pool(object):
    def __init__(self, conn, pool_name: str):
        self.conn = conn
        self.poolName = pool_name
        try:
            self.pool = self.conn.storagePoolLookupByName(self.poolName)
            self.poolXML = self.pool.XMLDesc(0)
        except libvirt.libvirtError:
            print("belirtilen pool bulunamadi: " +self.poolName)
            self.pool = None
            exit(1)

        root = ET.fromstring(self.poolXML)
        self.path = root.find('target/path').text
        self.capacity = root.find('capacity').text
        self.available = root.find('available').text

    def pool_check(self):
        return self.pool

    def pool_refresh(self):
        self.pool.refresh(0)

    def is_vol_exist(self, image_fullname: str):
        self.pool.refresh(0)
        _, fname = os.path.split(image_fullname)
        try:
            ret = self.pool.storageVolLookupByName(fname)
        except libvirt.libvirtError:
            return None

        return ret

    def print_volume_list(self, vol_name):
        for vol in self.pool.listVolumes():
            print("volumes :" + vol)

    def delete_volume(self, vol_name):
        vol = self.is_vol_exist(self, vol_name)
        if vol:

            return True
        else:
            return False

    def _create_volume(self, name, backing_fullname, img_format="qcow2"):

        stpVolXml = """
         <volume>
           <name>""" + name + """</name>
           <allocation>0</allocation>
           <target>
             <path>""" + os.getcwd() + "/" + name + """</path>
             <permissions>
               <owner>107</owner>
               <group>107</group>
               <mode>0744</mode>
               <label>virt_image_t</label>
             </permissions>
             <format type='""" + img_format + """'/>
           </target>
           <backingStore>
             <path>""" + backing_fullname + """</path>
             <format type='""" + img_format + """'/>
           </backingStore>
         </volume>"""

        stpVol = self.pool.createXML(stpVolXml, 0)
        return stpVol

    def delete_volume_with_name(self, image_info: dict):
        vol = self.is_vol_exist(image_info["name"])
        if vol == None:
            print("volume mevcut degil. silme islemi es geciliyor")
            return 0
        else:
            vol.delete(0)
            return 1

    def create_volume(self, image_info: dict):
        if self.is_vol_exist(image_info["base"]) and os.path.exists(image_info["base"]):
            if not self.is_vol_exist(image_info["name"]) is None:
                print(image_info["name"] + " : belirtilen volume " + self.path + " lokasyonunda zaten var. vol ismini kontrol ediniz.")
                return 0
            else:
                r = self._create_volume(image_info["name"], image_info["base"])
                return 1
        else:
            print(image_info["base"] + " adli base volume bulunamadi")
            return 0


##
#   BLOCK
#
class Block(object):
    queryBlockStr = '{"execute": "query-block"}'

    def __init__(self, domain):
        self.dirty_bitmaps = list()
        self.device_info = list()
        self.file_info_list = list()

        self.source_domain_name = domain
        query_returns = exec_monitor_command(domain, self.queryBlockStr)

        for qr in query_returns['return']:
            if not qr['removable'] and 'inserted' in qr:
                self.device_info.append(qr)
                # self.device_list.append(qr['device'])

                fpath, fullname = os.path.split(qr['inserted']['file'])
                self.file_info_list.append({'fullname': fullname,
                                            'filepath': fpath,
                                            'filename': fullname.split('.')[0],
                                            'fileext': fullname.split('.')[1],
                                            'format': qr['inserted']['drv'],
                                            'device': qr['device']
                                            })

                if 'dirty-bitmaps' in qr:
                    for dp in qr['dirty-bitmaps']:
                        dp['device'] = qr['device']
                        self.dirty_bitmaps.append(dp)

    def get_dirty_status(self):
        return

    # def get_device_list(self):
    #    return self.device_list

    def get_device_info(self, device_name):
        return self.device_info(device_name)

    def get_device(self, index):
        return self.device_list[index]

    def get_file_list(self):
        return self.file_info_list

    def get_file(self, index):
        return self.file_info_list[index]

    def has_dirty(self):
        self.__init__(self.source_domain_name)
        if len(self.dirty_bitmaps) == 0:
            return 0
        elif len(self.dirty_bitmaps) != len(self.get_file_list()):
            return -1
        else:
            return 1

    def get_dirty_drives(self):
        return self.dirty_bitmaps


class Domain(object):
    def __init__(self, conn: libvirt.virConnect, domain_name: str):
        self.dom = None


        try:
            self.dom = conn.lookupByName(domain_name)
            self.block = Block(self.dom)
        except Exception as e:
            print("makine bulunamadi, makineyi kontrol ediniz...", str(e.args))
            exit(1)
    #        root = ET.fromstring(self.dom.XMLDesc(0))
    #        print(self.dom.XMLDesc(0))

    #        devices = root.findall('devices/disk')
    #        for device in devices:
    #            self._showall(device)

    def get_image_list(self):
        return self.block.get_file_list()

    def getdomain(self):
        return self.dom

    def get_name(self):
        return self.dom.name()

    def exec_mon_cmd(self, cmd_str_list: list):
        for cmd_str in cmd_str_list:
            logging.debug("Execution :", cmd_str)
            q_results = json.loads(qemuMonitorCommand(self.dom, cmd_str, 0))
        return q_results

    def remove_bitmap(self,image_info: dict):
        dirty_info = dict()
        dirty_info['node'] = image_info['node']
        dirty_info['bitmap'] = image_info['bitmap']

        results = self.exec_mon_cmd(self._prep_block_bitmap_remove_str(dirty_info))
        return results
        #self.block.has_dirty()

    def backup_xml(self, pool: Pool):
        domxml = self.dom.XMLDesc(libvirt.VIR_DOMAIN_XML_MIGRATABLE)
        with open(pool.path + "/" + self.get_name() + ".xml", "w") as domfile:
            logging.info("Creating XML File :" + domfile.name)
            domfile.write(domxml)

    def backup_disk(self, image_info: dict, backup_type: str, pool: Pool):
        """ Backup operations """
        mon_str_list = list()

        if backup_type == "full":
            if not self.block.has_dirty() == 0:
                self.remove_bitmap(image_info)
                print("Var olan bitmap silindi.")
            mon_str_list.append(self._prep_block_bitmap_add_str(image_info))
        elif backup_type == "inc":
            if self.block.has_dirty() == 0:
                print("Dirty Bitmap(ler) bulunamiyor. Full alinmamis olabilir. önce full ile baslayiniz...")
                raise Exception
            elif self.block.has_dirty() == 1:
                if not pool.create_volume(image_info):
                    logging.error("imaj olustururken hata meydana geldi. islem tamamlanamadi.")
                    raise libvirt.libvirtError("create_volume() prosedurunde hata meydana geldi.")

                mon_str_list.append(self._prep_block_inc_drive_backup_str(image_info))
            else:
                return 0
        else:
            return 0

        print("Backup islemi basladi. Tip :" + backup_type)
        for mon_str in mon_str_list:
            while self.check_active_progress():
                print("Active operation continues, waiting for 5 second and trying...")
                sleep(5)

            ret = self.exec_mon_cmd(mon_str)

            if 'error' in ret:
                print("Backup isleminda hata meydana geldi. Islem tamamlanamadi...")
                print(ret['error'])
            elif 'return' in ret:
                self._blockjob_progress()
                print("Backup islemi tamamlandi")
                for r in ret['return']:
                    print(r)
            else:
                print('Anlamadim backupda bir hata var ama bu ney la :' + ret)

        # Backup islemi tamamlandiktan sonra
        if str(backup_type).lower() == "inc":
            logging.info("Alinan fark dosyasi temel imaja dahil ediliyor...")
            DiskImageHelper.commit_all(image_info["target"])
            logging.info("Gecici delta imaji siliniyor...")
            DiskImageHelper.delete_file(image_info["target"])

        return 1

    def _prep_block_bitmap_add_str(self, image_info):
        type_str = dict()

        type_str["execute"] = "transaction"
        type_str["arguments"] = {
            "actions":
                [{
                    "type": "block-dirty-bitmap-add",
                    "data": {
                        "node": image_info["node"],
                        "name": image_info["bitmap"]
                    }
                },
                    {
                        "type": "drive-backup",
                        "data": {
                            "device": image_info["node"],
                            "target": image_info["target"],
                            "format": "qcow2",
                            "sync": "full"
                        }
                    }]
        }

        return [json.dumps(type_str),]

    def _prep_block_bitmap_remove_str(self, dirty_info: dict):
        cmd_str = dict()

        cmd_str["execute"] = "block-dirty-bitmap-remove"
        cmd_str["arguments"] = {
            "node": dirty_info["node"],
            "name": dirty_info["bitmap"]
        }

        return [json.dumps(cmd_str),]

    def _prep_block_inc_drive_backup_str(self, image_info: dict):
        type_str = dict()
        type_str["execute"] = "drive-backup"
        type_str["arguments"] = {
            "device": image_info["node"],
            "bitmap": image_info["bitmap"],
            "target": image_info["target"],
            "format": "qcow2",
            "sync": "incremental",
            "mode": "existing"
        }
        return [json.dumps(type_str),]

    def _blockjob_progress(self):
        while True:
            info = json.loads(qemuMonitorCommand(self.dom, '{"execute":"query-block-jobs"}', 0))
            if len(info['return']) == 0:
                break

            bar_length = 50
            for i in info['return']:
                start = i['offset']
                end = i['len']
                percent = float(start) / float(end)
                hashes = '#' * int(round(percent * bar_length))
                spaces = '-' * (bar_length - len(hashes))
                sys.stdout.write(
                    "\r[{0}] {1}/{2} ({3}%)".format(
                        hashes + spaces,
                        start,
                        end,
                        int(round(percent * 100))
                    )
                )
                sys.stdout.flush()
                sleep(2)
            start = end
            percent = float(start) / float(end)
            hashes = '#' * int(round(percent * bar_length))
            spaces = '-' * (bar_length - len(hashes))
            sys.stdout.write(
                "\r[{0}] {1}/{2} ({3}%)".format(
                    hashes + spaces,
                    start,
                    end,
                    int(round(percent * 100))
                )
            )
            sys.stdout.flush()

    def check_active_progress(self):
        info = json.loads(qemuMonitorCommand(self.dom, '{"execute":"query-block-jobs"}', 0))
        if len(info['return']) == 0:
            return False
        return True


def exec_monitor_command(dom: Domain, execute_str: str):
    query_results = json.loads(qemuMonitorCommand(dom, execute_str, 0))
    if len(query_results['return']) == 0:
        return None
    return query_results


def check_start_backup(dom: Domain, pool: Pool):
    image_info_list = prep_img_info_list(dom, pool)

    for image_info in image_info_list:
        try:
            if pool.is_vol_exist(image_info["base"]):
                if dom.block.has_dirty() == 0:  # full backup alinmis fakat dirty block halihazirda yok
                    dom.backup_disk(image_info, "full", pool)
                    dom.backup_xml(pool)
                elif dom.block.has_dirty() == 1:  # full backup alinmis ve dirty block var
                    inc_info = prep_inc_info(image_info)
                    dom.backup_disk(inc_info, "inc", pool)
            elif os.path.exists(image_info["base"]) and not os.path.isdir(image_info["base"]):
                if dom.block.has_dirty() == 0:  # full backup alinmis fakat dirty block halihazirda yok
                    dom.backup_disk(image_info, "full", pool)
                    dom.backup_xml(pool)
                elif dom.block.has_dirty() == 1:  # full backup alinmis ve dirty block var
                    inc_info = prep_inc_info(image_info)
                    dom.backup_disk(inc_info, "inc", pool)
            else:
                dom.backup_disk(image_info, "full", pool)  # base imaj yok full alinmasi gerek
                dom.backup_xml(pool)
        except libvirt.libvirtError as le:
            logging.error("Backup isleminde hata: %s" % le.get_error_message())
            logging.error("olusan hata nedeniyle olusturulan imaj siliniyor...")
            pool.delete_volume_with_name(image_info)
            raise Exception("libvirtError:")


def prep_img_info_list(dom: Domain, pool: Pool):
    image_info_list = list()

    for idx, file in enumerate(dom.get_image_list()):
        image_info = dict()
        image_info["name"] = file["fullname"]
        image_info["node"] = file["device"]
        image_info["target"] = pool.path + "/" + image_info["name"]
        image_info["base"] = image_info["target"]
        image_info["bitmap"] = "bitmap" + str(idx)

        image_info_list.append(image_info)

    return image_info_list


def prep_inc_info(image_info: dict):
    suffix = datetime.now().strftime("%Y%m%d_%H%M%S")
    image_info["suffix"] = suffix
    image_info["name"] += "_" + image_info["suffix"]
    image_info["target"] += "_" + image_info["suffix"]
    return image_info



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

def get_backup_domain_dir(self, backup_dir):
    """ Gets full backup domain dir """
    # prepare backup domain directory path
    backup_domain_dir = os.path.join(backup_dir, self.name)
    return backup_domain_dir


def main(argv):
    if len(argv) != 5:
        logging.warning("Lutfen belirtilen şekilde parametrelere dikkat ederek yeniden çalıştıralım.")
        logging.warning("backup.py <kaynak host> <kaynak domain> <tempPool adi> <hedef host>")
        return 1

    src_host_ip = sys.argv[1]
    src_domain_name = sys.argv[2]
    src_pool_name = sys.argv[3]
    dest_domain_name = sys.argv[4]


    src_sasl_user = "admin"
    src_sasl_pass = "Trvm01!q"
    src_uri = 'qemu+tcp://' + src_host_ip + '/system'

    src_connection = Connection(src_uri, src_sasl_user, src_sasl_pass)

    src_conn = src_connection.connect()
    src_dom = Domain(src_conn, src_domain_name)
    src_pool = Pool(src_conn, src_pool_name)

    if src_pool.pool_check() is None:
        logging.error("Belirtilen pool bulunamadi. Lutfen kontrol ediniz..")
        exit(1)

    src_pool.pool_refresh()

    try:
        logging.basicConfig(format='%(levelname)s: %(message)s')

        logging.debug("START")
        logging.debug("Opening libvirt connection to qemu")

        start = datetime.now()
        check_start_backup(src_dom, src_pool)
        logging.warning("Backup Islemi Tamamlanma Süresi : " + str(datetime.now() - start) + "sn.")
    except Exception as e:
        src_conn.close()
        logging.error("Surecte bir problem meydana geldi:" + str(e.args))
        exit(1)

    src_conn.close()
    exit(0)


if __name__ == "__main__":
    sys.exit(main(sys.argv))
