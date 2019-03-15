import sys, os, json
import libvirt
from xml.etree import ElementTree as ET
from libvirt_qemu import qemuMonitorCommand
from time import time, sleep
from datetime import datetime
import Retention
from paramiko import SSHClient
from scp import SCPClient


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

    def _create_volume(self, name, back_fullname, img_format="qcow2"):

        stpVolXml = """
        # <volume>
        #   <name>""" + name + """</name>
        #   <allocation>0</allocation>
        #   <target>
        #     <path>""" + os.getcwd() + """</path>
        #     <permissions>
        #       <owner>107</owner>
        #       <group>107</group>
        #       <mode>0744</mode>
        #       <label>virt_image_t</label>
        #     </permissions>
        #     <format type='""" + img_format + """'/>
        #   </target>
        #   <backingStore>
        #     <path>""" + back_fullname + """</path>
        #     <format type='""" + img_format + """'/>
        #   </backingStore>
        # </volume>"""

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
        if self.is_vol_exist(image_info["base"]):
            if not self.is_vol_exist(image_info["name"]) is None:
                print(image_info["name"] + " : belirtilen volume zaten var. vol ismini kontrol ediniz")
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
        self.dirty_bitmaps = []
        # self.device_list = []
        self.device_info = []
        self.file_info_list = []

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
            print("Execution :", cmd_str)
            q_results = json.loads(qemuMonitorCommand(self.dom, cmd_str, 0))
        return q_results

    def remove_bitmap(self,image_info: dict):
        dirty_info = dict()
        dirty_info['bitmap'] = image_info['bitmap']
        dirty_info['node'] = image_info['node']

        results = self.exec_mon_cmd(self._prep_block_bitmap_remove_str(dirty_info))
        self.block.has_dirty()

    ##
    # BACKUP
    #
    def backup(self, backup_type: str, image_info):
        mon_str_list = list()

        if backup_type == "full":
            if not self.block.has_dirty() == 0:
                self.remove_bitmap(image_info)
                print("Var olan bitmapler silindi.")
            mon_str_list.append(self._prep_block_bitmap_add_str(image_info))

        elif backup_type == "inc":
            if self.block.has_dirty() == 0:
                print("Dirty Bitmap(ler) bulunamiyor. Full alinmamis olabilir. önce full ile baslayiniz...")
                raise Exception
            elif self.block.has_dirty() == 1:
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
                self.blockjob_progress()
                print("Backup islemi tamamlandi")

                for r in ret['return']:
                    print(r)
            else:
                print('Anlamadim backupda bir hata var ama bu ney la :' + ret)

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

    def blockjob_progress(self):
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


def exec_monitor_command(dom, execute_str: str):
    query_results = json.loads(qemuMonitorCommand(dom, execute_str, 0))
    if len(query_results['return']) == 0:
        return None
    return query_results


def prep_img_info_list(backup_type: str, dom: Domain, pool: Pool):
    image_info_list = list()
    suffix, _ = str(datetime.now()).replace("-", "").split(" ")
    for idx, file in enumerate(dom.get_image_list()):
        image_info = dict()
        image_info["name"] = file["fullname"]
        image_info["node"] = file["device"]
        image_info["target"] = pool.path + "/" + image_info["name"]
        image_info["base"] = image_info["target"]
        image_info["bitmap"] = "bitmap" + str(idx)
        image_info["suffix"] = suffix

        if backup_type == "inc":
            index, prev_image = populate_index(pool, dom, file)
            #image_info["name"] += "_" + index
            image_info["name"] += "_" + image_info["suffix"] + "_" + str(CURRENTID)
            image_info["base"] = prev_image["file"]
            image_info["target"] += "_" + image_info["suffix"] + "_" + str(CURRENTID)
        image_info_list.append(image_info)

    return image_info_list


# gecersiz silinecek
def prep_inc_info(dom: Domain, pool: Pool):
    image_info_list = list()
    for idx, image_file in enumerate(dom.get_image_list()):
        image_info = dict()
        index, prev_image = populate_index(pool, dom, image_file)
        image_info["name"] = image_file["fullname"] + "_" + index
        image_info["node"] = image_file["device"]
        image_info["target"] = pool.path + "/" + image_info["name"]
        image_info["base"] = prev_image["file"]
        image_info["bitmap"] = "bitmap" + str(idx)

        image_info_list.append(image_info)
    return image_info_list


CURRENTID = 0
def populate_index(pool: Pool, dom: Domain, file: dict):
    image_list = list()
    line = dict()

    global CURRENTID
    log_file_name = pool.path + "/" +dom.get_name() + "_" + file["device"] + ".log"
    try:
        with open(log_file_name, encoding='utf-8', mode='r') as logfile:
            for jline in logfile.readlines():
                if jline is None:
                    raise EOFError
                if jline == "":
                    pass
                line = json.loads(jline)
                image_list.append(line)

            image_list = sorted(image_list, key=lambda k: k["id"], reverse=True)
            last_image = image_list.pop(0)
            #current_id = "{0:03d}".format(int(last_image["id"]) + 1)
            CURRENTID = last_image["id"] + 1
            #current_id = str(datetime.utcnow()).replace(" ", "_").split(":", "")
            return CURRENTID, last_image
    except IOError:
        print(log_file_name +":")
        print(" -> log dosyasina ulasilamiyor. Dosyayi kontrol ediniz...")
        print(" -> Full yedek alinmamis olabilir.")
        exit(1)
    except EOFError:
        print("log dosyasi bos. full yedek alindi mi ?")
    except TypeError as e:
        print("Log dosyasinda hata var ", e.with_traceback())


def write_logs(pool: Pool, backup_type: str, dom: Domain, image_info: dict):
    log = dict()
    open_mode = "a" if backup_type == "inc" else "w"
    bid = 0

    log["btype"] = backup_type
    log["file"] = image_info["target"]
    log["date"] = str(datetime.now())
    print("Belirtilen klasore Log dosyasi olusturuluyor. Path: " + os.getcwd() )
    #with open(pool.path + "/" + dom.get_name() + "_" + image_info["node"] +".log", open_mode) as logfile:
    with open(dom.get_name() + "_" + image_info["node"] +".log", encoding='utf-8', mode=open_mode) as logfile:
        log["id"] = CURRENTID
        print(json.dumps(log), file=logfile)


def main(argv):
    if len(argv) != 8:
        print("Lutfen belirtilen şekilde parametrelere dikkat ederek yeniden çalıştıralım.")
        print("backup.py <kaynak host> <kaynak domain> <tempPool adi> <hedef host> <hedef domain> <hedef pool> <yedeklemeTipi-full/inc>")
        return 1

    src_host_ip = sys.argv[1]
    src_domain_name = sys.argv[2]
    src_pool_name = sys.argv[3]
    #dest_host_ip = sys.argv[4]
    #dest_domain_name = sys.argv[5]
    #dest_pool_name = sys.argv[6]
    backup_type = sys.argv[7]  # backup_type = sys.argv[6]

    src_sasl_user = "admin"
    src_sasl_pass = "Trvm01!q"
    src_uri = 'qemu+tcp://' + src_host_ip + '/system'

    #dest_sasl_user = "admin"
    #dest_sasl_pass = "Trvm01!q"
    #dest_uri = 'qemu+tcp://' + dest_host_ip + '/system'

    src_connection = Connection(src_uri, src_sasl_user, src_sasl_pass)
    #dest_connection = Connection(dest_uri, dest_sasl_user, dest_sasl_pass)

    src_conn = src_connection.connect()
    src_dom = Domain(src_conn, src_domain_name)

    #dest_conn = dest_connection.connect()
    src_pool = Pool(src_conn, src_pool_name)
    #dest_pool = Pool(dest_conn, dest_pool_name)

    if src_pool.pool_check() is None:
        print("Belirtilen pool bulunamadi. Lutfen kontrol ediniz..")
        exit(1)

    #backup_type = "inc"

    image_info_list = prep_img_info_list(backup_type, src_dom, src_pool)


    for ii in image_info_list:
        path, _ = os.path.split(ii["target"])
        os.chdir(path)
        try:
            if backup_type == "inc":
                if not src_pool.create_volume(ii):
                    print("imaj olustururken hata meydana geldi. islem tamamlanamadi.")
                    raise Exception("create_volume() prosedurunde hata meydana geldi.")
            start = time()
            src_dom.backup(backup_type, ii)
            print("Backup Islemi Tamamlanma süresi :", round(time() - start), "sn.")

        except libvirt.libvirtError as e:
            print("Backup isleminde hata:" + str(e.args))
            print ("olusan hata nedeniyle " + ii["name"] + " siliniyor...")
            src_pool.delete_volume_with_name(ii)
            print ("olusan hata nedeniyle " + ii["name"] + " silindi.")
            src_conn.close()
            exit(1)
        except Exception as e:
            print("Surecte bir problem meydana geldi:" + str(e.args))
            exit(1)

        #print("Hedef: %s adresli sunucuya kopyalama başlatılıyor..." % dest_host_ip)
        #dest_file_path= dest_pool.path + "/"
        #start = time()
        #scp(ii["target"], dest_file_path)
        #print("Hedef: %s adresli sunucuya kopyalama tamamlandi: %s" % (dest_host_ip, dest_file_path))
        #print("Kopyalama Islemi Tamamlanma süresi :", round(time() - start), "sn.")

        print("Yedekleme bilgileri log dosyasina kaydediliyor...")
        write_logs(src_pool, backup_type, src_dom, ii)
        print("Yedekleme bilgileri log dosyasina kaydedildi.")

        #print("Temp Yedek dosyasi siliniyor...")
        #sleep(2)
        #if vol_file_check(ii["name"], src_pool, dest_pool):
        #    src_pool.delete_volume(ii["name"])

        Retention.retention_check(src_pool, src_dom, ii)

    src_conn.close()
    exit(0)


def scp_progress(filename, size, sent):
    # Define progress callback that prints the current percentage completed for the file
    sys.stdout.write("%s\'s progress: %.2f%%   \r" % (filename, float(sent)/float(size)*100))


def scp(local, remote):
    server = '10.10.141.44'
    # setup ssh
    ssh = SSHClient()
    ssh.load_host_keys(os.path.expanduser('~/.ssh/known_hosts'))
    ssh.connect(server, username='root', password='!Qwerty123%')
    scp = SCPClient(ssh.get_transport(), progress=scp_progress)
    # transfer to remote
    scp.put(files=local, remote_path=remote)


def vol_file_check(filename: str, src_pool: Pool, dest_pool: Pool):
    if src_pool.pool_check() is not None:
        src_pool.pool_refresh()

    if dest_pool.pool_check() is not None:
        dest_pool.pool_refresh()

    src_vol = src_pool.is_vol_exist(filename)
    dest_vol = dest_pool.is_vol_exist(filename)

    if dest_vol is not None and src_vol is not None:
        src_info = src_vol.info()
        dest_info = dest_vol.info()
        print("Source File Info:" + str(src_info))
        print("Destination File Info:" + str(dest_info))
        #### fiziksel boyut bilgisini alamadigimdan allocation aldim ama dogru degil. diger boyutu karsilastirmak saglikli degil zaten.. suan ki de sagklikli degil...
        if src_info[1] == dest_info[1]:
            return True

    return False


if __name__ == "__main__":
    sys.exit(main(sys.argv))
