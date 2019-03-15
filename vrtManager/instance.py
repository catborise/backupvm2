#
# Copyright (C) 2013 Webvirtmgr.
#
import time, logging
import os.path

from vrtManager import util
from libvirt import libvirtError

from vrtManager.connection import wvmConnect
from vrtManager.storage import wvmStorage
from vrtManager.util import DiskImageHelper

from time import sleep

try:
    from libvirt import libvirtError, VIR_DOMAIN_XML_SECURE, VIR_MIGRATE_LIVE, VIR_MIGRATE_UNSAFE
except:
    from libvirt import libvirtError, VIR_DOMAIN_XML_SECURE, VIR_MIGRATE_LIVE


class wvmInstances(wvmConnect):
    def get_instance_status(self, name):
        inst = self.get_instance(name)
        return inst.info()[0]

    def get_instance_memory(self, name):
        inst = self.get_instance(name)
        mem = util.get_xml_path(inst.XMLDesc(0), "/domain/currentMemory")
        return int(mem) / 1024

    def get_instance_vcpu(self, name):
        inst = self.get_instance(name)
        cur_vcpu = util.get_xml_path(inst.XMLDesc(0), "/domain/vcpu/@current")
        if cur_vcpu:
            vcpu = cur_vcpu
        else:
            vcpu = util.get_xml_path(inst.XMLDesc(0), "/domain/vcpu")
        return vcpu

    def get_instance_managed_save_image(self, name):
        inst = self.get_instance(name)
        return inst.hasManagedSaveImage(0)

    def get_uuid(self, name):
        inst = self.get_instance(name)
        return inst.UUIDString()

    def start(self, name):
        dom = self.get_instance(name)
        dom.create()

    def shutdown(self, name):
        dom = self.get_instance(name)
        dom.shutdown()

    def force_shutdown(self, name):
        dom = self.get_instance(name)
        dom.destroy()

    def managedsave(self, name):
        dom = self.get_instance(name)
        dom.managedSave(0)

    def managed_save_remove(self, name):
        dom = self.get_instance(name)
        dom.managedSaveRemove(0)

    def suspend(self, name):
        dom = self.get_instance(name)
        dom.suspend()

    def resume(self, name):
        dom = self.get_instance(name)
        dom.resume()

    def moveto(self, conn, name, live, unsafe, undefine, offline):
        flags = 0
        if live and conn.get_status() == 1:
            flags |= VIR_MIGRATE_LIVE
        if unsafe and conn.get_status() == 1:
            flags |= VIR_MIGRATE_UNSAFE
        dom = conn.get_instance(name)
        xml = dom.XMLDesc(VIR_DOMAIN_XML_SECURE)
        if not offline:
            dom.migrate(self.wvm, flags, None, None, 0)
        if undefine:
            dom.undefine()
        self.wvm.defineXML(xml)

    def graphics_type(self, name):
        inst = self.get_instance(name)
        console_type = util.get_xml_path(inst.XMLDesc(0), "/domain/devices/graphics/@type")
        if console_type is None:
            return "None"
        return console_type

    def graphics_listen(self, name):
        inst = self.get_instance(name)
        listen_addr = util.get_xml_path(inst.XMLDesc(0), "/domain/devices/graphics/@listen")
        if listen_addr is None:
            listen_addr = util.get_xml_path(inst.XMLDesc(0), "/domain/devices/graphics/listen/@address")
            if listen_addr is None:
                    return "None"
        return listen_addr

    def graphics_port(self, name):
        inst = self.get_instance(name)
        console_port = util.get_xml_path(inst.XMLDesc(0), "/domain/devices/graphics/@port")
        if console_port is None:
            return "None"
        return console_port

    def domain_name(self, name):
        inst = self.get_instance(name)
        domname = util.get_xml_path(inst.XMLDesc(0), "/domain/name")
        if domname is None:
            return "NoName"
        return domname

    def graphics_passwd(self, name):
        inst = self.get_instance(name)
        password = util.get_xml_path(inst.XMLDesc(VIR_DOMAIN_XML_SECURE), "/domain/devices/graphics/@passwd")
        if password is None:
            return "None"
        return password



class wvmInstance(wvmConnect):

    def __init__(self, host, login, passwd, conn, vname):
        wvmConnect.__init__(self, host, login, passwd, conn)
        self.instance = self.get_instance(vname)
        self.name = vname
        global log
        log = logging.getLogger("BackupLogs")

    def get_uuid(self):
        return self.instance.UUIDString()

    def get_name(self):
        return self.name

    def _XMLDesc(self, flag):
        return self.instance.XMLDesc(flag)

    def get_disk_device(self):
        def disks(doc):
            result = []
            dev = None
            volume = None
            storage = None
            src_fl = None
            disk_format = None
            disk_size = None

            for disk in doc.xpath('/domain/devices/disk'):
                device = disk.xpath('@device')[0]
                if device == 'disk':
                    try:
                        dev = disk.xpath('target/@dev')[0]
                        src_fl = disk.xpath('source/@file|source/@dev|source/@name|source/@volume')[0]
                        disk_format = disk.xpath('driver/@type')[0]
                        try:
                            vol = self.get_volume_by_path(src_fl)
                            volume = vol.name()
                            disk_size = vol.info()[1]
                            stg = vol.storagePoolLookupByVolume()
                            storage = stg.name()
                        except libvirtError:
                            volume = src_fl
                    except:
                        pass
                    finally:
                        result.append(
                            {'dev': dev, 'image': volume, 'storage': storage, 'path': src_fl,
                             'format': disk_format, 'size': disk_size})
            return result

        return util.get_xml_path(self._XMLDesc(0), func=disks)


    def get_block_device(self):
        file_info_list = []
        query_returns = util.exec_monitor_command(self.instance, '{"execute": "query-block"}')

        for qr in query_returns['return']:
            if not qr['removable'] and 'inserted' in qr:
                fpath, fullname = os.path.split(qr['inserted']['file'])
                file_info_list.append({'fullname': fullname,
                                       'filepath': fpath,
                                       'filename': fullname.split('.')[0],
                                       'fileext': fullname.split('.')[1],
                                       'format': qr['inserted']['drv'],
                                       'device': qr['device'],
                                       'file': qr['inserted']['file']
                                       })
        return file_info_list

    def get_dirty_bitmap_list(self,image_info=None):
        dirty_bitmaps = list()
        query_returns = util.exec_monitor_command(self.instance, '{"execute": "query-block"}')

        for qr in query_returns['return']:
            if not qr['removable'] and 'inserted' in qr:
                if 'dirty-bitmaps' in qr:
                    for db in qr['dirty-bitmaps']:
                        db['device'] = qr['device']
                        db['file'] = qr['inserted']['file']
                        if image_info is None:
                            dirty_bitmaps.append(db)
                        elif image_info['file'] == db['file']:
                            dirty_bitmaps.append(db)
        return dirty_bitmaps

    def get_dirty_bitmap(self, image_info):
        dirty_bitmap_list = self.get_dirty_bitmap_list()
        for dirty_bitmap in dirty_bitmap_list:
            #if image_info['bitmap'] == dirty_bitmap['name']:

            if image_info['bitmap'] == dirty_bitmap['name']:
                return dirty_bitmap
            # bitmap bug in dan dolayi bug uzantili dirtymaplari de kontrol etmek gerekiyor. bug duzelince bu elif i silebiliriz.
            elif image_info['bitmap'] + "bug" == dirty_bitmap['name']:
                image_info['bitmap'] += "bug"
                return dirty_bitmap

        return None

    def delete_disk(self):
        disks = self.get_disk_device()
        for disk in disks:
            vol = self.get_volume_by_path(disk.get('path'))
            vol.delete(0)


    def backup_xml(self, pool: wvmStorage):
        domxml = self._XMLDesc(0)
        with open(pool.get_target_path() + "/" + self.get_name() + ".xml", "w") as domfile:
            log.info("Creating XML File :" + domfile.name)
            domfile.write(domxml)

    def backup_disk(self, image_info: dict, backup_type: str, pool: wvmStorage, compress=False, merge=True):
        """ Backup operations """
        mon_str_list = list()

        if backup_type == "full":
            if self.get_dirty_bitmap(image_info) is not None:
                self.remove_disk_all_bitmaps(image_info)
                log.warning("Bitmaps of {} is removed.".format(image_info['name']))
            backup_str = util.prepare_block_bitmap_add_str(image_info, compress, True)
            log.debug(backup_str)
            mon_str_list.append(backup_str)
        elif backup_type == "inc":
            if self.get_dirty_bitmap(image_info) is None:
                log.error("Not found dirty bitmap of {}. First, backup full!".format(image_info['name']))
                raise libvirtError("Dirt bitmap {} is not found".format(image_info["bitmap"]))
            else:
                if not pool.create_volume_winfo(image_info):
                    log.error("An error while creating image. Operation could not performed.")
                    raise libvirtError("An error while calling create_volume() procedure.")

                backup_str = util.prepare_block_inc_drive_backup_str(image_info, compress)
                log.debug("QMP Backup String: {}".format(backup_str))
                mon_str_list.append(backup_str)
        else:
            return 0

        log.info("Backup Operation Started. Backup Type : {} . Disk: {}".format(backup_type, image_info['name']))
        for mon_str in mon_str_list:
            while util.check_active_progress(self.instance):
                log.warning("Active operation continues, waiting for 5 second and trying...")
                sleep(5)

            log.debug("Execution of Command: {}".format(mon_str))
            ret = util.exec_monitor_command(self.instance, mon_str)

            if 'error' in ret:
                log.error("Backup operation failed...")
                log.error("Command : " + mon_str)
                log.error(ret['error'])

                ''' There is a qemu bug with related dirty-bitmaps: cannot see cannot remove!! '''
                if ret['error']['class'] == 'GenericError':
                    message = 'Bitmap with the same name is already stored'
                    retstr = ret['error']['desc']
                    if retstr.__contains__(message):
                        image_info['bitmap'] += "bug"
                        self.backup_disk(image_info,backup_type,pool,compress,merge)
            elif 'return' in ret:
                util.block_job_progress(self.instance)
                log.info(".!.")
                log.info("Backup of {} disk is finished.".format(image_info["name"]))
                log.info("Copied image size: {}".format(DiskImageHelper.get_img_size(image_info["target"])))
                log.info("-------------")
                for r in ret['return']:
                    log.info(r)
            else:
                log.error('An awkward error:' + ret)


        # after Backup-drive completion, merge delta and delete temp
        if str(backup_type).lower() == "inc" and merge:
            log.info("Delta file is merging to base image...")
            DiskImageHelper.commit_all(image_info["target"])
            log.info("Temporary delta file is deleting...")
            DiskImageHelper.delete_file(image_info["target"])

        return 1

    def remove_disk_all_bitmaps(self, image_info):
        result_list = list()
        dirt_bitmap_list = self.get_dirty_bitmap_list(image_info)
        for dirty_bitmap in dirt_bitmap_list:
            result = util.exec_monitor_command(self.instance, util.prepare_block_bitmap_remove_str(image_info))
            result_list.append(result)
        return result_list


    def remove_disk_bitmap(self, image_info: dict):
        result = util.exec_monitor_command(self.instance, util.prepare_block_bitmap_remove_str(image_info))
