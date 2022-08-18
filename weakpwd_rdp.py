#!/usr/bin/env python 3.6.8
# -*- coding: utf-8 -*-
# author ConradSun

import os
import winreg
import OpenSSL
import platform
import subprocess
from Cryptodome.Hash import MD4
from impacket.examples import logger
from impacket.examples.secretsdump import LocalOperations, SAMHashes

import utils.const as const
import utils.exceptions as exception
from utils.rdp_check import check_rdp

class RdpChecker():
    SAM_HIVE_PATH = os.path.join(os.path.abspath("./.temp"), "sam.hiv")
    SYS_HIVE_PATH = os.path.join(os.path.abspath("./.temp"), "sys.hiv")
    PASSWD_FILE_PATH = os.path.join(os.path.abspath("./conf"), "passwd.txt")


    def __init__(self):
        logger.init()
        logger.logging.getLogger().setLevel(logger.logging.DEBUG)
        self.output = {}

    def is_x64_platform(self):
        frame = platform.machine()
        return "64" in frame

    def gen_ntlm_hash(self, passwd):
        if not isinstance(passwd, str):
            return None

        ntlm = MD4.new()
        ntlm.update(passwd.encode("utf-16le"))
        hash = ntlm.hexdigest()
        return hash
    
    def change_rdp_status(self, set_value):
        """change_rdp_status 修改系统注册表中控制 RDP 开启或关闭项
        为方便单元测试编写的函数接口，本模块未使用

        Args:
            set_value (DWORD): [设置值：0表示开启，1表示关闭]
        Returns:
            None
        """
        rdp_set_key = "SYSTEM\\CurrentControlSet\\Control\\Terminal Server"  # 查询子键
        rdp_set_item = "fDenyTSConnections"    # 查询项

        try:
            if is_x64_platform():
                query_key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, rdp_set_key, 0, winreg.KEY_WOW64_64KEY | winreg.KEY_ALL_ACCESS)
            else:
                query_key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, rdp_set_key, 0, winreg.KEY_WOW64_32KEY | winreg.KEY_ALL_ACCESS)
            winreg.SetValueEx(query_key, rdp_set_item, 0, winreg.REG_DWORD, set_value)
            winreg.CloseKey(query_key)

        except WindowsError as e:
            RdpEngine.LOGGER.debug("[rdp] failed in setting RDP status, error: %s", str(e))

    def __clear_hive_file(self):
        if os.path.exists(self.SAM_HIVE_PATH):
            os.remove(self.SAM_HIVE_PATH)
        if os.path.exists(self.SYS_HIVE_PATH):
            os.remove(self.SYS_HIVE_PATH)

    def __dump_hive_file(self):
        dump_sam_cmd = " ".join(["reg save hklm\sam", self.SAM_HIVE_PATH, "/y"])
        dump_sys_cmd = " ".join(["reg save hklm\system", self.SYS_HIVE_PATH, "/y"])    
        
        success_msg = ["操作成功完成。\n", "operation completed successfully.\n"]
        ret_msg = subprocess.getoutput(dump_sam_cmd)
        if not ret_msg in success_msg:
            logger.logging.debug("[RDP] failed in dumping hive file: %s", ret_msg)
            raise exception.CmdCallError("[RDP] {}".format(ret_msg))
        ret_msg = subprocess.getoutput(dump_sys_cmd)
        if not ret_msg in success_msg:
            logger.logging.debug("[RDP] failed in dumping hive file: %s", ret_msg)
            raise exception.CmdCallError("[RDP] {}".format(ret_msg))

    def __parse_hive_file(self):
        if not os.path.exists(self.SAM_HIVE_PATH) or not os.path.exists(self.SYS_HIVE_PATH):
            logger.logging.debug("[RDP] check the path: %s", os.path.dirname(self.SAM_HIVE_PATH))
            raise exception.NoSuchFileError("[RDP] hive file not found")
        if not os.path.getsize(self.SAM_HIVE_PATH) or  not os.path.getsize(self.SYS_HIVE_PATH):
            logger.logging.debug("[RDP] check the path: %s", os.path.dirname(self.SAM_HIVE_PATH))
            raise exception.NoNeededInfoError("[RDP] empty hive file")
        
        try:
            local_operate = LocalOperations(self.SYS_HIVE_PATH)
            boot_key = local_operate.getBootKey()
            sam_hash = SAMHashes(self.SAM_HIVE_PATH, boot_key, isRemote=False)
            sam_hash.dump()
            parse_hash = sam_hash._SAMHashes__itemsFound
        except ValueError as e:
            raise exception.ProcessFileError("[RDP] failed in parsing hive file: {}".format(str(e)))

        hash_item_len = 7
        idx_user_item = 0
        idx_ntlm_item = 3
        hash_info = {}
        for index in parse_hash:
            items = parse_hash[index].split(':')
            if len(items) == hash_item_len:
                hash_info[items[idx_user_item]] = items[idx_ntlm_item]
                logger.logging.debug("[RDP] found user: %s, hash: %s", items[idx_user_item], items[idx_ntlm_item])
            
        return hash_info

    def __check_weak_passwd(self, hash_info):
        if not hash_info:
            raise exception.NoNeededInfoError("[RDP] empty hash info")
        
        login_info = {}
        with open(self.PASSWD_FILE_PATH, 'r', encoding="utf-8") as pwd_file:
            for pwd in pwd_file:
                pwd = pwd.strip().replace('\n', '')
                gen_hash = self.gen_ntlm_hash(pwd)
                for user, pwd_hash in hash_info.items():
                    if gen_hash and gen_hash == pwd_hash:
                        login_info[user] = pwd
                        logger.logging.debug("[RDP] found user: %s, pwd: %s", user, pwd)

        return login_info

    def __query_rdp_port(self):
        query_path = r"SYSTEM\CurrentControlSet\Control\Terminal Server\Wds\rdpwd\Tds\tcp"
        query_item = "PortNumber"
        port_number = 3389

        try:
            query_key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, query_path)
            query_val = winreg.QueryValueEx(query_key, query_item)
            winreg.CloseKey(query_key)
            port_number = query_val[0]            
        except WindowsError as e:
            logger.logging.debug("[RDP] failed in querying port number: %s", str(e))

        return port_number

    def __check_rdp_enabled(self):
        query_path = r"SYSTEM\CurrentControlSet\Control\Terminal Server"
        query_item = "fDenyTSConnections"
        rdp_enabled = False

        try:
            query_key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, query_path)
            query_val = winreg.QueryValueEx(query_key, query_item)
            winreg.CloseKey(query_key)
            rdp_enabled = query_val[0] == 0
        except WindowsError as e:
            logger.logging.debug("[RDP] failed in querying rdp status: %s", str(e))

        return rdp_enabled

    def __check_rdp_connect(self, login_info):
        if not self.__check_rdp_enabled():
            logger.logging.warning("[RDP] rdp is disabled")
            self.output = login_info
            return

        port_number = self.__query_rdp_port()
        logger.logging.info("[RDP] rdp is enabled with port %i", port_number)

        for user, passwd in login_info.items():
            try:
                is_connected, err_msg = check_rdp("localhost", user, passwd, port_number)
                if is_connected:
                    self.output[user] = passwd
                    logger.logging.debug("[RDP] succeeded in rdp connection with user: %s", user)
                else:
                    logger.logging.debug("[RDP] failed in rdp connection with user: %s, error: %s", user, err_msg)
            except (OpenSSL.SSL.Error, WindowsError) as e:
                logger.logging.debug("[RDP] failed in rdp connection: %s", str(e))
                self.output = login_info
        
    def run_rdp_scan(self):
        try:
            self.__dump_hive_file()
            hash_info = self.__parse_hive_file()
            login_info = self.__check_weak_passwd(hash_info)
            self.__check_rdp_connect(login_info)
            self.__clear_hive_file()
        except exception.CmdCallError:
            logger.logging.error("[RDP] CmdCallError occured.")
            return const.CmdCallError
        except exception.NoSuchFileError:
            logger.logging.error("[RDP] NoSuchFileError occured.")
            return const.NoSuchFileError
        except exception.NoNeededInfoError:
            logger.logging.error("[RDP] NoNeededInfoError occured.")
            return const.NoNeededInfoError
        except exception.ProcessFileError:
            logger.logging.error("[RDP] ProcessFileError occured.")
            return const.ProcessFileError

        logger.logging.info("[RDP] found weak password: %s", self.output)
        return const.ScanSucceeded


if __name__ == "__main__":
    rdp_test = RdpChecker()
    rdp_test.run_rdp_scan()
    
