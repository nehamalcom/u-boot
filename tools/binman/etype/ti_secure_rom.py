# SPDX-License-Identifier: GPL-2.0+
# Copyright 20
# Written by Neha Malcom Francis <n-francis@ti.com>
#

# Support for generating x509 certificate to binary for K3 bootloaders

from collections import OrderedDict
import os

from binman.entry import EntryArg
from binman.etype.x509_cert import Entry_x509_cert

import hashlib

from dtoc import fdt_util
from u_boot_pylib  import tools

VALID_SHAS = [256, 384, 512, 224]
SHA_OIDS = {256:'2.16.840.1.101.3.4.2.1',
            384:'2.16.840.1.101.3.4.2.2',
            512:'2.16.840.1.101.3.4.2.3',
            224:'2.16.840.1.101.3.4.2.4'}

class Entry_ti_secure_rom(Entry_x509_cert):
    def __init__(self, section, etype, node):
        super().__init__(section, etype, node)
        self.openssl = None

    def ReadNode(self):
        super().ReadNode()
        self.combined = fdt_util.GetBool(self._node, 'combined', False)
        self.countersign = fdt_util.GetBool(self._node, 'countersign', False)
        self.load_addr = fdt_util.GetInt(self._node, 'load')
        self.sw_rev = fdt_util.GetInt(self._node, 'sw-rev', 1)
        self.sha = fdt_util.GetInt(self._node, 'sha', 512)
        self.core = fdt_util.GetString(self._node, 'core')
        self.key_fname = self.GetEntryArgsOrProps([
            EntryArg('keyfile', str)], required=True)[0]
        if self.combined:
            self.load_addr_sysfw = fdt_util.GetInt(self._node, 'load-sysfw')
            self.load_addr_sysfw_data = fdt_util.GetInt(self._node, 'load-sysfw-data')

    def NonCombinedGetCertificate(self, required):
        """Generate certificate for contents of this entry, format followed is for
        devices that follow legacy boot flow

        Args:
            required: True if the data must be present, False if it is OK to
                return None

        Returns:
            bytes content of the entry, which is the certificate for the
                provided data
        """
        if self.core == 'secure':
            if self.countersign:
                self.cert_type = 2
            else:
                self.cert_type = 3
            self.bootcore = 0
            self.bootcore_opts = 32
        else:
            self.cert_type = 1
            self.bootcore = 16
            if self.combined:
                self.bootcore_opts = 32
            else:
                self.bootcore_opts = 0

        # Join up the data files to be signed
        input_data = self.GetContents(required)
        if input_data is None:
            return None

        uniq = self.GetUniqueName()
        output_fname = tools.get_output_filename('cert.%s' % uniq)
        input_fname = tools.get_output_filename('input.%s' % uniq)
        config_fname = tools.get_output_filename('config.%s' % uniq)
        tools.write_file(input_fname, input_data)

        indata = tools.read_file(input_fname)
        hashval = hashlib.sha512(indata).hexdigest()
        imagesize = len(indata)

        with open(config_fname, 'w', encoding='utf-8') as outf:
            print(f'''[ req ]
 distinguished_name     = req_distinguished_name
 x509_extensions        = v3_ca
 prompt                 = no
 dirstring_type         = nobmp

 [ req_distinguished_name ]
 C                      = US
 ST                     = TX
 L                      = Dallas
 O                      = Texas Instruments Incorporated
 OU                     = Processors
 CN                     = TI Support
 emailAddress           = support@ti.com

 [ v3_ca ]
 basicConstraints = CA:true
 1.3.6.1.4.1.294.1.1 = ASN1:SEQUENCE:boot_seq
 1.3.6.1.4.1.294.1.2 = ASN1:SEQUENCE:image_integrity
 1.3.6.1.4.1.294.1.3 = ASN1:SEQUENCE:swrv
# 1.3.6.1.4.1.294.1.4 = ASN1:SEQUENCE:encryption
 1.3.6.1.4.1.294.1.8 = ASN1:SEQUENCE:debug

 [ boot_seq ]
 certType = INTEGER:{self.cert_type}
 bootCore = INTEGER:{self.bootcore}
 bootCoreOpts = INTEGER:{self.bootcore_opts}
 destAddr = FORMAT:HEX,OCT:{self.load_addr:08x}
 imageSize = INTEGER:{imagesize}

 [ image_integrity ]
 shaType = OID:{SHA_OIDS[self.sha]}
 shaValue = FORMAT:HEX,OCT:{hashval}

 [ swrv ]
 swrv = INTEGER:{self.sw_rev}

# [ encryption ]
# initalVector = FORMAT:HEX,OCT:TEST_IMAGE_ENC_IV
# randomString = FORMAT:HEX,OCT:TEST_IMAGE_ENC_RS
# iterationCnt = INTEGER:TEST_IMAGE_KEY_DERIVE_INDEX
# salt = FORMAT:HEX,OCT:TEST_IMAGE_KEY_DERIVE_SALT

 [ debug ]
 debugUID = FORMAT:HEX,OCT:0000000000000000000000000000000000000000000000000000000000000000
 debugType = INTEGER:4
 coreDbgEn = INTEGER:0
 coreDbgSecEn = INTEGER:0''', file=outf)
        stdout = self.openssl.x509_cert_custom(
            cert_fname=output_fname,
            key_fname=self.key_fname,
            config_fname=config_fname,
            sha=self.sha)
        if stdout is not None:
            data = tools.read_file(output_fname)
        else:
            # Bintool is missing; just use 4KB of zero data
            self.record_missing_bintool(self.openssl)
            data = tools.get_bytes(0, 4096)
        return data

    def CombinedGetCertificate(self, required):
        """Generate certificate for contents of this entry, format followed is for
        devices that follow combined boot flow

        Args:
            required: True if the data must be present, False if it is OK to
                return None

        Returns:
            bytes content of the entry, which is the certificate for the
                provided data
        """
        self.sha_type = SHA_OIDS[self.sha]
        uniq = self.GetUniqueName()
        config_fname = tools.get_output_filename('config.%s' % uniq)
        output_fname = tools.get_output_filename('cert.%s' % uniq)

        self.num_comps = 3

        # SBL
        self.content = fdt_util.GetPhandleList(self._node, 'content-sbl')
        input_data_sbl = self.GetContents(required)
        if input_data_sbl is None:
            return None

        input_fname_sbl = tools.get_output_filename('input.%s' % uniq)
        tools.write_file(input_fname_sbl, input_data_sbl)

        indata_sbl = tools.read_file(input_fname_sbl)
        hashval_sbl = hashlib.sha512(indata_sbl).hexdigest()
        imagesize_sbl = len(indata_sbl)

        # SYSFW
        self.content = fdt_util.GetPhandleList(self._node, 'content-sysfw')
        input_data_sysfw = self.GetContents(required)
        if input_data_sysfw is None:
            return None

        input_fname_sysfw = tools.get_output_filename('input.%s' % uniq)
        tools.write_file(input_fname_sysfw, input_data_sysfw)

        indata_sysfw = tools.read_file(input_fname_sysfw)
        hashval_sysfw = hashlib.sha512(indata_sysfw).hexdigest()
        imagesize_sysfw = len(indata_sysfw)

        # SYSFW data
        self.content = fdt_util.GetPhandleList(self._node, 'content-sysfw-data')
        input_data_sysfw_data = self.GetContents(required)
        if input_data_sysfw_data is None:
            return None

        input_fname_sysfw_data = tools.get_output_filename('input.%s' % uniq)
        tools.write_file(input_fname_sysfw_data, input_data_sysfw_data)

        indata_sysfw_data = tools.read_file(input_fname_sysfw_data)
        hashval_sysfw_data = hashlib.sha512(indata_sysfw_data).hexdigest()
        imagesize_sysfw_data = len(indata_sysfw_data)

        # SYSFW Inner Cert
        if self.sysfw_inner_cert:
            self.content = fdt_util.GetPhandleList(self._node, 'content-sysfw-inner-cert')
            input_data_sysfw_inner_cert = self.GetContents(required)
            if input_data_sysfw_inner_cert is None:
                return None

            input_fname_sysfw_inner_cert = tools.get_output_filename('input.%s' % uniq)
            tools.write_file(input_fname_sysfw_inner_cert, input_data_sysfw_inner_cert)

            indata_sysfw_inner_cert = tools.read_file(input_fname_sysfw_inner_cert)
            hashval_sysfw_inner_cert = hashlib.sha512(indata_sysfw_inner_cert).hexdigest()
            imagesize_sysfw_inner_cert = len(indata_sysfw_inner_cert)
            self.num_comps += 1
            sysfw_inner_cert_ext_boot_sequence_string = "sysfw_inner_cert=SEQUENCE:sysfw_inner_cert"
            sysfw_inner_cert_ext_boot_block = f"""[sysfw_inner_cert]
compType = INTEGER:3
bootCore = INTEGER:0
compOpts = INTEGER:0
destAddr = FORMAT:HEX,OCT:00000000
compSize = INTEGER:{imagesize_sysfw_inner_cert}
shaType  = OID:{self.sha_type}
shaValue = FORMAT:HEX,OCT:{hashval_sysfw_inner_cert}"""
        else:
            sysfw_inner_cert_ext_boot_block = ""
            imagesize_sysfw_inner_cert = 0

        # DM data
        if self.dm_data:
            self.content = fdt_util.GetPhandleList(self._node, 'content-dm-data')
            input_data_dm_data = self.GetContents(required)
            if input_data_dm_data is None:
                return None

            input_fname_dm_data = tools.get_output_filename('input.%s' % uniq)
            tools.write_file(input_fname_dm_data, input_data_dm_data)

            indata_dm_data = tools.read_file(input_fname_dm_data)
            hashval_dm_data = hashlib.sha512(indata_dm_data).hexdigest()
            imagesize_dm_data = len(indata_dm_data)
            self.num_comps += 1
            dm_data_ext_boot_sequence_string = "dm_data=SEQUENCE:dm_data"
            dm_data_ext_boot_block = f"""[dm_data]
compType = INTEGER:17
bootCore = INTEGER:16
compOpts = INTEGER:0
destAddr = FORMAT:HEX,OCT:{self.load_dm_data:08x}
compSize = INTEGER:{imagesize_dm_data}
shaType  = OID:{self.sha_type}
shaValue = FORMAT:HEX,OCT:{hashval_dm_data}"""
        else:
            sysfw_inner_cert_ext_boot_block = ""
            imagesize_dm_data = 0

        self.total_size = imagesize_sbl +  imagesize_sysfw + imagesize_sysfw_data + imagesize_sysfw_inner_cert + imagesize_dm_data
        with open(config_fname, 'w', encoding='utf-8') as outf:
            print(f'''[ req ]
distinguished_name     = req_distinguished_name
x509_extensions        = v3_ca
prompt                 = no
dirstring_type         = nobmp

[ req_distinguished_name ]
C                      = US
ST                     = TX
L                      = Dallas
O                      = Texas Instruments Incorporated
OU                     = Processors
CN                     = TI Support
emailAddress           = support@ti.com

[ v3_ca ]
basicConstraints = CA:true
1.3.6.1.4.1.294.1.3=ASN1:SEQUENCE:swrv
1.3.6.1.4.1.294.1.9=ASN1:SEQUENCE:ext_boot_info

[swrv]
swrv=INTEGER:{self.sw_rev}

[ext_boot_info]
extImgSize=INTEGER:{self.total_size}
numComp=INTEGER:{self.num_comps}
sbl=SEQUENCE:sbl
sysfw=SEQUENCE:sysfw
sysfw_data=SEQUENCE:sysfw_data
{sysfw_inner_cert_ext_boot_sequence_string}
{dm_data_ext_boot_sequence_string}

[sbl]
compType = INTEGER:1
bootCore = INTEGER:16
compOpts = INTEGER:0
destAddr = FORMAT:HEX,OCT:{self.load_addr:08x}
compSize = INTEGER:{imagesize_sbl}
shaType  = OID:{self.sha_type}
shaValue = FORMAT:HEX,OCT:{hashval_sbl}

[sysfw]
compType = INTEGER:2
bootCore = INTEGER:0
compOpts = INTEGER:0
destAddr = FORMAT:HEX,OCT:{self.load_addr_sysfw:08x}
compSize = INTEGER:{imagesize_sysfw}
shaType  = OID:{self.sha_type}
shaValue = FORMAT:HEX,OCT:{hashval_sysfw}

[sysfw_data]
compType = INTEGER:18
bootCore = INTEGER:0
compOpts = INTEGER:0
destAddr = FORMAT:HEX,OCT:{self.load_addr_sysfw_data:08x}
compSize = INTEGER:{imagesize_sysfw_data}
shaType  = OID:{self.sha_type}
shaValue = FORMAT:HEX,OCT:{hashval_sysfw_data}
{sysfw_inner_cert_ext_boot_block}
{dm_data_ext_boot_block}''', file=outf)

    def GetCertificate(self, required):
        """Generate certificate based on boot flow followed by device

        Args:
            required: True if the data must be present, False if it is OK to
                return None

        Returns:
            bytes content of the entry, which is the certificate for the
                provided data
        """
        if self.combined:
            return self.CombinedGetCertificate(required)
        else:
            return self.NonCombinedGetCertificate(required)

    def ObtainContents(self):
        data = self.GetCertificate(False)
        if data is None:
            return False
        self.SetContents(data)
        return True

    def ProcessContents(self):
        # The blob may have changed due to WriteSymbols()
        data = self.GetCertificate(True)
        return self.ProcessContentsUpdate(data)

    def AddBintools(self, btools):
        super().AddBintools(btools)
        self.openssl = self.AddBintool(btools, 'openssl')
