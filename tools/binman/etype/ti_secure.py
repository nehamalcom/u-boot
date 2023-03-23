# SPDX-License-Identifier: GPL-2.0+
# Copyright 20
# Written by Neha Malcom Francis <n-francis@ti.com>
#

# Support for generating x509 certificate to binary for K3 devices

from collections import OrderedDict
import os

from binman.entry import EntryArg
from binman.etype.x509_cert import Entry_x509_cert

import hashlib

from dtoc import fdt_util
from u_boot_pylib  import tools

class Entry_ti_secure(Entry_x509_cert):
    def __init__(self, section, etype, node):
        super().__init__(section, etype, node)
        self.openssl = None

    def ReadNode(self):
        super().ReadNode()
        self.key_fname = self.GetEntryArgsOrProps([
            EntryArg('keyfile', str)], required=True)[0]
        self.sha = fdt_util.GetInt(self._node, 'sha', 512)

    def GetCertificate(self, required):
        """Generate certificate for contents of this entry

        Args:
            required: True if the data must be present, False if it is OK to
                return None

        Returns:
            bytes content of the entry, which is the certificate for the
                provided data
        """
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

        swrev = 1

        with open(config_fname, 'w', encoding='utf-8') as outf:
            print(f'''
[ req ]
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
basicConstraints       = CA:true
1.3.6.1.4.1.294.1.3    = ASN1:SEQUENCE:swrv
1.3.6.1.4.1.294.1.34   = ASN1:SEQUENCE:sysfw_image_integrity
1.3.6.1.4.1.294.1.35   = ASN1:SEQUENCE:sysfw_image_load

[ swrv ]
swrv = INTEGER:{swrev}

[ sysfw_image_integrity ]
shaType                = OID:2.16.840.1.101.3.4.2.3
shaValue               = FORMAT:HEX,OCT:{hashval}
imageSize              = INTEGER:{imagesize}

[ sysfw_image_load ]
destAddr = FORMAT:HEX,OCT:00000000
authInPlace = INTEGER:2

''', file=outf)
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
