# SPDX-License-Identifier: GPL-2.0+
# Copyright (c) 2022 Texas Instruments Incorporated - https://www.ti.com/
# Written by Neha Malcom Francis <n-francis@ti.com>
#
# Entry-type module for generating schema validated TI board
# configuration binary
#

import os
import struct
import tempfile
import yaml

from collections import OrderedDict
from jsonschema import validate
from shutil import copyfileobj
from shutil import rmtree

from binman.entry import Entry
from binman.etype.section import Entry_section
from binman.etype.blob_ext import Entry_blob_ext
from binman.etype.blob_ext_list import Entry_blob_ext_list
from dtoc import fdt_util
from u_boot_pylib import tools, tout

BOARDCFG = 0xB
BOARDCFG_SEC = 0xD
BOARDCFG_PM = 0xE
BOARDCFG_RM = 0xC
BOARDCFG_NUM_ELEMS = 4

class Entry_ti_board_config(Entry_section):
    """
    Support for generation of TI schema validated board configuration
    binary
    This etype supports generation of two kinds of board configuration
    binaries: singular board config binary as well as combined board config
    binary.

    Available parameters are:

    config-file
        File containing board configuration data in YAML

    schema-file
        File containing board configuration YAML schema against which the
        config file is validated

    These above parameters are used only when the generated binary is
    intended to be a single board configuration binary. Example::

    /* generate a my-ti-board-config.bin generated from a YAML configuration
    file validated against the schema*/
    my-ti-board-config {
        ti-board-config {
            config = "board-config.yaml";
            schema = "schema.yaml";
        };
    };

    To generate a combined board configuration binary, we pack the
    needed individual binaries into a ti-board-config binary. In this case,
    the available supported subnode names are board-cfg, pm-cfg, sec-cfg and
    rm-cfg. For example::

    /* generate a my-combined-ti-board-config.bin packed with a header
    (containing details about the included board config binaries), along
    with the YAML schema validated binaries themselves*/
    my-combined-ti-board-config {
        ti-board-config {
            board-cfg {
                config = "board-cfg.yaml";
                schema = "schema.yaml";
            };
            sec-cfg {
                config = "sec-cfg.yaml";
                schema = "schema.yaml";
            };
        }
    }
    """
    def __init__(self, section, etype, node):
        super().__init__(section, etype, node)

        self.config_file = None
        self.schema_file = None

        self._entries = OrderedDict()
        self._entries_data = OrderedDict()
        self.num_elems = BOARDCFG_NUM_ELEMS
        self.fmt = '<HHHBB'
        self.index = 0
        self.binary_offset = 0
        self.sw_rev = 1
        self.devgrp = 0

    def ReadNode(self):
        super().ReadNode()
        self.config_file = fdt_util.GetString(self._node, 'config')
        self.schema_file = fdt_util.GetString(self._node, 'schema')
        if self.config_file is None:
            self.ReadEntries()

    def ReadEntries(self):
        """Read the subnodes to find out what should go in this image"""
        num_cfgs = 0
        for node in self._node.subnodes:
            if 'type' not in node.props:
                num_cfgs += 1
                etype = 'ti-board-config'
                entry = Entry.Create(self, node, etype)
                entry.ReadNode()
                cfg_data = entry.BuildSectionData(True)
                self._entries[entry.name] = entry
                self._entries_data[entry.name] = cfg_data
        self.num_elems = num_cfgs

    def _convert_to_byte_chunk(self, val, data_type):
        """Convert value into byte array"""
        size = 0
        if (data_type == "#/definitions/u8"):
            size = 1
        elif (data_type == "#/definitions/u16"):
            size = 2
        elif (data_type == "#/definitions/u32"):
            size = 4
        else:
            raise Exception("Data type not present in definitions")
        if type(val) == int:
            br = val.to_bytes(size, byteorder="little")
        return br

    def _compile_yaml(self, schema_yaml, file_yaml):
        """Convert YAML file into byte array based on YAML schema"""
        br = bytearray()
        for key in file_yaml.keys():
            node = file_yaml[key]
            node_schema = schema_yaml['properties'][key]
            node_type = node_schema.get('type')
            if not 'type' in node_schema:
                br += self._convert_to_byte_chunk(node,
                                                  node_schema.get('$ref'))
            elif node_type == 'object':
                br += self._compile_yaml(node_schema, node)
            elif node_type == 'array':
                for item in node:
                    if not isinstance(item, dict):
                        br += self._convert_to_byte_chunk(
                            item, schema_yaml['properties'][key]['items']["$ref"])
                    else:
                        br += self._compile_yaml(node_schema.get('items'), item)
        return br

    def _generate_binaries(self):
        """Generate config binary artifacts from the loaded YAML configuration file"""
        try:
            cfg_binary = bytearray()
            for key in self.file_yaml.keys():
                node = self.file_yaml[key]
                node_schema = self.schema_yaml['properties'][key]
                br = self._compile_yaml(node_schema, node)
                cfg_binary += br
        except Exception as e:
            tout.warning("Combined board config binary was not generated properly")
            cfg_binary = tools.get_bytes(0, 512)
        return cfg_binary

    def _add_boardcfg(self, bcfgtype, bcfgdata):
        size = len(bcfgdata)
        desc = struct.pack(self.fmt, bcfgtype,
                            self.binary_offset, size, self.devgrp, 0)
        with open(self.descfile, "ab+") as desc_fh:
            desc_fh.write(desc)
        with open(self.bcfgfile, "ab+") as bcfg_fh:
            bcfg_fh.write(bcfgdata)
        self.binary_offset += size
        self.index += 1

    def _finalize(self):
        try:
            with open(self.descfile, "rb") as desc_fh:
                with open(self.bcfgfile, "rb") as bcfg_fh:
                    with open(self.fh_file, 'ab+') as fh:
                        desc_fh.seek(0)
                        bcfg_fh.seek(0)
                        copyfileobj(desc_fh, fh)
                        copyfileobj(bcfg_fh, fh)
            data = tools.read_file(self.fh_file)
        except Exception as e:
            tout.warning("Combined board config binary was not generated properly")
            data = tools.get_bytes(0, 512)
        rmtree(self.tmpdir)
        return data

    def BuildSectionData(self, required):
        if self.config_file is None:
            self.binary_offset = 0
            self.tmpdir = tempfile.mkdtemp()
            self.fh_file = os.path.join(self.tmpdir, "fh")
            self.descfile = os.path.join(self.tmpdir, "desc")
            self.bcfgfile = os.path.join(self.tmpdir, "bcfg")
            try:
                with open(self.fh_file, 'wb') as f:
                    t_bytes = f.write(struct.pack(
                        '<BB', self.num_elems, self.sw_rev))
                self.binary_offset += t_bytes
                self.binary_offset += self.num_elems * struct.calcsize(self.fmt)
            except Exception as e:
                tout.warning("Combined board config header was not generated properly")

            if 'board-cfg' in self._entries:
                self._add_boardcfg(BOARDCFG, self._entries_data['board-cfg'])

            if 'sec-cfg' in self._entries:
                self._add_boardcfg(BOARDCFG_SEC, self._entries_data['sec-cfg'])

            if 'pm-cfg' in self._entries:
                self._add_boardcfg(BOARDCFG_PM, self._entries_data['pm-cfg'])

            if 'rm-cfg' in self._entries:
                self._add_boardcfg(BOARDCFG_RM, self._entries_data['rm-cfg'])

            data = self._finalize()
            return data

        else:
            with open(self.config_file, 'r') as f:
                self.file_yaml = yaml.safe_load(f)
            with open(self.schema_file, 'r') as sch:
                self.schema_yaml = yaml.safe_load(sch)
            try:
                validate(self.file_yaml, self.schema_yaml)
            except Exception as e:
                tout.error(f"Schema validation error: {e}")

            data = self._generate_binaries()
            return data

    def SetImagePos(self, image_pos):
        Entry.SetImagePos(self, image_pos)

    def SetCalculatedProperties(self):
        Entry.SetCalculatedProperties(self)

    def CheckEntries(self):
        Entry.CheckEntries(self)
