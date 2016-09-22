#!/usr/bin/env python
# -*- coding: utf-8 -*-

import os
import logging
import commands

log = logging.getLogger(__name__)


def shellAnalyzer(target):
    cmd_path = "/polyhawk/bin/diec_lin64"
    key_word = ["protector:", "packer:"]
    target = '"' + target + '"'
    status, data = commands.getstatusoutput(" ".join([cmd_path, target]))
    if status != 0:
        log.error("Execute %s failed, data: %s" % (__name__.split('.')[-1], data))
        return -1

    # PE: protector: Crypto Obfuscator For .Net(5.X)[-]
    # PE: packer: ASPack(2.12-2.XX)[-]
    for key in key_word:
        if data.find(key) != -1:
            result = data[data.index(key) + len(key) + 1:].split("(", 1)
            return result[0]
    return None
