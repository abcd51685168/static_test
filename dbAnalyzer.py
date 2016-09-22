#!/usr/bin/env python
# -*- coding: utf-8 -*-

import os
import logging
import hashlib

log = logging.getLogger(__name__)
FILE_CHUNK_SIZE = 16 * 1024


def get_chunks(file_path):
    """Read file contents in chunks (generator)."""

    with open(file_path, "rb") as fd:
        while True:
            chunk = fd.read(FILE_CHUNK_SIZE)
            if not chunk: break
            yield chunk


def calc_md5(target):
    """Calculate all possible hashes for this file."""
    md5 = hashlib.md5()

    for chunk in get_chunks(target):
        md5.update(chunk)

    return md5.hexdigest()


def dbAnalyzer(target):
    cmd_path = "/polyhawk/bin/ti_mgmt_client"
    target_md5 = calc_md5(target)
    # log.info("%s: %s" % (target, target_md5))
    cmd = cmd_path + " --query-md5 " + target_md5
    ret = os.popen(cmd)
    data = ret.read().strip('\n')
    if data.find("error") != -1:
        log.error("server of {0} may not start, error msg: {1}".format(cmd_path, data))
        return "-1"
    result = data.split(" ")

    return result[0]
