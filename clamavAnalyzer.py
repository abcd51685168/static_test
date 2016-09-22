#!/usr/bin/env python
# -*- coding: utf-8 -*-

import os
import shutil
import logging
import clamd

log = logging.getLogger(__name__)

clamav = clamd.ClamdUnixSocket()
clamav.ping()


def clamavAnalyzer(target):
    task_tmp_dir = '/tmp/scan'
    if not os.path.exists(task_tmp_dir):
        os.mkdir(task_tmp_dir)

    dest_file_path = os.path.join(task_tmp_dir, os.path.basename(target))
    shutil.copy(target, task_tmp_dir)
    result = clamav.scan(dest_file_path)

    os.remove(dest_file_path)

    # result sample: {u'/run/shm/tmp_2998710558886437521_http_1.js': (u'OK', None)}
    # TODO: solve error:Can't create temporary directory
    # reference:(https://wiki.archlinux.org/index.php/ClamAV#Error:_Can.27t_create_temporary_directory)
    # {u'/tmp/test.pdf': (u'ERROR', u"Can't create temporary directory")}
    # result sample: {u'/run/shm/tmp_2998710558886437521_http_1.js': (u'FOUND', u"Trojan_Spy_Zbot_436")}

    found = result.values()[0][0]
    name = result.values()[0][1]
    if found in "FOUND":
        return name
    elif found in "ERROR":
        log.warning("check permissions of the binary folder, every parent folder should be with x "
                    "permission, %s" % name)
        return "-1"
    elif found in "OK":
        return None
