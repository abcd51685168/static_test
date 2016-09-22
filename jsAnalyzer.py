#!/usr/bin/env python
# -*- coding: utf-8 -*-

import os
import logging

log = logging.getLogger(__name__)


def jsAnalyzer(target):
    cmd_path = "/usr/bin/perl"
    perl_path = "/polydata/content/javascript/parse_javascript.pl"
    malicious_check = "js malicious: Yes"

    target = '"' + target + '"'
    ret = os.popen(" ".join([cmd_path, perl_path, target]))
    result = ret.read().strip()

    return "1" if result.find(malicious_check) != -1 else "0"
