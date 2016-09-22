#!/usr/bin/env python
# -*- coding: utf-8 -*-

import os
import logging
import yara

log = logging.getLogger(__name__)
RULE_PATH = "/polydata/content/yara/rules/all.yar"

rules = yara.compile(RULE_PATH)


def yaraAnalyzer(target):
    matches = rules.match(target.encode("utf8"))
    if matches:
        log.debug("results: %s" % matches)

    return matches[0].rule if matches else None
