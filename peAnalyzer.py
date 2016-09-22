#!/usr/bin/env python
# -*- coding: utf-8 -*-

import os
import logging
import pefile
from ctypes import cdll

log = logging.getLogger(__name__)

so_path = "/polyhawk/lib/libmcla.so"
cfg_path = "/polydata/content/mcla/mcla.cfg"
DLL_API_FEATURES = [u'libgcc_s_dw2-1.dll', u'qt5core.dll', u'olepro32.dll', u'msi.dll', u'libstdc++-6.dll',
                    u'mscoree.dll', u'methcallengine', u'gdipcreatebitmapfromscan0', u'getdiskfreespacew', u'memchr',
                    u'_corexemain', u'gdipdeletegraphics', u'__vbai4errvar', u'freeconsole', u'rtllookupfunctionentry',
                    u'gettextextentpoint32w', u'gdipgetimagewidth', u'setabortproc', u'lookupprivilegevaluew',
                    u'localeconv', u'getnearestpaletteindex', u'gdipgetimageheight', u'rtlcapturecontext',
                    u'setlayeredwindowattributes', u'writeprivateprofilestringw', u'translateacceleratorw',
                    u'__mb_cur_max', u'_cordllmain', u'getmenustringw', u'charupperbuffw', u'signalobjectandwait',
                    u'strerror', u'enumdisplaymonitors', u'appendmenuw', u'rtlvirtualunwind', u'shell_notifyiconw',
                    u'modf', u'proccallengine', u'messageboxindirectw', u'enumcalendarinfow', u'getobjecttype',
                    u'dodragdrop', u'dragqueryfilew', u'versetconditionmask', u'internetconnectw',
                    u'systemtimetotzspecificlocaltime', u'monitorfromwindow', u'varianttimetosystemtime',
                    u'gdipcreatefromhdc']
THRESH = 18

libpefile = cdll.LoadLibrary(so_path)
ret = libpefile.pecker_gmcla_init(cfg_path, len(DLL_API_FEATURES))
if not ret:
    log.debug("load %s successfully", so_path)
else:
    log.error("load %s failed, ret: %s" % (so_path, ret))


def get_pe_info(target):
    row = [0] * len(DLL_API_FEATURES)

    pe = pefile.PE(target)

    if hasattr(pe, "DIRECTORY_ENTRY_IMPORT"):
        for entry in pe.DIRECTORY_ENTRY_IMPORT:
            dll = entry.dll.lower()
            try:
                index = DLL_API_FEATURES.index(dll)
                row[index] = 1
            except ValueError:
                pass

            for imp in entry.imports:
                try:
                    index = DLL_API_FEATURES.index(imp.name)
                    row[index] = 1
                except ValueError:
                    pass
    else:
        return None

    # change list to string, input for libpefile's function
    return ",".join(map(str, row))


def peAnalyzer(target):
    pe_info = get_pe_info(target)
    if not pe_info:
        return -1

    category_count = libpefile.pecker_gmcla_group_checkall_vec_data(pe_info, len(DLL_API_FEATURES))
    return "1" if category_count >= THRESH else "0"
