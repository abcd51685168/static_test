import os
import logging
import unittest

BASE_DIR = "/root/samples/"
log = logging.getLogger()
engine_target_expected = {
    "yaraAnalyzer": {
        "a5a616b6bfdd07766e529446a6348c00.vir": "spyeye",
        "9ad95439209602fcfafb1952e22df3ac.vir": "js_downloader",
        "5aed18337027e7099637db4239efbb58.vir": "CAP_HookExKeylogger",
        "25f154f3b3bfcae64f1d565e1b34e52d.vir": "Njrat",
        "1ab0284377880006b30d6eaba93eceaf.vir": "Base64_encoded_Executable",
        "001cbe83a2f64dc7b9eb7dbb12a79d17.vir": "XtremeRATStrings",
        "0029468358c35200ec419b54e49925d2.vir": "webshell_Shell_ci_Biz_was_here_c100_v_xxx",
        "06f65f8ed72ff033a46ae38ad4c13014.vir": None,
        "0857958ebe4bd6ccd1e40d773b36883b.vir": None,
        "04ee8693c5e45b2dae944ef92becaa50.vir": None,
    },
    "jsAnalyzer": {
        "mail_b204bef9.js": "1",
        "scan_175109f9.js": "1",
        "m.html.js": "1",
        "normal.js": "0",
    },
    "clamavAnalyzer": {
        "21019fb6fcf5096669f558a04290c920.vir": "Win.Trojan.Agent-1388676.UNOFFICIAL",
        "02231a0ed1e23dafce7927d38c70450b.vir": "Win.Spyware.67058-2.UNOFFICIAL",
        "08e55e6808059da8fdcf95b665cbb004.vir": "Win.Trojan.Injector-14956.UNOFFICIAL",
        "d20e7ed6567aa5657f4f1693a59d226d.vir": "Win.Adware.Downware-367.UNOFFICIAL",
        "0fafe9a6df302647e71eedf0e04f3a4d.vir": "Win.Dropper.Agent-41897.UNOFFICIAL",
        "37adc8221a505b816b9e8f6c59f80dda.vir": "Win.Trojan.Zapchast-2506.UNOFFICIAL",
        "129a84e53e354d68697e8122bc7ddf5a.vir": "Win.Trojan.DustySky-22.UNOFFICIAL",
        "0975ff6c8f8c066b6b919e43c5d58aca.vir": "Win.Trojan.Keylog-321.UNOFFICIAL",
        "0da0ced5e1c9f47a46ebebd2cf4c966d.vir": "Win.Downloader.Banload-1442.UNOFFICIAL",
        "0231197819d05861a341dc977305c3cf.vir": None,
    },
    "shellAnalyzer": {
        "21019fb6fcf5096669f558a04290c920.vir": "UPX",
        "38ea4e0a82bf2eb5728ec9817d6aeea9.vir": "Confuser",
        "2bae3a0f72d07a9a60bd8bd0b1958a37.vir": "Smart Assembly",
        "09389c5a124a1400d76e83bc9c866295.vir": "ASPack",
        "0da0ced5e1c9f47a46ebebd2cf4c966d.vir": "NsPacK",
        "28ee09c92a637cfac9636557ea77baf8.vir": "Babel .NET",
        "90d71121fd7497f5ca3260f995861f62.vir": "VMProtect",
        "2ec609c670581810c89944ad002d8cba.vir": "AntiDote",
        "0041bd2786b49801b60a0e32d8e13e4d.vir": "EXECryptor",
        "00c7b63491f423e9644e32fe600fbb06.vir": "eXPressor",
        "06f65f8ed72ff033a46ae38ad4c13014.vir": None,
    },
    "peAnalyzer": {
        "0cc8f6693b8300d05a696fe2e90c4833.vir": "1",
        "bbfba3c2af4c2c86fb51981fbc1a992f.vir": "1",
        "d80dfc9c319d368097b64128c928031d.vir": "1",
        "232120432d54a3cea47481153b8b3870.vir": "1",
        "5131c0a3f30e52f1654e45667df57d96.vir": "1",
        "a4482b8b6b839bcfb457eadcccda9e6f.vir": "0",
        "7ddddfa915d5c69f191ca9063d587ead.vir": "0",
        "0ea6785c36055e184d73c9369d8c8b30.vir": "0",
        "86d833a2982e9724c68b7c4cde61729c.vir": "0",
        "2bae3a0f72d07a9a60bd8bd0b1958a37.vir": "0",
    },
    "dbAnalyzer": {
        "3bbd96a1cb5f122bf841ba07ac272beb.vir": "1",
        "21eafa0b8fa4e320341e0b25b057ddcd.vir": "1",
        "20ac74f633e3e7561cf1488c5e52235c.vir": "1",
        "144c03f23160b52e90532cd0823d71bf.vir": "1",
        "3cea377daf1fbf035524163092bb43d4.vir": "1",
        "097771ba36c8e762b950d35debf74c3d.vir": "0",
        "0231197819d05861a341dc977305c3cf.vir": "0",
        "04ee8693c5e45b2dae944ef92becaa50.vir": "0",
        "07135a70225134fe929759f5c3e71df0.vir": "0",
        "0857958ebe4bd6ccd1e40d773b36883b.vir": "0",
    }
}


def init_logging():
    formatter = logging.Formatter("%(asctime)s [%(name)s] %(levelname)s: %(message)s")

    # fh = logging.handlers.WatchedFileHandler(os.path.join(LOG_ROOT, FILE_NAME + ".log"))
    # fh.setFormatter(formatter)
    # log.addHandler(fh)

    ch = logging.StreamHandler()
    ch.setFormatter(formatter)
    log.addHandler(ch)

    log.setLevel(logging.INFO)


class TestStringMethods(unittest.TestCase):
    def test_all(self):
        for engine, target_expected in engine_target_expected.items():
            module = __import__(engine)
            func = getattr(module, engine)
            for target, expected in target_expected.items():
                result = func(os.path.join(BASE_DIR, target))
                self.assertEqual(result, expected,
                                 "engine: {}, target: {}, result: {}, expected: {}".format(engine, target, result,
                                                                                           expected))


if __name__ == "__main__":
    _current_dir = os.path.abspath(os.path.dirname(__file__))
    os.chdir(_current_dir)
    init_logging()
    unittest.main()
