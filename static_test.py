import os
import logging
import unittest

BASE_DIR = "/root/test_samples/"
log = logging.getLogger()
engine_target_expected = {
    "clamavAnalyzer": {
        "0100-21019fb6fcf5096669f558a04290c920-exe": "Win.Trojan.Agent-1388676.UNOFFICIAL",
        "0101-02231a0ed1e23dafce7927d38c70450b-exe": "Win.Spyware.67058-2.UNOFFICIAL",
        "0102-08e55e6808059da8fdcf95b665cbb004-exe": "Win.Trojan.Injector-14956.UNOFFICIAL",
        "0103-d20e7ed6567aa5657f4f1693a59d226d-exe": "Win.Adware.Downware-367.UNOFFICIAL",
        "0104-0fafe9a6df302647e71eedf0e04f3a4d-exe": "Win.Dropper.Agent-41897.UNOFFICIAL",
        "0105-37adc8221a505b816b9e8f6c59f80dda-exe": "Win.Trojan.Zapchast-2506.UNOFFICIAL",
        "0106-129a84e53e354d68697e8122bc7ddf5a-exe": "Win.Trojan.DustySky-22.UNOFFICIAL",
        "0107-0975ff6c8f8c066b6b919e43c5d58aca-exe": "Win.Trojan.Keylog-321.UNOFFICIAL",
        "0108-0da0ced5e1c9f47a46ebebd2cf4c966d-exe": "Win.Downloader.Banload-1442.UNOFFICIAL",
        "0109-0231197819d05861a341dc977305c3cf-exe": None,
    },
    "jsAnalyzer": {
        "0200-c7801420e89c0b3e707240485fdae28a-js": "1",
        "0201-8fad5a6d0a3ef95c2e7bdc2dc05610e0-js": "1",
        "0202-3bd1cbc59d9034daa70e7bf3a9684083-js": "1",
        "0203-7e5c686c402e0b37f7fc00dd2e22a227-js": "0",
    },
    "dbAnalyzer": {
        "0300-3bbd96a1cb5f122bf841ba07ac272beb-exe": "1",
        "0301-21eafa0b8fa4e320341e0b25b057ddcd-exe": "1",
        "0302-20ac74f633e3e7561cf1488c5e52235c-exe": "1",
        "0303-144c03f23160b52e90532cd0823d71bf-exe": "1",
        "0304-3cea377daf1fbf035524163092bb43d4-exe": "1",
        "0305-097771ba36c8e762b950d35debf74c3d-exe": "0",
        "0306-0231197819d05861a341dc977305c3cf-exe": "0",
        "0307-04ee8693c5e45b2dae944ef92becaa50-exe": "0",
        "0308-07135a70225134fe929759f5c3e71df0-exe": "0",
        "0309-0857958ebe4bd6ccd1e40d773b36883b-exe": "0",
    },
    "shellAnalyzer": {
        "0400-21019fb6fcf5096669f558a04290c920-exe": "UPX",
        "0401-38ea4e0a82bf2eb5728ec9817d6aeea9-exe": "Confuser",
        "0402-2bae3a0f72d07a9a60bd8bd0b1958a37-exe": "Smart Assembly",
        "0403-09389c5a124a1400d76e83bc9c866295-exe": "ASPack",
        "0404-0da0ced5e1c9f47a46ebebd2cf4c966d-exe": "NsPacK",
        "0405-90d71121fd7497f5ca3260f995861f62-exe": "VMProtect",
        "0406-2ec609c670581810c89944ad002d8cba-exe": "AntiDote",
        "0407-0041bd2786b49801b60a0e32d8e13e4d-exe": "EXECryptor",
        "0408-00c7b63491f423e9644e32fe600fbb06-exe": "eXPressor",
        "0409-06f65f8ed72ff033a46ae38ad4c13014-exe": None,
    },
    "peAnalyzer": {
        "0500-0cc8f6693b8300d05a696fe2e90c4833-exe": "1",
        "0501-bbfba3c2af4c2c86fb51981fbc1a992f-exe": "1",
        "0502-d80dfc9c319d368097b64128c928031d-exe": "1",
        "0503-232120432d54a3cea47481153b8b3870-exe": "1",
        "0504-5131c0a3f30e52f1654e45667df57d96-exe": "1",
        "0505-a4482b8b6b839bcfb457eadcccda9e6f-exe": "0",
        "0506-7ddddfa915d5c69f191ca9063d587ead-exe": "0",
        "0507-0ea6785c36055e184d73c9369d8c8b30-exe": "0",
        "0508-86d833a2982e9724c68b7c4cde61729c-exe": "0",
        "0509-2bae3a0f72d07a9a60bd8bd0b1958a37-exe": "0",
    },
    "yaraAnalyzer": {
        "0600-a5a616b6bfdd07766e529446a6348c00-dll": "spyeye",
        "0601-9ad95439209602fcfafb1952e22df3ac-dll": "js_downloader",
        "0602-5aed18337027e7099637db4239efbb58-dll": "CAP_HookExKeylogger",
        "0603-25f154f3b3bfcae64f1d565e1b34e52d-exe": "Njrat",
        "0604-1ab0284377880006b30d6eaba93eceaf-exe": "Base64_encoded_Executable",
        "0605-001cbe83a2f64dc7b9eb7dbb12a79d17-exe": "XtremeRATStrings",
        "0606-0029468358c35200ec419b54e49925d2-gif": "webshell_Shell_ci_Biz_was_here_c100_v_xxx",
        "0607-06f65f8ed72ff033a46ae38ad4c13014-exe": None,
        "0608-0857958ebe4bd6ccd1e40d773b36883b-exe": None,
        "0609-04ee8693c5e45b2dae944ef92becaa50-exe": None,
    },
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
