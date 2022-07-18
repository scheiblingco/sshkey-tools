import unittest
from random import randint

import faker
from paramiko.util import deflate_long, inflate_long

import src.sshkey_tools.utils as utils

EXPECTED_LONG_CONVERSIONS = [
    (0, b"\x00"),
    (1, b"\x01"),
    (11638779394004435200, b"\x00\xa1\x85@1\xa6\xc5A\x00"),
    (15203631582360839337, b"\x00\xd2\xfe&_2\x87$\xa9"),
    (15302225898842444598, b"\x00\xd4\\ma]IS6"),
    (15945599391219780268, b"\x00\xddJ&)\xb4W\n\xac"),
    (15242635186864927689, b"\x00\xd3\x88\xb7\xf1\x89\xf43\xc9"),
    (17517368859399259630, b"\x00\xf3\x1a2*\xa7\xfb\x85\xee"),
    (11464229064000469348, b"\x00\x9f\x19\x1f\x97\xf7t\xf9d"),
]

EXPECTED_HASHES = [
    (
        # trunk-ignore(flake8/W605)
        b"HYoNIlxkwde]GX]qBNdtH\^ZYGyRWf",
        "15:6d:0c:c7:cb:9f:9a:85:dd:5e:f4:ee:b3:2b:9d:3f",
        "tchAVFXDgszqtTYzokVmUfdQOHi5UvSsPVQzFsHnfXg",
        "mof7eHzmuTZzEkPnjAUbaFABqZl8YUanE3Ips+jy5B9aiRtA1D8fIJgmmfb4V/T0AZz08Gu4AsMOKfybrjOUAA",
    ),
    (
        # trunk-ignore(flake8/W605)
        b"sseJmSLI_RgSRciYac\M`BjxkziCFD",
        "cc:a4:4e:cc:1a:a4:3b:e6:26:f2:1b:a4:70:b6:0a:5a",
        "XYWSEK4LHNhkVSMrMTVBg73r4Nu0ElpFuQ1efJrp5Ks",
        "/vZr65Oj0vyIIaC+iVCFiXNnmf7Ntg3njkBwJZddOxYaZ3mvs3Ra2OOh/VN1bMDbKaZik9BOkzDTjIXNBMDgUg",
    ),
    (
        # trunk-ignore(flake8/W605)
        b"AGGPP]bLy[SKwkNGfgjkwGw_vPa\]h",
        "25:de:7e:8f:65:da:5c:1d:c2:aa:79:8b:58:72:69:12",
        "f6C8TqeIHwAIt0PvvjnR23uBzLcgr6MfTr+150u2+XE",
        "cLVxsX2k3HEX6/e+S3NROdAzEIM45gO/stYLyZiJrQ5n14fBGgZX25bwJFcAtB/FNZjrIwmG1m3jRJ+CgXgBBQ",
    ),
    (
        b"OTUwhulOPckus_M]EyuxXWz^URykVP",
        "df:d8:12:e2:bb:ad:70:0a:0a:e2:ba:b2:2c:82:0e:f7",
        "pWW/P8tP5qOFeEYeoDMxzJlTHowbs6VwkTzHeQWrg8g",
        "gF5ZmdFWxYVcDMUMyC4hIgFBXtgrxv8VZbw809UiqgTzpxOEyY1mVupma9joUGRHr3IjbDJdr+Uiq4TuZwVTjw",
    ),
    (
        b"JPvFmb^HoOw]KPwYAgVlWAhtZt]YSb",
        "5e:6e:12:09:50:b3:b4:e7:8f:f9:a0:d0:a6:40:e2:4c",
        "hsrRKQ8vR7oDIxYAALz48kyg0BZNs61S09KCrgNJMyk",
        "AmKjHbklKxWgk1EcUwtJenIYfvGC4bTfYwXnkOGvfFu2nvClgrTJix8MgZ+RtQq/3usweE2CIHgD+d3FH052kQ",
    ),
    (
        b"lLzVwDidpzTCNUbAmYgxaCV^ASbdy[",
        "c5:e9:35:ea:f9:32:e6:2b:68:c2:18:8a:9f:93:ba:01",
        "METh/occInzgqIvcRrJlyQa8E6nr095BXlrn9izySpA",
        "G3e2YkowIzM2k5VyKxSk7O8+TJlGzEYE8pL7SPS1Ts4OOg37q06jinNXeRVSDt3ICih3KNtJPXHnFV3M41xDSw",
    ),
    (
        b"`NSyrnrn[ZntLugeydWWiaSTlVTNuU",
        "1a:cb:13:fb:e9:a1:ea:84:55:fd:a1:c4:7a:05:7b:d0",
        "yQOxfh54aRBnH9tPxYsvDF/TLTy15nRze0AuftJWRcg",
        "u9xyMyKaldgr3EZ9WFUkpGVh3C+lqLci6D3fD9lq3k2vtqK90CzTwHDNA/OHBnsc/ukWPe+kxaGn5CtHROjtLg",
    ),
    (
        b"JCUdozAoqggVFeD`dAXo]ElrDOrgVV",
        "42:5c:7b:4b:44:ac:f4:21:e8:fb:17:fb:b4:46:62:d4",
        "uuGOfXTNMvcwfS6nol/cJ5ijVw0DVBA+4rpt18PsQjo",
        "j6JOK8j8cjZnddm3IjjjnmHQobIewIelGOeSGMa9WEcKd8nkvTD17coSYdObQ9/X+kbU+9nPDSaRjjA3eQW6QA",
    ),
    (
        b"]Beog]hAviJSgTZlbTDcytqftqaDof",
        "e0:d3:0a:36:75:31:eb:e8:20:73:25:c3:2e:67:aa:54",
        "FRreFuNrKbZ1lkJAhtaQSyqCHkrkRoZ6oKc7JNyLTAE",
        "MBrk8xn3kkXmV+KefP7Lg0plxd+rI0dZ+QExCL3NlSfC54Y8j6GENtmheUFknHwaLpiwgKSRtwPN6ZP6EfaK0A",
    ),
    (
        b"XKHCjGvvtJgPdDkGSGDyPkZDBif^BZ",
        "7e:e4:29:df:b4:77:2a:6f:5d:eb:9f:25:8e:bd:45:b6",
        "BmF8Pt4E/z0M8/rMy6mXkUpVlDG9Zje5+KA3dBVIR7c",
        "I9lVFWPx6YkwnsZRMf21TPFvquV59+ng11F3EFFhDLKHrK/l6cdGQu1K0idWQQfRK44d77z00TK/aKmPmgZ2kg",
    ),
]


class TestStringBytestringConversion(unittest.TestCase):
    def setUp(self):
        self.faker = faker.Faker()

    def test_ensure_string(self):
        self.assertEqual(utils.ensure_string(""), utils.ensure_string(b""))

        self.assertEqual(None, utils.ensure_string(None))

        for _ in range(100):
            val = self.faker.pystr()

            self.assertEqual(
                utils.ensure_string(val), utils.ensure_string(val.encode("utf-8"))
            )

        lst = list([self.faker.pystr() for _ in range(10)])
        lst_byt = list([x.encode("utf-8") if randint(0, 1) == 1 else x for x in lst])

        self.assertIsInstance(utils.ensure_string(lst), list)
        self.assertEqual(lst, utils.ensure_string(lst), utils.ensure_string(lst_byt))

        tpl = tuple(self.faker.pystr() for _ in range(10))
        tpl_byt = tuple(x.encode("utf-8") if randint(0, 1) == 1 else x for x in tpl)

        self.assertIsInstance(utils.ensure_string(tpl), list)

        self.assertEqual(
            list(tpl), utils.ensure_string(tpl), utils.ensure_string(tpl_byt)
        )

        st = set(self.faker.pystr() for _ in range(10))
        st_byt = set(x.encode("utf-8") if randint(0, 1) == 1 else x for x in st)

        self.assertIsInstance(utils.ensure_string(st), list)
        self.assertEqual(list(st), utils.ensure_string(st), utils.ensure_string(st_byt))

        dct = dict({self.faker.pystr(): self.faker.pystr() for _ in range(10)})
        dct_byt = dict(
            {
                x.encode("utf-8")
                if randint(0, 1) == 1
                else x: y.encode("utf-8")
                if randint(0, 1) == 1
                else y
                for x, y in dct.items()
            }
        )

        self.assertIsInstance(utils.ensure_string(dct), dict)
        self.assertEqual(dct, utils.ensure_string(dct), utils.ensure_string(dct_byt))

    def test_ensure_bytestring(self):
        self.assertEqual(utils.ensure_bytestring(""), utils.ensure_bytestring(b""))

        self.assertEqual(None, utils.ensure_bytestring(None))

        for _ in range(100):
            val = self.faker.pystr().encode("utf-8")

            self.assertEqual(
                utils.ensure_bytestring(val),
                utils.ensure_bytestring(val.decode("utf-8")),
            )

        lst = list([self.faker.pystr().encode("utf-8") for _ in range(10)])
        lst_byt = list([x.decode("utf-8") if randint(0, 1) == 1 else x for x in lst])

        self.assertIsInstance(utils.ensure_bytestring(lst), list)
        self.assertEqual(
            lst, utils.ensure_bytestring(lst), utils.ensure_bytestring(lst_byt)
        )

        tpl = tuple(self.faker.pystr().encode("utf-8") for _ in range(10))
        tpl_byt = tuple(x.decode("utf-8") if randint(0, 1) == 1 else x for x in lst)

        self.assertIsInstance(utils.ensure_bytestring(tpl), list)

        self.assertEqual(
            list(tpl), utils.ensure_bytestring(tpl), utils.ensure_bytestring(tpl_byt)
        )

        st = set(self.faker.pystr().encode("utf-8") for _ in range(10))
        st_byt = set(x.decode("utf-8") if randint(0, 1) == 1 else x for x in lst)

        self.assertIsInstance(utils.ensure_bytestring(st), list)
        self.assertEqual(
            list(st), utils.ensure_bytestring(st), utils.ensure_bytestring(st_byt)
        )

        dct = dict(
            {
                self.faker.pystr().encode("utf-8"): self.faker.pystr().encode("utf-8")
                for _ in range(10)
            }
        )
        dct_byt = dict(
            {
                x.decode("utf-8")
                if randint(0, 1) == 1
                else x: y.decode("utf-8")
                if randint(0, 1) == 1
                else y
                for x, y in dct.items()
            }
        )

        self.assertIsInstance(utils.ensure_bytestring(dct), dict)
        self.assertEqual(
            dct, utils.ensure_bytestring(dct), utils.ensure_bytestring(dct_byt)
        )

    def test_concat_to_string(self):
        self.assertEqual(utils.concat_to_string(""), utils.concat_to_string(b""))
        self.assertEqual(utils.concat_to_string(None), "")

        for _ in range(100):
            strs = [self.faker.pystr() for _ in range(randint(10, 100))]
            strs_byt = [x.encode("utf-8") if randint(0, 1) == 1 else x for x in strs]

            self.assertEqual(
                utils.concat_to_string(*strs),
                utils.concat_to_string(*strs_byt),
                "".join(strs),
            )

    def test_concat_to_bytestring(self):
        self.assertEqual(
            utils.concat_to_bytestring(b""), utils.concat_to_bytestring("")
        )
        self.assertEqual(utils.concat_to_bytestring(None), b"")

        for _ in range(100):
            byts = [self.faker.pystr().encode("utf-8") for _ in range(randint(10, 100))]
            byts_str = [x.decode("utf-8") if randint(0, 1) == 1 else x for x in byts]

            self.assertEqual(
                utils.concat_to_bytestring(*byts),
                utils.concat_to_bytestring(*byts_str),
                b"".join(byts),
            )


class TestLongConversion(unittest.TestCase):
    def test_expected_deflation(self):
        """
        Ensure the built-in function handles deflation as expected
        compared to the established function
        """
        for before, after in EXPECTED_LONG_CONVERSIONS:
            self.assertEqual(
                utils.long_to_bytes(before),
                after,
                f"Failed to convert {before} to a byte string "
                + "(expected: {after}, got: {long_to_bytes(before)})",
            )

            self.assertEqual(
                deflate_long(before),
                utils.long_to_bytes(before),
                "The comparative function failed to deliver the same result as built-in",
            )

    def test_expected_inflation(self):
        """
        Ensure the built-in function handles inflation as expected
        compared to the established function
        """
        for after, before in EXPECTED_LONG_CONVERSIONS:
            self.assertEqual(
                utils.bytes_to_long(before),
                after,
                f"Failed to convert {before} to a byte string "
                + f"(expected: {after}, got: {utils.bytes_to_long(before)})",
            )

            self.assertEqual(
                inflate_long(before),
                utils.bytes_to_long(before),
                "The comparative function failed to deliver the same result as built-in",
            )

    def test_expected_exception(self):
        """
        Ensure appropriate exceptions are thrown when the input is invalid
        """
        with self.assertRaises(ValueError):
            utils.long_to_bytes(-1)

        with self.assertRaises(TypeError):
            utils.long_to_bytes("one")

    def test_random_values(self):
        """
        Extend testing with random results, comparing to the established function.
        """
        start_length = 16
        for _ in range(15):
            print(start_length)

            for _ in range(10):
                value = randint(2**start_length - 1, 2**start_length)

                builtin = utils.long_to_bytes(value)
                compare = deflate_long(value)

                self.assertEqual(builtin, compare)

                self.assertEqual(utils.bytes_to_long(compare), inflate_long(builtin))

            start_length = start_length * 2


class TestNonceGeneration(unittest.TestCase):
    def test_nonce_generation(self):
        """
        Ensure the nonce is generated correctly
        """
        for _ in range(10):
            self.assertIsInstance(utils.generate_secure_nonce(), str)


class TestHashGeneration(unittest.TestCase):
    def test_hashing_functions(self):
        """
        Test the md5 hash function
        """
        for bytestring, md5, sha256, sha512 in EXPECTED_HASHES:
            md5_2 = utils.md5_fingerprint(bytestring, False)
            md5_3 = utils.md5_fingerprint(bytestring, True)
            sha256_2 = utils.sha256_fingerprint(bytestring, False)
            sha256_3 = utils.sha256_fingerprint(bytestring, True)
            sha512_2 = utils.sha512_fingerprint(bytestring, False)
            sha512_3 = utils.sha512_fingerprint(bytestring, True)

            self.assertEqual(md5, md5_2)
            self.assertEqual(sha256, sha256_2)
            self.assertEqual(sha512, sha512_2)

            self.assertEqual(f"MD5:{md5}", md5_3)
            self.assertEqual(f"SHA256:{sha256}", sha256_3)
            self.assertEqual(f"SHA512:{sha512}", sha512_3)


if __name__ == "__main__":
    unittest.main()
