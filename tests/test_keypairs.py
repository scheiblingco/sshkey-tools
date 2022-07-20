# Test privkey generation with valid and invalid parameters
# Test privkey import
# Test import to right class
# Test pubkey generation from priv
import os
import shutil
import unittest

from cryptography.hazmat.primitives.asymmetric import dsa as _DSA
from cryptography.hazmat.primitives.asymmetric import ec as _EC
from cryptography.hazmat.primitives.asymmetric import ed25519 as _ED25519
from cryptography.hazmat.primitives.asymmetric import rsa as _RSA

import src.sshkey_tools.exceptions as _EX
from src.sshkey_tools.keys import (
    DsaPrivateKey,
    DsaPublicKey,
    EcdsaCurves,
    EcdsaPrivateKey,
    EcdsaPublicKey,
    Ed25519PrivateKey,
    Ed25519PublicKey,
    PrivateKey,
    PublicKey,
    RsaPrivateKey,
    RsaPublicKey,
)


class KeypairMethods(unittest.TestCase):
    def generateClasses(self):
        self.rsa_key = RsaPrivateKey.generate(2048)
        self.dsa_key = DsaPrivateKey.generate()
        self.ecdsa_key = EcdsaPrivateKey.generate(EcdsaCurves.P256)
        self.ed25519_key = Ed25519PrivateKey.generate()

    def generateFiles(self, folder):
        self.folder = folder
        try:
            os.mkdir(f"tests/{folder}")
        except FileExistsError:
            shutil.rmtree(f"tests/{folder}")
            os.mkdir(f"tests/{folder}")

        os.system(
            f'ssh-keygen -t rsa -b 2048 -f tests/{folder}/rsa_key_sshkeygen -N "password" > /dev/null 2>&1'
        )
        os.system(
            f'ssh-keygen -t dsa -b 1024 -f tests/{folder}/dsa_key_sshkeygen -N "" > /dev/null 2>&1'
        )
        os.system(
            f'ssh-keygen -t ecdsa -b 256 -f tests/{folder}/ecdsa_key_sshkeygen -N "" > /dev/null 2>&1'
        )
        os.system(
            f'ssh-keygen -t ed25519 -f tests/{folder}/ed25519_key_sshkeygen -N "" > /dev/null 2>&1'
        )

    def setUp(self):
        self.generateClasses()
        self.generateFiles("KeypairMethods")

    def tearDown(self):
        shutil.rmtree(f"tests/{self.folder}")

    def assertEqualPrivateKeys(
        self, priv_class, pub_class, a, b, privkey_attr=["private_numbers"]
    ):
        self.assertIsInstance(a, priv_class)
        self.assertIsInstance(b, priv_class)

        for att in privkey_attr:
            try:
                self.assertEqual(getattr(a, att), getattr(b, att))
            except AssertionError:
                print("Hold")

        self.assertEqualPublicKeys(pub_class, a.public_key, b.public_key)

    def assertEqualPublicKeys(self, keyclass, a, b):
        self.assertIsInstance(a, keyclass)
        self.assertIsInstance(b, keyclass)

        self.assertEqual(a.raw_bytes(), b.raw_bytes())

    def assertEqualKeyFingerprint(self, file_a, file_b):
        self.assertEqual(
            0,
            os.system(
                f"""bash -c "
               diff \
               <( ssh-keygen -lf {file_a}) \
               <( ssh-keygen -lf {file_b}) \
            "
            """
            ),
        )


class TestKeypairMethods(KeypairMethods):
    def test_fail_assertions(self):
        with self.assertRaises(AssertionError):
            self.assertEqualPrivateKeys(
                RsaPrivateKey,
                RsaPublicKey,
                RsaPrivateKey.from_file(
                    f"tests/{self.folder}/rsa_key_sshkeygen", "password"
                ),
                DsaPrivateKey.from_file(f"tests/{self.folder}/dsa_key_sshkeygen"),
            )

        with self.assertRaises(AssertionError):
            self.assertEqualPublicKeys(
                RsaPublicKey,
                RsaPublicKey.from_file(f"tests/{self.folder}/rsa_key_sshkeygen.pub"),
                DsaPublicKey.from_file(f"tests/{self.folder}/dsa_key_sshkeygen.pub"),
            )

        with self.assertRaises(AssertionError):
            self.assertEqualKeyFingerprint(
                f"tests/{self.folder}/rsa_key_sshkeygen",
                f"tests/{self.folder}/dsa_key_sshkeygen",
            )

    def test_successful_assertions(self):
        self.assertTrue(os.path.isfile(f"tests/{self.folder}/rsa_key_sshkeygen"))
        self.assertEqualKeyFingerprint(
            f"tests/{self.folder}/rsa_key_sshkeygen",
            f"tests/{self.folder}/rsa_key_sshkeygen.pub",
        )

        self.assertTrue(os.path.isfile(f"tests/{self.folder}/dsa_key_sshkeygen"))
        self.assertEqualKeyFingerprint(
            f"tests/{self.folder}/dsa_key_sshkeygen",
            f"tests/{self.folder}/dsa_key_sshkeygen.pub",
        )

        self.assertTrue(os.path.isfile(f"tests/{self.folder}/ecdsa_key_sshkeygen"))
        self.assertEqualKeyFingerprint(
            f"tests/{self.folder}/ecdsa_key_sshkeygen",
            f"tests/{self.folder}/ecdsa_key_sshkeygen.pub",
        )

        self.assertTrue(os.path.isfile(f"tests/{self.folder}/ed25519_key_sshkeygen"))
        self.assertEqualKeyFingerprint(
            f"tests/{self.folder}/ed25519_key_sshkeygen",
            f"tests/{self.folder}/ed25519_key_sshkeygen.pub",
        )


class TestKeyGeneration(KeypairMethods):
    def setUp(self):
        pass

    def tearDown(self):
        pass

    def test_rsa(self):
        key_bits = [512, 1024, 2048, 4096, 8192]

        for bits in key_bits:
            key = RsaPrivateKey.generate(bits)

            assert isinstance(key, RsaPrivateKey)
            assert isinstance(key, PrivateKey)
            assert isinstance(key.key, _RSA.RSAPrivateKey)
            assert isinstance(key.private_numbers, _RSA.RSAPrivateNumbers)

            assert isinstance(key.public_key, RsaPublicKey)
            assert isinstance(key.public_key, PublicKey)
            assert isinstance(key.public_key.key, _RSA.RSAPublicKey)
            assert isinstance(key.public_key.public_numbers, _RSA.RSAPublicNumbers)

    def test_rsa_incorrect_keysize(self):
        with self.assertRaises(ValueError):
            RsaPrivateKey.generate(256)

    def test_dsa(self):

        key = DsaPrivateKey.generate()

        assert isinstance(key, DsaPrivateKey)
        assert isinstance(key, PrivateKey)
        assert isinstance(key.key, _DSA.DSAPrivateKey)
        assert isinstance(key.private_numbers, _DSA.DSAPrivateNumbers)

        assert isinstance(key.public_key, DsaPublicKey)
        assert isinstance(key.public_key, PublicKey)
        assert isinstance(key.public_key.key, _DSA.DSAPublicKey)
        assert isinstance(key.public_key.public_numbers, _DSA.DSAPublicNumbers)
        assert isinstance(key.public_key.parameters, _DSA.DSAParameterNumbers)

    def test_ecdsa(self):
        curves = [EcdsaCurves.P256, EcdsaCurves.P384, EcdsaCurves.P521]

        for curve in curves:
            key = EcdsaPrivateKey.generate(curve)

            assert isinstance(key, EcdsaPrivateKey)
            assert isinstance(key, PrivateKey)
            assert isinstance(key.key, _EC.EllipticCurvePrivateKey)
            assert isinstance(key.private_numbers, _EC.EllipticCurvePrivateNumbers)

            assert isinstance(key.public_key, EcdsaPublicKey)
            assert isinstance(key.public_key, PublicKey)
            assert isinstance(key.public_key.key, _EC.EllipticCurvePublicKey)
            assert isinstance(
                key.public_key.public_numbers, _EC.EllipticCurvePublicNumbers
            )

    def test_ecdsa_not_a_curve(self):
        with self.assertRaises(AttributeError):
            EcdsaPrivateKey.generate("p256")

    def test_ed25519(self):
        key = Ed25519PrivateKey.generate()

        assert isinstance(key, Ed25519PrivateKey)
        assert isinstance(key, PrivateKey)
        assert isinstance(key.key, _ED25519.Ed25519PrivateKey)

        assert isinstance(key.public_key, Ed25519PublicKey)
        assert isinstance(key.public_key, PublicKey)
        assert isinstance(key.public_key.key, _ED25519.Ed25519PublicKey)


class TestToFromFiles(KeypairMethods):
    def setUp(self):
        self.generateClasses()
        self.generateFiles("TestToFromFiles")

    def test_encoding(self):
        with open(
            f"tests/{self.folder}/rsa_key_sshkeygen", "r", encoding="utf-8"
        ) as file:
            from_string = PrivateKey.from_string(file.read(), "password", "utf-8")

        with open(
            f"tests/{self.folder}/rsa_key_sshkeygen.pub", "r", encoding="utf-8"
        ) as file:
            from_string_pub = PublicKey.from_string(file.read(), "utf-8")

        from_file = PrivateKey.from_file(
            f"tests/{self.folder}/rsa_key_sshkeygen", "password"
        )
        from_file_pub = PublicKey.from_file(
            f"tests/{self.folder}/rsa_key_sshkeygen.pub"
        )

        self.assertEqualPrivateKeys(RsaPrivateKey, RsaPublicKey, from_string, from_file)

        self.assertEqualPublicKeys(RsaPublicKey, from_string_pub, from_file_pub)

    def test_rsa_files(self):
        parent = PrivateKey.from_file(
            f"tests/{self.folder}/rsa_key_sshkeygen", "password"
        )
        child = RsaPrivateKey.from_file(
            f"tests/{self.folder}/rsa_key_sshkeygen", "password"
        )

        parent_pub = PublicKey.from_file(f"tests/{self.folder}/rsa_key_sshkeygen.pub")
        child_pub = RsaPublicKey.from_file(f"tests/{self.folder}/rsa_key_sshkeygen.pub")

        parent.to_file(f"tests/{self.folder}/rsa_key_saved_parent", "password")
        child.to_file(f"tests/{self.folder}/rsa_key_saved_child")

        parent_pub.to_file(f"tests/{self.folder}/rsa_key_saved_parent.pub")
        child_pub.to_file(f"tests/{self.folder}/rsa_key_saved_child.pub")

        self.assertEqualPrivateKeys(RsaPrivateKey, RsaPublicKey, parent, child)

        self.assertEqualPublicKeys(RsaPublicKey, parent_pub, child_pub)

        self.assertEqualPublicKeys(RsaPublicKey, parent.public_key, child_pub)

        self.assertEqualKeyFingerprint(
            f"tests/{self.folder}/rsa_key_sshkeygen",
            f"tests/{self.folder}/rsa_key_saved_parent",
        )

        self.assertEqualKeyFingerprint(
            f"tests/{self.folder}/rsa_key_sshkeygen.pub",
            f"tests/{self.folder}/rsa_key_saved_parent.pub",
        )

        self.assertEqualKeyFingerprint(
            f"tests/{self.folder}/rsa_key_saved_parent",
            f"tests/{self.folder}/rsa_key_saved_child",
        )

        self.assertEqualKeyFingerprint(
            f"tests/{self.folder}/rsa_key_saved_parent.pub",
            f"tests/{self.folder}/rsa_key_sshkeygen.pub",
        )
        self.assertEqualKeyFingerprint(
            f"tests/{self.folder}/rsa_key_saved_parent.pub",
            f"tests/{self.folder}/rsa_key_sshkeygen.pub",
        )

    def test_dsa_files(self):
        parent = PrivateKey.from_file(f"tests/{self.folder}/dsa_key_sshkeygen")
        child = DsaPrivateKey.from_file(f"tests/{self.folder}/dsa_key_sshkeygen")

        parent_pub = PublicKey.from_file(f"tests/{self.folder}/dsa_key_sshkeygen.pub")
        child_pub = DsaPublicKey.from_file(f"tests/{self.folder}/dsa_key_sshkeygen.pub")

        parent.to_file(f"tests/{self.folder}/dsa_key_saved_parent")
        child.to_file(f"tests/{self.folder}/dsa_key_saved_child")

        parent_pub.to_file(f"tests/{self.folder}/dsa_key_saved_parent.pub")
        child_pub.to_file(f"tests/{self.folder}/dsa_key_saved_child.pub")

        self.assertEqualPrivateKeys(DsaPrivateKey, DsaPublicKey, parent, child)

        self.assertEqualPublicKeys(DsaPublicKey, parent_pub, child_pub)

        self.assertEqualPublicKeys(DsaPublicKey, parent.public_key, child_pub)

        self.assertEqualKeyFingerprint(
            f"tests/{self.folder}/dsa_key_sshkeygen",
            f"tests/{self.folder}/dsa_key_saved_parent",
        )

        self.assertEqualKeyFingerprint(
            f"tests/{self.folder}/dsa_key_sshkeygen.pub",
            f"tests/{self.folder}/dsa_key_saved_parent.pub",
        )

        self.assertEqualKeyFingerprint(
            f"tests/{self.folder}/dsa_key_saved_parent",
            f"tests/{self.folder}/dsa_key_saved_child",
        )

        self.assertEqualKeyFingerprint(
            f"tests/{self.folder}/dsa_key_saved_parent.pub",
            f"tests/{self.folder}/dsa_key_sshkeygen.pub",
        )
        self.assertEqualKeyFingerprint(
            f"tests/{self.folder}/dsa_key_saved_parent.pub",
            f"tests/{self.folder}/dsa_key_sshkeygen.pub",
        )

    def test_ecdsa_files(self):
        parent = PrivateKey.from_file(f"tests/{self.folder}/ecdsa_key_sshkeygen")
        child = EcdsaPrivateKey.from_file(f"tests/{self.folder}/ecdsa_key_sshkeygen")

        parent_pub = PublicKey.from_file(f"tests/{self.folder}/ecdsa_key_sshkeygen.pub")
        child_pub = EcdsaPublicKey.from_file(
            f"tests/{self.folder}/ecdsa_key_sshkeygen.pub"
        )

        parent.to_file(f"tests/{self.folder}/ecdsa_key_saved_parent")
        child.to_file(f"tests/{self.folder}/ecdsa_key_saved_child")

        parent_pub.to_file(f"tests/{self.folder}/ecdsa_key_saved_parent.pub")
        child_pub.to_file(f"tests/{self.folder}/ecdsa_key_saved_child.pub")

        self.assertEqualPrivateKeys(EcdsaPrivateKey, EcdsaPublicKey, parent, child)

        self.assertEqualPublicKeys(EcdsaPublicKey, parent_pub, child_pub)

        self.assertEqualPublicKeys(EcdsaPublicKey, parent.public_key, child_pub)

        self.assertEqualKeyFingerprint(
            f"tests/{self.folder}/ecdsa_key_sshkeygen",
            f"tests/{self.folder}/ecdsa_key_saved_parent",
        )

        self.assertEqualKeyFingerprint(
            f"tests/{self.folder}/ecdsa_key_sshkeygen.pub",
            f"tests/{self.folder}/ecdsa_key_saved_parent.pub",
        )

        self.assertEqualKeyFingerprint(
            f"tests/{self.folder}/ecdsa_key_saved_parent",
            f"tests/{self.folder}/ecdsa_key_saved_child",
        )

        self.assertEqualKeyFingerprint(
            f"tests/{self.folder}/ecdsa_key_saved_parent.pub",
            f"tests/{self.folder}/ecdsa_key_sshkeygen.pub",
        )
        self.assertEqualKeyFingerprint(
            f"tests/{self.folder}/ecdsa_key_saved_parent.pub",
            f"tests/{self.folder}/ecdsa_key_sshkeygen.pub",
        )

    def test_ed25519_files(self):
        parent = PrivateKey.from_file(f"tests/{self.folder}/ed25519_key_sshkeygen")
        child = Ed25519PrivateKey.from_file(
            f"tests/{self.folder}/ed25519_key_sshkeygen"
        )

        parent_pub = PublicKey.from_file(
            f"tests/{self.folder}/ed25519_key_sshkeygen.pub"
        )
        child_pub = Ed25519PublicKey.from_file(
            f"tests/{self.folder}/ed25519_key_sshkeygen.pub"
        )

        parent.to_file(f"tests/{self.folder}/ed25519_key_saved_parent")
        child.to_file(f"tests/{self.folder}/ed25519_key_saved_child")

        parent_pub.to_file(f"tests/{self.folder}/ed25519_key_saved_parent.pub")
        child_pub.to_file(f"tests/{self.folder}/ed25519_key_saved_child.pub")

        self.assertEqualPrivateKeys(Ed25519PrivateKey, Ed25519PublicKey, parent, child)

        self.assertEqualPublicKeys(Ed25519PublicKey, parent_pub, child_pub)

        self.assertEqualPublicKeys(Ed25519PublicKey, parent.public_key, child_pub)

        self.assertEqualKeyFingerprint(
            f"tests/{self.folder}/ed25519_key_sshkeygen",
            f"tests/{self.folder}/ed25519_key_saved_parent",
        )

        self.assertEqualKeyFingerprint(
            f"tests/{self.folder}/ed25519_key_sshkeygen.pub",
            f"tests/{self.folder}/ed25519_key_saved_parent.pub",
        )

        self.assertEqualKeyFingerprint(
            f"tests/{self.folder}/ed25519_key_saved_parent",
            f"tests/{self.folder}/ed25519_key_saved_child",
        )

        self.assertEqualKeyFingerprint(
            f"tests/{self.folder}/ed25519_key_saved_parent.pub",
            f"tests/{self.folder}/ed25519_key_sshkeygen.pub",
        )
        self.assertEqualKeyFingerprint(
            f"tests/{self.folder}/ed25519_key_saved_parent.pub",
            f"tests/{self.folder}/ed25519_key_sshkeygen.pub",
        )


class TestFromClass(KeypairMethods):
    def setUp(self):
        self.rsa_key = _RSA.generate_private_key(public_exponent=65537, key_size=2048)
        self.dsa_key = _DSA.generate_private_key(key_size=1024)
        self.ecdsa_key = _EC.generate_private_key(curve=_EC.SECP384R1())
        self.ed25519_key = _ED25519.Ed25519PrivateKey.generate()

    def tearDown(self):
        pass

    def test_invalid_key_exception(self):
        with self.assertRaises(_EX.InvalidKeyException):
            PublicKey.from_class(
                key_class=self.rsa_key, key_type="invalid-key-type", comment="Comment"
            )

    def test_rsa_from_class(self):
        parent = PrivateKey.from_class(self.rsa_key)
        child = RsaPrivateKey.from_class(self.rsa_key)

        self.assertEqualPrivateKeys(RsaPrivateKey, RsaPublicKey, parent, child)

    def test_dsa_from_class(self):
        parent = PrivateKey.from_class(self.dsa_key)
        child = DsaPrivateKey.from_class(self.dsa_key)

        self.assertEqualPrivateKeys(DsaPrivateKey, DsaPublicKey, parent, child)

    def test_ecdsa_from_class(self):
        parent = PrivateKey.from_class(self.ecdsa_key)
        child = EcdsaPrivateKey.from_class(self.ecdsa_key)

        self.assertEqualPrivateKeys(EcdsaPrivateKey, EcdsaPublicKey, parent, child)

    def test_ed25519_from_class(self):
        parent = PrivateKey.from_class(self.ed25519_key)
        child = Ed25519PrivateKey.from_class(self.ed25519_key)

        self.assertEqualPrivateKeys(Ed25519PrivateKey, Ed25519PublicKey, parent, child)


class TestFromComponents(KeypairMethods):
    def setUp(self):
        self.generateClasses()

    def tearDown(self):
        pass

    def test_rsa_from_numbers(self):
        from_numbers = RsaPrivateKey.from_numbers(
            n=self.rsa_key.public_key.public_numbers.n,
            e=self.rsa_key.public_key.public_numbers.e,
            d=self.rsa_key.private_numbers.d,
        )

        from_numbers_pub = RsaPublicKey.from_numbers(
            n=self.rsa_key.public_key.public_numbers.n,
            e=self.rsa_key.public_key.public_numbers.e,
        )

        self.assertEqualPublicKeys(
            RsaPublicKey, from_numbers_pub, from_numbers.public_key
        )

        self.assertIsInstance(from_numbers, RsaPrivateKey)

        self.assertEqual(
            self.rsa_key.public_key.public_numbers.n,
            from_numbers.public_key.public_numbers.n,
        )

        self.assertEqual(
            self.rsa_key.public_key.public_numbers.e,
            from_numbers.public_key.public_numbers.e,
        )

        self.assertEqual(self.rsa_key.private_numbers.d, from_numbers.private_numbers.d)

    def test_dsa_from_numbers(self):
        from_numbers = DsaPrivateKey.from_numbers(
            p=self.dsa_key.public_key.parameters.p,
            q=self.dsa_key.public_key.parameters.q,
            g=self.dsa_key.public_key.parameters.g,
            y=self.dsa_key.public_key.public_numbers.y,
            x=self.dsa_key.private_numbers.x,
        )

        from_numbers_pub = DsaPublicKey.from_numbers(
            p=self.dsa_key.public_key.parameters.p,
            q=self.dsa_key.public_key.parameters.q,
            g=self.dsa_key.public_key.parameters.g,
            y=self.dsa_key.public_key.public_numbers.y,
        )

        self.assertEqualPrivateKeys(
            DsaPrivateKey, DsaPublicKey, self.dsa_key, from_numbers
        )

        self.assertEqualPublicKeys(
            DsaPublicKey, from_numbers_pub, self.dsa_key.public_key
        )

    def test_ecdsa_from_numbers(self):
        from_numbers = EcdsaPrivateKey.from_numbers(
            curve=self.ecdsa_key.public_key.key.curve,
            x=self.ecdsa_key.public_key.public_numbers.x,
            y=self.ecdsa_key.public_key.public_numbers.y,
            private_value=self.ecdsa_key.private_numbers.private_value,
        )

        from_numbers_pub = EcdsaPublicKey.from_numbers(
            curve=self.ecdsa_key.public_key.key.curve,
            x=self.ecdsa_key.public_key.public_numbers.x,
            y=self.ecdsa_key.public_key.public_numbers.y,
        )

        self.assertEqualPrivateKeys(
            EcdsaPrivateKey, EcdsaPublicKey, self.ecdsa_key, from_numbers
        )

        self.assertEqualPublicKeys(
            EcdsaPublicKey, from_numbers_pub, self.ecdsa_key.public_key
        )

        from_numbers = EcdsaPrivateKey.from_numbers(
            curve=self.ecdsa_key.public_key.key.curve.name,
            x=self.ecdsa_key.public_key.public_numbers.x,
            y=self.ecdsa_key.public_key.public_numbers.y,
            private_value=self.ecdsa_key.private_numbers.private_value,
        )

        self.assertEqualPrivateKeys(
            EcdsaPrivateKey, EcdsaPublicKey, self.ecdsa_key, from_numbers
        )

    def test_ed25519_from_raw_bytes(self):
        from_raw = Ed25519PrivateKey.from_raw_bytes(self.ed25519_key.raw_bytes())
        from_raw_pub = Ed25519PublicKey.from_raw_bytes(
            self.ed25519_key.public_key.raw_bytes()
        )

        self.assertEqualPrivateKeys(
            Ed25519PrivateKey, Ed25519PublicKey, self.ed25519_key, from_raw, []
        )

        self.assertEqualPublicKeys(
            Ed25519PublicKey, self.ed25519_key.public_key, from_raw_pub
        )


class TestFingerprint(KeypairMethods):
    def setUp(self):
        self.generateFiles("TestFingerprint")

    def test_rsa_fingerprint(self):
        key = RsaPrivateKey.from_file(
            f"tests/{self.folder}/rsa_key_sshkeygen", "password"
        )

        with os.popen(f"ssh-keygen -lf tests/{self.folder}/rsa_key_sshkeygen") as cmd:
            sshkey_fingerprint = cmd.read().split(" ")[1]

        self.assertEqual(key.get_fingerprint(), sshkey_fingerprint)

    def test_dsa_fingerprint(self):
        key = DsaPrivateKey.from_file(
            f"tests/{self.folder}/dsa_key_sshkeygen",
        )

        with os.popen(f"ssh-keygen -lf tests/{self.folder}/dsa_key_sshkeygen") as cmd:
            sshkey_fingerprint = cmd.read().split(" ")[1]

        self.assertEqual(key.get_fingerprint(), sshkey_fingerprint)

    def test_ecdsa_fingerprint(self):
        key = EcdsaPrivateKey.from_file(
            f"tests/{self.folder}/ecdsa_key_sshkeygen",
        )
        with os.popen(f"ssh-keygen -lf tests/{self.folder}/ecdsa_key_sshkeygen") as cmd:
            sshkey_fingerprint = cmd.read().split(" ")[1]

        self.assertEqual(key.get_fingerprint(), sshkey_fingerprint)

    def test_ed25519_fingerprint(self):
        key = Ed25519PrivateKey.from_file(
            f"tests/{self.folder}/ed25519_key_sshkeygen",
        )
        with os.popen(
            f"ssh-keygen -lf tests/{self.folder}/ed25519_key_sshkeygen"
        ) as cmd:
            sshkey_fingerprint = cmd.read().split(" ")[1]

        self.assertEqual(key.get_fingerprint(), sshkey_fingerprint)


class TestSignatures(KeypairMethods):
    def setUp(self):
        self.generateClasses()

    def tearDown(self):
        pass

    def test_rsa_signature(self):
        data = b"\x00" + os.urandom(32) + b"\x00"
        signature = self.rsa_key.sign(data)

        self.assertIsNone(self.rsa_key.public_key.verify(data, signature))

        with self.assertRaises(_EX.InvalidSignatureException):
            self.rsa_key.public_key.verify(data, signature + b"\x00")

    def test_dsa_signature(self):
        data = b"\x00" + os.urandom(32) + b"\x00"
        signature = self.dsa_key.sign(data)

        self.assertIsNone(self.dsa_key.public_key.verify(data, signature))

        with self.assertRaises(_EX.InvalidSignatureException):
            self.dsa_key.public_key.verify(data, signature + b"\x00")

    def test_ecdsa_signature(self):
        data = b"\x00" + os.urandom(32) + b"\x00"
        signature = self.ecdsa_key.sign(data)

        self.assertIsNone(self.ecdsa_key.public_key.verify(data, signature))

        with self.assertRaises(_EX.InvalidSignatureException):
            self.ecdsa_key.public_key.verify(data, signature + b"\x00")

    def test_ed25519_signature(self):
        data = b"\x00" + os.urandom(32) + b"\x00"
        signature = self.ed25519_key.sign(data)

        self.assertIsNone(self.ed25519_key.public_key.verify(data, signature))

        with self.assertRaises(_EX.InvalidSignatureException):
            self.ed25519_key.public_key.verify(data, signature + b"\x00")


class TestExceptions(KeypairMethods):
    def setUp(self):
        self.generateClasses()

    def tearDown(self):
        pass

    def test_invalid_private_key(self):
        with self.assertRaises(_EX.InvalidKeyException):
            _ = PrivateKey.from_class(KeypairMethods)

    def test_invalid_ecdsa_curve(self):
        with self.assertRaises(_EX.InvalidCurveException):
            _ = EcdsaPublicKey.from_numbers(
                "abc123",
                x=self.ecdsa_key.public_key.public_numbers.x,
                y=self.ecdsa_key.public_key.public_numbers.y,
            )

        with self.assertRaises(_EX.InvalidCurveException):
            _ = EcdsaPrivateKey.from_numbers(
                "abc123",
                x=self.ecdsa_key.public_key.public_numbers.x,
                y=self.ecdsa_key.public_key.public_numbers.y,
                private_value=self.ecdsa_key.private_numbers.private_value,
            )


if __name__ == "__main__":
    unittest.main()
