# Test privkey generation with valid and invalid parameters
# Test privkey import
# Test import to right class
# Test pubkey generation from priv
import os
import shutil
import unittest
import src.sshkey_tools.exceptions as _EX
from base64 import b64encode
from src.sshkey_tools.keys import (
    PrivkeyClasses,
    PrivateKey,
    RSAPrivateKey,
    DSAPrivateKey,
    ECDSAPrivateKey,
    ED25519PrivateKey,
    PubkeyClasses,
    PublicKey,
    RSAPublicKey,
    DSAPublicKey,
    ECDSAPublicKey,
    ED25519PublicKey,
    EcdsaCurves
)

from cryptography.hazmat.primitives.asymmetric import (
    rsa as _RSA,
    dsa as _DSA,
    ec as _EC,
    ed25519 as _ED25519
)

from cryptography.exceptions import InvalidSignature

class KeypairMethods(unittest.TestCase):
    def generateClasses(self):
        self.rsa_key = RSAPrivateKey.generate(2048)
        self.dsa_key = DSAPrivateKey.generate()
        self.ecdsa_key = ECDSAPrivateKey.generate(EcdsaCurves.P256)
        self.ed25519_key = ED25519PrivateKey.generate()

    def generateFiles(self, folder):
        self.folder = folder
        try:
            os.mkdir(f'tests/{folder}')
        except FileExistsError:
            shutil.rmtree(f'tests/{folder}')
            os.mkdir(f'tests/{folder}')

        os.system(f'ssh-keygen -t rsa -b 2048 -f tests/{folder}/rsa_key_sshkeygen -N "password" > /dev/null 2>&1')
        os.system(f'ssh-keygen -t dsa -b 1024 -f tests/{folder}/dsa_key_sshkeygen -N "" > /dev/null 2>&1')
        os.system(f'ssh-keygen -t ecdsa -b 256 -f tests/{folder}/ecdsa_key_sshkeygen -N "" > /dev/null 2>&1')
        os.system(f'ssh-keygen -t ed25519 -f tests/{folder}/ed25519_key_sshkeygen -N "" > /dev/null 2>&1')


    def setUp(self):
        self.generateClasses()
        self.generateFiles('KeypairMethods')

    def tearDown(self):
        shutil.rmtree(f'tests/{self.folder}')

    def assertEqualPrivateKeys(
        self,
        priv_class,
        pub_class,
        a,
        b,
        privkey_attr = ['private_numbers']
    ):
        self.assertIsInstance(a, priv_class)
        self.assertIsInstance(b, priv_class)

        for att in privkey_attr:
            try:
                self.assertEqual(getattr(a, att), getattr(b, att))
            except AssertionError:
                print("Hold")

        self.assertEqualPublicKeys(
            pub_class,
            a.public_key,
            b.public_key
        )

    def assertEqualPublicKeys(
        self,
        keyclass,
        a,
        b
    ):
        self.assertIsInstance(a, keyclass)
        self.assertIsInstance(b, keyclass)

        self.assertEqual(a.raw_bytes(), b.raw_bytes())

    def assertEqualKeyFingerprint(
        self,
        file_a,
        file_b
    ):
        self.assertEqual(0,
            os.system(
            f'''bash -c "
               diff \
               <( ssh-keygen -lf {file_a}) \
               <( ssh-keygen -lf {file_b}) \
            "
            '''
            )
        )

class TestKeypairMethods(KeypairMethods):
    def test_fail_assertions(self):
        with self.assertRaises(AssertionError):
            self.assertEqualPrivateKeys(
                RSAPrivateKey,
                RSAPublicKey,
                RSAPrivateKey.from_file(f'tests/{self.folder}/rsa_key_sshkeygen', 'password'),
                DSAPrivateKey.from_file(f'tests/{self.folder}/dsa_key_sshkeygen')
            )

        with self.assertRaises(AssertionError):
            self.assertEqualPublicKeys(
                RSAPublicKey,
                RSAPublicKey.from_file(f'tests/{self.folder}/rsa_key_sshkeygen.pub'),
                DSAPublicKey.from_file(f'tests/{self.folder}/dsa_key_sshkeygen.pub')
            )

        with self.assertRaises(AssertionError):
            self.assertEqualKeyFingerprint(
                f'tests/{self.folder}/rsa_key_sshkeygen',
                f'tests/{self.folder}/dsa_key_sshkeygen'
            )

    def test_successful_assertions(self):
        self.assertTrue(
            os.path.isfile(
                f'tests/{self.folder}/rsa_key_sshkeygen'
            )
        )
        self.assertEqualKeyFingerprint(
            f'tests/{self.folder}/rsa_key_sshkeygen',
            f'tests/{self.folder}/rsa_key_sshkeygen.pub'
        )

        self.assertTrue(
            os.path.isfile(
                f'tests/{self.folder}/dsa_key_sshkeygen'
            )
        )
        self.assertEqualKeyFingerprint(
            f'tests/{self.folder}/dsa_key_sshkeygen',
            f'tests/{self.folder}/dsa_key_sshkeygen.pub'
        )

        self.assertTrue(
            os.path.isfile(
                f'tests/{self.folder}/ecdsa_key_sshkeygen'
            )
        )
        self.assertEqualKeyFingerprint(
            f'tests/{self.folder}/ecdsa_key_sshkeygen',
            f'tests/{self.folder}/ecdsa_key_sshkeygen.pub'
        )

        self.assertTrue(
            os.path.isfile(
                f'tests/{self.folder}/ed25519_key_sshkeygen'
            )
        )
        self.assertEqualKeyFingerprint(
            f'tests/{self.folder}/ed25519_key_sshkeygen',
            f'tests/{self.folder}/ed25519_key_sshkeygen.pub'
        )

class TestKeyGeneration(KeypairMethods):
    def setUp(self):
        pass

    def tearDown(self):
        pass

    def test_rsa(self):
        key_bits = [
            512,
            1024,
            2048,
            4096,
            8192
        ]

        for bits in key_bits:
            key = RSAPrivateKey.generate(bits)

            assert isinstance(key, RSAPrivateKey)
            assert isinstance(key, PrivateKey)
            assert isinstance(key.key, _RSA.RSAPrivateKey)
            assert isinstance(key.private_numbers, _RSA.RSAPrivateNumbers)

            assert isinstance(key.public_key, RSAPublicKey)
            assert isinstance(key.public_key, PublicKey)
            assert isinstance(key.public_key.key, _RSA.RSAPublicKey)
            assert isinstance(key.public_key.public_numbers, _RSA.RSAPublicNumbers)

    def test_rsa_incorrect_keysize(self):
        with self.assertRaises(ValueError):
            RSAPrivateKey.generate(256)

    def test_dsa(self):

        key = DSAPrivateKey.generate()

        assert isinstance(key, DSAPrivateKey)
        assert isinstance(key, PrivateKey)
        assert isinstance(key.key, _DSA.DSAPrivateKey)
        assert isinstance(key.private_numbers, _DSA.DSAPrivateNumbers)

        assert isinstance(key.public_key, DSAPublicKey)
        assert isinstance(key.public_key, PublicKey)
        assert isinstance(key.public_key.key, _DSA.DSAPublicKey)
        assert isinstance(key.public_key.public_numbers, _DSA.DSAPublicNumbers)
        assert isinstance(key.public_key.parameters, _DSA.DSAParameterNumbers)

    def test_ecdsa(self):
        curves = [
            EcdsaCurves.P256,
            EcdsaCurves.P384,
            EcdsaCurves.P521
        ]

        for curve in curves:
            key = ECDSAPrivateKey.generate(curve)


            assert isinstance(key, ECDSAPrivateKey)
            assert isinstance(key, PrivateKey)
            assert isinstance(key.key, _EC.EllipticCurvePrivateKey)
            assert isinstance(key.private_numbers, _EC.EllipticCurvePrivateNumbers)

            assert isinstance(key.public_key, ECDSAPublicKey)
            assert isinstance(key.public_key, PublicKey)
            assert isinstance(key.public_key.key, _EC.EllipticCurvePublicKey)
            assert isinstance(key.public_key.public_numbers, _EC.EllipticCurvePublicNumbers)


    def test_ecdsa_not_a_curve(self):
        with self.assertRaises(AttributeError):
            ECDSAPrivateKey.generate('p256')

    def test_ed25519(self):
        key = ED25519PrivateKey.generate()

        assert isinstance(key, ED25519PrivateKey)
        assert isinstance(key, PrivateKey)
        assert isinstance(key.key, _ED25519.Ed25519PrivateKey)

        assert isinstance(key.public_key, ED25519PublicKey)
        assert isinstance(key.public_key, PublicKey)
        assert isinstance(key.public_key.key, _ED25519.Ed25519PublicKey)

class TestToFromFiles(KeypairMethods):
    def setUp(self):
        self.generateClasses()
        self.generateFiles('TestToFromFiles')
        
    def test_encoding(self):
        with open(f'tests/{self.folder}/rsa_key_sshkeygen', 'r', encoding='utf-8') as file:
            from_string = PrivateKey.from_string(file.read(), 'password', 'utf-8')
          
        with open(f'tests/{self.folder}/rsa_key_sshkeygen.pub', 'r', encoding='utf-8') as file:
            from_string_pub = PublicKey.from_string(file.read(), 'utf-8')
            
        from_file = PrivateKey.from_file(f'tests/{self.folder}/rsa_key_sshkeygen', 'password')
        from_file_pub = PublicKey.from_file(f'tests/{self.folder}/rsa_key_sshkeygen.pub')
        
        self.assertEqualPrivateKeys(
            RSAPrivateKey,
            RSAPublicKey,
            from_string,
            from_file
        )
        
        self.assertEqualPublicKeys(
            RSAPublicKey,
            from_string_pub,
            from_file_pub
        )
        

    def test_rsa_files(self):
        parent = PrivateKey.from_file(f'tests/{self.folder}/rsa_key_sshkeygen', 'password')
        child = RSAPrivateKey.from_file(f'tests/{self.folder}/rsa_key_sshkeygen', 'password')

        parent_pub = PublicKey.from_file(f'tests/{self.folder}/rsa_key_sshkeygen.pub')
        child_pub = RSAPublicKey.from_file(f'tests/{self.folder}/rsa_key_sshkeygen.pub')

        parent.to_file(f'tests/{self.folder}/rsa_key_saved_parent', 'password')
        child.to_file(f'tests/{self.folder}/rsa_key_saved_child')

        parent_pub.to_file(f'tests/{self.folder}/rsa_key_saved_parent.pub')
        child_pub.to_file(f'tests/{self.folder}/rsa_key_saved_child.pub')


        self.assertEqualPrivateKeys(
            RSAPrivateKey,
            RSAPublicKey,
            parent,
            child
        )

        self.assertEqualPublicKeys(
            RSAPublicKey,
            parent_pub,
            child_pub
        )

        self.assertEqualPublicKeys(
            RSAPublicKey,
            parent.public_key,
            child_pub
        )

        self.assertEqualKeyFingerprint(
            f'tests/{self.folder}/rsa_key_sshkeygen',
            f'tests/{self.folder}/rsa_key_saved_parent'
        )

        self.assertEqualKeyFingerprint(
            f'tests/{self.folder}/rsa_key_sshkeygen.pub',
            f'tests/{self.folder}/rsa_key_saved_parent.pub'
        )

        self.assertEqualKeyFingerprint(
            f'tests/{self.folder}/rsa_key_saved_parent',
            f'tests/{self.folder}/rsa_key_saved_child'
        )

        self.assertEqualKeyFingerprint(
            f'tests/{self.folder}/rsa_key_saved_parent.pub',
            f'tests/{self.folder}/rsa_key_sshkeygen.pub'
        )
        self.assertEqualKeyFingerprint(
            f'tests/{self.folder}/rsa_key_saved_parent.pub',
            f'tests/{self.folder}/rsa_key_sshkeygen.pub'
        )

    def test_dsa_files(self):
        parent = PrivateKey.from_file(f'tests/{self.folder}/dsa_key_sshkeygen')
        child = DSAPrivateKey.from_file(f'tests/{self.folder}/dsa_key_sshkeygen')

        parent_pub = PublicKey.from_file(f'tests/{self.folder}/dsa_key_sshkeygen.pub')
        child_pub = DSAPublicKey.from_file(f'tests/{self.folder}/dsa_key_sshkeygen.pub')

        parent.to_file(f'tests/{self.folder}/dsa_key_saved_parent')
        child.to_file(f'tests/{self.folder}/dsa_key_saved_child')

        parent_pub.to_file(f'tests/{self.folder}/dsa_key_saved_parent.pub')
        child_pub.to_file(f'tests/{self.folder}/dsa_key_saved_child.pub')

        self.assertEqualPrivateKeys(
            DSAPrivateKey,
            DSAPublicKey,
            parent,
            child
        )

        self.assertEqualPublicKeys(
            DSAPublicKey,
            parent_pub,
            child_pub
        )

        self.assertEqualPublicKeys(
            DSAPublicKey,
            parent.public_key,
            child_pub
        )

        self.assertEqualKeyFingerprint(
            f'tests/{self.folder}/dsa_key_sshkeygen',
            f'tests/{self.folder}/dsa_key_saved_parent'
        )

        self.assertEqualKeyFingerprint(
            f'tests/{self.folder}/dsa_key_sshkeygen.pub',
            f'tests/{self.folder}/dsa_key_saved_parent.pub'
        )

        self.assertEqualKeyFingerprint(
            f'tests/{self.folder}/dsa_key_saved_parent',
            f'tests/{self.folder}/dsa_key_saved_child'
        )

        self.assertEqualKeyFingerprint(
            f'tests/{self.folder}/dsa_key_saved_parent.pub',
            f'tests/{self.folder}/dsa_key_sshkeygen.pub'
        )
        self.assertEqualKeyFingerprint(
            f'tests/{self.folder}/dsa_key_saved_parent.pub',
            f'tests/{self.folder}/dsa_key_sshkeygen.pub'
        )

    def test_ecdsa_files(self):
        parent = PrivateKey.from_file(f'tests/{self.folder}/ecdsa_key_sshkeygen')
        child = ECDSAPrivateKey.from_file(f'tests/{self.folder}/ecdsa_key_sshkeygen')

        parent_pub = PublicKey.from_file(f'tests/{self.folder}/ecdsa_key_sshkeygen.pub')
        child_pub = ECDSAPublicKey.from_file(f'tests/{self.folder}/ecdsa_key_sshkeygen.pub')

        parent.to_file(f'tests/{self.folder}/ecdsa_key_saved_parent')
        child.to_file(f'tests/{self.folder}/ecdsa_key_saved_child')

        parent_pub.to_file(f'tests/{self.folder}/ecdsa_key_saved_parent.pub')
        child_pub.to_file(f'tests/{self.folder}/ecdsa_key_saved_child.pub')

        self.assertEqualPrivateKeys(
            ECDSAPrivateKey,
            ECDSAPublicKey,
            parent,
            child
        )

        self.assertEqualPublicKeys(
            ECDSAPublicKey,
            parent_pub,
            child_pub
        )

        self.assertEqualPublicKeys(
            ECDSAPublicKey,
            parent.public_key,
            child_pub
        )

        self.assertEqualKeyFingerprint(
            f'tests/{self.folder}/ecdsa_key_sshkeygen',
            f'tests/{self.folder}/ecdsa_key_saved_parent'
        )

        self.assertEqualKeyFingerprint(
            f'tests/{self.folder}/ecdsa_key_sshkeygen.pub',
            f'tests/{self.folder}/ecdsa_key_saved_parent.pub'
        )

        self.assertEqualKeyFingerprint(
            f'tests/{self.folder}/ecdsa_key_saved_parent',
            f'tests/{self.folder}/ecdsa_key_saved_child'
        )

        self.assertEqualKeyFingerprint(
            f'tests/{self.folder}/ecdsa_key_saved_parent.pub',
            f'tests/{self.folder}/ecdsa_key_sshkeygen.pub'
        )
        self.assertEqualKeyFingerprint(
            f'tests/{self.folder}/ecdsa_key_saved_parent.pub',
            f'tests/{self.folder}/ecdsa_key_sshkeygen.pub'
        )

    def test_ed25519_files(self):
        parent = PrivateKey.from_file(f'tests/{self.folder}/ed25519_key_sshkeygen')
        child = ED25519PrivateKey.from_file(f'tests/{self.folder}/ed25519_key_sshkeygen')

        parent_pub = PublicKey.from_file(f'tests/{self.folder}/ed25519_key_sshkeygen.pub')
        child_pub = ED25519PublicKey.from_file(f'tests/{self.folder}/ed25519_key_sshkeygen.pub')

        parent.to_file(f'tests/{self.folder}/ed25519_key_saved_parent')
        child.to_file(f'tests/{self.folder}/ed25519_key_saved_child')

        parent_pub.to_file(f'tests/{self.folder}/ed25519_key_saved_parent.pub')
        child_pub.to_file(f'tests/{self.folder}/ed25519_key_saved_child.pub')

        self.assertEqualPrivateKeys(
            ED25519PrivateKey,
            ED25519PublicKey,
            parent,
            child
        )

        self.assertEqualPublicKeys(
            ED25519PublicKey,
            parent_pub,
            child_pub
        )

        self.assertEqualPublicKeys(
            ED25519PublicKey,
            parent.public_key,
            child_pub
        )

        self.assertEqualKeyFingerprint(
            f'tests/{self.folder}/ed25519_key_sshkeygen',
            f'tests/{self.folder}/ed25519_key_saved_parent'
        )

        self.assertEqualKeyFingerprint(
            f'tests/{self.folder}/ed25519_key_sshkeygen.pub',
            f'tests/{self.folder}/ed25519_key_saved_parent.pub'
        )

        self.assertEqualKeyFingerprint(
            f'tests/{self.folder}/ed25519_key_saved_parent',
            f'tests/{self.folder}/ed25519_key_saved_child'
        )

        self.assertEqualKeyFingerprint(
            f'tests/{self.folder}/ed25519_key_saved_parent.pub',
            f'tests/{self.folder}/ed25519_key_sshkeygen.pub'
        )
        self.assertEqualKeyFingerprint(
            f'tests/{self.folder}/ed25519_key_saved_parent.pub',
            f'tests/{self.folder}/ed25519_key_sshkeygen.pub'
        )

class TestFromClass(KeypairMethods):
    def setUp(self):
        self.rsa_key = _RSA.generate_private_key(
            public_exponent=65537,
            key_size=2048
        )
        self.dsa_key = _DSA.generate_private_key(
            key_size=1024
        )
        self.ecdsa_key = _EC.generate_private_key(
            curve=_EC.SECP384R1()
        )
        self.ed25519_key = _ED25519.Ed25519PrivateKey.generate()

    def tearDown(self):
        pass
    
    def test_invalid_key_exception(self):
        with self.assertRaises(_EX.InvalidKeyException):
            PublicKey.from_class(
                key_class=self.rsa_key,
                key_type='invalid-key-type',
                comment='Comment'
            )
            

    def test_rsa_from_class(self):
        parent = PrivateKey.from_class(self.rsa_key)
        child = RSAPrivateKey.from_class(self.rsa_key)

        self.assertEqualPrivateKeys(
            RSAPrivateKey,
            RSAPublicKey,
            parent,
            child
        )

    def test_dsa_from_class(self):
        parent = PrivateKey.from_class(self.dsa_key)
        child = DSAPrivateKey.from_class(self.dsa_key)

        self.assertEqualPrivateKeys(
            DSAPrivateKey,
            DSAPublicKey,
            parent,
            child
        )

    def test_ecdsa_from_class(self):
        parent = PrivateKey.from_class(self.ecdsa_key)
        child = ECDSAPrivateKey.from_class(self.ecdsa_key)

        self.assertEqualPrivateKeys(
            ECDSAPrivateKey,
            ECDSAPublicKey,
            parent,
            child
        )

    def test_ed25519_from_class(self):
        parent = PrivateKey.from_class(self.ed25519_key)
        child = ED25519PrivateKey.from_class(self.ed25519_key)

        self.assertEqualPrivateKeys(
            ED25519PrivateKey,
            ED25519PublicKey,
            parent,
            child
        )

class TestFromComponents(KeypairMethods):
    def setUp(self):
        self.generateClasses()

    def tearDown(self):
        pass

    def test_rsa_from_numbers(self):
        from_numbers = RSAPrivateKey.from_numbers(
            n=self.rsa_key.public_key.public_numbers.n,
            e=self.rsa_key.public_key.public_numbers.e,
            d=self.rsa_key.private_numbers.d
        )
        
        from_numbers_pub = RSAPublicKey.from_numbers(
            n=self.rsa_key.public_key.public_numbers.n,
            e=self.rsa_key.public_key.public_numbers.e
        )

        self.assertEqualPublicKeys(
            RSAPublicKey,
            from_numbers_pub,
            from_numbers.public_key
        )

        self.assertIsInstance(from_numbers, RSAPrivateKey)
        
        self.assertEqual(
            self.rsa_key.public_key.public_numbers.n,
            from_numbers.public_key.public_numbers.n
        )
        
        self.assertEqual(
            self.rsa_key.public_key.public_numbers.e,
            from_numbers.public_key.public_numbers.e
        )
        
        self.assertEqual(
            self.rsa_key.private_numbers.d,
            from_numbers.private_numbers.d
        )

    def test_dsa_from_numbers(self):
        from_numbers = DSAPrivateKey.from_numbers(
            p=self.dsa_key.public_key.parameters.p,
            q=self.dsa_key.public_key.parameters.q,
            g=self.dsa_key.public_key.parameters.g,
            y=self.dsa_key.public_key.public_numbers.y,
            x=self.dsa_key.private_numbers.x
        )
        
        from_numbers_pub = DSAPublicKey.from_numbers(
            p=self.dsa_key.public_key.parameters.p,
            q=self.dsa_key.public_key.parameters.q,
            g=self.dsa_key.public_key.parameters.g,
            y=self.dsa_key.public_key.public_numbers.y   
        )

        self.assertEqualPrivateKeys(
            DSAPrivateKey,
            DSAPublicKey,
            self.dsa_key,
            from_numbers
        )
        
        self.assertEqualPublicKeys(
            DSAPublicKey,
            from_numbers_pub,
            self.dsa_key.public_key
        )

    def test_ecdsa_from_numbers(self):
        from_numbers = ECDSAPrivateKey.from_numbers(
            curve=self.ecdsa_key.public_key.key.curve,
            x=self.ecdsa_key.public_key.public_numbers.x,
            y=self.ecdsa_key.public_key.public_numbers.y,
            private_value=self.ecdsa_key.private_numbers.private_value
        )
        
        from_numbers_pub = ECDSAPublicKey.from_numbers(
            curve=self.ecdsa_key.public_key.key.curve,
            x=self.ecdsa_key.public_key.public_numbers.x,
            y=self.ecdsa_key.public_key.public_numbers.y
        )

        self.assertEqualPrivateKeys(
            ECDSAPrivateKey,
            ECDSAPublicKey,
            self.ecdsa_key,
            from_numbers
        )
        
        self.assertEqualPublicKeys(
            ECDSAPublicKey,
            from_numbers_pub,
            self.ecdsa_key.public_key
        )

        from_numbers = ECDSAPrivateKey.from_numbers(
            curve=self.ecdsa_key.public_key.key.curve.name,
            x=self.ecdsa_key.public_key.public_numbers.x,
            y=self.ecdsa_key.public_key.public_numbers.y,
            private_value=self.ecdsa_key.private_numbers.private_value
        )

        self.assertEqualPrivateKeys(
            ECDSAPrivateKey,
            ECDSAPublicKey,
            self.ecdsa_key,
            from_numbers
        )
        
    def test_ed25519_from_raw_bytes(self):
        from_raw = ED25519PrivateKey.from_raw_bytes(
            self.ed25519_key.raw_bytes()
        )
        from_raw_pub = ED25519PublicKey.from_raw_bytes(
            self.ed25519_key.public_key.raw_bytes()
        )
        
        self.assertEqualPrivateKeys(
            ED25519PrivateKey,
            ED25519PublicKey,
            self.ed25519_key,
            from_raw,
            []
        )
        
        self.assertEqualPublicKeys(
            ED25519PublicKey,
            self.ed25519_key.public_key,
            from_raw_pub
        )
        

class TestFingerprint(KeypairMethods):
    
    def setUp(self):
        self.generateFiles('TestFingerprint')

    def test_rsa_fingerprint(self):
        key = RSAPrivateKey.from_file(
            f'tests/{self.folder}/rsa_key_sshkeygen',
            'password'
        )
        
        sshkey_fingerprint = os.popen(f'ssh-keygen -lf tests/{self.folder}/rsa_key_sshkeygen').read().split(' ')[1]
        
        self.assertEqual(key.get_fingerprint(), sshkey_fingerprint)
        
    def test_dsa_fingerprint(self):
        key = DSAPrivateKey.from_file(
            f'tests/{self.folder}/dsa_key_sshkeygen',
        )
        
        sshkey_fingerprint = os.popen(f'ssh-keygen -lf tests/{self.folder}/dsa_key_sshkeygen').read().split(' ')[1]
        
        self.assertEqual(key.get_fingerprint(), sshkey_fingerprint)

    def test_ecdsa_fingerprint(self):
        key = ECDSAPrivateKey.from_file(
            f'tests/{self.folder}/ecdsa_key_sshkeygen',
        )
        
        sshkey_fingerprint = os.popen(f'ssh-keygen -lf tests/{self.folder}/ecdsa_key_sshkeygen').read().split(' ')[1]
        
        self.assertEqual(key.get_fingerprint(), sshkey_fingerprint)
        
    def test_ed25519_fingerprint(self):
        key = ED25519PrivateKey.from_file(
            f'tests/{self.folder}/ed25519_key_sshkeygen',
        )
        
        sshkey_fingerprint = os.popen(f'ssh-keygen -lf tests/{self.folder}/ed25519_key_sshkeygen').read().split(' ')[1]
        
        self.assertEqual(key.get_fingerprint(), sshkey_fingerprint)

class TestSignatures(KeypairMethods):
    def setUp(self):
        self.generateClasses()
        
    def tearDown(self):
        pass
    
    def test_rsa_signature(self):
        data = b"\x00"+os.urandom(32)+b"\x00"
        signature = self.rsa_key.sign(data)
        
        
        self.assertIsNone(
            self.rsa_key.public_key.verify(
                data,
                signature
            )
        )
        
        with self.assertRaises(_EX.InvalidSignatureException):
            self.rsa_key.public_key.verify(
                data,
                signature+b'\x00'
            )
        
    def test_dsa_signature(self):
        data = b"\x00"+os.urandom(32)+b"\x00"
        signature = self.dsa_key.sign(data)
        
        
        self.assertIsNone(
            self.dsa_key.public_key.verify(
                data,
                signature
            )
        )
        
        with self.assertRaises(_EX.InvalidSignatureException):
            self.dsa_key.public_key.verify(
                data,
                signature+b'\x00'
            )
        
    def test_ecdsa_signature(self):
        data = b"\x00"+os.urandom(32)+b"\x00"
        signature = self.ecdsa_key.sign(data)
        
        
        self.assertIsNone(
            self.ecdsa_key.public_key.verify(
                data,
                signature
            )
        )
        
        with self.assertRaises(_EX.InvalidSignatureException):
            self.ecdsa_key.public_key.verify(
                data,
                signature+b'\x00'
            )
        
    def test_ed25519_signature(self):
        data = b"\x00"+os.urandom(32)+b"\x00"
        signature = self.ed25519_key.sign(data)
        
        
        self.assertIsNone(
            self.ed25519_key.public_key.verify(
                data,
                signature
            )
        )
        
        with self.assertRaises(_EX.InvalidSignatureException):
            self.ed25519_key.public_key.verify(
                data,
                signature+b'\x00'
            )

class TestExceptions(KeypairMethods):
    def setUp(self):
        self.generateClasses()
        
    def tearDown(self):
        pass
    
    def test_invalid_private_key(self):
        with self.assertRaises(_EX.InvalidKeyException):
            key = PrivateKey.from_class(KeypairMethods)
            
    def test_invalid_ecdsa_curve(self):
        with self.assertRaises(_EX.InvalidCurveException):
            key = ECDSAPublicKey.from_numbers(
                'abc123',
                x=self.ecdsa_key.public_key.public_numbers.x,
                y=self.ecdsa_key.public_key.public_numbers.y
            )
            
        with self.assertRaises(_EX.InvalidCurveException):
            key = ECDSAPrivateKey.from_numbers(
                'abc123',
                x=self.ecdsa_key.public_key.public_numbers.x,
                y=self.ecdsa_key.public_key.public_numbers.y,
                private_value=self.ecdsa_key.private_numbers.private_value
            )

if __name__ == '__main__':
    unittest.main()

