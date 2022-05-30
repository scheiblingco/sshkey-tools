# Test privkey generation with valid and invalid parameters
# Test privkey import
# Test import to right class
# Test pubkey generation from priv
import os
import shutil
import unittest
from src.sshkey_tools.keys import (
    PrivateKey,
    RSAPrivateKey,
    DSAPrivateKey,
    ECDSAPrivateKey,
    ED25519PrivateKey,
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

class TestKeypairMethods(unittest.TestCase):
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
        
        os.system(f'ssh-keygen -t rsa -b 2048 -f tests/{folder}/rsa_key_sshkeygen -N "password"')
        os.system(f'ssh-keygen -t dsa -b 1024 -f tests/{folder}/dsa_key_sshkeygen -N ""')
        os.system(f'ssh-keygen -t ecdsa -b 256 -f tests/{folder}/ecdsa_key_sshkeygen -N ""')
        os.system(f'ssh-keygen -t ed25519 -f tests/{folder}/ed25519_key_sshkeygen -N ""')
        
    
    def setUp(self):
        self.generateClasses()
        self.generateFiles('TestKeypairMethods')
        
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
            self.assertEqual(getattr(a, att), getattr(b, att))
            
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
        
    def test_fail_assertions(self):
        with self.assertRaises(AssertionError):
            self.assertEqualPrivateKeys(
                RSAPrivateKey,
                RSAPublicKey,
                RSAPrivateKey.from_file('tests/test_keypairs/rsa_key_sshkeygen'),
                DSAPrivateKey.from_file('tests/test_keypairs/dsa_key_sshkeygen')
            )
            
        with self.assertRaises(AssertionError):
            self.assertEqualPublicKeys(
                RSAPublicKey,
                RSAPublicKey.from_file('tests/test_keypairs/rsa_key_sshkeygen.pub'),
                DSAPublicKey.from_file('tests/test_keypairs/dsa_key_sshkeygen.pub')
            )
            
        with self.assertRaises(AssertionError):
            self.assertEqualKeyFingerprint(
                'tests/test_keypairs/rsa_key_sshkeygen',
                'tests/test_keypairs/dsa_key_sshkeygen'
            )
            
    def test_successfull_assertions(self):
        self.assertEqualKeyFingerprint(
            'tests/test_keypairs/rsa_key_sshkeygen',
            'tests/test_keypairs/rsa_key_sshkeygen.pub'
        )
        self.assertEqualKeyFingerprint(
            'tests/test_keypairs/dsa_key_sshkeygen',
            'tests/test_keypairs/dsa_key_sshkeygen.pub'
        )
        self.assertEqualKeyFingerprint(
            'tests/test_keypairs/ecdsa_key_sshkeygen',
            'tests/test_keypairs/ecdsa_key_sshkeygen.pub'
        )
        self.assertEqualKeyFingerprint(
            'tests/test_keypairs/ed25519_key_sshkeygen',
            'tests/test_keypairs/ed25519_key_sshkeygen.pub'
        )     

class TestKeyGeneration(TestKeypairMethods):
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
        key_bits = [
            1024,
            2048,
            3072,
            4096,
        ]
        
        for bits in key_bits:
            key = DSAPrivateKey.generate(bits)
            
            assert isinstance(key, DSAPrivateKey)
            assert isinstance(key, PrivateKey)
            assert isinstance(key.key, _DSA.DSAPrivateKey)
            assert isinstance(key.private_numbers, _DSA.DSAPrivateNumbers)
            
            assert isinstance(key.public_key, DSAPublicKey)
            assert isinstance(key.public_key, PublicKey)
            assert isinstance(key.public_key.key, _DSA.DSAPublicKey)
            assert isinstance(key.public_key.public_numbers, _DSA.DSAPublicNumbers)
            assert isinstance(key.public_key.parameters, _DSA.DSAParameterNumbers)

    def test_dsa_incorrect_keysize(self):
        key_bits = [
            256,
            512,
            8192
        ]
        
        for bits in key_bits:
            with self.assertRaises(ValueError):
                DSAPrivateKey.generate(bits)
                
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
        
class TestToFromFiles(TestKeypairMethods):
    def setUp(self):
        self.generateClasses()
        self.generateFiles('TestToFromFiles')

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

class TestFromClass(TestKeypairMethods):
    def setUp(self):
        self.rsa_key = _RSA.generate_private_key(
            public_exponent=65537, 
            key_size=2048
        )
        self.dsa_key = _DSA.generate_private_key(
            key_size=2048
        )
        self.ecdsa_key = _EC.generate_private_key(
            curve=_EC.SECP384R1()
        )
        self.ed25519_key = _ED25519.Ed25519PrivateKey.generate()
        
    def tearDown(self):
        pass
        
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

class TestFromNumbers(TestKeypairMethods):
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
        
        self.assertEqualPrivateKeys(
            RSAPrivateKey,
            RSAPublicKey,
            self.rsa_key,
            from_numbers
        )
        
    def test_dsa_from_numbers(self):
        from_numbers = DSAPrivateKey.from_numbers(
            p=self.dsa_key.public_key.parameters.p,
            q=self.dsa_key.public_key.parameters.q,
            g=self.dsa_key.public_key.parameters.g,
            y=self.dsa_key.public_key.public_numbers.y,
            x=self.dsa_key.private_numbers.x
        )
        
        self.assertEqualPrivateKeys(
            DSAPrivateKey,
            DSAPublicKey,
            self.dsa_key,
            from_numbers
        )
        
    def test_ecdsa_from_numbers(self):
        from_numbers = ECDSAPrivateKey.from_numbers(
            curve=self.ecdsa_key.public_key.key.curve,
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

# class TestFingerprint(TestKeypairMethods):
#     def setUp(self):
#         self.generateFiles('TestFingerprint')

#     def test_rsa_fingerprint(self):
#         key = 

if __name__ == '__main__':
    unittest.main()