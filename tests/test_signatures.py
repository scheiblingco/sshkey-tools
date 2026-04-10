# Test SSH signatures (SSHSIG format)
# Tests for signature-specific fields, SSHSignature creation/parsing
# Tests creating signatures with sshkey-tools and verifying with ssh-keygen, and vice versa
import io
import os
import shutil
import unittest
import subprocess

import src.sshkey_tools.exceptions as _EX
import src.sshkey_tools.fields as _FIELD
import src.sshkey_tools.keys as _KEY
import src.sshkey_tools.signatures as _SIG

KEY_TYPES = ["rsa", "ecdsa", "ed25519"]
PRINCIPAL = "testuser@sshkey-tools"


class TestSignatureFields(unittest.TestCase):
    def setUp(self):
        self.rsa_key = _KEY.RsaPrivateKey.generate(2048)
        self.ecdsa_key = _KEY.EcdsaPrivateKey.generate()
        self.ed25519_key = _KEY.Ed25519PrivateKey.generate()

    def assertFieldContainsException(self, field, exception):
        for item in field.exception:
            if isinstance(item, exception):
                return True
        return False

    # --- SshsigField ---

    def test_sshsig_field_encode(self):
        field = _FIELD.SshsigField("SSHSIG")
        self.assertEqual(bytes(field), b"SSHSIG")

    def test_sshsig_field_decode(self):
        decoded, remaining = _FIELD.SshsigField.decode(b"SSHSIGextraBytes")
        self.assertEqual(decoded, "SSHSIG")
        self.assertEqual(remaining, b"extraBytes")

    def test_sshsig_field_decode_exact(self):
        decoded, remaining = _FIELD.SshsigField.decode(b"SSHSIG")
        self.assertEqual(decoded, "SSHSIG")
        self.assertEqual(remaining, b"")

    def test_sshsig_field_validate(self):
        field = _FIELD.SshsigField("SSHSIG")
        self.assertTrue(field.validate())

    def test_sshsig_field_validate_bytes(self):
        field = _FIELD.SshsigField(b"SSHSIG")
        self.assertTrue(field.validate())

    def test_invalid_sshsig_field(self):
        field = _FIELD.SshsigField("INVALID")
        field.validate()
        self.assertFieldContainsException(field, _EX.InvalidDataException)

    def test_invalid_sshsig_field_type(self):
        field = _FIELD.SshsigField(12345)
        field.validate()
        self.assertFieldContainsException(field, (_EX.InvalidDataException, _EX.InvalidFieldDataException))

    def test_sshsig_field_from_decode(self):
        field, remaining = _FIELD.SshsigField.from_decode(b"SSHSIGrest")
        self.assertIsInstance(field, _FIELD.SshsigField)
        self.assertEqual(field.value, "SSHSIG")
        self.assertEqual(remaining, b"rest")

    # --- SignatureVersionField ---

    def test_signature_version_field_encode(self):
        field = _FIELD.SignatureVersionField(1)
        self.assertEqual(bytes(field), b"\x00\x00\x00\x01")

    def test_signature_version_field_validate(self):
        field = _FIELD.SignatureVersionField(1)
        self.assertTrue(field.validate())

    def test_signature_version_field_default(self):
        field = _FIELD.SignatureVersionField.factory()
        self.assertIsInstance(field, _FIELD.SignatureVersionField)
        self.assertEqual(field.value, 1)

    def test_invalid_signature_version_zero(self):
        field = _FIELD.SignatureVersionField(0)
        field.validate()
        self.assertFieldContainsException(field, _EX.InvalidDataException)

    def test_invalid_signature_version_two(self):
        field = _FIELD.SignatureVersionField(2)
        field.validate()
        self.assertFieldContainsException(field, _EX.InvalidDataException)

    def test_invalid_signature_version_type(self):
        field = _FIELD.SignatureVersionField(ValueError)
        field.validate()
        self.assertFieldContainsException(field, _EX.InvalidFieldDataException)

    # --- SignatureNamespaceField ---

    def test_signature_namespace_field_file(self):
        field = _FIELD.SignatureNamespaceField("file")
        self.assertTrue(field.validate())

    def test_signature_namespace_field_various(self):
        for ns in ("file", "email", "git", "custom-namespace", "host"):
            field = _FIELD.SignatureNamespaceField(ns)
            self.assertTrue(field.validate())

    def test_signature_namespace_field_encode_decode(self):
        ns = "file"
        encoded = _FIELD.SignatureNamespaceField.encode(ns)
        decoded, _ = _FIELD.SignatureNamespaceField.decode(encoded)
        self.assertEqual(decoded, ns)

    def test_invalid_signature_namespace_empty(self):
        field = _FIELD.SignatureNamespaceField("")
        field.validate()
        self.assertFieldContainsException(field, _EX.InvalidDataException)

    def test_invalid_signature_namespace_type(self):
        field = _FIELD.SignatureNamespaceField(ValueError)
        field.validate()
        self.assertFieldContainsException(field, _EX.InvalidFieldDataException)

    # --- SignatureHashAlgorithmField ---

    def test_signature_hash_algorithm_sha256(self):
        field = _FIELD.SignatureHashAlgorithmField("sha256")
        self.assertTrue(field.validate())

    def test_signature_hash_algorithm_sha512(self):
        field = _FIELD.SignatureHashAlgorithmField("sha512")
        self.assertTrue(field.validate())

    def test_signature_hash_algorithm_default(self):
        field = _FIELD.SignatureHashAlgorithmField.factory()
        self.assertIsInstance(field, _FIELD.SignatureHashAlgorithmField)
        self.assertEqual(field.value, "sha512")

    def test_signature_hash_algorithm_encode_decode(self):
        for alg in ("sha256", "sha512"):
            encoded = _FIELD.SignatureHashAlgorithmField.encode(alg)
            decoded, _ = _FIELD.SignatureHashAlgorithmField.decode(encoded)
            self.assertEqual(decoded, alg)

    def test_invalid_signature_hash_algorithm_sha1(self):
        field = _FIELD.SignatureHashAlgorithmField("sha1")
        field.validate()
        self.assertFieldContainsException(field, _EX.InvalidDataException)

    def test_invalid_signature_hash_algorithm_md5(self):
        field = _FIELD.SignatureHashAlgorithmField("md5")
        field.validate()
        self.assertFieldContainsException(field, _EX.InvalidDataException)

    def test_invalid_signature_hash_algorithm_arbitrary(self):
        field = _FIELD.SignatureHashAlgorithmField("blake2b")
        field.validate()
        self.assertFieldContainsException(field, _EX.InvalidDataException)

    def test_invalid_signature_hash_algorithm_type(self):
        field = _FIELD.SignatureHashAlgorithmField(ValueError)
        field.validate()
        self.assertFieldContainsException(field, _EX.InvalidFieldDataException)


class SignatureMethods(unittest.TestCase):
    def generateClasses(self):
        self.rsa_key = _KEY.RsaPrivateKey.generate(2048)
        self.ecdsa_key = _KEY.EcdsaPrivateKey.generate()
        self.ed25519_key = _KEY.Ed25519PrivateKey.generate()

    def generateFiles(self, folder):
        self.folder = folder
        try:
            os.mkdir(f"tests/{folder}")
        except FileExistsError:
            shutil.rmtree(f"tests/{folder}")
            os.mkdir(f"tests/{folder}")

        with open(f"tests/{folder}/testdata.txt", "w") as f:
            f.write("This is test data for SSH signature testing.")

        subprocess.run(
            ["ssh-keygen", "-t", "rsa", "-b", "2048", "-f", f"tests/{folder}/rsa_key", "-N", '']
        )
        
        subprocess.run(
            ["ssh-keygen", "-t", "ecdsa", "-b", "256", "-f", f"tests/{folder}/ecdsa_key", "-N", '']
        )
        
        subprocess.run(
            ["ssh-keygen", "-t", "ed25519", "-f", f"tests/{folder}/ed25519_key", "-N", '']
        )
        
        for key_type in KEY_TYPES:
            os.chmod(f"tests/{folder}/{key_type}_key", 0o600)
            with open(f"tests/{folder}/{key_type}_key.pub") as f:
                pubkey = f.read().strip()
            with open(f"tests/{folder}/{key_type}_allowed_signers", "w") as f:
                f.write(f"{PRINCIPAL} {pubkey}\n")

    def setUp(self):
        self.generateClasses()
        self.generateFiles("TestSignatures")

    def tearDown(self):
        shutil.rmtree(f"tests/{self.folder}")

    def createSshkeyToolsAllowedSigners(self, key_type, pubkey_obj):
        pubkey_str = pubkey_obj.to_string().strip()
        path = f"tests/{self.folder}/{key_type}_sshkeytools_allowed_signers"
        with open(path, "w") as f:
            f.write(f"{PRINCIPAL} {pubkey_str}\n")
        return path


class TestSshkeyToolsSignaturesVerifiedBySshkeygen(SignatureMethods):
    """Sign with sshkey-tools, verify the output with ssh-keygen."""
    
    def assertNotStartsWith(self, string, prefix):
        if string.startswith(prefix):
            self.fail(f"Expected string not to start with '{prefix}', but got: {string}")

    def assertSignAndVerifyWithSshkeygen(self, key_type, namespace="file", hash_alg="sha512"):
        privkey = getattr(self, f"{key_type}_key")
        pubkey = privkey.public_key

        sig = _SIG.SSHSignature(signer_privkey=privkey)
        sig.fields.namespace = namespace
        sig.fields.hash_algorithm = hash_alg

        data = b"This is test data for SSH signature testing."
        sig.sign(data)

        sig_path = f"tests/{self.folder}/{key_type}_{namespace}_{hash_alg}.sig"
        sig.to_file(sig_path)

        allowed_signers_path = self.createSshkeyToolsAllowedSigners(
            f"{key_type}_{namespace}_{hash_alg}", pubkey
        )

        data_path = f"tests/{self.folder}/{key_type}_{namespace}_{hash_alg}_data.txt"
        with open(data_path, "wb") as f:
            f.write(data)
        
        
        p = subprocess.Popen([
                "ssh-keygen", "-Y", "verify", "-f", allowed_signers_path, "-I", PRINCIPAL,
                "-n", namespace, "-s", sig_path
            ],
            stdout=subprocess.PIPE, 
            stdin=subprocess.PIPE, 
            stderr=subprocess.PIPE, 
            text=True
        )
        stdout_data = p.communicate(input=data.decode("utf-8"))
        
        self.assertNotStartsWith(
            stdout_data[0],
            'Could not verify signature'
        )

    def test_rsa_sign_sha512(self):
        self.assertSignAndVerifyWithSshkeygen("rsa", "file", "sha512")

    def test_rsa_sign_sha256(self):
        self.assertSignAndVerifyWithSshkeygen("rsa", "file", "sha256")

    def test_ecdsa_sign_sha512(self):
        self.assertSignAndVerifyWithSshkeygen("ecdsa", "file", "sha512")

    def test_ecdsa_sign_sha256(self):
        self.assertSignAndVerifyWithSshkeygen("ecdsa", "file", "sha256")

    def test_ed25519_sign_sha512(self):
        self.assertSignAndVerifyWithSshkeygen("ed25519", "file", "sha512")

    def test_ed25519_sign_sha256(self):
        self.assertSignAndVerifyWithSshkeygen("ed25519", "file", "sha256")

    def test_custom_namespace(self):
        self.assertSignAndVerifyWithSshkeygen("ed25519", "git", "sha512")

    def test_sign_file_method(self):
        privkey = self.ed25519_key
        pubkey = privkey.public_key

        sig = _SIG.SSHSignature(signer_privkey=privkey)
        sig.fields.namespace = "file"
        sig.sign_file(f"tests/{self.folder}/testdata.txt")

        sig_path = f"tests/{self.folder}/ed25519_file_method.sig"
        sig.to_file(sig_path)

        allowed_signers_path = self.createSshkeyToolsAllowedSigners("ed25519_file_method", pubkey)

        result = subprocess.run(
            ["bash", "-c", 
                f"ssh-keygen -Y verify -f {allowed_signers_path} -I {PRINCIPAL} "
            f"-n file -s {sig_path} < tests/{self.folder}/testdata.txt",
            ],
            capture_output=True
        )
        self.assertEqual(result.returncode, 0, "ssh-keygen failed to verify file-signed ed25519 signature")


class TestSshkeygenSignaturesParsedBySshkeyTools(SignatureMethods):
    """Sign with ssh-keygen, parse and verify with sshkey-tools."""

    def assertParseSshkeygenSignature(self, key_type):
        data_path = f"tests/{self.folder}/testdata_{key_type}.txt"
        sig_path = f"{data_path}.sig"

        with open(f"tests/{self.folder}/testdata.txt", "rb") as f:
            data = f.read()
        with open(data_path, "wb") as f:
            f.write(data)

        ret = subprocess.run(
            ["ssh-keygen", "-Y", "sign", "-f", f"tests/{self.folder}/{key_type}_key", "-n", "file", data_path],
            capture_output=True
        )
        self.assertEqual(ret.returncode, 0, f"ssh-keygen failed to sign {data_path}")

        sig = _SIG.SSHSignature.from_file(sig_path)

        self.assertEqual(sig.fields.magic_preamble.value, "SSHSIG")
        self.assertEqual(sig.fields.sig_version.value, 1)
        self.assertEqual(sig.fields.namespace.value, "file")
        self.assertIn(sig.fields.hash_algorithm.value, ("sha256", "sha512"))

        pubkey = _KEY.PublicKey.from_file(f"tests/{self.folder}/{key_type}_key.pub")
        sig.verify(data, pubkey)

    def test_parse_rsa_signature(self):
        self.assertParseSshkeygenSignature("rsa")

    def test_parse_ecdsa_signature(self):
        self.assertParseSshkeygenSignature("ecdsa")

    def test_parse_ed25519_signature(self):
        self.assertParseSshkeygenSignature("ed25519")


class TestSSHSignatureIO(SignatureMethods):
    """Tests for SSHSignature to/from file and string methods."""

    def test_to_file_and_from_file(self):
        sig = _SIG.SSHSignature(signer_privkey=self.ed25519_key)
        sig.fields.namespace = "file"
        sig.sign(b"test data for file round-trip")

        path = f"tests/{self.folder}/roundtrip.sig"
        sig.to_file(path)

        loaded = _SIG.SSHSignature.from_file(path)
        self.assertEqual(loaded.fields.namespace.value, "file")
        self.assertEqual(loaded.fields.magic_preamble.value, "SSHSIG")
        self.assertEqual(loaded.fields.sig_version.value, 1)

        loaded.verify(b"test data for file round-trip", self.ed25519_key.public_key)

    def test_to_string_and_from_string(self):
        sig = _SIG.SSHSignature(signer_privkey=self.ed25519_key)
        sig.fields.namespace = "file"
        sig.sign(b"test data for string round-trip")

        sig_str = sig.to_string()

        self.assertIn(b"-----BEGIN SSH SIGNATURE-----", sig_str)
        self.assertIn(b"-----END SSH SIGNATURE-----", sig_str)

        loaded = _SIG.SSHSignature.from_string(sig_str)
        self.assertEqual(loaded.fields.namespace.value, "file")
        loaded.verify(b"test data for string round-trip", self.ed25519_key.public_key)

    def test_from_string_text(self):
        sig = _SIG.SSHSignature(signer_privkey=self.rsa_key)
        sig.fields.namespace = "email"
        sig.sign(b"email content")

        sig_str = sig.to_string().decode("utf-8")

        loaded = _SIG.SSHSignature.from_string(sig_str, encoding="utf-8")
        self.assertEqual(loaded.fields.namespace.value, "email")
        loaded.verify(b"email content", self.rsa_key.public_key)

    def test_signature_fields_preserved_round_trip(self):
        for key_type in KEY_TYPES:
            privkey = getattr(self, f"{key_type}_key")
            sig = _SIG.SSHSignature(signer_privkey=privkey)
            sig.fields.namespace = f"test-{key_type}"
            sig.fields.hash_algorithm = "sha256"
            sig.sign(b"field preservation test")

            loaded = _SIG.SSHSignature.from_string(sig.to_string())
            self.assertEqual(loaded.fields.namespace.value, f"test-{key_type}")
            self.assertEqual(loaded.fields.hash_algorithm.value, "sha256")
            self.assertEqual(loaded.fields.magic_preamble.value, "SSHSIG")
            self.assertEqual(loaded.fields.sig_version.value, 1)


class TestSSHSignatureVerification(SignatureMethods):
    """Tests for SSHSignature sign and verify logic."""

    def test_verify_uses_embedded_pubkey(self):
        sig = _SIG.SSHSignature(signer_privkey=self.ed25519_key)
        sig.fields.namespace = "file"
        sig.sign(b"verify with embedded key")

        loaded = _SIG.SSHSignature.from_string(sig.to_string())
        loaded.verify(b"verify with embedded key")

    def test_verify_wrong_data_raises(self):
        sig = _SIG.SSHSignature(signer_privkey=self.ed25519_key)
        sig.fields.namespace = "file"
        sig.sign(b"correct data")

        loaded = _SIG.SSHSignature.from_string(sig.to_string())
        with self.assertRaises(Exception):
            loaded.verify(b"wrong data", self.ed25519_key.public_key)

    def test_verify_wrong_key_raises(self):
        other_key = _KEY.Ed25519PrivateKey.generate()

        sig = _SIG.SSHSignature(signer_privkey=self.ed25519_key)
        sig.fields.namespace = "file"
        sig.sign(b"some data")

        loaded = _SIG.SSHSignature.from_string(sig.to_string())
        with self.assertRaises(Exception):
            loaded.verify(b"some data", other_key.public_key)

    def test_all_key_types_sign_and_verify(self):
        data = b"all key types test"
        for key_type in KEY_TYPES:
            privkey = getattr(self, f"{key_type}_key")

            sig = _SIG.SSHSignature(signer_privkey=privkey)
            sig.fields.namespace = "file"
            sig.sign(data)

            loaded = _SIG.SSHSignature.from_string(sig.to_string())
            loaded.verify(data, privkey.public_key)

    def test_sign_file_and_verify(self):
        sig = _SIG.SSHSignature(signer_privkey=self.ed25519_key)
        sig.fields.namespace = "file"
        sig.sign_file(f"tests/{self.folder}/testdata.txt")

        with open(f"tests/{self.folder}/testdata.txt", "rb") as f:
            data = f.read()

        loaded = _SIG.SSHSignature.from_string(sig.to_string())
        loaded.verify(data, self.ed25519_key.public_key)


if __name__ == "__main__":
    unittest.main()
