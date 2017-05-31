import unittest
import logging
from random import choice
from mflod.crypto.crypto import Crypto
from dummy_key_manager import DummyKeyManager
from pyasn1.type import univ
from os import urandom
from pyasn1.codec.der.encoder import encode
from pyasn1.type.univ import OctetString
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa

# set up root logger
logger = logging.getLogger()
logger.setLevel(logging.DEBUG)

# set up logging formatter
logging_formatter = logging.Formatter('%(name)s - %(levelname)s - %(message)s')

# set up console output handler
logging_handler = logging.StreamHandler()
logging_handler.setFormatter(logging_formatter)

# add handler to a root logger
logger.addHandler(logging_handler)


class TestCrypto(unittest.TestCase):

    # messages for testing
    TEST_MSGS = [
            'hello, crypto',
            str(urandom(404)),
            "enda kohta tehtud päringuid andmekogudes",
            "Töövõimetuslehtede täiendamine",
            str(urandom(999))
    ]

    def setUp(self):
        self.crypto_obj = Crypto()
        self.key_manager = DummyKeyManager()

    def test_aes_encryption_consistency(self):

        # test encryption-decryption for each test message
        for msg in self.TEST_MSGS:

            # precreate simple ASN.1 structure to encode and encrypt
            test_der = encode(OctetString(msg))

            # generate random IV and a key
            iv = urandom(16)
            key = urandom(16)

            # encrypt and decrypt message
            ct = self.crypto_obj._Crypto__encrypt_with_aes(test_der, key, iv)
            pt = self.crypto_obj._Crypto__decrypt_with_aes(ct, key, iv)

            # check whether they are equal
            self.assertEqual(test_der, pt)

    def test_content_block_assembly_consistency(self):

        # test assembly-disassembly of a content block for each test message
        for msg in self.TEST_MSGS:

            # generate key and IV
            key = urandom(16)
            iv = urandom(16)

            # test assembly and disassembly consistency
            self.assertEqual(
                    self.crypto_obj._Crypto__disassemble_content_block(
                        self.crypto_obj._Crypto__assemble_content_block(
                            msg, key, iv),
                        key)[1],
                    msg)

    def test_signing_consistency(self):

        # test signature creation and verification for each test message
        for msg in self.TEST_MSGS:

            # generate a test RSA private key
            private_key = rsa.generate_private_key(
                    public_exponent=65537,
                    key_size=2048,
                    backend=default_backend()
                )

            # get a corresponding public key
            public_key = private_key.public_key()

            # precreate simple ASN.1 structure to encode and encrypt
            test_der = encode(OctetString(msg))

            # generate a signature of a test message
            sign = self.crypto_obj._Crypto__sign_content(test_der, private_key)

            # attempt to verify a signature
            res = self.crypto_obj._Crypto__verify_signature(sign, public_key,
                                                            test_der)

            # check whether verification was successful
            self.assertTrue(res)

    def test_generate_hmac(self):
        self.crypto_obj._Crypto__generate_hmac(encode(
                            univ.OctetString("test_me")),
                            urandom(20)
                        )

    def test_assemble_hmac_block(self):
        self.crypto_obj._Crypto__assemble_hmac_block(
            self.crypto_obj._Crypto__generate_hmac(
                encode(univ.OctetString("test_me")),
                urandom(20)), urandom(20))

    def test_verify_hmac(self):
        key = urandom(20)
        key2 = urandom(20)
        msg = urandom(10000)
        hmac_digest = self.crypto_obj._Crypto__generate_hmac(
                encode(univ.OctetString(msg)), key)

        hmac_blk = self.crypto_obj._Crypto__assemble_hmac_block(
            self.crypto_obj._Crypto__generate_hmac(
                encode(univ.OctetString(msg)), key), key)
        self.crypto_obj.\
            _Crypto__verify_hmac(hmac_blk, key, hmac_digest)

    def test_rsa_encrypt_and_decrypt(self):
        key_manager = DummyKeyManager()
        sk = choice(key_manager.keys)
        pk = sk.public_key()
        encrypted_packet = self.crypto_obj.assemble_message_packet('HelloHello', pk)
        msg = self.crypto_obj.disassemble_message_packet(encrypted_packet, key_manager)
        print(msg)

