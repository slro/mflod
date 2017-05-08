import unittest
import logging
from mflod.crypto.crypto import Crypto
from pyasn1.codec.der.encoder import encode as asn1_encode
from pyasn1.type import univ
from os import urandom
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

    def setUp(self):
        self.crypto_obj = Crypto()

    def test_generate_hmac(self):
        self.crypto_obj._Crypto__generate_hmac(asn1_encode(
                            univ.OctetString("test_me")),
                            urandom(20)
                        )

    def test_assemble_hmac_block(self):
        self.crypto_obj._Crypto__assemble_hmac_block(
            self.crypto_obj._Crypto__generate_hmac(
                asn1_encode(univ.OctetString("test_me")),
                urandom(20)), urandom(20))

    def test_verify_hmac(self):
        key = urandom(20)
        msg = urandom(10000)
        hmac_digest = self.crypto_obj._Crypto__generate_hmac(
                asn1_encode(univ.OctetString(msg)), key)

        hmac_blk = self.crypto_obj._Crypto__assemble_hmac_block(
            self.crypto_obj._Crypto__generate_hmac(
                asn1_encode(univ.OctetString(msg)), key), key)
        self.crypto_obj.\
            _Crypto__verify_hmac(hmac_blk, key, hmac_digest)

    def test_rsa_encrypt_and_decrypt(self):
        sk = rsa.generate_private_key(
            public_exponent=65537,
            key_size=4096,
            backend=default_backend()
        )
        pk = sk.public_key()

        sk_2 = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
            backend=default_backend()
        )
        test_content = self.crypto_obj._Crypto__encrypt_with_rsa(
            asn1_encode(univ.OctetString("1"*466)), pk)
        self.crypto_obj._Crypto__decrypt_with_rsa(
            test_content, sk)