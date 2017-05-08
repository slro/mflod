import unittest
import logging
from mflod.crypto.crypto import Crypto

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

    def test_aes_encryption_decription(self):
        self.crypto_obj._Crypto__encrypt_with_aes("", "", "")

