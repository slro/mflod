import unittest
import logging
from mflod.crypto.crypto import Crypto


class TestCrypto(unittest.TestCase):

    def test_department_init(self):
        logger = logging.getLogger()
        h = logging.StreamHandler()
        logger.setLevel(logging.DEBUG)
        logger.addHandler(h)
        logger.debug("unittest logger debugs")
        c = Crypto()