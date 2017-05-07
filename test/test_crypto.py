import unittest
import logging
from mflod.crypto.crypto import Crypto


class TestCrypto(unittest.TestCase):

    def test_department_init(self):
        
        ca = Crypto()
