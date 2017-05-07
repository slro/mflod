import unittest
import logging
from mflod.crypto.crypto_assembler import CryptoAssembler


class TestCryptoAssembler(unittest.TestCase):

    def test_department_init(self):
        
        ca = CryptoAssembler()
