from random import choice
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa


class DummyKeyManager(object):

    def __init__(self, gen_keys_num=10, sizes=[1024, 2048]):

        # initialize key storage
        self.keys = []

        # generate specified amount of random RSA keys
        for i in range(gen_keys_num):
            self.keys.append(self.gen_rsa_key(choice(sizes)))

    def gen_rsa_key(self, size):
        return rsa.generate_private_key(
                public_exponent=65537,
                key_size=size,
                backend=default_backend()
            )

    def get_keys(self):
        return self.keys

    def yield_keys(self):
        for key in self.keys:
            yield key

    def get_pk_by_pgp_id(self):
        raise NotImplementedError("NO WAY")
