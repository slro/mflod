from random import choice
import _pickle as pkl
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

    def dump_key_pickle(self, key_ind, path):

        if not 0 < key_ind < len(self.keys):
            raise IndexError("Key index out of range")

        try:
            with open(path, 'wb') as f:
                pkl.dump(self.keys[key_ind], f)
        except Exception as e:
            print("failed to dump key: %s" % e)

    def load_key_from_pickle(self, path):

        try:
            with open(path, 'rb') as f:
                self.keys.append(pkl.load(f))
        except Exception as e:
            print("failed to load key: %s" % e)

        return len(self.keys) - 1
