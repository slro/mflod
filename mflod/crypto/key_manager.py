import pgpdump
from mflod.crypto.gnupg_wrapper import GnuPGWrapper
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa


class KeyManager(GnuPGWrapper):
    """
    Class manages operations on user keys, implements GnuPGWrapper parent class

    Specifically, goal is to implement and provide parent class (GnuPGWrapper) functionality,
    generate plain RSA key pair, parse and retrieve PGP key information such as RSA semi-primes
    (p, q, n, e, d) in order to generate specific PGP key's RSA key. In addition convert and
    return PGP keys to a cryptography lib object instances for further processing.

    Developers:
        - Tornike Nanobashvili
    """

    def __init__(self):
        """
        Initialize KeyManager and parent GnuPGWrapper classes
        """

        GnuPGWrapper.__init__(self)

        self.logger.debug('KeyManager instance is being created.')

    def generate_plain_rsa_key(self, key_size=2048):
        """
        Generates RSA key pair based on provided key_size
        and returns cryptography lib object.

        Response example:
            cryptography.hazmat.backends.openssl.rsa._RSAPrivateKey object

        :param key_size: int
        :return: object
        """
        try:
            # Generates plain RSA key pair
            key = rsa.generate_private_key(
                public_exponent=65537,
                key_size=key_size,
                backend=default_backend()
            )

            self.logger.info('Plain RSA (' + str(key_size) + ' bits) key pair is being generated: ' + str(key))

            return key
        except Exception as ERROR:
            self.logger.error(ERROR)

    def get_pgp_rsa_keys(self):
        """
        Iterates through retrieved PGP private keys, get the RSA semi-primes information (from pgpdump),
        invokes __return_rsa_key_from_pgp private method and yields returned data.

        :return: Generator
        """
        try:
            for private_key in self.retrieve_local_pgp_private_keys():
                yield self.__return_rsa_key_from_pgp(private_key.encode('utf-8'))
        except Exception as ERROR:
            self.logger.error(ERROR)

    def __return_rsa_key_from_pgp(self, pgp_key):
        """
        Accepts pgp_key bytes, process it to pgpdump packets, which is a Generator class with following
        consisting objects:

            SecretKeyPacket object
            UserIDPacket object
            SignaturePacket object

            SecretKeyPacket object dict structure:

                {
                    'prime_p': '...', (p)
                    'prime_q': '...', (q)
                    'exponent': '...', (e)
                    'modulus': '...', (p * q = n)
                    'exponent_d': '...', (d)
                    'data': '...',
                    'raw_creation_time': '...',
                    's2k_type': '...',
                    'checksum': '...',
                    'pubkey_version': '...',
                    'exponent_x': '...',
                    's2k_id': '...',
                    's2k_cipher': '...',
                    'new': '...',
                    'creation_time': '...',
                    'fingerprint': '...',
                    'multiplicative_inverse': '...',
                    'raw': '...',
                    'prime': '...',
                    'length': '...',
                    'group_gen': '...',
                    'pub_algorithm_type': '...',
                    'raw_days_valid': '...',
                    'name': '...',
                    'key_id': '...',
                    's2k_hash': '...',
                    'raw_pub_algorithm': '...',
                    'expiration_time': '...',
                    's2k_iv': '...',
                    'group_order': '...'
                }

        :param pgp_key: bytes
        :return: str
        """
        try:
            packets = list(pgpdump.AsciiData(pgp_key).packets())

            return self.__compute_rsa_private_key(
                packets[0].__dict__['prime_p'],
                packets[0].__dict__['prime_q'],
                packets[0].__dict__['exponent'],
                packets[0].__dict__['modulus'],
                packets[0].__dict__['exponent_d']
            )
        except Exception as ERROR:
            self.logger.error(ERROR)

    @classmethod
    def __compute_rsa_private_key(cls, p, q, e, n, d):
        """
        Computes RSA private key based on provided RSA semi-primes
            and returns cryptography lib instance.

        :param p: int
        :param q: int
        :param e: int
        :param n: int
        :param d: int
        :return: object
        """

        # Computes: d % (p - 1)
        dmp1 = rsa.rsa_crt_dmp1(d, p)

        # Computes: d % (q - 1)
        dmq1 = rsa.rsa_crt_dmq1(d, q)

        # Modular inverse q of p, (q ^ -1 mod p)
        iqmp = rsa.rsa_crt_iqmp(p, q)

        public_numbers = rsa.RSAPublicNumbers(e, n)

        return rsa.RSAPrivateNumbers(p, q, d, dmp1, dmq1, iqmp, public_numbers).private_key(default_backend())

try:
    cls = KeyManager()

    for rsa_private_key in cls.get_pgp_rsa_keys():
        print(rsa_private_key)

except Exception as ERR:
    print(ERR)
