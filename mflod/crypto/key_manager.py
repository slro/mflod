import pgpdump
import os
from mflod.crypto.gnupg_wrapper import GnuPGWrapper
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization


class KeyManager(GnuPGWrapper):
    """
    Class manages operations on user keys, implements GnuPGWrapper parent class

    Specifically, goal is to implement and provide parent class (GnuPGWrapper) functionality,
    generate plain RSA key pair, parse and retrieve PGP key information such as RSA semi-primes
    (p, q, n, e, d) in order to generate specific PGP key's RSA key. In addition convert and
    return PGP keys to a cryptography lib object instances for further processing.

    Developers:
        - (tnanoba) Tornike Nanobashvili
    """

    def __init__(self, gnupg_home_dir='' + os.environ['HOME'] + '/.gnupg/'):
        """
        Initialize KeyManager and parent GnuPGWrapper classes

        @:param gnupg_home_dir: str (Default is whatever GnuPG defaults to)
        """

        GnuPGWrapper.__init__(self, gnupg_home_dir)

        self.logger.debug('KeyManager instance is being created.')

    def generate_plain_rsa_key(self, key_size=2048):
        """
        Generates RSA key pair based on provided key_size
        and returns cryptography lib object.

        @developer: tnanoba

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

    def get_pgp_rsa_key_id(self, key_id):
        """
        Searches PGP private key either by keyid or either fingerprint and returns
            cryptography lib instance on success, None otherwise.

        @developer: tnanoba

            E.g
                keyid format => 4E2ADFB8D4C78B63
                fingerprint format => D94FC56AFD1D1AD8B56D35EA9FB10119E057B48F

        :param key_id: str
        :return: Object|None
        """
        try:
            pgp_private_key = self._retrieve_local_pgp_private_key_id(key_id)

            if isinstance(pgp_private_key, type(None)):
                raise ValueError

            return self._return_rsa_key_from_pgp(
                pgp_private_key.encode('utf-8')
            )
        except Exception as ERROR:
            self.logger.error(ERROR)
            return None

    def get_pgp_rsa_keys(self, limit=30):
        """
        Iterates through retrieved PGP private keys, get the RSA semi-primes information (from pgpdump),
        invokes _return_rsa_key_from_pgp private method and yields returned data.

        @developer: tnanoba

        :param limit: int
        :return: Generator|None
        """
        try:
            # Terminates process if limit is not a valid integer or it equals to 0
            if not isinstance(limit, int) or limit == 0:
                raise ValueError

            for count, private_key in enumerate(self._retrieve_local_pgp_private_keys()):
                yield self._return_rsa_key_from_pgp(private_key.encode('utf-8'))

                # Terminates on specified limit
                if count == limit - 1:
                    break
        except Exception as ERROR:
            self.logger.error(ERROR)
            return None

    def _return_rsa_key_from_pgp(self, pgp_key):
        """
        Accepts pgp_key bytes, process it to pgpdump packets, which is a Generator class with following
        consisting objects:

        @developer: tnanoba

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
        :return: object
        """
        try:
            packets = list(pgpdump.AsciiData(pgp_key).packets())

            return self.compute_rsa_private_key(
                packets[0].__dict__['prime_p'],
                packets[0].__dict__['prime_q'],
                packets[0].__dict__['exponent'],
                packets[0].__dict__['modulus'],
                packets[0].__dict__['exponent_d']
            )
        except Exception as ERROR:
            self.logger.error(ERROR)

    @classmethod
    def compute_rsa_private_key(cls, p, q, e, n, d):
        """
        Computes RSA private key based on provided RSA semi-primes
            and returns cryptography lib instance.

        @developer: tnanoba

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

    @staticmethod
    def rsa_key_to_pem(rsa_secret_key):
        """
        Converts and returns RSA key from cryptography lib instance into RSA key
            PEM (Privacy Enhanced Mail) format.

        @developer: tnanoba

        @link @link https://cryptography.io/en/latest/hazmat/primitives/asymmetric/rsa/

        :param rsa_secret_key: object
        :return: bytes
        """
        return rsa_secret_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption(),
        )

    @staticmethod
    def rsa_public_key_to_pem(rsa_public_key):
        """
        Converts and returns RSA public key from cryptography lib instance into RSA public key
            PEM (Privacy Enhanced Mail) format.

        @developer: tnanoba

        @link https://cryptography.io/en/latest/hazmat/primitives/asymmetric/rsa/

        @note Generating RSA public key from RSA private key: "private_rsa_key.public_key()"

        :param rsa_public_key: object
        :return: bytes
        """
        return rsa_public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
