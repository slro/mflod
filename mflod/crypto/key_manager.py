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

    def gen_plain_rsa_key(self, key_size=2048):
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
