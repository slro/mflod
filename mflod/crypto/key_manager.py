import logging
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa


class KeyManager(object):
    """
    Class manages operations on user GPG keys

    Specifically, goal is to implement and provide gnupg_wrapper.py (GnuPGWrapper) functionality,
    generate plain RSA key pair and support helper methods. Also convert and provide PGP keys to
    a cryptography lib key instances.

    Developers:
        - Tornike Nanobashvili
    """

    def __init__(self):
        """
        Initialize KeyManager class

        Initialization processes:
            - Defines logging instance
        """

        self.logger = logging
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
            # Generates RSA key pair
            key = rsa.generate_private_key(
                public_exponent=65537,
                key_size=key_size,
                backend=default_backend()
            )

            self.logger.info('Plain RSA (' + str(key_size) + ' bits) key pair is being generated: ' + str(key))

            return key
        except Exception as ERROR:
            self.logger.error(ERROR)
