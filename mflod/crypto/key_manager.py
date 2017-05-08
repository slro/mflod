import logging


class KeyManager(object):
    """ Class that operates on user keys

    DEV_INFO: The bare minimum functionality should involve RSA key generation
              (just plain RSA key, not PGP one), and helper methods specified
              below. Also this class should deal with an instance of a
              gnupg_wrapper module to pull PGP keys from a system key chain and
              convert them to a cryptography lib key instances.

    Developers:
        - ?

    """

    def __init__(self):
        """ Initialization method """

        self.logger = logging.getLogger(__name__)
        self.logger.debug("KeyManager instance was created")

    def get_user_secret_keys(self):
        """ Generator function that yields all user secret keys

        @developer: ???

        DEV_INFO: this function is needed for crypto module to brute over
                  all possible keys of a user to determine whether the message
                  was sent to him

        :param ???: TODO: do we need any params?

        :yield: instance of cryptography.hazmat.primitives.assymetric.rsa.
                RSAPrivateKey

        """

        # -- template
        # for user_key in user_keys:
        #   yield user_key
