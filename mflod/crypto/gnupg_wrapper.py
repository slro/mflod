import logging


class GnuPGWrapper(object):
    """
    Class manages operations related to gnupg_wrapper

    Specifically, goal is to generate/delete RSA key pair on a local environment,
    pull down RSA key pair from RSA key server, etc.

    Developers:
        - Tornike Nanobashvili
    """

    def __init__(self):
        """
        Initializes GnuPGWrapper class

        Initialization processes:
            - Defines logging basic configuration
        """

        logging.basicConfig(filename='./logs/gnupg_wrapper.log', level=logging.DEBUG)

        self.logger = logging.getLogger('GnuPGWrapper')
        self.logger.debug('GnuPGWrapper instance is being created.')
