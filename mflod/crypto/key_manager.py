class KeyManager(object):
    """
    class is responsible for managing and retrieving GPG keys from GPG keychain

        Specifically, goal is to provide GPG key pairs:
            - GPG key ID
            - GPG public key
            - GPG private key

        Class uses GPG wrapper behind the scene (python3-gnupg package).

        Developers:
            - Tornike Nanobashvili
    """

    def __init__(self):
        pass
