class NoMatchingRSAKeyForMessage(Exception):
    pass


class SignatureVerificationFailed(Exception):
    pass


class HMACVerificationFailed(Exception):
    pass
