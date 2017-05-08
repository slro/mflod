class LogStrings(object):

    # DEBUG level strings
    CRYPTO_CLASS_INIT = 'module instance was created'
    ASSEMBLE_CONTENT_BLOCK_CALL = 'starting a content block assembly'
    DISASSEMBLE_CONTENT_BLOCK_CALL = 'starting a content block disassembly'
    AES_ENC_CALL = 'starting AES encryption routine'
    AES_DEC_CALL = 'starting AES decription routine'
    DISASSEMBLE_MESSAGE_PACKET_CALL = 'starting message packet ' + \
                                      'disassembly (brute forcing keys)'
    ATTEMPT_DECRYPT_HEADER = 'trying to decrypt init header block'
    INVALID_RSA_KEY = 'decryption failed because of an invalid RSA key'
    WRONG_RSA_KEY = 'decryption failed as RSA key does not match'
    MESSAGE_FOR_USER = 'the message received can be decrypted and was ' + \
                       'intended for a user'
    MESSAGE_NOT_FOR_USER = 'the message received cannot be decrypted ' + \
                           'was any of users RSA keys'
    MESSAGE_IS_SIGNED = 'received message was signed by a sender'
    SIGN_CANNOT_VERIF = 'signature cannot be verified - no correspoding ' + \
                        'public key found'
    NON_PGP_KEY_SIGN = 'signature was produced using non-PGP RSA key'
    NOT_SIGNED_MESSAGE = 'message was not signed by a sender'
    MSG_CONTENT_WAS_RECOVERED = 'message was successfully recovered from' + \
                                ' a message packer'
