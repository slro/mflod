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
