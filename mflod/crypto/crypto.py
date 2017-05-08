import logging


class Crypto(object):
    """ Class that handles assembly of FLOD protocol message packet

    The main purpose of this class is to provide cryptographic back-end
    for FLOD protocol client to prepare content user wishes to send to
    a transportation.

    The Steps involved are hybrid encryption, HMAC calculation, signing
    etc. The structure of a message packet and some implementation notes
    can be found in module README.md file: https://goo.gl/leWWa4

    Developers:
        - vsmysle (Kyrylo Voronchenko)
        - ddnomad (Artem Fliunt)
        - Sofiya Demchuk

    """

    def __init__(self):
        """ Initialization method """

        self.logger = logging.getLogger(__name__)
        self.logger.debug("created instance of Crypto module")

    def assemble_message_packet(msg_content, recipient_pk, sign=None):
        """ Assemble FLOD message packet

        @developer: ???

        Assembly involves a creation of DER-encoded ASN.1 structure that
        corresponds to a specification of FLOD message packet format. To
        include optional signing in header block pass a sender_sk named
        argument.

        Also this method handles the assembly of a HEADER block that involves
        putting all the keys and meta-information together.

        :param msg_content:         string message to include into FLOD
                                    message packet
        :param recipient_pk:        instance of cryptography.hazmat.
                                    primitives.asymmetric.rsa.RSAPublicKey
                                    that is a public key of a recipient.
                                    Used to encrypt a header block of the
                                    message packet.
        :param sign=None:      instance of cryptography.hazmat.
                                    primitives.asymmetric.rsa.RSAPrivateKey
                                    that is used to create a signature in the
                                    header block of FLOD message packet

        :return: string DER-encoded ASN.1 structure that is FLOD message packet
                 ready to be sent to a recipient

        :raise: ???

        """

        pass

    def disassemble_message_packet(msg_packet, get_sks_func, get_pk_byid_func):
        """ Attempt to disassemble FLOD message packet that was received

        @developer: ???

        Disassembly involves test decryption of header block with all available
        private keys of a user. If decryption was successful then the message
        was addressed to the user. This does not means though that the
        signature verification will succeed as well as HMAC integrity check.

        On successful decryption the method returns a recovered message
        together with a supplementary exit code which determines conditions
        that occur during disassembly process. The code can be one of the
        following integers:

            - 0: indicates that signature verification was successful with a
              known sender PGPKeyID
            - 1: indicates that signature verification was successful but the
              key used was not a PGP key (but it exists in a user key chain)
            - 2: indicates that decryption was successful but the message was
              not signed by a sender
            - 3: indicates that the signature authenticity cannot be
              established due to an absence of a corresponding public key

        :param msg_packet:          string DER-encoded ASN.1 structure of FLOD
                                    message packet to decrypt
        :param get_sks_func:        generator that yields all available secret
                                    keys of a user. The user keys have to be
                                    instances of cryptography.hazmat.primitives
                                    .assymetric.rsa.RSAPublicKey class.
        :param get_pk_byid_func:    function that returns an instance of
                                    cryptography.hazmat.primitives.assymetric.rsa
                                    .RSAPrivateKey that corresponds to a
                                    PGPKeyID that is passed to it. If there is
                                    no such key available the function should
                                    return a list of instances of the same
                                    class that are non-PGP keys without IDs.

        :return: one of the following lists (see supplementary exit codes
                 paragraph for details):
                    - [dec_msg, 0, pgp_key_id]
                    - [dec_msg, 1, sign_pk]
                    - [dec_msg, 2]
                    - [dec_msg, 3]
                The values in lists are the following:
                    - dec_msg:      string decryption of a message received
                    - pgp_key_id:   string PGPKeyID of a public key that
                                    verified a signature
                    - sign_pk:      an instance of cryptography.hazmat.
                                    primitives.rsa.RSAPublicKey that verified a
                                    signature

        :raise ???

        """

        pass

    def __assemble_content_block(content, key):
        """ Create an ASN.1 DER-encoded structure of a content block

        @developer: ???

        The corresponding ASN.1 structure from a documentation is
        MPContentContainer

        :param content: string content to encapsulate
        :param key: string AES key to use for encryption

        :return: string DER-encoding of MPContentContainer ASN.1 structure

        """

        pass

    def __disassemble_content_block(content, key):
        """ Decrypt and decode content from a content block

        @developer: ???

        :param content: DER-encoded ASN.1 structure that encapsulates
                        encrypted content
        :param key:     string AES key to be used for decryption

        :return: string decrypted message

        """

        pass

    def __assemble_hmac_block(content, key):
        """ Produce HMAC block ASN.1 structure (MPHMACContainer)

        @developer: ???

        :param content: string DER-encoded content generate HMAC of and
                        encapsulate into HMAC FLOD block
        :param key:     string key to use for HMAC generation

        :return: DER-encoded ASN.1 structure that encapsulates HMAC
                 block

        """

        pass

    def __verify_hmac(hmac_blk, key, content_blk):
        """ Verify content HMAC

        @developer: ???

        :param hmac_blk:        string DER-encoded ASN.1 structure of HMAC
                                block (MPHMACContainer)
        :param key:             string HMAC secret key
        :param content_blk:     string DER-encoded ASN.1 structure of content
                                block

        :return: bool verification result

        """

        pass

    def __generate_hmac(content, key):
        """ Generate HMAC for in input content and key

        @developer: ???

        :param content: string DER-encoded content to produce digest of
        :param key:     string key to use for HMAC

        :return: string HMAC of the input content

        """

        pass

    def __encrypt_with_aes(content, key):
        """ Encrypt content with AES-128-CBC (with PCKS#7 padding)

        @developer: ???

        :param content: string DER-encoded MPContent ASN.1 structure to encrypt
        :param key:     string key to use for encryption

        :return: string encryption of an input content

        """

        pass

    def __decrypt_with_aes(content, key):
        """ Decrypt AES-128-CBC encrypted content (PCKS#7 padded)

        @developer: ???

        :param content: string ciphertext of MPContent ASN.1 structure
        :param key:     string AES secret key

        :return: string decrypted DER-encoded MPContent ASN.1 structure

        """

        pass

    def __encrypt_with_rsa(content, recipient_pk):
        """ Encrypt content with RSAES-OAEP scheme

        @developer: ???

        This method handles an encryption of a *single* RSA block with a
        specified above scheme. It does not handle splitting of a header into
        several blocks. It has to be done by other method that would use this
        one only for single block encryption purpose.

        TODO: what is a maximum size of a content that can be padded and
        encrypted given a particular size of RSA key?

        :param content:         string content to encrypt (probably a part of
                                ASN.1 DER-encoded MPHeader block)
        :param recipient_pk:    instance of cryptography.hazmat.primitives.rsa
                                .RSAPublicKey to use for a content encryption

        :return: string encryption of an input content

        """

        pass

    def __decrypt_with_rsa(content, user_sk):
        """ Decrypt RSAES-OAEP encrypted content (single block)

        @developer: ???

        This method decrypts a single RSA ciphertext block only

        :param content: string content to decrypt
        :param user_sk: instance of cryptography.hazmat.primitives.rsa
                        .RSAPrivateKey to use for a decryption

        :return: string decryption of an input content

        """

    def __sign_content(content, user_sk):
        """ Produce a signature of an input content using RSASSA-PSS scheme

        @developer: ???

        :param content: string content to sign
        :param user_sk: instance of cryptography.hazmat.primitives.rsa.
                        RSAPrivateKey

        :return: string signature of the input content

        """

        pass

    def __verify_signature(signature, signer_pk, content):
        """ Verify RSASSA-PSS signature

        @developer: ???

        :param signature: string signature to verify
        :param signer_pk: instance of cryptography.hazmat.primitives.
                          rsa.RSAPublicKey that is a public key of a signer
        :param content:   content to verify a signature of

        :return: bool verification result

        """

        pass

    def __get_asn1_algorithm_identifier_der(oid_str):
        """ Generate ASN.1 structure for algorithm identifier

        @developer: ???

        :param oid_str: string OID to encapsulate

        :return: pyasn1.type.univ.Sequence object

        """

        pass

    def __get_random_bytes(spec_lst):
        """ Generate random bytes

        @developer: ???

        :param spec_lst: list of integers that is lengths of bytestings to
                         return

        :return: list of random bytestrings with lengths corresponding to the
                 ones from a spec list

        """

        pass
