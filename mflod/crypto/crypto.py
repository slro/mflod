# generic imports
import logging
from datetime import datetime

# crypto module headers and helpers imports
import mflod.crypto.asn1_structures as asn1_dec
from mflod.crypto.constants import Constants as const
from mflod.crypto.log_strings import LogStrings as logstr

# ASN.1 tools imports
from pyasn1.type import univ
from pyasn1.codec.der.encoder import encode as asn1_encode
from pyasn1.codec.der.decoder import decode as asn1_decode

# cryptography connected imports
import hmac
import hashlib
from os import urandom
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.hashes import SHA1
from cryptography.hazmat.primitives.asymmetric import padding as asym_padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.exceptions import InvalidSignature, InvalidKey


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

        # init logger object
        self.logger = logging.getLogger(__name__)
        self.logger.debug(logstr.CRYPTO_CLASS_INIT)

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
        # NOTE:
        # A
        # A 2048-bit key can encrypt up to (2048/8) – 42 - 3 = 256 – 42 - 3 = 211 bytes.
        # A 1024-bit key can encrypt up to (1024/8) - 42 - 2 = 128 - 42 - 2 = 84 bytes.

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

    def __assemble_content_block(self, content, key, iv):
        """ Create an ASN.1 DER-encoded structure of a content block

        @developer: ddnomad

        The corresponding ASN.1 structure from a documentation is
        MPContentContainer

        :param content: string content to encapsulate
        :param key:     string AES key to use for encryption
        :param iv:      string CBC mode initialization vector

        :return: string DER-encoding of MPContentContainer ASN.1 structure

        """

        # logger entry
        self.logger.debug(logstr.ASSEMBLE_CONTENT_BLOCK_CALL)

        # create an ASN.1 structure of MPContent and DER-encode it
        mp_content_pt = asn1_dec.MPContent()
        mp_content_pt['timestamp'] = datetime.utcnow(). \
            strftime(const.TIMESTAMP_FORMAT)
        mp_content_pt['content'] = content
        mp_content_pt_der = asn1_encode(mp_content_pt)

        # encrypt MPContent DER
        mp_content_ct = self.__encrypt_with_aes(mp_content_pt_der, key, iv)

        # wrap MPContent into MPContentContainer
        mp_content_container = asn1_dec.MPContentContainer()
        mp_content_container['initializationVector'] = iv
        mp_content_container['encryptionAlgorithm'] = \
            self.__get_asn1_algorithm_identifier(const.AES_128_CBC_OID)
        mp_content_container['encryptedContent'] = mp_content_ct

        # encode MPContentContainer and return it
        return asn1_encode(mp_content_container)

    def __disassemble_content_block(self, content, key):
        """ Decrypt and decode content from a content block

        @developer: ddnomad

        :param content: DER-encoded ASN.1 structure that encapsulates
                        encrypted content
        :param key:     string AES key to be used for decryption

        :return: list of the following values:
                    [0] datetime.datetime timestamp object
                    [1] string decrypted message

        """

        # log entry
        self.logger.debug(logstr.DISASSEMBLE_CONTENT_BLOCK_CALL)

        # decode MPContentContainer from DER
        # TODO: try-except in a case when decoding failed
        mp_content_container_asn1 = asn1_decode(content)

        # recover values that are necessary for decryption
        # TODO: verify encryptionAlgorithm OID
        iv = bytes(mp_content_container_asn1[0][0])
        enc_content = bytes(mp_content_container_asn1[0][2])

        # decrypt DER-encoded MPContent
        mp_content_pt_der = self.__decrypt_with_aes(enc_content, key, iv)

        # recover timestamp and message from DER-encoded MPContent
        mp_content_pt_asn1 = asn1_decode(mp_content_pt_der)
        timestamp = datetime.strptime(str(mp_content_pt_asn1[0][0]),
                                      const.TIMESTAMP_FORMAT)
        message = str(mp_content_pt_asn1[0][1])

        # return the resulting data
        return timestamp, message

    def __assemble_hmac_block(self, content, key):
        """ Produce HMAC block ASN.1 structure (MPHMACContainer)

        @developer: vsmysle

        :param content: string DER-encoded content generate HMAC of and
                        encapsulate into HMAC FLOD block
        :param key:     string key to use for HMAC generation

        :return: DER-encoded ASN.1 structure that encapsulates HMAC
                 block

        """
        # TODO: add exceptions

        self.logger.debug("producing HMAC block with ASN.1 structure")
        # calculating hmac digest of content
        digest = self.__generate_hmac(content, key)

        # oid for SHA1 hash function
        oid = const.SHA1_OID

        # creating instance of AlgorithmIdentifier class
        ai = asn1_dec.AlgorithmIdentifier()

        # setting corresponding parameters
        ai['algorithm'] = oid
        ai['parameters'] = univ.Null()

        # creating instance of AlgorithmIdentifier class
        hmac_block = asn1_dec.MPHMACContainer()

        # setting corresponding parameters
        hmac_block['digestAlgorithm'] = ai
        hmac_block['digest'] = digest

        return asn1_encode(hmac_block)

    def __verify_hmac(self, hmac_blk, key, content_blk):
        """ Verify content HMAC

        @developer: vsmysle

        :param hmac_blk:        string DER-encoded ASN.1 structure of HMAC
                                block (MPHMACContainer)
        :param key:             string HMAC secret key
        :param content_blk:     string DER-encoded ASN.1 structure of content
                                block

        :return: bool verification result

        """
        # TODO: add exceptions

        self.logger.debug("verifying  HMAC")
        2
        # calculation of the HMAC digest for received content block
        hmac_of_content_blk = self.__generate_hmac(content_blk, key)

        # get digest from the HMAC block
        decoded_hmac_block = asn1_decode(hmac_blk)[0][1]

        if decoded_hmac_block == hmac_of_content_blk:
            self.logger.info("successful HMAC verification")
            return True
        self.logger.warning("HMAC verification failed!")
        return False

    def __generate_hmac(self, content, key):
        """ Generate HMAC for in input content and key

        @developer: vsmysle

        :param content: string DER-encoded content to produce digest of
        :param key:     string key to use for HMAC

        :return: string HMAC of the input content

        """
        # TODO: add exceptions

        self.logger.debug("generation HMAC for input content")

        # generating instance of HMAC with sha1 hash function
        hmac_digest = hmac.new(key, None, hashlib.sha1)

        # feed the content to generated HMAC instance
        hmac_digest.update(content)
        return hmac_digest.digest()

    def __encrypt_with_aes(self, content, key, iv):
        """ Encrypt content with AES-128-CBC (with PCKS#7 padding)

        @developer: ddnomad

        :param content: bytes DER-encoded MPContent ASN.1 structure to encrypt
        :param key:     string key to use for encryption
        :param iv:      string CBC mode initialization vector

        :return: string encryption of an input content

        """

        # log entry
        self.logger.debug(logstr.AES_ENC_CALL)

        # pad MPContent with PKCS#7
        padder = padding.PKCS7(const.AES_BLOCK_SIZE).padder()
        padded_content = padder.update(content) + padder.finalize()

        # initialize AES cipher instance
        backend = default_backend()
        aes = Cipher(algorithms.AES(key), modes.CBC(iv),
                     backend=backend).encryptor()

        # encrypt padded content
        content_ct = aes.update(padded_content) + aes.finalize()

        # return the resulting ciphertext
        return content_ct

    def __decrypt_with_aes(self, content, key, iv):
        """ Decrypt AES-128-CBC encrypted content (PCKS#7 padded)

        @developer: ddnomad

        :param content: bytes ciphertext of MPContent ASN.1 structure
        :param key:     string AES secret key
        :param iv:      string CBC mode initialization vector

        :return: string decrypted DER-encoded MPContent ASN.1 structure

        """

        # log entry
        self.logger.debug(logstr.AES_DEC_CALL)

        # initialize AES cipher instance
        backend = default_backend()
        aes = Cipher(algorithms.AES(key), modes.CBC(iv),
                     backend=backend).decryptor()

        # decrypt content
        dec_content = aes.update(content) + aes.finalize()

        # unpad content
        unpadder = padding.PKCS7(const.AES_BLOCK_SIZE).unpadder()
        dec_content_unpadded = unpadder.update(dec_content) + \
            unpadder.finalize()

        # return the resulting plaintext content
        return dec_content_unpadded

    def __encrypt_with_rsa(self, content, recipient_pk):
        """ Encrypt content with RSAES-OAEP scheme

        @developer: vsmysle

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
        # TODO: add exceptions
        self.logger.debug("RSA encryption ...")

        ciphertext = recipient_pk.encrypt(
            content, asym_padding.OAEP(
                mgf=asym_padding.MGF1(algorithm=SHA1()),
                algorithm=SHA1(),
                label=None
            )
        )
        self.logger.info("Encrypted!")
        return ciphertext

    def __decrypt_with_rsa(self, content, user_sk):
        """ Decrypt RSAES-OAEP encrypted content (single block)

        @developer: ???

        This method decrypts a single RSA ciphertext block only

        :param content: string content to decrypt
        :param user_sk: instance of cryptography.hazmat.primitives.rsa
                        .RSAPrivateKey to use for a decryption

        :return: string decryption of an input content

        """
        # TODO: add exceptions

        self.logger.debug("RSA decryption ...")
        try:
            plaintext = user_sk.decrypt(
                content, asym_padding.OAEP(
                    mgf=asym_padding.MGF1(algorithm=SHA1()),
                    algorithm=SHA1(),
                    label=None
                )
            )
        except InvalidKey:
            self.logger.warning("Invalid key!")
            return
        return plaintext

    def __sign_content(self, content, user_sk):
        """ Produce a signature of an input content using RSASSA-PSS scheme

        @developer: vsmysle

        :param content: string content to sign
        :param user_sk: instance of cryptography.hazmat.primitives.rsa.
                        RSAPrivateKey

        :return: string signature of the input content

        """

        # TODO: add exceptions

        self.logger.debug("generating a signature of an input content")
        # creating signer that will sign our content
        try:
            signer = user_sk.signer(
                # we use RSASSA-PSS padding for the signature scheme
                asym_padding.PSS(
                    mgf=asym_padding.MGF1(SHA1()),
                    salt_length=asym_padding.PSS.MAX_LENGTH
                ),
                SHA1()
            )
        except InvalidKey:
            self.logger.warning("Invalid key!")
            return
        signer.update(content)
        signature = signer.finalize()
        self.logger.info("signature generation finished")
        return signature

    def __verify_signature(self, signature, signer_pk, content):
        """ Verify RSASSA-PSS signature

        @developer: vsmysle

        :param signature: string signature to verify
        :param signer_pk: instance of cryptography.hazmat.primitives.
                          rsa.RSAPublicKey that is a public key of a signer
        :param content:   content to verify a signature of

        :return: bool verification result

        """
        self.logger.debug("starting signature verification routine")
        try:
            signer_pk.verify(
                signature,
                content,
                asym_padding.PSS(
                    mgf=asym_padding.MGF1(SHA1()),
                    salt_length=asym_padding.PSS.MAX_LENGTH
                ),
                SHA1()
            )
        except InvalidSignature:
            self.logger.warn("signature verification failed")
            return False
        self.logger.info("signature OK")
        return True

    def __get_asn1_algorithm_identifier(self, oid_str):
        """ Generate ASN.1 structure for algorithm identifier

        @developer: vsmysle

        :param oid_str: string OID to encapsulate

        :return: pyasn1.type.univ.Sequence object

        """

        # TODO: add exceptions

        # log entry
        self.logger.debug("creating AlgorithmIdentifier ASN.1 "
                          "structure with OID=%s" % oid_str)

        # create the instance of AlgorithmIdentifier
        ai = asn1_dec.AlgorithmIdentifier()

        # set corresponding parameters
        ai['algorithm'] = oid_str
        ai['parameters'] = univ.Null()

        # return the result
        return ai

    def __get_random_bytes(self, spec_lst):
        """ Generate random bytes

        @developer: vsmysle

        :param spec_lst: list of integers that is lengths of bytestings to
                         return

        :return: list of random bytestrings with lengths corresponding to the
                 ones from a spec list

        """

        # TODO: add exception for negative integers

        self.logger.debug("generating random bytes")
        return [urandom(i) for i in spec_lst]

    def __get_rsa_max_bytestring_size(self, key_size):
        """ Helper function that says how many bytes you can encrypt
            with RSA

        @developer: vsmysle

        :param key_size: size of the RSA key

        :return: int specifying how many bytes you can encrypt using
                 RSA key with specified key size

        """
        return (key_size/8) - 42 - int(key_size >> 8).bit_length() - 1
