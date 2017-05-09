from pyasn1.type import univ, namedtype, useful


class AlgorithmIdentifier(univ.Sequence):
    """ AlgorithmIdentifier class inherits pyasn1.type.univ.Sequence class
    and encapsulated AlgorithmIdentifier structure in it
    You can take a look for the information about the structure in our docs:
    https://github.com/arachnid42/mflod/blob/master/mflod/crypto/README.md

    @developer: vsmysle

    You need to set these parameters:
        algorithm:              string representing OID of
                                the Object Identifier
        parameters:             pyasn1.type.univ.Null()

    Example:
        ai = AlgorithmIdentifier()
        ai['algorithm'] = oid
        ai['parameters'] = pyasn1.type.univ.Null()

    """

    componentType = namedtype.NamedTypes(
        namedtype.NamedType('algorithm', univ.ObjectIdentifier()),
        namedtype.NamedType('parameters', univ.Null())
    )


class MPContentContainer(univ.Sequence):
    """ MPContentContainer class inherits pyasn1.type.univ.Sequence class
    and encapsulates MPContentContainer structure in it
    You can take a look for the information about the structure in our docs:
    https://github.com/arachnid42/mflod/blob/master/mflod/crypto/README.md
    #0-content-block-asn1-structure

    @developer: vsmysle

    You need to set these parameters:
        initializationVector:   string representing initializationVector
        encryptionAlgorithm:    instance of AlgorithmIdentifier class
        encryptedContent:       string representing encrypted data

    Example:
        ai = AlgorithmIdentifier()
        ai['algorithm'] = oid
        ai['parameters'] = pyasn1.type.univ.Null()

        mp_content_container = MPContentContainer()
        mp_content_container['initializationVector'] = 'FLOD'
        mp_content_container['encryptionAlgorithm'] = ai
        mp_content_container['encryptedContent'] = encrypted_data

    """

    componentType = namedtype.NamedTypes(
        namedtype.NamedType('initializationVector', univ.OctetString()),
        namedtype.NamedType('encryptionAlgorithm', AlgorithmIdentifier()),
        namedtype.NamedType('encryptedContent', univ.OctetString())
    )


class MPContent(univ.Sequence):
    """ MPContent class inherits pyasn1.type.univ.Sequence class
    and encapsulates MPContent structure in it
    You can take a look for the information about the structure in our docs:
    https://github.com/arachnid42/mflod/blob/master/mflod/crypto/README.md
    #0-content-block-asn1-structure

    @developer: vsmysle

    You need to set these parameters:
        timestamp:              string representing current time
                                in YYMMDDhhmmssZ format
        content:                string representing message of the user

    Example:
        mp_content = MPContent()
        mp_content['timestamp'] =
                        datetime.datetime.utcnow().strftime("%Y%m%d%H%M%SZ")
        mp_content['content'] = 'Hello, world!'

    """

    componentType = namedtype.NamedTypes(
        namedtype.NamedType('timestamp', useful.UTCTime()),
        namedtype.NamedType('content', univ.OctetString())
    )


class MPHMACContainer(univ.Sequence):
    """ MPHMACContainer class inherits pyasn1.type.univ.Sequence class
    and encapsulates MPHMACContainer structure in it
    You can take a look for the information about the structure in our docs:
    https://github.com/arachnid42/mflod/blob/master/mflod/crypto/README.md
    #1-hmac-block-asn1-structure

    You need to set these parameters:
        digestAlgorithm:        instance of AlgorithmIdentifier class
        digest:                 string representing HMAC digest

    """
    componentType = namedtype.NamedTypes(
        namedtype.NamedType('digestAlgorithm', AlgorithmIdentifier()),
        namedtype.NamedType('digest', univ.OctetString())
    )


class MPHeaderContainer(univ.Sequence):
    """ MPHeaderContainer class inherits pyasn1.type.univ.Sequence class
    and encapsulates MPHeaderContainer structure in it
    You can take a look for the information about the structure in our docs:
    https://github.com/arachnid42/mflod/blob/master/mflod/crypto/README.md
    #2-header-block-asn1-structure

    @developer: vsmysle

    You need to set these parameters:
        encryptionAlgorithm:    instance of AlgorithmIdentifier class
        encryptedHeader:        ASN.1 DER-encoded MPHeader data encapsulated
                                into OCTET STRING
    """
    componentType = namedtype.NamedTypes(
        namedtype.NamedType('encryptionAlgorithm', AlgorithmIdentifier()),
        namedtype.NamedType('encryptedHeader', univ.OctetString())
    )


class MPHeader(univ.Sequence):
    """ MPHeader class ihnerits pyasn1.type.univ.Sequence class
    and encapsulates MPHeader structure in it
    You can take a look for the information about the structure in our docs:
    https://github.com/arachnid42/mflod/blob/master/mflod/crypto/README.md
    #2-header-block-asn1-structure

    @developer: vsmysle

    You need to set these parameters:

        identificationString:   identification string for verifying
                                result of decryption
        signatureAlgorithm:     instance of AlgorithmIdentifier class
        PGPKeyID:               string that specify PGPKey ID
                                (must be 8 bytes long!)
        signature:              signature bytes
        HMACKey:                20 bytes of HMAC key

    """
    componentType = namedtype.NamedTypes(
        namedtype.NamedType('identificationString', univ.OctetString()),
        namedtype.NamedType('signatureAlgorithm', AlgorithmIdentifier()),
        namedtype.NamedType('PGPKeyID', univ.OctetString()),
        namedtype.NamedType('signature', univ.OctetString()),
        namedtype.NamedType('HMACKey', univ.OctetString()),
        namedtype.NamedType('AESKey', univ.OctetString())

    )


class MessagePacket(univ.Sequence):
    """ MessagePacket class ihnerits pyasn1.type.univ.Sequence class
    and encapsulates MessagePacket structure in it
    You can take a look for the information about the structure in our docs:
    https://github.com/arachnid42/mflod/blob/master/mflod/crypto/README.md

    @developer: vsmysle

    You need to set these parameters:
        protocolVersion:        integer
        headerBlock:            instance of MPHeaderContainer class
        hmacBlock:              instance of MPHMACContainer class
        contentBlock:           instance of MPContentContainer

    """
    componentType = namedtype.NamedTypes(
        namedtype.NamedType('protocolVersion', univ.Integer()),
        namedtype.NamedType('headerBlock', MPHeaderContainer()),
        namedtype.NamedType('hmacBlock', MPHMACContainer()),
        namedtype.NamedType('contentBlock', MPContentContainer())
    )