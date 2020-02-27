from Crypto.Random.random import getrandbits
import time
import struct
from abc import ABC, abstractmethod
import enum
from Crypto.PublicKey import RSA
from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA256
import base64


class AttributeType(enum.Enum):
    NULL = 0
    INT = 1
    FLOAT = 2
    STRING = 3
    BOOL = 4
    SET = 5


class ACPart(ABC):
    @abstractmethod
    def encode(self):
        pass

    @staticmethod
    @abstractmethod
    def decode(byte_array):
        pass


class ACInformation(ACPart):
    SERIAL_SIZE = 160  # Has to be a multiple of 8 (160 is 20 bytes)

    def __init__(self, version=0, serial=None, issued=None):
        self.version = version

        if serial is None:
            self.serial = getrandbits(ACInformation.SERIAL_SIZE)
        else:
            self.serial = serial

        if issued is None:
            self.issued = int(time.time())
        else:
            self.issued = issued

    def __str__(self):
        output = '==== BEGIN INFORMATION ====\nVERSION: %d\n' % self.version
        if self.serial is not None:
            output += 'SERIAL: %d\n' % self.serial
        if self.issued is not None:
            output += 'ISSUED: %d\n' % self.issued
        output += '==== END INFORMATION ====\n'
        return output

    def encode(self):
        # TODO: Exception if serial is wrong size
        header_bytes = struct.pack('<BB', self.version, int(ACInformation.SERIAL_SIZE / 8))
        serial_bytes = self.serial.to_bytes(int(ACInformation.SERIAL_SIZE / 8), 'little')
        time_bytes = struct.pack('<I', self.issued)
        return b''.join((header_bytes, serial_bytes, time_bytes))

    @staticmethod
    def decode(byte_array):
        # TODO: Exceptions, version check, length check
        info = ACInformation.__new__(ACInformation)
        info.version, serial_size = struct.unpack('<BB', byte_array[0:2])
        info.serial = int.from_bytes(byte_array[2:2 + serial_size], 'little')
        info.issued = struct.unpack('<I', byte_array[2 + serial_size:6 + serial_size])[0]

        byte_array[:] = byte_array[6 + serial_size:]

        return info

    def __eq__(self, other):
        return isinstance(other, ACPart) and self.version == other.version and self.serial == other.serial and \
               self.issued == other.issued


class ACIssuer(ACPart):
    def __init__(self, pub_key, key_algo, uid, name=None, url=None):
        self.pub_key = pub_key  # as a DER encoded byte string (not base64 string)
        self.key_algo = key_algo
        self.uid = uid
        self.name = name
        self.url = url

    def __str__(self):
        output = '==== BEGIN ISSUER ====\nPUBLIC KEY: %s\nKEY ALGORITHM: %s\nUID: %s\n' % (
            base64.b64encode(self.pub_key).decode('utf-8'), self.key_algo, self.uid)
        if self.name is not None:
            output += 'NAME: %s\n' % self.name

        if self.url is not None:
            output += 'URL: %s\n' % self.url

        output += '==== END ISSUER ====\n'
        return output

    def encode(self):
        pub_key_size = len(self.pub_key)
        key_algo_size = len(self.key_algo)
        uid_size = len(self.uid)

        if self.name is not None:
            name_size = len(self.name)
        else:
            name_size = 0

        if self.url is not None:
            url_size = len(self.url)
        else:
            url_size = 0

        header = struct.pack('<HHHHH', pub_key_size, key_algo_size, uid_size, name_size, url_size)

        key_algo = self.key_algo.encode('utf-8')
        uid = self.uid.encode('utf-8')
        name = b'' if self.name is None else self.name.encode('utf-8')
        url = b'' if self.url is None else self.url.encode('utf-8')

        strings = struct.pack('<' + str(key_algo_size) + 's' + str(uid_size) + 's' + str(name_size) + 's' +
                              str(url_size) + 's', key_algo, uid, name, url)

        encoded = b''.join((header, self.pub_key, strings))
        return encoded

    @staticmethod
    def decode(byte_array):
        issuer = ACIssuer.__new__(ACIssuer)
        pub_key_size, key_algo_size, uid_size, name_size, url_size = struct.unpack('<HHHHH', byte_array[:10])
        issuer.pub_key = bytes(byte_array[10:10 + pub_key_size])
        string_size = 10 + pub_key_size + key_algo_size + uid_size + name_size + url_size
        key_algo, uid, name, url = struct.unpack('<' + str(key_algo_size) + 's' + str(uid_size) + 's' + str(name_size)
                                                 + 's' + str(url_size) + 's', byte_array[10 + pub_key_size:string_size])

        issuer.key_algo = key_algo.decode('utf-8')
        issuer.uid = uid.decode('utf-8')
        issuer.url = url.decode('utf-8') if url != b'' else None
        issuer.name = name.decode('utf-8') if name != b'' else None

        byte_array[:] = byte_array[string_size:]
        return issuer

    def __eq__(self, other):
        return isinstance(other, ACPart) and self.pub_key == other.pub_key and self.key_algo == other.key_algo and \
               self.uid == other.uid and self.url == other.url


class ACHolder(ACPart):
    def __init__(self, pub_key, key_algo, uid, name=None):
        self.pub_key = pub_key
        self.key_algo = key_algo
        self.uid = uid
        self.name = name

    def __str__(self):
        output = '==== BEGIN HOLDER ====\nPUBLIC KEY: %s\nKEY ALGORITHM: %s\nUID: %s\n' % (
            base64.b64encode(self.pub_key).decode('utf-8'), self.key_algo, self.uid)
        if self.name is not None:
            output += 'NAME: %s\n' % self.name

        output += '==== END HOLDER ====\n'
        return output

    def encode(self):
        pub_key_size = len(self.pub_key)
        key_algo_size = len(self.key_algo)
        uid_size = len(self.uid)

        if self.name is not None:
            name_size = len(self.name)
        else:
            name_size = 0

        header = struct.pack('<HHHH', pub_key_size, key_algo_size, uid_size, name_size)

        key_algo = self.key_algo.encode('utf-8')
        uid = self.uid.encode('utf-8')
        name = b'' if self.name is None else self.name.encode('utf-8')

        strings = struct.pack('<' + str(key_algo_size) + 's' + str(uid_size) + 's' + str(name_size) + 's', key_algo,
                              uid, name)

        encoded = b''.join((header, self.pub_key, strings))
        return encoded

    @staticmethod
    def decode(byte_array):
        holder = ACHolder.__new__(ACHolder)
        pub_key_size, key_algo_size, uid_size, name_size = struct.unpack('<HHHH', byte_array[:8])
        holder.pub_key = bytes(byte_array[8:8 + pub_key_size])
        string_size = 8 + pub_key_size + key_algo_size + uid_size + name_size
        key_algo, uid, name = struct.unpack('<' + str(key_algo_size) + 's' + str(uid_size) + 's' + str(name_size)
                                            + 's', byte_array[8 + pub_key_size:string_size])

        holder.key_algo = key_algo.decode('utf-8')
        holder.uid = uid.decode('utf-8')
        holder.name = name.decode('utf-8') if name != b'' else None

        byte_array[:] = byte_array[string_size:]
        return holder

    def __eq__(self, other):
        return isinstance(other, ACPart) and self.pub_key == other.pub_key and self.key_algo == other.key_algo and \
               self.uid == other.uid


class ACAttribute(ACPart):
    def __init__(self, att_id, att_type, att_value, att_name=None, extra_bytes=None):
        self.att_id = att_id
        self.att_type = att_type  # TODO: Check that this is a enum
        self.att_value = att_value if att_value != '' else None # String encoded
        self.att_name = att_name if att_name != '' else None
        self.extra_bytes = extra_bytes  # byte string

    def __str__(self):
        output = '#### BEGIN ATTRIBUTE: %s ####\nATTRIBUTE ID: %s\nATTRIBUTE TYPE: %s\n' % \
                 (self.att_id, self.att_id, self.att_type)

        if self.att_value is not None:
            output += 'ATTRIBUTE VALUE: %s\n' % self.att_value

        if self.att_name is not None:
            output += 'ATTRIBUTE NAME: %s\n' % self.att_name

        if self.extra_bytes is not None:
            output += 'EXTENSION BYTES: %s\n' % base64.b64encode(self.extra_bytes).decode('utf-8')

        output += '#### END ATTRIBUTE: %s ####\n' % self.att_id
        return output

    def encode(self):
        att_id_size = len(self.att_id)
        att_value_size = len(self.att_value) if self.att_value is not None else 0
        att_name_size = len(self.att_name) if self.att_name is not None else 0
        extra_byte_size = len(self.extra_bytes) if self.extra_bytes is not None else 0
        att_id = self.att_id.encode('utf-8')
        att_value = self.att_value.encode('utf-8') if self.att_value is not None else b''
        att_name = self.att_name.encode('utf-8') if self.att_name is not None else b''
        headandbody = struct.pack('<HHHHB%ss%ss%ss' % (att_id_size, att_value_size, att_name_size), att_id_size,
                                  att_value_size, att_name_size, extra_byte_size, self.att_type.value, att_id,
                                  att_value, att_name)

        if self.extra_bytes is not None:
            encoded = b''.join((headandbody, self.extra_bytes))
        else:
            encoded = headandbody
        return encoded

    @staticmethod
    def decode(byte_array):
        attribute = ACAttribute.__new__(ACAttribute)
        att_id_size, att_value_size, att_name_size, extra_byte_size, att_type_val = struct.unpack('<HHHHB',
                                                                                                  byte_array[:9])
        attribute.att_type = AttributeType(att_type_val)
        size = 9 + att_id_size + att_value_size + att_name_size
        att_id, att_value, att_name = struct.unpack('%ss%ss%ss' % (att_id_size, att_value_size, att_name_size),
                                                    byte_array[9:size])
        attribute.att_id = att_id.decode('utf-8')
        attribute.att_value = att_value.decode('utf-8') if att_value != b'' else None
        attribute.att_name = att_name.decode('utf-8') if att_name != b'' else None

        if extra_byte_size == 0:
            attribute.extra_bytes = None
        else:
            attribute.extra_bytes = bytes(byte_array[size:size + extra_byte_size])

        byte_array[:] = byte_array[size + extra_byte_size:]

        return attribute

    def __eq__(self, other):
        return isinstance(other, ACPart) and self.att_id == other.att_id and self.att_name == other.att_name and \
               self.att_type == other.att_type and self.att_value == other.att_value and \
               self.extra_bytes == other.extra_bytes


class ACRevocationRules(ACPart):
    DEFAULT_LENGTH = 86400  # 1 Day

    def __init__(self, valid_after=None, valid_before=None, url=None, extra_bytes=None):
        self.url = url
        self.extra_bytes = extra_bytes

        if valid_after is None:
            self.valid_after = int(time.time())
        else:
            self.valid_after = valid_after

        if valid_before is None:
            self.valid_before = int(time.time()) + ACRevocationRules.DEFAULT_LENGTH
        else:
            self.valid_before = valid_before

    def __str__(self):
        output = '==== BEGIN REVOCATION RULES ====\nVALID AFTER: %d\nVALID BEFORE: %d\n' % (self.valid_after,
                                                                                            self.valid_before)
        if self.url is not None:
            output += 'URL: %s\n' % self.url

        if self.extra_bytes is not None:
            output += 'EXTENSION BYTES: %s\n' % base64.b64encode(self.extra_bytes).decode('utf-8')

        output += '==== END REVOCATION RULES ====\n'
        return output

    def encode(self):
        url_size = len(self.url) if self.url is not None else 0
        extra_byte_size = len(self.extra_bytes) if self.extra_bytes is not None else 0
        url = self.url.encode('utf-8') if self.url is not None else b''

        headandbody = struct.pack('<HHII%ss' % url_size, url_size, extra_byte_size, self.valid_after,
                                  self.valid_before, url)

        if self.extra_bytes is not None:
            encoded = b''.join((headandbody, self.extra_bytes))
        else:
            encoded = headandbody
        return encoded

    @staticmethod
    def decode(byte_array):
        rev_rules = ACRevocationRules.__new__(ACRevocationRules)
        url_size, extra_byte_size, rev_rules.valid_after, rev_rules.valid_before = struct.unpack('<HHII',
                                                                                                 byte_array[:12])
        url = byte_array[12:12 + url_size]
        rev_rules.url = url.decode('utf-8') if url_size != 0 else None

        if extra_byte_size == 0:
            rev_rules.extra_bytes = None
        else:
            rev_rules.extra_bytes = bytes(byte_array[12 + url_size:12 + url_size + extra_byte_size])

        byte_array[:] = byte_array[12 + url_size + extra_byte_size:]

        return rev_rules

    def __eq__(self, other):
        return isinstance(other, ACPart) and self.valid_before == other.valid_before and \
               self.valid_after == other.valid_after and self.url == other.url and self.extra_bytes == other.extra_bytes


class ACDelegationRules(ACPart):
    def __init__(self, extra_bytes=None):
        self.extra_bytes = extra_bytes

    def __str__(self):
        if self.extra_bytes is not None:
            output = '==== BEGIN DELEGATION RULES ====\n'
            output += 'EXTENSION BYTES: %s\n' % base64.b64encode(self.extra_bytes).decode('utf-8')
            output += '==== END DELEGATION RULES ====\n'
        else:
            output = ''
        return output

    def encode(self):
        size = len(self.extra_bytes) if self.extra_bytes is not None else 0
        header = struct.pack('<H', size)
        return b''.join((header, self.extra_bytes)) if self.extra_bytes is not None else header

    @staticmethod
    def decode(byte_array):
        del_rules = ACDelegationRules.__new__(ACDelegationRules)
        size = struct.unpack('<H', byte_array[:2])[0]
        del_rules.extra_bytes = byte_array[2:size + 2] if size != 0 else None

        byte_array[:] = byte_array[size + 2:]
        return del_rules

    def __eq__(self, other):
        return isinstance(other, ACPart) and self.extra_bytes == other.extra_bytes


class ACExtensions(ACPart):
    def __init__(self, eid, extra_bytes=None):
        self.eid = eid
        self.extra_bytes = extra_bytes

    def __str__(self):
        output = '#### BEGIN EXTENSION: %s ####\nEXTENSION ID: %s\n' % (self.eid, self.eid)
        if self.extra_bytes is not None:
            output += 'EXTENSION BYTES: %s\n' % base64.b64encode(self.extra_bytes).decode('utf-8')
        output += '#### END EXTENSION: %s ####\n' % self.eid
        return output

    def encode(self):
        eid_size = len(self.eid)
        extra_byte_size = len(self.extra_bytes) if self.extra_bytes is not None else 0
        eid = self.eid.encode('utf-8')

        headerandbody = struct.pack('<HH%ss' % eid_size, eid_size, extra_byte_size, eid)

        if extra_byte_size != 0:
            encoded = b''.join((headerandbody, self.extra_bytes))
        else:
            encoded = headerandbody

        return encoded

    @staticmethod
    def decode(byte_array):
        ext = ACExtensions.__new__(ACExtensions)
        eid_size, extra_byte_size = struct.unpack('<HH', byte_array[:4])

        ext.eid = bytearray(byte_array[4:4 + eid_size]).decode('utf-8')

        if extra_byte_size != 0:
            ext.extra_bytes = byte_array[4 + eid_size:4 + eid_size + extra_byte_size]
        else:
            ext.extra_bytes = None

        byte_array[:] = byte_array[4 + eid_size + extra_byte_size:]
        return ext

    def __eq__(self, other):
        return isinstance(other, ACPart) and self.extra_bytes == other.extra_bytes and self.eid == other.eid


class ACSignature(ACPart):
    def __init__(self, sig_algo, sig_value):
        self.sig_algo = sig_algo  # as String
        self.sig_value = sig_value  # as byte string

    def __str__(self):
        output = '==== BEGIN SIGNATURE ====\nSIGNATURE ALGORITHM: %s\n' % self.sig_algo
        output += 'SIGNATURE VALUE: %s\n' % base64.b64encode(self.sig_value).decode('utf-8')
        output += '==== END SIGNATURE ====\n'
        return output

    def encode(self):
        algo_size = len(self.sig_algo)
        value_size = len(self.sig_value)
        algo = self.sig_algo.encode('utf-8')

        headandalgo = struct.pack('<HH%ss' % algo_size, algo_size, value_size, algo)
        encoded = b''.join((headandalgo, self.sig_value))
        return encoded

    @staticmethod
    def decode(byte_array):
        sig = ACSignature.__new__(ACSignature)
        algo_size, value_size = struct.unpack('<HH', byte_array[:4])
        sig.sig_algo = byte_array[4:4 + algo_size].decode('utf-8') if algo_size > 0 else None
        sig.sig_value = byte_array[4 + algo_size:4 + algo_size + value_size] if value_size > 0 else None

        byte_array[:] = byte_array[4 + algo_size + value_size:]
        return sig

    def __eq__(self, other):
        return isinstance(other, ACPart) and self.sig_value == other.sig_value and self.sig_algo == other.sig_algo


class ExportFormat(enum.Enum):
    BYTES = 0
    TEXT = 1
    XML = 2
    BASE64 = 3
    BASE64FULL = 4


class AttributeCertificate(object):
    def __init__(self, issuer, holder, info, att_set, rev_rules, del_rules=None,
                 extensions=None, signature=None):
        self.issuer = issuer
        self.holder = holder
        self.info = info
        self.att_set = att_set  # List/Set
        self.rev_rules = rev_rules
        self.del_rules = del_rules
        self.extensions = extensions  # List/Set
        self.signature = signature

    def __str__(self):
        output = '---- BEGIN ATTRIBUTE CERTIFICATE ----\nFORMAT: TEXT\nVERSION: ' + str(self.info.version) + '\n'
        output += self.info.__str__()
        output += self.issuer.__str__()
        output += self.holder.__str__()

        if self.att_set is not None and len(self.att_set) > 0:
            output += '==== BEGIN ATTRIBUTE SET ====\n'
            for att in self.att_set:
                output += att.__str__()
            output += '==== END ATTRIBUTE SET ====\n'

        output += self.rev_rules.__str__()

        if self.del_rules is not None:
            output += self.del_rules.__str__()

        if self.extensions is not None and len(self.extensions) > 0:
            output += '==== BEGIN EXTENSIONS ====\n'
            for ext in self.extensions:
                output += ext.__str__()
            output += '==== END EXTENSIONS ====\n'

        if self.signature is not None:
            output += self.signature.__str__()

        output += '---- END ATTRIBUTE CERTIFICATE ----'
        return output

    def export_ac(self, format=ExportFormat.BYTES, sign=False, prvi_key=None, sig_algo='RSASSA-PKCS1-v1_5:SHA256'):
        if format == ExportFormat.BYTES:
            return self.encode(sign, prvi_key, sig_algo)
        elif format == ExportFormat.BASE64:
            encoded = self.encode(sign, prvi_key, sig_algo)
            return base64.b64encode(encoded)
        elif format == ExportFormat.XML:
            # TODO: Support XML format.
            raise Exception('XML format not yet supported.')
        elif format == ExportFormat.TEXT:
            if sign:
                if prvi_key is None:
                    # TODO: Custom exception
                    raise Exception("Need prvi_key to sign.")
                self.sign(prvi_key, sig_algo)
            return self.__str__()
        elif format == ExportFormat.BASE64FULL:
            body = self.export_ac(ExportFormat.BASE64, sign, prvi_key, sig_algo)
            return ''.join(('---- BEGIN ATTRIBUTE CERTIFICATE ----\nFORMAT: BASE64\nVERSION: ' + str(self.info.version)
                            + '\n', body.decode('utf-8'), '\n---- END ATTRIBUTE CERTIFICATE ----'))
        else:
            # TODO: Custom exception
            raise Exception('Unsupported format.')

    @staticmethod
    def import_ac(input, format=ExportFormat.BYTES, verify=False):
        if format == ExportFormat.BYTES:
            return AttributeCertificate.decode(input, verify)
        elif format == ExportFormat.BASE64:
            decode = base64.b64decode(input)
            return AttributeCertificate.decode(bytearray(decode), verify)
        elif format == ExportFormat.XML:
            # TODO: Support XML format.
            raise Exception('XML format not yet supported.')
        elif format == ExportFormat.TEXT:
            # TODO: Support TEXT format import.
            raise Exception('TEXT import not yet supported.')
        elif format == ExportFormat.BASE64FULL:
            parts = input.split('\n')
            # TODO: Check that all parts are valid/right version.
            return AttributeCertificate.import_ac(parts[3], ExportFormat.BASE64, verify)
        else:
            # TODO: Custom exception
            raise Exception('Unsupported format.')

    def encode(self, sign=False, prvi_key=None, sig_algo='RSASSA-PKCS1-v1_5:SHA256'):
        body = self._encode_body()
        if sign:
            if prvi_key is None:
                # TODO: Custom exception
                raise Exception("Need prvi_key to sign.")
            self.sign(prvi_key, sig_algo)

        if self.signature is not None:
            sig = self.signature.encode()
        else:
            sig = b'\x00\x00\x00\x00'

        return bytearray(b''.join((body, sig)))

    @staticmethod
    def decode(byte_array, verify=False):
        ac = AttributeCertificate._decode_body(byte_array)
        ac.signature = ACSignature.decode(byte_array)

        if ac.signature.sig_value is None and ac.signature.sig_algo is None:
            ac.signature = None

        if len(byte_array) > 0:
            # TODO: Custom exception.
            raise Exception('Extra bytes on end of certificate.')

        if verify and not ac.verify_signature():
            # TODO: Custom exception.
            raise Exception('Bad signature.')

        return ac

    def sign(self, prvi_key, sig_algo='RSASSA-PKCS1-v1_5:SHA256'):
        # TODO: Check algo/key, support more algos/key types
        encoded = self._encode_body()
        hash = SHA256.new(encoded)
        sig_hash = pkcs1_15.new(prvi_key).sign(hash)
        self.signature = ACSignature(sig_algo, sig_hash)

    def verify_time(self, now=None):
        if now is None:
            now = int(time.time())
        return self.rev_rules.valid_after < now < self.rev_rules.valid_before

    def verify_signature(self):
        # TODO: Check algo/key, support more algos/key types
        if self.signature is None or self.signature.sig_value is None or self.signature.sig_algo is None or \
           self.issuer is None or self.issuer.pub_key is None or self.issuer.key_algo is None:
            return False

        pub_key = RSA.import_key(self.issuer.pub_key)

        encoded = self._encode_body()
        sig_hash = SHA256.new(encoded)
        try:
            pkcs1_15.new(pub_key).verify(sig_hash, self.signature.sig_value)
            return True
        except ValueError:
            return False

    def _encode_body(self):
        issuer_bytes = self.issuer.encode()
        holder_bytes = self.holder.encode()
        info_bytes = self.info.encode()
        rev_rules_bytes = self.rev_rules.encode()
        del_rules_bytes = self.del_rules.encode() if self.del_rules is not None else b'\x00\x00'

        if self.att_set is not None and len(self.att_set) != 0:
            att_set_byte_set = [struct.pack('<H', len(self.att_set))]
            for att in self.att_set:
                att_set_byte_set.append(att.encode())
            att_set_bytes = b''.join(att_set_byte_set)
        else:
            att_set_bytes = b'\x00\x00'

        if self.extensions is not None and len(self.extensions) != 0:
            ext_byte_set = [struct.pack('<H', len(self.extensions))]
            for ext in self.extensions:
                ext_byte_set.append(ext.encode())
            ext_bytes = b''.join(ext_byte_set)
        else:
            ext_bytes = b'\x00\x00'

        encoded = b''.join((issuer_bytes, holder_bytes, info_bytes, att_set_bytes, rev_rules_bytes, del_rules_bytes,
                            ext_bytes))
        return encoded

    @staticmethod
    def _decode_body(byte_array):
        ac = AttributeCertificate.__new__(AttributeCertificate)
        ac.issuer = ACIssuer.decode(byte_array)
        ac.holder = ACHolder.decode(byte_array)
        ac.info = ACInformation.decode(byte_array)

        num_atts = struct.unpack('<H', byte_array[:2])[0]
        byte_array[:] = byte_array[2:]
        ac.att_set = []
        for i in range(num_atts):
            ac.att_set.append(ACAttribute.decode(byte_array))

        ac.rev_rules = ACRevocationRules.decode(byte_array)

        check_del_rules = struct.unpack('<H', byte_array[:2])[0]
        if check_del_rules != 0:
            ac.del_rules = ACDelegationRules.decode(byte_array)
        else:
            ac.del_rules = None
            byte_array[:] = byte_array[2:]

        num_ext = struct.unpack('<H', byte_array[:2])[0]
        byte_array[:] = byte_array[2:]
        ac.extensions = []
        for i in range(num_ext):
            ac.extensions.append(ACExtensions.decode(byte_array))

        if len(ac.extensions) == 0:
            ac.extensions = None

        ac.signature = None

        return ac

    def __eq__(self, other):
        # TODO: There is probably a much better way to code this function.
        if isinstance(other, AttributeCertificate) and self.issuer == other.issuer and self.holder == other.holder and \
           self.info == other.info and self.rev_rules == other.rev_rules:

            if self.del_rules != other.del_rules:
                if (self.del_rules is None and other.del_rules.extra_bytes is None) or \
                   (other.del_rules is None and self.del_rules.extra_bytes is None):
                    pass
                else:
                    return False

            if self.signature != other.signature:
                if (self.signature is None and other.signature.sig_value is None and other.signature.sig_algo is None) \
                   or (other.signature is None and self.signature.sig_value is None and self.signature.sig_algo
                       is None):
                    pass
                else:
                    return False

            # TODO: Refactor this (poorly coded)
            if self.att_set is None and other.att_set is None:
                pass
            elif len(self.att_set) == len(other.att_set):
                for self_att in self.att_set:
                    ok = False
                    for other_att in other.att_set:
                        if self_att.att_id == other_att.att_id:
                            if self_att == other_att:
                                ok = True
                                break
                            else:
                                return False
                    if not ok:
                        return False
            else:
                return False

            # TODO: Refactor this (poorly coded)
            if self.extensions is None and other.extensions is None:
                pass
            elif len(self.extensions) == len(other.extensions):
                for self_ext in self.extensions:
                    ok = False
                    for other_ext in other.extensions:
                        if self_ext.eid == other_ext.eid:
                            if self_ext == other_ext:
                                ok = True
                                break
                            else:
                                return False
                    if not ok:
                        return False
            else:
                return False

            return True
        else:
            return False
