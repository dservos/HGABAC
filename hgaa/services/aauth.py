from ladon.ladonizer import ladonize
from ladon.types.ladontype import LadonType
from ladon.compat import PORTABLE_STRING, PORTABLE_BYTES
from ladon.types.attachment import attachment
from ladon.exceptions.service import ClientFault, ServerFault
from enum import Enum
from Crypto.PublicKey import RSA
import bcrypt
import base64
from logging import DEBUG
import time
import os

from hgaa.log import SERVICE_LOG, make_logger
from hgaa.config import get_conf
from hgaa.database import get_session
from hgaa.schema.aauth import User, Attribute, AttributeAssignment
from hgaa.attcert import ExportFormat, ACIssuer, ACSignature, ACExtensions, ACDelegationRules, ACRevocationRules, \
    ACAttribute, ACInformation, ACHolder, AttributeCertificate, AttributeType


class CredentialType(Enum):
    USER_PASS = 0


class Credentials(LadonType):
    # TODO: Add doc and filters
    type = {'type': int, 'nullable': False}
    username = {'type': PORTABLE_STRING, 'nullable': True}
    password = {'type': PORTABLE_STRING, 'nullable': True}


class AttributeList(LadonType):
    # TODO: Add doc and filters
    attribute_names = [PORTABLE_STRING]
    attribute_ids = [PORTABLE_STRING]


class CredentialList(LadonType):
    name = {'type': PORTABLE_STRING, 'nullable': False}
    value = {'type': int, 'nullable': False}


class KeyAlgorithm(LadonType):
    cipher = {'type': PORTABLE_STRING, 'nullable': False}
    key_size = {'type': int, 'nullable': False}


class PublicKey(LadonType):
    public_key = {'type': PORTABLE_BYTES, 'nullable': False}
    key_algorithm = {'type': KeyAlgorithm, 'nullable': False}


class SignatureType(LadonType):
    hash_algorithm = {'type': PORTABLE_STRING, 'nullable': False}
    signature_algorithm = {'type': PORTABLE_STRING, 'nullable': False}


class AttributeAuthorityInfo(LadonType):
    # TODO: Add doc
    aauth_id = {'type': PORTABLE_STRING, 'nullable': False}
    attribute_authority_version = {'type': int, 'nullable': False}
    attribute_certificate_version = {'type': int, 'nullable': False}
    attribute_uri = {'type': PORTABLE_STRING, 'nullable': False}
    revocation_url = {'type': PORTABLE_STRING, 'nullable': False}
    public_key = {'type': PORTABLE_BYTES, 'nullable': False}
    credential_types = [CredentialList]
    key_algorithm = KeyAlgorithm
    signature_type = SignatureType


class AttributeCertificateType(LadonType):
    # TODO: Add doc
    data = attachment
    version = {'type': int, 'nullable': False}
    format = {'type': int, 'nullable': False}


class AttributeAuthority(object):
    # TODO: Rework what is public/private/class var.
    AA_VERSION = 1
    AC_VERSION = 1
    AC_FORMAT = ExportFormat.BYTES
    KEY_CIPHER = 'RSA'  # Only RSA supported right now.
    SIG_ALGO = 'RSASSA-PKCS1-v1_5'  # Only RSASSA-PKCS1-v1_5 supported right now.
    HASH_ALGO = 'SHA256'  # Only SHA256 supported right now.
    LOG = make_logger('AAUTH', True, SERVICE_LOG)
    AC_DIR = os.path.dirname(os.path.abspath(__file__)) + '/attribute_certificates/'

    def __init__(self):
        # TODO: aauth_id should be renamed to aauth_name
        self.aauth_id = get_conf('AAUTH_ID', True, 'AAUTH')
        # TODO: a_uri should be renamed to uid
        self.a_uri = get_conf('A_URI', True, 'AAUTH')
        self.rev_url = get_conf('REV_URI', True, 'AAUTH')

        # TODO: Make sure these URLs are being generated correctly in all environments
        host = get_conf('SERVICE_HOST', True, 'LADON')
        port = get_conf('SERVICE_PORT', True, 'LADON')
        if self.rev_url is None or self.rev_url.strip() == '':
            self.rev_url = 'http://'
            self.rev_url += 'localhost' if host.strip() == '' else host
            self.rev_url += ':' + port
            self.rev_url += '/AttributeAuthority/jsonwsp/revocation_list'
        self.aauth_url = 'http://'
        self.aauth_url += 'localhost' if host.strip() == '' else host
        self.aauth_url += ':' + port
        self.aauth_url += '/AttributeAuthority/jsonwsp/'

        self.pass_pepper = get_conf('PASS_PEPPER', True, 'AAUTH')

        self.ac_expire_length = int(get_conf('AC_EXPIRE_LENGTH', True, 'AAUTH'))

        self.key_file = get_conf('KEY_FILE', True, 'AAUTH')
        self.key_pass = get_conf('KEY_PASS', True, 'AAUTH')
        encoded_key = open(self.key_file, "rb").read()
        self.key = RSA.import_key(encoded_key, passphrase=self.key_pass)
        self.pub_key = self.key.publickey().exportKey()

        self.key_cipher = AttributeAuthority.KEY_CIPHER

        self.aa_ver = AttributeAuthority.AA_VERSION
        self.ac_ver = AttributeAuthority.AC_VERSION
        self.c_types = [ct.value for ct in CredentialType]

        self.sig_hash = AttributeAuthority.HASH_ALGO
        self.sig_algo = AttributeAuthority.SIG_ALGO

        AttributeAuthority.LOG.debug('Setup AttributeAuthority with following attributes: aauth_id: %(aauth_id)s, '
                                     'a_uri: %(a_uri)s, rev_uri: %(rev_uri)s, pub_key: %(pub_key)s, aa_ver: %(aa_ver)s,'
                                     ' ac_ver: %(ac_ver)s, c_types: %(c_types)s' % {'aauth_id': self.aauth_id,
                                                                                    'a_uri': self.a_uri,
                                                                                    'rev_uri': self.rev_url,
                                                                                    'pub_key': self.pub_key,
                                                                                    'aa_ver': self.aa_ver,
                                                                                    'ac_ver': self.ac_ver,
                                                                                    'c_types': self.c_types})

        AttributeAuthority.LOG.debug('Setting up issuer AC section.')
        self.ac_issuer = ACIssuer(key_algo='%s[%s]' % (self.key_cipher, self.key.size_in_bits()),
                                  pub_key=self.pub_key,
                                  url=self.aauth_url,
                                  name=self.aauth_id,
                                  uid=self.a_uri)

        AttributeAuthority.LOG.debug('Setting up database session for AttributeAuthority')
        self._db_session = get_session('AAUTH') # TODO: Need new session for each request?

    def _get_info_attr(self, attr):
        if hasattr(self, attr) and getattr(self, attr) is not None:
            return getattr(self, attr)
        else:
            raise ServerFault('Attribute authority does not have ' + attr + ' attribute set.')

    @ladonize(rtype=AttributeAuthorityInfo)
    def info(self, **exports):
        AttributeAuthority.LOG.info('Info request on AttributeAuthority from %s.' % exports['REMOTE_ADDR'])
        aa_info = AttributeAuthorityInfo()
        aa_info.aauth_id = self._get_info_attr('aauth_id')
        aa_info.attribute_authority_version = self._get_info_attr('aa_ver')
        aa_info.attribute_certificate_version = self._get_info_attr('ac_ver')
        aa_info.attribute_uri = self._get_info_attr('a_uri')
        aa_info.revocation_url = self._get_info_attr('rev_url')
        aa_info.public_key = self._get_info_attr('pub_key')

        aa_info.credential_types = []
        for ctval in self.c_types:
            ct = CredentialList()
            ct.value = ctval
            ct.name = CredentialType(ctval).name
            aa_info.credential_types += [ct]

        ka = KeyAlgorithm()
        ka.cipher = self.key_cipher
        ka.key_size = self.key.size_in_bits()
        aa_info.key_algorithm = ka

        st = SignatureType()
        st.hash_algorithm = self.sig_hash
        st.signature_algorithm = self.sig_algo
        aa_info.signature_type = st

        return aa_info

    def _make_con_att_set(self, credentials, user_public_key, exports, ac_serial, length):
        # TODO: Better and more automated way of collecting connection atts.
        export_vars = ['REMOTE_ADDR', 'REMOTE_HOST', 'REMOTE_IDENT', 'REMOTE_USER']

        con_att_set = {}

        for var in export_vars:
            if var in exports:
                con_att_set[var.lower()] = {'name': var.lower(),
                                            'id': '/attribute/connection/' + var.lower(),
                                            'type': AttributeType.STRING,
                                            'value': exports[var]}


        if 'REMOTE_ADDR' in exports:
            i = 0
            if '.' in exports['REMOTE_ADDR']:
                con_att_set['ip_v4'] = {'name': 'ip_v4',
                                        'id': '/attribute/connection/ip_v4',
                                        'type': AttributeType.BOOL,
                                        'value': True}
                con_att_set['ip_v6'] = {'name': 'ip_v6',
                                        'id': '/attribute/connection/ip_v6',
                                        'type': AttributeType.BOOL,
                                        'value': False}

                octets = exports['REMOTE_ADDR'].split('.')
                for oct in octets:
                    con_att_set['remote_addr_v4_oct%d' % i] = {'name': 'remote_addr_v4_oct%d' % i,
                                                          'id': '/attribute/connection/remote_addr_v4_oct%d' % i,
                                                          'type': AttributeType.INT,
                                                          'value': int(oct)}
                    i += 1
            elif ':' in exports['REMOTE_ADDR']:
                con_att_set['ip_v4'] = {'name': 'ip_v4',
                                        'id': '/attribute/connection/ip_v4',
                                        'type': AttributeType.BOOL,
                                        'value': False}
                con_att_set['ip_v6'] = {'name': 'ip_v6',
                                        'id': '/attribute/connection/ip_v6',
                                        'type': AttributeType.BOOL,
                                        'value': True}

                hextets = exports['REMOTE_ADDR'].split(':')
                for hex in hextets:
                    con_att_set['remote_addr_v6_hex%d' % i] = {'name': 'remote_addr_v6_hex%d' % i,
                                                          'id': '/attribute/connection/remote_addr_v6_hex%d' % i,
                                                          'type': AttributeType.INT,
                                                          'value': int(hex, 16)}
                    i += 1


        con_att_set['auth_method'] = {'name': 'auth_method',
                                      'id': '/attribute/connection/auth_method',
                                      'type': AttributeType.INT,
                                      'value': credentials.type}

        con_att_set['pub_key'] = {'name': 'pub_key',
                                  'id': '/attribute/connection/pub_key',
                                  'type': AttributeType.STRING,
                                  'value': base64.b64encode(user_public_key.public_key).decode('utf-8')}

        con_att_set['pub_key_size'] = {'name': 'pub_key_size',
                                       'id': '/attribute/connection/pub_key_size',
                                       'type': AttributeType.INT,
                                       'value': user_public_key.key_algorithm.key_size}

        con_att_set['pub_key_algo'] = {'name': 'pub_key_algo',
                                       'id': '/attribute/connection/pub_key_algo',
                                       'type': AttributeType.STRING,
                                       'value': user_public_key.key_algorithm.cipher}

        t = time.time()
        st = time.gmtime(t)
        con_att_set['con_time'] = {'name': 'con_time',
                                   'id': '/attribute/connection/con_time',
                                   'type': AttributeType.INT,
                                   'value': int(t)}
        con_att_set['con_time_weekdayname'] = {'name': 'con_time_weekday',
                                           'id': '/attribute/connection/con_time_weekday',
                                           'type': AttributeType.STRING,
                                           'value': time.strftime('%A')}
        con_att_set['con_time_monthname'] = {'name': 'con_time_monthname',
                                             'id': '/attribute/connection/con_time_monthname',
                                             'type': AttributeType.STRING,
                                             'value': time.strftime('%B')}
        con_att_set['con_time_month'] = {'name': 'con_time_month',
                                             'id': '/attribute/connection/con_time_month',
                                             'type': AttributeType.INT,
                                             'value': st.tm_mon}
        con_att_set['con_time_day'] = {'name': 'con_time_day',
                                             'id': '/attribute/connection/con_time_day',
                                             'type': AttributeType.INT,
                                             'value': st.tm_mday}
        con_att_set['con_time_weekday'] = {'name': 'con_time_weekday',
                                             'id': '/attribute/connection/con_time_weekday',
                                             'type': AttributeType.INT,
                                             'value': st.tm_wday}
        con_att_set['con_time_year'] = {'name': 'con_time_year',
                                           'id': '/attribute/connection/con_time_year',
                                           'type': AttributeType.INT,
                                           'value': st.tm_year}
        con_att_set['con_time_yearday'] = {'name': 'con_time_yearday',
                                        'id': '/attribute/connection/con_time_yearday',
                                        'type': AttributeType.INT,
                                        'value': st.tm_yday}
        con_att_set['con_time_hour'] = {'name': 'con_time_hour',
                                           'id': '/attribute/connection/con_time_hour',
                                           'type': AttributeType.INT,
                                           'value': st.tm_hour}
        con_att_set['con_time_min'] = {'name': 'con_time_min',
                                           'id': '/attribute/connection/con_time_min',
                                           'type': AttributeType.INT,
                                           'value': st.tm_min}
        con_att_set['con_time_sec'] = {'name': 'con_time_sec',
                                           'id': '/attribute/connection/con_time_sec',
                                           'type': AttributeType.INT,
                                           'value': st.tm_sec}
        con_att_set['con_time_zone'] = {'name': 'con_time_zone',
                                           'id': '/attribute/connection/con_time_zone',
                                           'type': AttributeType.STRING,
                                           'value': 'GMT'}
        if st.tm_isdst >= 0:
            con_att_set['con_time_dst'] = {'name': 'con_time_dst',
                                               'id': '/attribute/connection/con_time_dst',
                                               'type': AttributeType.BOOL,
                                               'value': st.tm_isdst == 1}

        con_att_set['aauth_uid'] = {'name': 'aauth_uid',
                                           'id': '/attribute/connection/aauth_uid',
                                           'type': AttributeType.STRING,
                                           'value': self.a_uri}
        con_att_set['aauth_name'] = {'name': 'aauth_name',
                                           'id': '/attribute/connection/aauth_name',
                                           'type': AttributeType.STRING,
                                           'value': self.aauth_id}
        con_att_set['aauth_url'] = {'name': 'aauth_url',
                                           'id': '/attribute/connection/aauth_url',
                                           'type': AttributeType.STRING,
                                           'value': self.aauth_url}
        con_att_set['aauth_pub_key'] = {'name': 'aauth_pub_key',
                                           'id': '/attribute/connection/aauth_pub_key',
                                           'type': AttributeType.STRING,
                                           'value': base64.b64encode(self.pub_key).decode('utf-8')}
        con_att_set['aauth_pub_key_size'] = {'name': 'aauth_pub_key_size',
                                       'id': '/attribute/connection/aauth_pub_key_size',
                                       'type': AttributeType.INT,
                                       'value': self.key.size_in_bits()}
        con_att_set['aauth_pub_key_algo'] = {'name': 'aauth_pub_key_algo',
                                       'id': '/attribute/connection/aauth_pub_key_algo',
                                       'type': AttributeType.STRING,
                                       'value': self.key_cipher}
        con_att_set['aauth_version'] = {'name': 'aauth_version',
                                       'id': '/attribute/connection/aauth_version',
                                       'type': AttributeType.INT,
                                       'value': AttributeAuthority.AA_VERSION}

        con_att_set['ac_version'] = {'name': 'ac_version',
                                       'id': '/attribute/connection/ac_version',
                                       'type': AttributeType.INT,
                                       'value': AttributeAuthority.AC_VERSION}

        con_att_set['session_id'] = {'name': 'session_id',
                                     'id': '/attribute/connection/session_id',
                                     'type': AttributeType.INT,
                                     'value': ac_serial}
        con_att_set['session_length'] = {'name': 'session_length',
                                     'id': '/attribute/connection/session_length',
                                     'type': AttributeType.INT,
                                     'value': length}

        return con_att_set

    def _make_ac(self, credentials, user_public_key, user_att_set, exports):
        t0 = time.time()

        # TODO: ALl input from the user going into the AC needs to be sanitized and checked
        info = ACInformation(AttributeAuthority.AC_VERSION)

        algo = '%s[%d]' % (user_public_key.key_algorithm.cipher, user_public_key.key_algorithm.key_size)
        holder = ACHolder(key_algo=algo,
                          uid='%s/user/%s' % (self.a_uri, credentials.username),
                          pub_key=user_public_key.public_key,
                          name=credentials.username)

        rev_rules = ACRevocationRules(valid_before=info.issued + self.ac_expire_length,
                                      valid_after=info.issued,
                                      url=self.rev_url)

        del_rules = ACDelegationRules()

        att_set = []
        if user_att_set is not None:
            for att in user_att_set.values():
                att_set.append(ACAttribute(
                        att_id=att.id,
                        att_type=att.type,
                        att_name=att.name,
                        att_value=str(att.value)
                    )
                )

        con_att_set = self._make_con_att_set(credentials, user_public_key, exports, info.serial, self.ac_expire_length)
        for att in con_att_set.values():
            att_set.append(ACAttribute(
                            att_id=att['id'],
                            att_type=att['type'],
                            att_name=att['name'],
                            att_value=str(att['value'])
                        )
            )

        ac = AttributeCertificate(
                issuer=self.ac_issuer,
                info=info,
                holder=holder,
                rev_rules=rev_rules,
                del_rules=del_rules,
                att_set=att_set
        )

        bin = ac.export_ac(
                format=AttributeAuthority.AC_FORMAT,
                sign=True,
                prvi_key=self.key,
                sig_algo=AttributeAuthority.SIG_ALGO + ':' + AttributeAuthority.HASH_ALGO
        )

        t1 = time.time()

        AttributeAuthority.LOG.info('AC generation time: %s seconds.' % str(t1-t0))

        hex_serial = ('0x%0.2X.ac' % info.serial)[2:]
        file_name = '%s/%s' % (AttributeAuthority.AC_DIR, hex_serial)
        ac_file = open(file_name, 'wb')
        ac_file.write(bin)
        ac_file.close()

        AttributeAuthority.LOG.info('AC Byte Encoded Size: %d bytes.' % os.path.getsize(file_name))

        return file_name


    @ladonize(Credentials, PublicKey, AttributeList, rtype=AttributeCertificateType)
    def attribute_request(self, credentials, user_public_key, attributes, **exports):
        t0 = time.time()
        AttributeAuthority.LOG.info('Attribute request on AttributeAuthority from %s.' % exports['REMOTE_ADDR'])

        if credentials.type == CredentialType.USER_PASS.value:
            s = self._db_session()
            user = s.query(User).filter(User.username == credentials.username.lower()).first()
            if user is None:
                AttributeAuthority.LOG.info(
                    'ClientFault: No such username (%s) found in attribute_request from %s' % (credentials.username,
                                                                                               exports['REMOTE_ADDR']))
                raise ClientFault('Invalid credentials.')

            if AttributeAuthority.LOG.isEnabledFor(DEBUG):
                AttributeAuthority.LOG.debug('Hash for request is: %s' %
                                             bcrypt.hashpw(('%s%s' % (credentials.password, self.pass_pepper)).encode(),
                                                           user.password.encode()))

            if bcrypt.checkpw(('%s%s' % (credentials.password, self.pass_pepper)).encode(), user.password.encode()):
                AttributeAuthority.LOG.info('Successful login by %s from %s.' % (credentials.username,
                                                                                 exports['REMOTE_ADDR']))
                t1 = time.time()
                AttributeAuthority.LOG.info('Time to login: %s seconds.' % str(t1-t0))
                user_attributes = s.query(Attribute,AttributeAssignment.value).join(Attribute.values).\
                    filter_by(user_id=user.id).all()

                t2 = time.time()
                AttributeAuthority.LOG.info('Time to get atts: %s seconds.' % str(t2 - t1));


                map(str.strip, attributes.attribute_ids)
                map(str.lower, attributes.attribute_ids)
                map(str.strip, attributes.attribute_names)
                map(str.lower, attributes.attribute_names)
                while None in attributes.attribute_ids: attributes.attribute_ids.remove(None)
                while '*' in attributes.attribute_ids: attributes.attribute_ids.remove('*')
                while '' in attributes.attribute_ids: attributes.attribute_ids.remove('')
                while None in attributes.attribute_names: attributes.attribute_names.remove(None)
                while '*' in attributes.attribute_names: attributes.attribute_names.remove('*')
                while '' in attributes.attribute_names: attributes.attribute_names.remove('')

                user_att_set = {}
                if len(attributes.attribute_ids) + len(attributes.attribute_names) == 0:
                    AttributeAuthority.LOG.debug('%s has requested all attributes.' % credentials.username)
                    for att, att_value in user_attributes:
                        att.value = att_value
                        user_att_set[att.id] = att
                else:
                    AttributeAuthority.LOG.debug('%s has requested a subset or their attributes.'
                                                 % credentials.username)
                    att_list_by_name = {}
                    att_list_by_id = {}
                    for att, att_value in user_attributes:
                        att.value = att_value
                        att_list_by_name[att.name] = att
                        att_list_by_id[att.id] = att

                    for att_id in attributes.attribute_ids:
                        att = att_list_by_id.get(att_id, None)
                        if att is None:
                            AttributeAuthority.LOG.info('%s requested the attribute %s but they have not been assigned \
                            that attribute.' % (credentials.username, att_id))
                            raise ClientFault('Invalid attribute id: You have not been assigned the attribute %s.'
                                              % att_id)
                        else:
                            user_att_set[att.id] = att

                    for att_name in attributes.attribute_names:
                        att = att_list_by_name.get(att_name, None)
                        if att is None:
                            AttributeAuthority.LOG.info('%s requested the attribute by name (%s) but they have not '
                                                        'been assigned an attribute with that name.' %
                                                        (credentials.username, att_name))
                            raise ClientFault('Invalid attribute id: You have not been assigned an attribute with the '
                                              'name %s.' % att_name)
                        if att.id not in user_att_set:
                            user_att_set[att.id] = att

                AttributeAuthority.LOG.info('%s has activated the following attributes: [%s]' %
                                            (credentials.username, ', '.join(user_att_set.keys())))

                t2b = time.time()
                AttributeAuthority.LOG.info('Time to proccess atts: %s seconds.' % str(t2b-t2));

                ladon_ac = AttributeCertificateType()
                ladon_ac.version = AttributeAuthority.AC_VERSION
                ladon_ac.format = AttributeAuthority.AC_FORMAT.value
                ac_file_name = self._make_ac(credentials, user_public_key, user_att_set, exports)

                t3 = time.time()
                AttributeAuthority.LOG.info('Time make AC: %s seconds.' % str(t3-t2));
                ac_file = open(ac_file_name, 'rb')
                ladon_ac.data = attachment(ac_file)

                t4 = time.time()
                AttributeAuthority.LOG.info('Time to add attachment: %s seconds.' % str(t4-t3));
                return ladon_ac

            else:
                AttributeAuthority.LOG.info('ClientFault: Bad password for user %s in attribute_request from %s' %
                                             (credentials.username, exports['REMOTE_ADDR']))
                raise ClientFault('Invalid credentials.')
        else:
            AttributeAuthority.LOG.debug('ClientFault: Unsupported credential type: %s in attribute_request from %s'
                                         % (str(credentials.type), exports['REMOTE_ADDR']))
            raise ClientFault('Unsupported credential type.')
