from ladon.ladonizer import ladonize
from ladon.types.ladontype import LadonType
from ladon.compat import PORTABLE_STRING, PORTABLE_BYTES
from ladon.types.attachment import attachment
from ladon.exceptions.service import ClientFault, ServerFault
from Crypto.Random.random import getrandbits
from Crypto.Hash import SHA256
import time
import base64

from hgaa.log import SERVICE_LOG, make_logger
from hgaa.config import get_conf
from hgaa.database import get_session
from hgaa.schema.pauth import Policy as P, AttributeAuthority, Session, AttributeCertificate as AC, \
    AttributeCertificateAssignment as ACA
from hgaa.attcert import ExportFormat, AttributeCertificate, ACInformation

from hgpl.lexing import Lexer
from hgpl.parsing import Parser
from hgpl.semantics import TypeChecker
from hgpl.errors import ErrorType


class KeyAlgorithm(LadonType):
    # TODO: Add doc
    cipher = {'type': PORTABLE_STRING, 'nullable': False}
    key_size = {'type': int, 'nullable': False}


class AttributeAuthorityInfo(LadonType):
    # TODO: Add doc
    name = {'type': PORTABLE_STRING, 'nullable': False}
    url = {'type': PORTABLE_STRING, 'nullable': False}
    uid= {'type': PORTABLE_STRING, 'nullable': False}
    public_key = {'type': PORTABLE_BYTES, 'nullable': False}
    key_algorithm = KeyAlgorithm
    trust_level = {'type': int, 'nullable': False}


class AttributeAuthorityList(LadonType):
    # TODO: Add doc
    attribute_authorities = [AttributeAuthorityInfo]


class PolicyAuthorityInfo(LadonType):
    # TODO: Add doc
    name = {'type': PORTABLE_STRING, 'nullable': False}
    uid = {'type': PORTABLE_STRING, 'nullable': False}
    version = {'type': int, 'nullable': False}
    attribute_certificate_version = {'type': int, 'nullable': False}
    url = {'type': PORTABLE_STRING, 'nullable': False}
    policy_language_version = {'type': int, 'nullable': False}


class AttributeCertificateType(LadonType):
    # TODO: Add doc
    data = attachment
    version = {'type': int, 'nullable': False}
    format = {'type': int, 'nullable': False}


class AttributeCertificateSet(LadonType):
    # TODO: Add doc
    attribute_certificates = [AttributeCertificateType]


class ObjectAttribute(LadonType):
    # TODO: Add doc
    name = {'type': PORTABLE_STRING, 'nullable': True}
    uid = {'type': PORTABLE_STRING, 'nullable': True}
    type = {'type': int, 'nullable': False}
    value = {'type': PORTABLE_STRING, 'nullable': True}


class SessionReturn(LadonType):
    session_id = {'type': int, 'nullable': False}
    valid_till = {'type': int, 'nullable': False}
    start = {'type': int, 'nullable': False}


class EvaluationResult(LadonType):
    result = {'type': int, 'nullable': False}


class Policy(LadonType):
    # TODO: Add doc
    policy_uid = {'type': PORTABLE_STRING, 'nullable': True}
    policy_string = {'type': PORTABLE_STRING, 'nullable': True}
    policy_lang_ver = {'type': int, 'nullable': True}


class PolicyObjectAttPair(LadonType):
    # TODO: Add doc
    policy = {'type': Policy, 'nullable': False}
    object_attributes = [ObjectAttribute]


class PolicyAuthority(object):
    PA_VERSION = 1
    AC_VERSION = 1
    PL_VERSION = 1

    SESSION_ID_SIZE = 160
    MAX_SESSION_LENGTH = 86400  # 1 Day # TODO: Move to config
    RECHECK_CERT_EACH_EVAL = True  # TODO: Move to config
    LOG = make_logger('PAUTH', True, SERVICE_LOG)

    def __init__(self):
        self.name = get_conf('PAUTH_NAME', True, 'PAUTH')
        self.uid = get_conf('PAUTH_UID', True, 'PAUTH')
        host = get_conf('SERVICE_HOST', True, 'LADON')
        port = get_conf('SERVICE_PORT', True, 'LADON')
        self.url = 'http://'
        self.url += 'localhost' if host.strip() == '' else host
        self.url += ':' + port
        self.url += '/PolicyAuthority/jsonwsp/'

        PolicyAuthority.LOG.debug('Setup PolicyAuthority with following attributes: name: %(name)s, uid: %(uid)s, '
                                  'pa_ver: %(pa_ver)s, ac_ver: %(ac_ver)s, pl_ver: %(pl_ver)s, url: %(url)s'
                                  % {'name': self.name,
                                     'uid': self.uid,
                                     'pa_ver': PolicyAuthority.PA_VERSION,
                                     'ac_ver': PolicyAuthority.AC_VERSION,
                                     'pl_ver': PolicyAuthority.PL_VERSION,
                                     'url': self.url})

        PolicyAuthority.LOG.debug('Setting up database session for PolicyAuthority')
        self._db_session = get_session('AAUTH') # TODO: Need new session for each request?

    @ladonize(rtype=int)
    def simp(self):
        return 1

    @ladonize(rtype=AttributeAuthorityList)
    def trusted_attribute_authorities(self, **exports):
        PolicyAuthority.LOG.info('Trusted attribute authorities request on PolicyAuthority from %s.'
                                 % exports['REMOTE_ADDR'])
        auth_list = AttributeAuthorityList()
        auth_list.attribute_authorities = []

        s = self._db_session()
        aauths = s.query(AttributeAuthority).all()

        for aauth in aauths:
            aauth_info = AttributeAuthorityInfo()
            aauth_info.name = aauth.name
            aauth_info.uid = aauth.uid
            aauth_info.url = aauth.url
            aauth_info.public_key = aauth.pub_key
            aauth_info.trust_level = aauth.trust_level
            key_info = KeyAlgorithm()
            key_info.key_size = aauth.key_size
            key_info.cipher = aauth.key_cipher
            aauth_info.key_algorithm = key_info
            auth_list.attribute_authorities += [aauth_info]

        return auth_list

    @ladonize(rtype=PolicyAuthorityInfo)
    def info(self, **exports):
        PolicyAuthority.LOG.info('Info request on PolicyAuthority from %s.' % exports['REMOTE_ADDR'])
        pa_info = PolicyAuthorityInfo()
        pa_info.url = self.url
        pa_info.version = PolicyAuthority.PA_VERSION
        pa_info.uid = self.uid
        pa_info.name = self.name
        pa_info.attribute_certificate_version = PolicyAuthority.AC_VERSION
        pa_info.policy_language_version = PolicyAuthority.PL_VERSION

        return pa_info

    def _check_cert(self, raw_cert, aauth_dict, exports, request):
        # TODO: Use request to switch between client and server fault, also customize error and log messages.
        if raw_cert.version != PolicyAuthority.AC_VERSION:
            PolicyAuthority.LOG.error(
                'ClientFault: Invalid ac version in request from %s'
                % exports['REMOTE_ADDR'])
            raise ClientFault('Unsupported attribute certificate version in certificate set.')
        elif raw_cert.format not in (ExportFormat.BYTES, ExportFormat.BASE64, ExportFormat.BASE64FULL):
            PolicyAuthority.LOG.error(
                'ClientFault: Invalid ac format in request from %s'
                % exports['REMOTE_ADDR'])
            raise ClientFault('Unsupported attribute certificate format in certificate set.')
        else:
            try:
                cert = AttributeCertificate.import_ac(raw_cert.data_raw, format=raw_cert.format, verify=True)
            except Exception as e:
                PolicyAuthority.LOG.error(
                    'ClientFault: Could not verify ac in request from %s'
                    % exports['REMOTE_ADDR'])
                raise ClientFault('Could to verify signature of attribute certificate in certificate set.')

            aauth_uid = cert.issuer.uid
            aauth = aauth_dict.get(aauth_uid, None)
            if aauth is None or aauth.trust_level <= 0:
                PolicyAuthority.LOG.error(
                    'ClientFault: aauth in ac is not trusted in request from %s'
                    % exports['REMOTE_ADDR'])
                raise ClientFault('An attribute authority in an attribute certificate in your certificate '
                                  'set is not trusted.')
            elif not cert.verify_time():
                PolicyAuthority.LOG.error(
                    'ClientFault: ac is expired in evaluate from %s'
                    % exports['REMOTE_ADDR'])
                raise ClientFault('An attribute certificate in your certificate set '
                                  'is expired.')

            return cert

    def _int_to_b64(self, n, size):
        bytes = n.to_bytes(int(size / 8), 'little')
        return base64.b64encode(bytes).decode('utf-8')

    @ladonize(PORTABLE_STRING, AttributeCertificateSet, rtype=SessionReturn)
    def start_session(self, service_uid, att_cert_set, **exports):
        # TODO: Some check on service_uid and authentication of service

        s = self._db_session()

        aauths = s.query(AttributeAuthority).all()
        aauth_dict = {}
        for aauth in aauths:
            aauth_dict[aauth.uid] = aauth

        processed_att_certs = {}
        min_valid_date = -1
        max_start_date = -1
        session_start = int(time.time())
        session_valid_till = session_start + PolicyAuthority.MAX_SESSION_LENGTH

        to_add = []

        if att_cert_set is None or att_cert_set.attribute_certificates is None \
                or len(att_cert_set.attribute_certificates) < 1:
            PolicyAuthority.LOG.error(
                'ClientFault: No att cert set in start_session request from %s'
                % exports['REMOTE_ADDR'])
            raise ClientFault('Need attribute certificate set to start session.')

        session_id = getrandbits(PolicyAuthority.SESSION_ID_SIZE)
        b64_session = self._int_to_b64(session_id, PolicyAuthority.SESSION_ID_SIZE)

        for raw_cert in att_cert_set.attribute_certificates:
            raw_bytes = raw_cert.data.read()
            raw_cert.data_raw = bytearray(raw_bytes)
            raw_cert.format = ExportFormat(raw_cert.format)

            cert = self._check_cert(raw_cert, aauth_dict, exports, 'start_session')
            if cert is not None:
                if min_valid_date == -1 or cert.rev_rules.valid_before < min_valid_date:
                    min_valid_date = cert.rev_rules.valid_before

                if max_start_date == -1 or cert.info.issued > max_start_date:
                    max_start_date = cert.info.issued

                b64_serial = self._int_to_b64(cert.info.serial, ACInformation.SERIAL_SIZE)


                processed_att_certs[b64_serial] = cert

                cert_hash=base64.b64encode(SHA256.new(raw_cert.data_raw).digest()).decode('utf-8')


                has_cert = s.query(AC).filter(AC.serial == b64_serial).first()

                if has_cert is None:
                    to_add.append(AC(serial=b64_serial, certificate=raw_bytes,
                                     format=raw_cert.format.value, version=raw_cert.version,
                                     valid_till=cert.rev_rules.valid_before, hash=cert_hash))
                else:
                    if has_cert.hash != cert_hash:
                        PolicyAuthority.LOG.error(
                            'ClientFault: Cert with serial %s in request from %s is already in database but hash does '
                            'not match!' % (b64_serial, exports['REMOTE_ADDR']))
                        raise ClientFault('Certificate serial already in use.')

                to_add.append(ACA(ac_serial=b64_serial, session_id=b64_session))

        if min_valid_date < session_valid_till:
            session_valid_till = min_valid_date

        if len(processed_att_certs) < 1:
            PolicyAuthority.LOG.error(
                'ClientFault: No valid certs in start_session request from %s'
                % exports['REMOTE_ADDR'])
            raise ClientFault('Need at least one valid attribute certificate in your certificate '
                              'set.')
        else:
            to_add.append(Session(id=b64_session, cert_start=max_start_date, cert_valid_till=min_valid_date,
                                  session_start=session_start, initial_service_ip=exports['REMOTE_ADDR'],
                                  service_uid=service_uid, session_valid_till=session_valid_till))
            PolicyAuthority.LOG.info('Adding session and attribute certs as result of start_session request from %s'
                                     % exports['REMOTE_ADDR'])
            s.add_all(to_add)
            s.commit()

            session = SessionReturn()
            session.session_id = session_id
            session.start = session_start
            session.valid_till = session_valid_till
            return session


    @ladonize(int, PolicyObjectAttPair, rtype=EvaluationResult)
    def evaluate(self, session_id, policy_objatt_pair, **exports):
        s = self._db_session()

        if policy_objatt_pair.policy_uid is None and policy_objatt_pair.policy_string is None:
            PolicyAuthority.LOG.error(
                'ClientFault: Need to give policy uid or policy string in evaluate request from %s'
                % exports['REMOTE_ADDR'])
            raise ClientFault('Need to give policy uid or policy string.')
        elif policy_objatt_pair.policy_uid is not None:
            # TODO: Support for relative policy uids and names
            p = s.query(Session).filter(P.uid == policy_objatt_pair.policy_uid).first()
            if p is None:
                PolicyAuthority.LOG.error(
                    'ClientFault: Unknown policy uid in evaluate request from %s'
                    % exports['REMOTE_ADDR'])
                raise ClientFault('Unknown policy uid.')
            policy = p.policy
        else:
            policy = policy_objatt_pair.policy_string

        try:
            # TODO: Cache ast
            lex = Lexer(policy)
            p = Parser(lex)
            ast = p.parse()
            tc = TypeChecker(ast, policy)
            tc.check(ErrorType.NONE)
        except Exception as e:
            PolicyAuthority.LOG.error(
                'ClientFault: Invalid policy in evaluate request from %s, error is %s'
                % (exports['REMOTE_ADDR'], e))
            raise ClientFault('Invalid policy: %s' % e)

        if policy_objatt_pair.object_attributes is not None and len(policy_objatt_pair.object_attributes) >= 1:
            for att in policy_objatt_pair.object_attributes:
                if att.name is None and att.uid is None:
                    PolicyAuthority.LOG.error(
                        'ClientFault: Attribute without name or uid in evaluate request from %s'
                        % exports['REMOTE_ADDR'])
                    raise ClientFault('Attribute without name or uid, need one or the other.')

        # ************************************************************************
        # NEED TO START BUILDING SYMBOL TABLE HERE WITH OBJECT ATTS
        # ************************************************************************


        aauths = s.query(AttributeAuthority).all()
        aauth_dict = {}
        for aauth in aauths:
            aauth_dict[aauth.uid] = aauth

        cert_dict = {}

        session = s.query(Session).filter(Session.id == session_id).first()
        if session is None:
            PolicyAuthority.LOG.error(
                'ClientFault: Unknown session_id in evaluate request from %s'
                % exports['REMOTE_ADDR'])
            raise ClientFault('Unknown session_id.')
        elif int(time.time()) > session.valid_till:
            PolicyAuthority.LOG.error(
                'ClientFault: Expired session in evaluate request from %s'
                % exports['REMOTE_ADDR'])
            raise ClientFault('Session has expired.')

        certs = s.query(AC).join(AC.sessions).filter_by(ACA.session_id == session_id).all()
        for cert in certs:
            if PolicyAuthority.RECHECK_CERT_EACH_EVAL:
                act = AttributeCertificateType()
                act.format = cert.format
                act.version = cert.version
                act.data = cert.certificate
                cert_hash = SHA256.new(cert.certificate)

                ac = self._check_cert(act, aauth_dict, exports, 'evaluate')

                if ac.info.serial != cert.serial or ac.info.version != cert.version or cert_hash != cert.hash or \
                   ac.rev_rules.valid_till != cert.valid_till:
                    PolicyAuthority.LOG.error(
                        'ServerFault: Unknown session_id in evaluate request from %s'
                        % exports['REMOTE_ADDR'])
                    raise ServerFault('Mismatch certificate information in database and raw data.')
            else:
                ac = AttributeCertificate.import_ac(cert.certificate, format=cert.format, verify=False)

            cert_dict[ac.info.serial] = ac


        # **************************************************************************
        # NEED TO FINISH BUILDING SYMBOL TABLE HERE WITH ATTS FROM AC, ENV AND ADMIN
        # **************************************************************************

        # LOTS MORE TO DO
