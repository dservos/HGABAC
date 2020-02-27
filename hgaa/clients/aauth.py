from ladon.clients.jsonwsp import JSONWSPClient
from Crypto.PublicKey import RSA
from ladon.compat import PORTABLE_STRING, PORTABLE_BYTES
import pprint

from hgaa.log import CLIENT_LOG, make_logger
from hgaa.config import get_conf


class AttributeAuthorityClient(object):
    LOG = make_logger('AAUTH', False, CLIENT_LOG)

    def __init__(self, credentials=None):
        # TODO: Set defaults for these new client config vars
        self.client_type = get_conf('CLIENT_TYPE', False, 'AAUTH')
        self.service_desc = get_conf('SERVICE_DESCRIPTION', False, 'AAUTH')
        self.key_size = int(get_conf('KEY_SIZE', False, 'AAUTH'))
        self.last_key = None

        if credentials is None:
            self.credentials = {'type': get_conf('CRED_TYPE', False, 'AAUTH'),
                                'username': get_conf('CRED_USER', False, 'AAUTH'),
                                'password': get_conf('CRED_PASS', False, 'AAUTH')}
        else:
            self.credentials = credentials

        if self.client_type == 'JSONWSP':
            AttributeAuthorityClient.LOG.info('Setting up JSONWSP client for service %s' % self.service_desc)
            self.cli = JSONWSPClient(self.service_desc)
        else:
            AttributeAuthorityClient.LOG.error('%s client type is not yet supported.' % self.client_type)
            raise Exception('%s client type is not yet supported.' % self.client_type)

    def update_service(self, url=None, client_type=None):
        AttributeAuthorityClient.LOG.info('Updating service for change of url and/or client type.')

        if url is not None:
            self.service_desc = url

        if client_type is not None:
            self.client_type = client_type

        if self.client_type == 'JSONWSP':
            AttributeAuthorityClient.LOG.info('Setting up JSONWSP client for service %s' % self.service_desc)
            self.cli = JSONWSPClient(self.service_desc)
        else:
            AttributeAuthorityClient.LOG.error('%s client type is not yet supported.' % self.client_type)
            raise Exception('%s client type is not yet supported.' % self.client_type)

    def info(self):
        AttributeAuthorityClient.LOG.info('Calling info method for service %s' % self.service_desc)
        response = self.cli.info()
        # TODO: More logging.
        # TODO: Check status + for errors

        if response.status != 200:
            raise Exception("Bad status in response.")

        return response.response_dict['result']

    def attribute_request(self, attribute_names=None, attribute_ids=None, key=None):
        if key is None:
            AttributeAuthorityClient.LOG.info('Generating session key of size %d for attribute request with %s' %
                                              (self.key_size, self.service_desc))
            key = RSA.generate(self.key_size)
            key_size = self.key_size
        else:
            key_size = key.size_in_bits()
        pub_key = key.publickey().exportKey()
        AttributeAuthorityClient.LOG.info('Public session key is %s' % pub_key)

        user_public_key = {
            'public_key': pub_key.decode("utf-8"),
            'key_algorithm': {
                'cipher': 'RSA',
                'key_size': key_size
            }
        }

        attributes = {
            'attribute_names': attribute_names,
            'attribute_ids': attribute_ids
        }

        AttributeAuthorityClient.LOG.info('Calling attribute_request method for service %s' % self.service_desc)
        # TODO: Error checking
        response = self.cli.attribute_request(credentials=self.credentials, user_public_key=user_public_key,
                                              attributes=attributes)

        if response.status != 200:
            raise Exception("Bad status in response.")

        if 'fault' in response.response_dict:
            raise Exception("Fault encountered in request reply.\nERROR: %s\n\nDetails:\n%s" %
                            (response.response_dict['fault']['string'],
                             pprint.pformat(response.response_dict['fault']['detail'], width=300)))

        self.last_key = key
        return response.response_dict['result']