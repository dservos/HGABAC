from ladon.clients.jsonwsp import JSONWSPClient

from hgaa.log import CLIENT_LOG, make_logger
from hgaa.config import get_conf


class PolicyAuthorityClient(object):
    LOG = make_logger('PAUTH', False, CLIENT_LOG)

    def __init__(self, service_uid):
        self.service_uid=service_uid
        self.client_type = get_conf('CLIENT_TYPE', False, 'PAUTH')
        self.service_desc = get_conf('SERVICE_DESCRIPTION', False, 'PAUTH')

        if self.client_type == 'JSONWSP':
            PolicyAuthorityClient.LOG.info('Setting up JSONWSP client for service %s' % self.service_desc)
            self.cli = JSONWSPClient(self.service_desc)
        else:
            PolicyAuthorityClient.LOG.error('%s client type is not yet supported.' % self.client_type)
            raise Exception('%s client type is not yet supported.' % self.client_type)

    def update_service(self, url=None, client_type=None):
        PolicyAuthorityClient.LOG.info('Updating service for change of url and/or client type.')

        if url is not None:
            self.service_desc = url

        if client_type is not None:
            self.client_type = client_type

        if self.client_type == 'JSONWSP':
            PolicyAuthorityClient.LOG.info('Setting up JSONWSP client for service %s' % self.service_desc)
            self.cli = JSONWSPClient(self.service_desc)
        else:
            PolicyAuthorityClient.LOG.error('%s client type is not yet supported.' % self.client_type)
            raise Exception('%s client type is not yet supported.' % self.client_type)

    def info(self):
        PolicyAuthorityClient.LOG.info('Calling info method for service %s' % self.service_desc)
        response = self.cli.info()
        # TODO: More logging.
        # TODO: Check status + for errors

        if response.status != 200:
            raise Exception("Bad status in response.")

        return response.response_dict['result']

    def trusted_attribute_authorities(self):
        PolicyAuthorityClient.LOG.info('Calling trusted_attribute_authorities method for service %s'
                                       % self.service_desc)
        response = self.cli.trusted_attribute_authorities()
        # TODO: More logging.
        # TODO: Check status + for errors

        if response.status != 200:
            raise Exception("Bad status in response.")

        return response.response_dict['result']

    def start_session(self, att_cert_set):
        PolicyAuthorityClient.LOG.info('Calling start_session method for service %s' % self.service_desc)
        response = self.cli.start_session(service_uid=self.service_uid,
                                          att_cert_set={'attribute_certificates': att_cert_set})

        #if response.status != 200:
        #    raise Exception("Bad status in response.")

        return response #.response_dict['result']