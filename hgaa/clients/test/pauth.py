import unittest
from pprint import pprint
import binascii
import os

from hgaa.clients.pauth import PolicyAuthorityClient
from hgaa.attcert import AttributeCertificate
from hgaa.attcert import ExportFormat

# Note: Requires correct settings in clients.ini
# TODO: Make testing settings in clients.ini rather then using production settings.
class PolicyAuthorityClientTest(unittest.TestCase):
    TEST_SERVICE_UID = "hgabac://localhost:8888/service/pauth_test"
    TEST_AC_DIR = os.path.dirname(os.path.abspath(__file__)) + '/test_attribute_certificates/'
    TEST_AC = "C9FAAE0573DEBCBFFD42C9FFEA8E523B392C2871.ac"

    def test_info(self):
        # TODO: Make this a real test
        paclient = PolicyAuthorityClient(PolicyAuthorityClientTest.TEST_SERVICE_UID)
        info = paclient.info()
        pprint(info)

    def test_trusted_attribute_authorities(self):
        # TODO: Make this a real test
        paclient = PolicyAuthorityClient(PolicyAuthorityClientTest.TEST_SERVICE_UID)
        attribute_authorities = paclient.trusted_attribute_authorities()
        pprint(attribute_authorities)

    def test_start_session(self):
        ac_file = open(PolicyAuthorityClientTest.TEST_AC_DIR + PolicyAuthorityClientTest.TEST_AC, mode='rb')
        paclient = PolicyAuthorityClient(PolicyAuthorityClientTest.TEST_SERVICE_UID)
        att_cert_set = [ {'data':ac_file, 'version':1, 'format':ExportFormat.BYTES.value} ]
        print(len(att_cert_set))
        session = paclient.start_session(att_cert_set)
        pprint(session.response_dict)

# TODO: Add this kind of line to other test files.
if __name__ == '__main__':
    unittest.main()
