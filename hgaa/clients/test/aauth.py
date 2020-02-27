import unittest
from pprint import pprint
import binascii

from hgaa.clients.aauth import AttributeAuthorityClient
from hgaa.attcert import AttributeCertificate


# Note: Requires correct settings in clients.ini
# TODO: Make testing settings in clients.ini rather then using production settings.
class AttributeAuthorityClientTest(unittest.TestCase):
    def test_info(self):
        # TODO: Make this a real test
        aaclient = AttributeAuthorityClient()
        info = aaclient.info()
        pprint(info)

    def test_attribute_request(self):
        aaclient = AttributeAuthorityClient()
        rawac = aaclient.attribute_request()
        print(binascii.hexlify(rawac).decode('utf-8').upper())
        ac = AttributeCertificate.decode(bytearray(rawac), verify=True)
        print(ac)


# TODO: Add this kind of line to other test files.
if __name__ == '__main__':
    unittest.main()
