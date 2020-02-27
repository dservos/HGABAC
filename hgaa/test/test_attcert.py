from unittest import TestCase
import time
import random
from Crypto.PublicKey import RSA
from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA256

from hgaa.attcert import ACInformation, ACIssuer, ACAttribute, AttributeType, ACRevocationRules, ACDelegationRules, \
    ACExtensions, ACSignature, AttributeCertificate, ACHolder, ExportFormat


class TestACInformation(TestCase):
    def test_default_encode_decode(self):
        info = ACInformation()
        encoded = bytearray(info.encode())
        new_info = ACInformation.decode(encoded)
        self.assertEqual(info, new_info)
        self.assertEqual(0, len(encoded))

    def test_custom_encode_decode(self):
        t = int(time.time()) - 1000
        s = random.getrandbits(ACInformation.SERIAL_SIZE)
        info = ACInformation(version=5, issued=t, serial=s)
        encoded = bytearray(b''.join((info.encode(), b'testing some Extra b3tes!!!')))
        new_info = ACInformation.decode(encoded)
        self.assertEqual(info, new_info)
        self.assertEqual(bytearray(b'testing some Extra b3tes!!!'), encoded)

    def test_custom_init(self):
        t = int(time.time()) - 1000
        s = random.getrandbits(ACInformation.SERIAL_SIZE)
        info = ACInformation(version=5, issued=t, serial=s)
        self.assertEqual(t, info.issued)
        self.assertEqual(5, info.version)
        self.assertEqual(s, info.serial)

    def test_default_init(self):
        t = int(time.time())
        info = ACInformation()
        self.assertEqual(t, info.issued)
        self.assertEqual(0, info.version)


class TestACIssuer(TestCase):
    def test_encode_decode(self):
        key = RSA.generate(2048)
        pub_key = key.publickey().exportKey('DER')
        key_algo = 'RSA[%s]' % key.publickey().size_in_bits()
        uid = 'hgaa.testing.testac'
        name = 'My Test AC'
        url = 'http://hgaa.test/testing/testac?test=1234abc&abc=4#test'
        issuer = ACIssuer(pub_key, key_algo, uid, name, url)
        encoded = bytearray(b''.join((issuer.encode(), b'testing some Extra b3tes!!!')))
        new_issuer = ACIssuer.decode(encoded)

        # Extra asserts for debugging (remove?)
        self.assertEqual(issuer.pub_key, new_issuer.pub_key)
        self.assertEqual(issuer.key_algo, new_issuer.key_algo)
        self.assertEqual(issuer.uid, new_issuer.uid)
        self.assertEqual(issuer.url, new_issuer.url)
        self.assertEqual(issuer.name, new_issuer.name)

        self.assertEqual(issuer, new_issuer)
        self.assertEqual(bytearray(b'testing some Extra b3tes!!!'), encoded)

    def test_encode_decode_with_none(self):
        key = RSA.generate(2048)
        pub_key = key.publickey().exportKey('DER')
        key_algo = 'RSA[%s]' % key.publickey().size_in_bits()
        uid = 'hgaa.testing.testac'
        issuer = ACIssuer(pub_key, key_algo, uid)
        encoded = bytearray(issuer.encode())
        new_issuer = ACIssuer.decode(encoded)

        # Extra asserts for debugging (remove?)
        self.assertEqual(issuer.pub_key, new_issuer.pub_key)
        self.assertEqual(issuer.key_algo, new_issuer.key_algo)
        self.assertEqual(issuer.uid, new_issuer.uid)
        self.assertEqual(issuer.url, new_issuer.url)
        self.assertEqual(issuer.name, new_issuer.name)

        self.assertEqual(issuer, new_issuer)
        self.assertEqual(0, len(encoded))

    def test_encode_decode_with_half_none(self):
        key = RSA.generate(2048)
        pub_key = key.publickey().exportKey('DER')
        key_algo = 'RSA[%s]' % key.publickey().size_in_bits()
        uid = 'hgaa.testing.testac'
        name = 'My Test AC'
        url = 'http://hgaa.test/testing/testac?test=1234abc&abc=4#test'
        issuer1 = ACIssuer(pub_key, key_algo, uid, name=name, url=None)
        issuer2 =  ACIssuer(pub_key, key_algo, uid, name=None, url=url)
        encoded1 = issuer1.encode()
        encoded2 = issuer2.encode()
        new_issuer1 = ACIssuer.decode(bytearray(encoded1))
        new_issuer2 = ACIssuer.decode(bytearray(encoded2))

        self.assertEqual(issuer1, new_issuer1)
        self.assertEqual(issuer2, new_issuer2)


class TestACHolder(TestCase):
    def test_encode_decode(self):
        key = RSA.generate(2048)
        pub_key = key.publickey().exportKey('DER')
        key_algo = 'RSA[%s]' % key.publickey().size_in_bits()
        uid = 'hgaa.testing.testacholder'
        name = 'My Test AC Holder'
        holder = ACHolder(pub_key, key_algo, uid, name)
        encoded = bytearray(holder.encode())
        new_holder = ACHolder.decode(encoded)

        # Extra asserts for debugging (remove?)
        self.assertEqual(holder.pub_key, new_holder.pub_key)
        self.assertEqual(holder.key_algo, new_holder.key_algo)
        self.assertEqual(holder.uid, new_holder.uid)
        self.assertEqual(holder.name, new_holder.name)

        self.assertEqual(holder, new_holder)
        self.assertEqual(0, len(encoded))

    def test_encode_decode_with_no_name(self):
        key = RSA.generate(2048)
        pub_key = key.publickey().exportKey('DER')
        key_algo = 'RSA[%s]' % key.publickey().size_in_bits()
        uid = 'hgaa.testing.testacholder.withnoname'
        holder = ACHolder(pub_key, key_algo, uid)
        encoded = bytearray(b''.join((holder.encode(), b'testing some Extra b3tes!!!123')))
        new_holder = ACHolder.decode(encoded)

        # Extra asserts for debugging (remove?)
        self.assertEqual(holder.pub_key, new_holder.pub_key)
        self.assertEqual(holder.key_algo, new_holder.key_algo)
        self.assertEqual(holder.uid, new_holder.uid)
        self.assertEqual(holder.name, new_holder.name)

        self.assertEqual(holder, new_holder)
        self.assertEqual(bytearray(b'testing some Extra b3tes!!!123'), encoded)


class TestACAttribute(TestCase):
    def test_encode_decode(self):
        att_id = 'hgabac:attr:usr:localhost:testing:mytestatt'
        name = 'My Test Att'
        value = 'Hello World'
        att_type = AttributeType.STRING
        extra_bytes = b'This is some extra bytes!!!!'
        att = ACAttribute(att_id, att_type, value, name, extra_bytes)
        encoded = bytearray(b''.join((att.encode(), b'testing some Extra b3tes!!!')))
        new_att = ACAttribute.decode(encoded)
        self.assertEqual(att, new_att)
        self.assertEqual(bytearray(b'testing some Extra b3tes!!!'), encoded)

    def test_encode_decode_with_none(self):
        att_id = 'hgabac:attr:usr:localhost:testing:mytestatt'
        att_type = AttributeType.STRING
        value = 'Hello World'
        att = ACAttribute(att_id, att_type, value, None, None)
        encoded = bytearray(att.encode())
        new_att = ACAttribute.decode(encoded)
        self.assertEqual(att, new_att)
        self.assertEqual(0, len(encoded))

    def test_encode_decode_with_half_none(self):
        att_id = 'hgabac:attr:usr:localhost:testing:mytestatt'
        att_type = AttributeType.STRING
        value = 'Hello World'
        name = 'My Test Att'
        extra_bytes = b'This is some extra bytes!!!!'
        att1 = ACAttribute(att_id, att_type, value, att_name=None, extra_bytes=extra_bytes)
        att2 = ACAttribute(att_id, att_type, value, att_name=name, extra_bytes=None)
        encoded1 = att1.encode()
        encoded2 = att2.encode()
        new_att1 = ACAttribute.decode(bytearray(encoded1))
        new_att2 = ACAttribute.decode(bytearray(encoded2))
        self.assertEqual(att1, new_att1)
        self.assertEqual(att2, new_att2)


class TestACRevocationRules(TestCase):
    def test_default_encode_decode(self):
        rev_rules = ACRevocationRules()
        encoded = bytearray(b''.join((rev_rules.encode(), b'testing some Extra b3tes!!!')))
        new_rev_rules = ACRevocationRules.decode(encoded)
        self.assertEqual(rev_rules, new_rev_rules)
        self.assertEqual(b'testing some Extra b3tes!!!', encoded)

    def test_custom_encode_decode(self):
        after = int(time.time()) - 12345
        before = int(time.time()) + 12345
        url = 'http://myhgaatest/testing/revocation/rules?a=b&abc=123#test'
        extra_bytes = b'Some extra Bytes for the test 1234!@#$'
        rev_rules = ACRevocationRules(after, before, url, extra_bytes)
        encoded = bytearray(rev_rules.encode())
        new_rev_rules = ACRevocationRules.decode(encoded)
        self.assertEqual(rev_rules, new_rev_rules)
        self.assertEqual(0, len(encoded))

    def test_encode_decode_with_none(self):
        url = 'http://myhgaatest/testing/revocation/rules?a=b&abc=123#test'
        extra_bytes = b'Some extra Bytes for the test 1234!@#$'
        rev_rules1 = ACRevocationRules(url=url, extra_bytes=None)
        rev_rules2 = ACRevocationRules(url=None, extra_bytes=extra_bytes)
        rev_rules3 = ACRevocationRules(url=None, extra_bytes=None)
        encoded1 = bytearray(rev_rules1.encode())
        encoded2 = bytearray(rev_rules2.encode())
        encoded3 = bytearray(rev_rules3.encode())
        new_rev_rules1 = ACRevocationRules.decode(encoded1)
        new_rev_rules2 = ACRevocationRules.decode(encoded2)
        new_rev_rules3 = ACRevocationRules.decode(encoded3)
        self.assertEqual(rev_rules1, new_rev_rules1)
        self.assertEqual(rev_rules2, new_rev_rules2)
        self.assertEqual(rev_rules3, new_rev_rules3)

    def test_default_init(self):
        after = int(time.time())
        before = int(time.time()) + ACRevocationRules.DEFAULT_LENGTH
        rev_rules = ACRevocationRules()
        self.assertEqual(after, rev_rules.valid_after)
        self.assertEqual(before, rev_rules.valid_before)
        self.assertEqual(None, rev_rules.url)
        self.assertEqual(None, rev_rules.extra_bytes)

    def test_custom_init(self):
        after = 1337
        before = 121022472
        url = 'http://myhgaatest/testing/revocation/rules?a=b&abc=123#test'
        extra_bytes = b'Some extra Bytes for the test 1234!@#$'
        rev_rules = ACRevocationRules(after, before, url, extra_bytes)
        self.assertEqual(after, rev_rules.valid_after)
        self.assertEqual(before, rev_rules.valid_before)
        self.assertEqual(url, rev_rules.url)
        self.assertEqual(extra_bytes, rev_rules.extra_bytes)


class TestACDelegationRules(TestCase):
    def test_encode_decode(self):
        extra_bytes = b'Some extra Bytes for the test 1234!@#$'
        del_rules = ACDelegationRules(extra_bytes)
        encoded = bytearray(b''.join((del_rules.encode(), b'testing some Extra b3tes!!!')))
        new_del_rules = ACDelegationRules.decode(encoded)
        self.assertEqual(new_del_rules, del_rules)
        self.assertEqual(b'testing some Extra b3tes!!!', encoded)

    def test_encode_decode_with_none(self):
        del_rules = ACDelegationRules()
        encoded = bytearray(del_rules.encode())
        new_del_rules = ACDelegationRules.decode(encoded)
        self.assertEqual(new_del_rules, del_rules)
        self.assertEqual(0, len(encoded))


class TestACExtensions(TestCase):
    def test_encode_decode(self):
        eid = 'hgabac:ext:mytestext:someeid:sometest'
        extra_bytes = b'Some extra Bytes for the test 1234!@#$'
        ext = ACExtensions(eid, extra_bytes)
        encoded = bytearray(b''.join((ext.encode(), b'testing some Extra b3tes!!!')))
        new_ext = ACExtensions.decode(encoded)
        self.assertEqual(new_ext, ext)
        self.assertEqual(b'testing some Extra b3tes!!!', encoded)

    def test_encode_decode_with_none(self):
        eid = 'hgabac:ext:mytestext:someeid:sometest'
        ext = ACExtensions(eid)
        encoded = bytearray(ext.encode())
        new_ext = ACExtensions.decode(encoded)
        self.assertEqual(new_ext, ext)
        self.assertEqual(0, len(encoded))


class TestACSignature(TestCase):
    def test_encode_decode_real(self):
        key = RSA.generate(2048)
        test_data = \
            SHA256.new(b'This is some test data that a signature will be taken of! 1234 23 asdf 3412r 5!@#$!@#$')
        algo = 'RSA[%s],SHA256' % key.size_in_bits()
        sig_hash = pkcs1_15.new(key).sign(test_data)
        sig = ACSignature(algo, sig_hash)
        encoded = bytearray(b''.join((sig.encode(), b'testing some Extra b3tes!!!')))
        new_sig = ACSignature.decode(encoded)
        self.assertEqual(new_sig, sig)
        self.assertEqual(b'testing some Extra b3tes!!!', encoded)
        pkcs1_15.new(key).verify(test_data, new_sig.sig_value)

    def test_encode_decode_fake(self):
        algo = 'This is my algo'
        value = b'This are some bytes in my sig value.'
        sig = ACSignature(algo, value)
        encoded = bytearray(sig.encode())
        new_sig = ACSignature.decode(encoded)
        self.assertEqual(new_sig, sig)
        self.assertEqual(0, len(encoded))


class TestAttributeCertificate(TestCase):
    @staticmethod
    def _make_basic_ac():
        info = ACInformation()

        key = RSA.generate(2048)
        pub_key = key.publickey().exportKey('DER')
        key_algo = 'RSA[%s]' % key.publickey().size_in_bits()
        uid = 'hgaa.testing.testac'
        name = 'My Test AC'
        url = 'http://hgaa.test/testing/testac?test=1234abc&abc=4#test'
        issuer = ACIssuer(pub_key, key_algo, uid, name, url)

        key = RSA.generate(2048)
        pub_key = key.publickey().exportKey('DER')
        key_algo = 'RSA[%s]' % key.publickey().size_in_bits()
        uid = 'hgaa.testing.testacholder'
        name = 'My Test AC Holder'
        holder = ACHolder(pub_key, key_algo, uid, name)

        att_set = []

        rev_rules = ACRevocationRules()

        return AttributeCertificate(issuer, holder, info, att_set, rev_rules)

    @staticmethod
    def _make_full_ac():
        t = int(time.time()) - 1000
        s = random.getrandbits(ACInformation.SERIAL_SIZE)
        info = ACInformation(version=5, issued=t, serial=s)

        key = RSA.generate(2048)
        pub_key = key.publickey().exportKey('DER')
        key_algo = 'RSA[%s]' % key.publickey().size_in_bits()
        uid = 'uidwithoutanydots_-'
        name = 'MyTestAC1234_-1234567890.'
        url = 'http://hgaa.test/testing/testac?test=1234abc&abc=4#test'
        issuer = ACIssuer(pub_key, key_algo, uid, name, url)

        key = RSA.generate(2048)
        pub_key = key.publickey().exportKey('DER')
        key_algo = 'RSA[%s]' % key.publickey().size_in_bits()
        uid = 'hgaatestingtestacholderwithoutanydotsandverylong1234567890_-'
        name = 'MyTestAC1234_-1234567890.'
        holder = ACHolder(pub_key, key_algo, uid, name)

        att_id = 'hgabac:attr:usr:localhost:testing:mytestatt'
        name = 'My Test Att'
        value = 'Hello World'
        att_type = AttributeType.STRING
        extra_bytes = b'This is some extra bytes!!!!'
        att1 = ACAttribute(att_id, att_type, value, name, extra_bytes)

        att_id = 'hgabac:myint'
        name = 'mytestint'
        value = '5'
        att_type = AttributeType.INT
        extra_bytes = b'1234567890_-.~`@#$%^&*()+=abcdefghijklmnopqrstuvwxyz'
        att2 = ACAttribute(att_id, att_type, value, name, extra_bytes)

        att_id = 'hgabac:attr:usr:localhost:testing:Another_Test_Att_With_A_Float'
        name = 'Another Test Att for a Float1234_-.'
        value = '3.14'
        att_type = AttributeType.FLOAT
        extra_bytes = b'ABCDEFGHIJKLMNOPQRSTUVWXYZ{}|[]\:";\'<>?,./'
        att3 = ACAttribute(att_id, att_type, value, name, extra_bytes)

        att_id = 'hgabac:attr:usr:localhost:testing:my test bool'
        name = 'test_bool_att'
        value = 'TRUE'
        att_type = AttributeType.BOOL
        extra_bytes = b'\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0A'
        att4 = ACAttribute(att_id, att_type, value, name, extra_bytes)

        att_id = 'nullatt'
        name = 'null'
        value = None
        att_type = AttributeType.NULL
        extra_bytes = b'\xFF\xF0\xA2\x63\x3B'
        att5 = ACAttribute(att_id, att_type, value, name, extra_bytes)

        att_id = 'nullattstr'
        name = 'nullstr'
        value = ''
        att_type = AttributeType.STRING
        extra_bytes = b'\xFF\xF0\xA2\x63\x3B'
        att5b = ACAttribute(att_id, att_type, value, name, extra_bytes)

        att_id = 'hgabac:attr:usr:localhost:testing:mytestsetatt'
        name = 'My Test Set Att'
        value = '(0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20)'
        att_type = AttributeType.SET
        extra_bytes = b'This is some extra bytes!!!!'
        att6 = ACAttribute(att_id, att_type, value, name, extra_bytes)

        att_set = [att1, att2, att3, att4, att5, att5b, att6]

        after = int(time.time()) - 12345
        before = int(time.time()) + 12345
        url = 'http://myhgaatest/testing/revocation/rules?a=b&abc=123#test'
        extra_bytes = b'Some extra Bytes for the test 1234!@#$'
        rev_rules = ACRevocationRules(after, before, url, extra_bytes)

        extra_bytes = b'Some extra Bytes for the test 1234!@#$'
        del_rules = ACDelegationRules(extra_bytes)

        eid = 'hgabac:ext:mytestext:someeid:sometest'
        extra_bytes = b'Some extra Bytes for the test 1234!@#$'
        ext1 = ACExtensions(eid, extra_bytes)

        eid = 'hgabac:ext2'
        extra_bytes = b'\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0A'
        ext2 = ACExtensions(eid, extra_bytes)

        eid = 'null byte ext1234567890+=_-.:'
        ext3 = ACExtensions(eid)

        extensions = [ext1, ext2, ext3]

        return AttributeCertificate(issuer, holder, info, att_set, rev_rules, del_rules, extensions)

    @staticmethod
    def _make_full_ac_with_nones():
        info = ACInformation()

        key = RSA.generate(2048)
        pub_key = key.publickey().exportKey('DER')
        key_algo = 'RSA[%s]' % key.publickey().size_in_bits()
        uid = 'hgaa.testing.testac'
        issuer = ACIssuer(pub_key, key_algo, uid)

        key = RSA.generate(2048)
        pub_key = key.publickey().exportKey('DER')
        key_algo = 'RSA[%s]' % key.publickey().size_in_bits()
        uid = 'hgaa.testing.testacholder.withnoname'
        holder = ACHolder(pub_key, key_algo, uid)

        att_id = 'hgabac:attr:usr:localhost:testing:mytestatt'
        att_type = AttributeType.STRING
        value = 'Hello World'
        att1 = ACAttribute(att_id, att_type, value, None, None)

        att_id1 = 'hgabac:attr:usr:localhost:testing:mytestatt1'
        att_id2 = 'hgabac:attr:usr:localhost:testing:mytestatt2'
        att_type = AttributeType.STRING
        value = 'Hello World'
        name = 'My Test Att'
        extra_bytes = b'This is some extra bytes!!!!'
        att2 = ACAttribute(att_id1, att_type, value, att_name=None, extra_bytes=extra_bytes)
        att3 = ACAttribute(att_id2, att_type, value, att_name=name, extra_bytes=None)

        att_set = [att1, att2, att3]

        rev_rules = ACRevocationRules(url=None, extra_bytes=None)

        del_rules = ACDelegationRules()

        eid = 'hgabac:ext:mytestext:someeid:sometest'
        extensions = [ACExtensions(eid)]

        return AttributeCertificate(issuer, holder, info, att_set, rev_rules, del_rules, extensions)

    @staticmethod
    def _make_full_ac_with_half_nones():
        info = ACInformation()

        key = RSA.generate(2048)
        pub_key = key.publickey().exportKey('DER')
        key_algo = 'RSA[%s]' % key.publickey().size_in_bits()
        uid = 'hgaa.testing.testac'
        url = 'http://hgaa.test/testing/testac?test=1234abc&abc=4#test'
        issuer =  ACIssuer(pub_key, key_algo, uid, name=None, url=url)

        key = RSA.generate(2048)
        pub_key = key.publickey().exportKey('DER')
        key_algo = 'RSA[%s]' % key.publickey().size_in_bits()
        uid = 'hgaa.testing.testacholder.withnoname'
        holder = ACHolder(pub_key, key_algo, uid)

        att_set = []

        extra_bytes = b'Some extra Bytes for the test 1234!@#$'
        rev_rules = ACRevocationRules(url=None, extra_bytes=extra_bytes)

        del_rules = ACDelegationRules()

        eid = 'hgabac:ext:mytestext:someeid:sometest'
        extensions = [ACExtensions(eid)]

        return AttributeCertificate(issuer, holder, info, att_set, rev_rules, del_rules, extensions)

    def test_init(self):
        ac1 = TestAttributeCertificate._make_basic_ac()
        ac2 = TestAttributeCertificate._make_full_ac()
        ac3 = TestAttributeCertificate._make_full_ac_with_nones()
        ac4 = TestAttributeCertificate._make_full_ac_with_half_nones()

        # TODO: Check the values are correct

    def test_encode_decode_body(self):
        ac1 = TestAttributeCertificate._make_basic_ac()
        ac2 = TestAttributeCertificate._make_full_ac()
        ac3 = TestAttributeCertificate._make_full_ac_with_nones()
        ac4 = TestAttributeCertificate._make_full_ac_with_half_nones()

        ac1_encoded = bytearray(ac1._encode_body())
        ac2_encoded = bytearray(ac2._encode_body())
        ac3_encoded = bytearray(ac3._encode_body())
        ac4_encoded = bytearray(ac4._encode_body())

        new_ac1 = AttributeCertificate._decode_body(ac1_encoded)
        new_ac2 = AttributeCertificate._decode_body(ac2_encoded)
        new_ac3 = AttributeCertificate._decode_body(ac3_encoded)
        new_ac4 = AttributeCertificate._decode_body(ac4_encoded)

        self.assertEqual(ac1, new_ac1)
        self.assertEqual(ac2, new_ac2)
        self.assertEqual(ac3, new_ac3)
        self.assertEqual(ac4, new_ac4)

    def test_signing(self):
        key = RSA.generate(2048)
        pub_key = key.publickey().exportKey('DER')
        key_algo = 'RSA[%s]' % key.publickey().size_in_bits()

        ac1 = TestAttributeCertificate._make_basic_ac()
        ac2 = TestAttributeCertificate._make_full_ac()
        ac3 = TestAttributeCertificate._make_full_ac_with_nones()
        ac4 = TestAttributeCertificate._make_full_ac_with_half_nones()

        ac1.issuer.pub_key = pub_key
        ac2.issuer.pub_key = pub_key
        ac3.issuer.pub_key = pub_key
        ac4.issuer.pub_key = pub_key
        ac1.issuer.key_algo = key_algo
        ac2.issuer.key_algo = key_algo
        ac3.issuer.key_algo = key_algo
        ac4.issuer.key_algo = key_algo

        ac1.sign(key, 'RSASSA-PKCS1-v1_5:SHA256')
        ac2.sign(key, 'RSASSA-PKCS1-v1_5:SHA256')
        ac3.sign(key, 'RSASSA-PKCS1-v1_5:SHA256')
        ac4.sign(key, 'RSASSA-PKCS1-v1_5:SHA256')

        self.assertNotEqual(ac1.signature, None)
        self.assertNotEqual(ac2.signature, None)
        self.assertNotEqual(ac3.signature, None)
        self.assertNotEqual(ac4.signature, None)
        self.assertEqual(ac1.signature.sig_algo, 'RSASSA-PKCS1-v1_5:SHA256')
        self.assertEqual(ac2.signature.sig_algo, 'RSASSA-PKCS1-v1_5:SHA256')
        self.assertEqual(ac3.signature.sig_algo, 'RSASSA-PKCS1-v1_5:SHA256')
        self.assertEqual(ac4.signature.sig_algo, 'RSASSA-PKCS1-v1_5:SHA256')
        self.assertTrue(ac1.verify_signature())
        self.assertTrue(ac2.verify_signature())
        self.assertTrue(ac3.verify_signature())
        self.assertTrue(ac4.verify_signature())

    def test_bad_signature(self):
        key = RSA.generate(2048)
        pub_key = key.publickey().exportKey('DER')
        key_algo = 'RSA[%s]' % key.publickey().size_in_bits()

        ac1 = TestAttributeCertificate._make_basic_ac()
        ac2 = TestAttributeCertificate._make_full_ac()
        ac3 = TestAttributeCertificate._make_full_ac_with_nones()
        ac4 = TestAttributeCertificate._make_full_ac_with_half_nones()
        ac5 = TestAttributeCertificate._make_full_ac()
        ac6 = TestAttributeCertificate._make_basic_ac()
        ac7 = TestAttributeCertificate._make_basic_ac()
        ac8 = TestAttributeCertificate._make_basic_ac()

        ac1.issuer.pub_key = pub_key
        ac2.issuer.pub_key = pub_key
        ac3.issuer.pub_key = pub_key
        ac4.issuer.pub_key = pub_key
        ac5.issuer.pub_key = pub_key
        ac6.issuer.pub_key = pub_key
        ac7.issuer.pub_key = pub_key
        ac8.issuer.pub_key = pub_key
        ac1.issuer.key_algo = key_algo
        ac2.issuer.key_algo = key_algo
        ac3.issuer.key_algo = key_algo
        ac4.issuer.key_algo = key_algo
        ac5.issuer.key_algo = 'bad key algo'
        ac6.issuer.key_algo = key_algo
        ac7.issuer.key_algo = key_algo
        ac8.issuer.key_algo = key_algo

        ac1.sign(key, 'RSASSA-PKCS1-v1_5:SHA256')
        ac2.sign(key, 'RSASSA-PKCS1-v1_5:SHA256')
        ac3.sign(key, 'RSASSA-PKCS1-v1_5:SHA256')
        ac4.sign(key, 'RSASSA-PKCS1-v1_5:SHA256')
        ac5.sign(key, 'RSASSA-PKCS1-v1_5:SHA256')
        # ac6 intentionally not signed.
        ac7.sign(key, 'RSASSA-PKCS1-v1_5:SHA256')
        ac8.sign(key, 'RSASSA-PKCS1-v1_5:SHA256')

        ac1.holder.uid = 'bad uid'
        ac2.att_set[0].att_id = 'bad att_id'
        #ac3.signature.sig_algo = 'bad sig algo' # TODO: Test sig algo once it is checked in code.
        ac3.info.version = 100
        ac4.signature.sig_value = ac1.signature.sig_value
        ac5.issuer.uid = 'bad uid'
        ac7.signature.sig_algo = None
        ac8.signature.sig_value = None

        self.assertFalse(ac1.verify_signature())
        self.assertFalse(ac2.verify_signature())
        self.assertFalse(ac3.verify_signature())
        self.assertFalse(ac4.verify_signature())
        self.assertFalse(ac5.verify_signature())
        self.assertFalse(ac6.verify_signature())
        self.assertFalse(ac7.verify_signature())
        self.assertFalse(ac8.verify_signature())

    def test_full_encode_decode_no_sig(self):
        ac1 = TestAttributeCertificate._make_basic_ac()
        ac2 = TestAttributeCertificate._make_full_ac()
        ac3 = TestAttributeCertificate._make_full_ac_with_nones()
        ac4 = TestAttributeCertificate._make_full_ac_with_half_nones()

        ac1_encode = ac1.encode(sign=False)
        ac2_encode = ac2.encode(sign=False)
        ac3_encode = ac3.encode(sign=False)
        ac4_encode = ac4.encode(sign=False)

        new_ac1 = AttributeCertificate.decode(ac1_encode, verify=False)
        new_ac2 = AttributeCertificate.decode(ac2_encode, verify=False)
        new_ac3 = AttributeCertificate.decode(ac3_encode, verify=False)
        new_ac4 = AttributeCertificate.decode(ac4_encode, verify=False)

        self.assertEqual(ac1, new_ac1)
        self.assertEqual(ac2, new_ac2)
        self.assertEqual(ac3, new_ac3)
        self.assertEqual(ac4, new_ac4)

    def test_full_encode_decode_with_sig(self):
        key = RSA.generate(2048)
        pub_key = key.publickey().exportKey('DER')
        key_algo = 'RSA[%s]' % key.publickey().size_in_bits()

        ac1 = TestAttributeCertificate._make_basic_ac()
        ac2 = TestAttributeCertificate._make_full_ac()
        ac3 = TestAttributeCertificate._make_full_ac_with_nones()
        ac4 = TestAttributeCertificate._make_full_ac_with_half_nones()

        ac1.issuer.pub_key = pub_key
        ac2.issuer.pub_key = pub_key
        ac3.issuer.pub_key = pub_key
        ac4.issuer.pub_key = pub_key
        ac1.issuer.key_algo = key_algo
        ac2.issuer.key_algo = key_algo
        ac3.issuer.key_algo = key_algo
        ac4.issuer.key_algo = key_algo

        ac1_encode = ac1.encode(sign=True, prvi_key=key)
        ac2_encode = ac2.encode(sign=True, prvi_key=key)
        ac3_encode = ac3.encode(sign=True, prvi_key=key, sig_algo='RSASSA-PKCS1-v1_5:SHA256')
        ac4_encode = ac4.encode(sign=True, prvi_key=key, sig_algo='RSASSA-PKCS1-v1_5:SHA256')

        new_ac1 = AttributeCertificate.decode(ac1_encode, verify=True)
        new_ac2 = AttributeCertificate.decode(ac2_encode, verify=True)
        new_ac3 = AttributeCertificate.decode(ac3_encode, verify=True)
        new_ac4 = AttributeCertificate.decode(ac4_encode, verify=True)

        self.assertNotEqual(ac1.signature.sig_value, None)
        self.assertNotEqual(ac2.signature.sig_value, None)
        self.assertNotEqual(ac3.signature.sig_value, None)
        self.assertNotEqual(ac4.signature.sig_value, None)

        self.assertEqual(ac1.signature.sig_algo, 'RSASSA-PKCS1-v1_5:SHA256')
        self.assertEqual(ac2.signature.sig_algo, 'RSASSA-PKCS1-v1_5:SHA256')
        self.assertEqual(ac3.signature.sig_algo, 'RSASSA-PKCS1-v1_5:SHA256')
        self.assertEqual(ac4.signature.sig_algo, 'RSASSA-PKCS1-v1_5:SHA256')

        self.assertEqual(ac1, new_ac1)
        self.assertEqual(ac2, new_ac2)
        self.assertEqual(ac3, new_ac3)
        self.assertEqual(ac4, new_ac4)

        ac1.verify_signature()
        ac2.verify_signature()
        ac3.verify_signature()
        ac4.verify_signature()

    def test_str(self):
        key = RSA.generate(2048)
        ac1 = TestAttributeCertificate._make_basic_ac()
        ac2 = TestAttributeCertificate._make_full_ac()
        ac3 = TestAttributeCertificate._make_full_ac_with_nones()
        ac4 = TestAttributeCertificate._make_full_ac_with_half_nones()

        ac1.sign(key)
        ac2.sign(key)
        ac3.sign(key)
        # ac4 intentionally not signed

        str1 = str(ac1)
        str2 = str(ac2)
        str3 = str(ac3)
        str4 = str(ac4)

        # TODO: Test value of strings.
        # print(str1)
        # print(str2)
        # print(str3)
        # print(str4)

    def test_import_export(self):
        key = RSA.generate(2048)
        pub_key = key.publickey().exportKey('DER')
        key_algo = 'RSA[%s]' % key.publickey().size_in_bits()

        ac1 = TestAttributeCertificate._make_full_ac()
        ac2 = TestAttributeCertificate._make_full_ac()
        ac3 = TestAttributeCertificate._make_full_ac()
        ac4 = TestAttributeCertificate._make_full_ac()
        ac5 = TestAttributeCertificate._make_full_ac()
        ac6 = TestAttributeCertificate._make_full_ac()
        ac7 = TestAttributeCertificate._make_full_ac()
        ac8 = TestAttributeCertificate._make_full_ac()

        ac1.issuer.pub_key = pub_key
        ac2.issuer.pub_key = pub_key
        ac3.issuer.pub_key = pub_key
        ac4.issuer.pub_key = pub_key
        ac5.issuer.pub_key = pub_key
        ac6.issuer.pub_key = pub_key
        ac7.issuer.pub_key = pub_key
        ac8.issuer.pub_key = pub_key
        ac1.issuer.key_algo = key_algo
        ac2.issuer.key_algo = key_algo
        ac3.issuer.key_algo = key_algo
        ac4.issuer.key_algo = key_algo
        ac5.issuer.key_algo = key_algo
        ac6.issuer.key_algo = key_algo
        ac7.issuer.key_algo = key_algo
        ac8.issuer.key_algo = key_algo

        out1 = ac1.export_ac()
        out2 = ac2.export_ac(format=ExportFormat.BASE64)
        out3 = ac3.export_ac(format=ExportFormat.BASE64FULL)
        out4 = ac4.export_ac(format=ExportFormat.TEXT)
        # TODO: Test XML import/export when done.
        out5 = ac5.export_ac(format=ExportFormat.BYTES, sign=True, prvi_key=key)
        out6 = ac6.export_ac(format=ExportFormat.BASE64, sign=True, prvi_key=key, sig_algo='RSASSA-PKCS1-v1_5:SHA256')
        out7 = ac7.export_ac(format=ExportFormat.BASE64FULL, sign=True, prvi_key=key)
        out8 = ac8.export_ac(format=ExportFormat.TEXT, sign=True, prvi_key=key)

        newac1 = AttributeCertificate.import_ac(out1)
        newac2 = AttributeCertificate.import_ac(out2, format=ExportFormat.BASE64)
        newac3 = AttributeCertificate.import_ac(out3, format=ExportFormat.BASE64FULL)
        # TODO: Test text output validity.
        newac5 = AttributeCertificate.import_ac(out5, format=ExportFormat.BYTES, verify=True)
        newac6 = AttributeCertificate.import_ac(out6, format=ExportFormat.BASE64, verify=True)
        newac7 = AttributeCertificate.import_ac(out7, format=ExportFormat.BASE64FULL, verify=True)

        self.assertTrue(newac5.verify_signature())
        self.assertTrue(newac6.verify_signature())
        self.assertTrue(newac7.verify_signature())

        self.assertTrue(ac5.verify_signature())
        self.assertTrue(ac6.verify_signature())
        self.assertTrue(ac7.verify_signature())
        self.assertTrue(ac8.verify_signature())

        self.assertEqual(ac1, newac1)
        self.assertEqual(ac2, newac2)
        self.assertEqual(ac3, newac3)
        self.assertEqual(ac5, newac5)
        self.assertEqual(ac6, newac6)
        self.assertEqual(ac7, newac7)
