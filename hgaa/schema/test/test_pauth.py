from hgaa.attcert import AttributeType
from hgaa.schema.pauth import AttributeAuthority, Attribute, Policy

DB_TEST_SET = (
    AttributeAuthority(uid="hgabac://localhost:8888", name="localhost", url="http://localhost:8888/AttributeAuthority",
                       key_cipher="RSA", key_size=2048, trust_level=100,
                       pub_key='-----BEGIN RSA PUBLIC KEY-----\n'
                               'MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA57+4n5L6qOTHD17aeq87\n'
                               'mwz+HQoJDySnI9E0d5qv4YcdFvYf4uUHL4SsyKvIGsU6mRchqJCWqax0Xefp2Th+\n'
                               'x3n9oGZFEY0kbX1nnZ2DNVkApf3u7F/Kcka9Euufm66gRhPS6EtX1go3woX0lYvh\n'
                               'y6FuNlFnvuwc4eYWcr4I9IB65JE8HuXstW7cVVpuHti/4aI24Hsba8ZEtlN8T3oK\n'
                               'UpUFGLo+YzQTlySeJ3wPpZBevq3NRC82s7mcFl8B5CEJ1o0e9GPMTjrePMd5QLYO\n'
                               '+MsZ9y6a1B1w4rogpB4QTtZRdWcLmea4koKnlkOwXY3CZhcvxIdGFPsug8OT2v+z\n'
                               'dwIDAQAB\n'
                               '-----END RSA PUBLIC KEY-----'),
    Policy(uid="hgabc://localhost:8888/policy/p1", name="p1",
           policy="user.id IN {5, 72, 4, 6, 4} OR user.id = object.owner", ast=None),
    Policy(uid="hgabc://localhost:8888/policy/p2", name="p2",
           policy="object.required_perms SUBSET user.perms AND user.age >= 18", ast=None),
    Policy(uid="hgabc://localhost:8888/policy/p3", name="p3",
           policy="user.admin OR (user.role = \"doctor\" AND user.id != object.patient)", ast=None),
    Attribute(uid="hgabc://localhost:8888/attribute/admin/trust_level", name="trust_level", value="50",
              type=AttributeType.INT),
    Attribute(uid="hgabc://localhost:8888/attribute/admin/admin_user", name="admin_user",
              value="hgabc://localhost:8888/user/dan", type=AttributeType.STRING),
    Attribute(uid="hgabc://localhost:8888/attribute/environment/pl_ver", name="pl_ver",
              value=1, type=AttributeType.INT),
    Attribute(uid="hgabc://localhost:8888/attribute/environment/pa_ver", name="pa_ver",
              value=1, type=AttributeType.INT),
    Attribute(uid="hgabc://localhost:8888/attribute/environment/pa_uid", name="pa_uid", value="hgabc://localhost:8888",
              type=AttributeType.STRING),
    Attribute(uid="hgabc://localhost:8888/attribute/environment/pa_name", name="pa_name", value="localhost:8888",
              type=AttributeType.STRING)
)