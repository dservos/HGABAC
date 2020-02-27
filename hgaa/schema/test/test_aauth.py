from hgaa.schema.aauth import User, Attribute, AttributeAssignment
from hgaa.attcert import AttributeType

DB_TEST_SET = (
    User(id=1, username='dan', password='$2b$12$QN689kLXzZ.wCmCr8ykOr.lPSoepRtvBZdPHioZYtPTQ9K6ZkWvWq'),     # Pass: admin
    User(id=2, username='jess', password='$2b$12$zGQE2YzG.IGAy6qsnxCyI.yBJeFSEycPCH.9iuRjn11O2Le9O2LNW'),    # Pass: password
    User(id=3, username='alice', password='$2b$12$WTZb9Axx4mOmCmwqtZ.8qu/Z/pUNcsuftJAxloft66M0wCEsA9tO6'),   # Pass: pass1234567890
    User(id=4, username='bob', password='$2b$12$PX3OdDeUgflz9KOJ3aPznuK4gj/aQnPZ96CgIh3J8yX0T0OCmA4Oy'),     # Pass: ThIsIsMyPassWord123ABC
    User(id=5, username='charlie', password='$2b$12$c7bvChM0FGg7.ISaMi/jZO9VpDlm8CR2aOnRI7bv6YAb6WCm.ilI2'), # Pass: password with a space
    User(id=6, username='david', password='$2b$12$YdYF3gxSGPi9YOvTLIvu2OGJjlJsRQyZ7/X1LFIEtle72JTQ12/0C'),   # Pass: D
    User(id=7, username='eve', password='$2b$12$ztnUuCfMtmaROESHahZPVeHyxbvcyLxMPXY8X9oMMx8XV9wtt.r/6'),     # Pass: Test_#$%^&*()!@~`{}|\][:"';?><,./ABCabc123
    Attribute(id='/attribute/user/user_id', name='user_id', type=AttributeType.INT),
    Attribute(id='/attribute/user/name', name='name', type=AttributeType.STRING),
    Attribute(id='/attribute/user/age', name='age', type=AttributeType.INT),
    Attribute(id='/attribute/user/credits', name='credits', type=AttributeType.FLOAT),
    Attribute(id='/attribute/user/year_level', name='year_level', type=AttributeType.INT),
    Attribute(id='/attribute/user/department', name='department',  type=AttributeType.STRING),
    Attribute(id='/attribute/user/student_type', name='student_type', type=AttributeType.STRING),
    Attribute(id='/attribute/user/courses', name='courses', type=AttributeType.SET),
    Attribute(id='/attribute/user/student', name='student', type=AttributeType.BOOL),
    Attribute(id='/attribute/user/staff', name='staff', type=AttributeType.BOOL),
    Attribute(id='/attribute/user/admin', name='admin', type=AttributeType.BOOL),
    Attribute(id='/attribute/user/office', name='office', type=AttributeType.STRING),
    Attribute(id='/attribute/user/account_balance', name='account_balance', type=AttributeType.FLOAT),
    Attribute(id='/attribute/user/registered', name='registered', type=AttributeType.NULL),
    AttributeAssignment(user_id=1, att_id='/attribute/user/admin', value='TRUE'),
    AttributeAssignment(user_id=1, att_id='/attribute/user/age', value='31'),
    AttributeAssignment(user_id=1, att_id='/attribute/user/name', value='Daniel Servos'),
    AttributeAssignment(user_id=1, att_id='/attribute/user/account_balance', value='9999.9999'),
    AttributeAssignment(user_id=1, att_id='/attribute/user/courses', value='CS2211,CS2034,CS1234,CS5678,CS9000'),
    AttributeAssignment(user_id=1, att_id='/attribute/user/registered')
)