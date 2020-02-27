from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy import Column, Integer, String, Text, ForeignKey, BigInteger, DateTime, LargeBinary
from sqlalchemy.types import Enum
from sqlalchemy.orm import relationship

from hgaa.attcert import AttributeType


PAuthBase = declarative_base(name='PAuthBase')
table_prefix = "pauth_"


class AttributeAuthority(PAuthBase):
    __tablename__ = table_prefix + 'attribute_authorities'
    uid = Column('uid', String(100), primary_key=True)
    name = Column('name', String(100), nullable=False)
    url = Column('url', String(100), nullable=False)
    key_cipher = Column('key_cipher', String(100), nullable=False)
    key_size = Column('key_size', Integer, nullable=False)
    pub_key = Column('pub_key', Text, nullable=False)
    trust_level = Column('trust_level', Integer, nullable=False)

#class PolicyAttribute(PAuthBase):
#    __tablename__ = 'policy_attributes'
#    policy_id = Column('policy_id', String, ForeignKey(table_prefix+'policies.uid'), primary_key=True)
#    attribute_id = Column('attribute_id', String, primary_key=True)
#
#    policy = relationship('Policy', back_populates='attributes')
#    attribute = relationship('Attribute', back_populates='policies')

# Admin and static environment attributes
class Attribute(PAuthBase):
    __tablename__ = table_prefix + 'attributes'
    uid = Column('uid', String(100), primary_key=True)
    name = Column('name', String(100), nullable=True)
    type = Column('type', Enum(AttributeType), nullable=False)
    value = Column('value', String(100), nullable=True)

#    policies = relationship('PolicyAttribute', back_populates='attribute')


class Policy(PAuthBase):
    __tablename__ = table_prefix + 'policies'
    uid = Column('uid', String(100), primary_key=True)
    name = Column('name', String(100), nullable=True)
    policy = Column('policy', Text, nullable=False)
    ast = Column('ast', LargeBinary, nullable=True)

 #   attributes = relationship('PolicyAttribute', back_populates='policy')


class AttributeCertificate(PAuthBase):
    __tablename__ = table_prefix + 'attribute_certificates'
    serial = Column('serial', String(50), primary_key=True)
    certificate = Column('certificate', LargeBinary, nullable=False)
    format = Column('format', Integer, nullable=False)
    version = Column('version', Integer, nullable=False)
    valid_till = Column('valid_till', Integer, nullable=False)
    hash = Column('hash', Text, nullable=False)

    sessions = relationship('AttributeCertificateAssignment', back_populates='attribute_certificates')


class AttributeCertificateAssignment(PAuthBase):
    __tablename__ = table_prefix + 'attribute_certificate_assignments'
    ac_serial = Column('ac_serial', String(50), ForeignKey(table_prefix+'attribute_certificates.serial'), primary_key=True)
    session_id = Column('session_id', String(50), ForeignKey(table_prefix+'sessions.id'), primary_key=True)

    sessions = relationship('Session', back_populates='attribute_certificates')
    attribute_certificates = relationship('AttributeCertificate', back_populates='sessions')


class Session(PAuthBase):
    __tablename__ = table_prefix + 'sessions'
    id = Column('id', String(50), primary_key=True)
    cert_start = Column('cert_start', Integer, nullable=False)
    cert_valid_till = Column('cert_valid_till', Integer, nullable=False)
    session_start = Column('session_start', Integer, nullable=False)
    initial_service_ip = Column('initial_service_ip', String(100), nullable=False)
    service_uid = Column('name', String(100), nullable=False)
    session_valid_till = Column('session_valid_till', Integer, nullable=False)

    attribute_certificates = relationship('AttributeCertificateAssignment', back_populates='sessions')