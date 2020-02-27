from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy import Column, Integer, String, ForeignKey
from sqlalchemy.types import Enum
from sqlalchemy.orm import relationship

from hgaa.attcert import AttributeType


AAuthBase = declarative_base(name='AAuthBase')
table_prefix = 'aauth_'


class Attribute(AAuthBase):
    __tablename__ = table_prefix + 'attributes'

    id = Column('id', String(100), primary_key=True)
    name = Column('name', String(100), nullable=False)
    type = Column('type', Enum(AttributeType))

    values = relationship('AttributeAssignment', back_populates='attribute')


class User(AAuthBase):
    __tablename__ = table_prefix + 'users'

    id = Column('id', Integer, primary_key=True) # TODO: Use user uid.
    username = Column('username', String(25), nullable=False)
    password = Column('password', String(60), nullable=False)

    attributes = relationship('AttributeAssignment', back_populates='user')


class AttributeAssignment(AAuthBase):
    __tablename__ = table_prefix + 'attribute_assignments'

    user_id = Column('user_id', Integer, ForeignKey(table_prefix + 'users.id'), primary_key=True)
    att_id = Column('att_id', String(100), ForeignKey(table_prefix + 'attributes.id'), primary_key=True)

    value = Column('value', String(100), nullable=True)

    user = relationship('User', back_populates='attributes')
    attribute = relationship('Attribute', back_populates='values')
