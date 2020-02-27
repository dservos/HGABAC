import sys
from Crypto.PublicKey import RSA
import bcrypt

import hgaa.schema as schema
from hgaa.log import make_logger, SERVICE_LOG, CLIENT_LOG
from hgaa.database import get_engine, populate_db, get_session
from hgaa.config import get_conf
from hgaa.schema.test import test_aauth
from hgaa.schema.test import test_pauth
from hgaa.schema.aauth import User, Attribute, AttributeAssignment
from hgaa.attcert import AttributeType

SERVICE_TOOLS_LOG = make_logger('TOOLS', True, SERVICE_LOG)
CLIENT_TOOLS_LOG = make_logger('TOOLS', False, CLIENT_LOG)


def build_database(services):
    # TODO: Only run command if all services are valid.
    SERVICE_TOOLS_LOG.info('Building databases for services ' + ', '.join(services))
    for s in services:
        base = schema.ServiceBases.get(s, None)
        if base is not None:
            engine = get_engine(s, SERVICE_TOOLS_LOG)
            if engine is not None:
                SERVICE_TOOLS_LOG.debug('Creating all tables for service ' + s)
                base.metadata.create_all(engine)
                engine.dispose()
                SERVICE_TOOLS_LOG.debug('Finished creating tables for service ' + s)
            else:
                SERVICE_TOOLS_LOG.error('Could not make engine for ' + s)
                raise Exception('Could not make engine for ' + s)
        else:
            SERVICE_TOOLS_LOG.error('No service with name ' + s)
            raise Exception('No service with name ' + s)
    SERVICE_TOOLS_LOG.info('Finished building databases.')


def gen_aauth_key(key_file, key_pass, key_size=2048):
    SERVICE_TOOLS_LOG.info('Generating new private/public key pair for AAUTH service.')
    key = RSA.generate(key_size)
    SERVICE_TOOLS_LOG.info('Encrypting new private/public key pair.')
    encrypted_key = key.exportKey(passphrase=key_pass, pkcs=8, protection="scryptAndAES128-CBC")
    file_out = open(key_file, "wb")
    SERVICE_TOOLS_LOG.info('Saving new private/public key pair to %s' % key_file)
    file_out.write(encrypted_key)
    file_out.close()
    SERVICE_TOOLS_LOG.info('Finished generating key pair.')


def gen_atts(num_atts):
    SERVICE_TOOLS_LOG.info('Generating %d attributes.' % num_atts)
    session = get_session("AAUTH")()

    att_set = []
    for i in range(0, num_atts):
        att_set.append(Attribute(id='/attribute/user/a%d' % i, name='a%d' % i, type=AttributeType.INT))
        att_set.append(AttributeAssignment(user_id=1, att_id='/attribute/user/a%d' % i, value='%d' % i))

    SERVICE_TOOLS_LOG.info('Adding attributes to AAUTH database.')
    session.add_all(att_set)
    session.commit()
    session.close()
    SERVICE_TOOLS_LOG.info('Population of attributes complete.')


def pop_and_gen(num_atts):
    populate_db('AAUTH', [User(id=1, username='dan', password='$2b$12$QN689kLXzZ.wCmCr8ykOr.lPSoepRtvBZdPHioZYtPTQ9K6ZkWvWq')], wipe_first=True, use_test_db=False,
                parent_log=SERVICE_TOOLS_LOG)
    gen_atts(num_atts)


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Need at least one command argument. Valid commands are: build, genkey.")
        raise Exception("Need at least one command argument.")

    if sys.argv[1].lower() == 'build':
        if len(sys.argv) < 3:
            print("Need at least one service name or just \"all\"")
            raise Exception("Need at least one service name.")
        elif sys.argv[2] == "all" and len(sys.argv) == 3:
            services = schema.ServiceBases.keys()
        else:
            services = [x.lower() for x in sys.argv[2:]]

        build_database(services)
    elif sys.argv[1].lower() == 'genkey':
        if len(sys.argv) != 3:
            print("Need second argument listing key type to generate. Valid types are: aauth.")
            raise Exception("Need a key type.")
        elif sys.argv[2].lower() == 'aauth':
            key_file = get_conf('KEY_FILE', True, 'AAUTH')
            key_pass = get_conf('KEY_PASS', True, 'AAUTH')
            gen_aauth_key(key_file, key_pass)
        else:
            print('Unknown key type: %s' % sys.argv[2].lower())
            raise Exception("Unknown key type.")
    elif sys.argv[1].lower() == 'populate' or sys.argv[1].lower() == 'pop':
        if len(sys.argv) != 3:
            print("Need second argument listing service to populate. Valid types are: all, aauth or pauth")
            raise Exception("Need a service name.")
        # TODO: Automate finding tests like build does with services.
        elif sys.argv[2].lower() == 'all':
            populate_db('AAUTH', test_aauth.DB_TEST_SET, wipe_first=True, use_test_db=False,
                        parent_log=SERVICE_TOOLS_LOG)
            populate_db('PAUTH', test_pauth.DB_TEST_SET, wipe_first=True, use_test_db=False,
                        parent_log=SERVICE_TOOLS_LOG)
        elif sys.argv[2].lower() == 'aauth':
            populate_db('AAUTH', test_aauth.DB_TEST_SET, wipe_first=True, use_test_db=False,
                        parent_log=SERVICE_TOOLS_LOG)
        elif sys.argv[2].lower() == 'pauth':
            populate_db('PAUTH', test_pauth.DB_TEST_SET, wipe_first=True, use_test_db=False,
                        parent_log=SERVICE_TOOLS_LOG)
        else:
            print('Unknown key type: %s' % sys.argv[2].lower())
            raise Exception("Unknown key type.")
    elif sys.argv[1].lower() == 'password' or sys.argv[1].lower() == 'pass':
        if len(sys.argv) != 4:
            print("Need second and third argument listing service to make password for and password plaintext.")
            raise Exception("Need a service name.")
        else:
            pass_pepper = get_conf('PASS_PEPPER', True, sys.argv[2].upper())
            hash = bcrypt.hashpw(('%s%s' % (sys.argv[3], pass_pepper)).encode(), bcrypt.gensalt())
            print("Password: %s\nHash: %s" % (sys.argv[3], hash.decode("utf-8")))
    elif sys.argv[1].lower() == 'genatts':
        if len(sys.argv) != 3:
            print("Need second argument giving number of attributes to generate.")
            raise Exception("Need number of attributes.")
        else:
            gen_atts(int(sys.argv[2]))