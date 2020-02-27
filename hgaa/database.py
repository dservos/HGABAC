from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from hgaa.config import get_conf
from hgaa.log import SERVICE_LOG
from hgaa.schema import ServiceBases

ACTIVE_ENGINES = {}


def populate_db(hgaa_name, instances, wipe_first=False, use_test_db=False, parent_log=SERVICE_LOG):
    if use_test_db:
        # TODO: Add testing configs
        logname = get_conf('LOG_NAME', True, hgaa_name + '_TEST')
        dbname = get_conf('DB_NAME', True, hgaa_name + '_TEST')
        session = get_session(hgaa_name + '_TEST')()
    else:
        logname = get_conf('LOG_NAME', True, hgaa_name)
        dbname = get_conf('DB_NAME', True, hgaa_name)
        session = get_session(hgaa_name)()

    log = parent_log.getChild(logname)
    log.info('Starting population of tables for database %s' % dbname)

    if wipe_first:
        log.info('Wiping rows from tables in %s' % dbname)
        base = ServiceBases.get(hgaa_name.lower(), None)

        if base is None:
            log.error('HGAA name, %s, does not have known database linked to it.' % hgaa_name)
            raise Exception("ERROR: HGAA name, %s, does not have known database linked to it." % hgaa_name)

        for table in reversed(base.metadata.sorted_tables):
            log.debug('Wiping table %s.' % table.name)
            session.execute(table.delete())
        log.debug('Committing wipe for %s.' % dbname)
        session.commit()
        log.info('Wipe complete.')

    log.info('Adding all model instances to %s database.' % dbname)
    session.add_all(instances)
    session.commit()
    session.close()
    log.info('Population of %s complete.' % dbname)


def get_session(hgaa_name, parent_log=SERVICE_LOG):
    engine = get_engine(hgaa_name, parent_log)
    Session = sessionmaker(bind=engine)
    return Session


def get_engine(hgaa_name, parent_log=SERVICE_LOG):
    global ACTIVE_ENGINES
    engine = ACTIVE_ENGINES.get(hgaa_name, None)

    if engine is None:
        dbname = get_conf('DB_NAME', True, hgaa_name)
        dbuser = get_conf('DB_USER', True, hgaa_name)
        dbpass = get_conf('DB_PASS', True, hgaa_name)
        dbport = get_conf('DB_PORT', True, hgaa_name)
        dbhost = get_conf('DB_HOST', True, hgaa_name)
        dbtype = get_conf('DB_TYPE', True, hgaa_name)
        logname = get_conf('LOG_NAME', True, hgaa_name)

        log = parent_log.getChild(logname)
        log.info('Creating %s database engine for %s', dbtype, hgaa_name)

        if dbtype.upper() == 'MYSQL':
            connect = 'mysql+mysqlconnector://{user}:{password}@{host}:{port}/{dbname}'.format(user=dbuser, password=dbpass,
                                                                                     host=dbhost, dbname=dbname,
                                                                                     port=dbport)
        elif dbtype.upper() == 'SQLITE':
            connect = 'sqlite:///{dbname}.db'.format(dbname=dbname)
        elif dbtype.upper() == 'MEMORY':
            connect = 'sqlite://'
        else:
            log.error('Database type ' + dbtype + ' is not supported.')
            return None

        log.debug('Connection string: %s', connect)
        engine = create_engine(connect, echo=False, logging_name=log.name, pool_logging_name=log.name)
        ACTIVE_ENGINES[hgaa_name] = engine
    return engine


