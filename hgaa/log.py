import logging
import datetime
import os

from hgaa.config import get_conf

# TODO: Fix client log overwriting service logs (client should not make service logs and vice versa).

LOG_DIR = os.path.dirname(os.path.abspath(__file__)) + '/logs/'

ROOT_LOG = logging.getLogger('hgaa')
ROOT_LOG.info('HGAA root log started on %s', datetime.datetime.now())

SERVICE_LOG = None
CLIENT_LOG = None
SQL_LOG = None
LADON_LOG = None


def str_to_log_level(string):
    string = string.upper()

    if string == 'ALL' or string == 'DEBUG':
        loglevel = logging.DEBUG
    elif string == 'WARN' or string == 'WARNING':
        loglevel = logging.WARN
    elif string == 'INFO' or string == 'INFORMATION':
        loglevel = logging.INFO
    elif string == 'ERROR':
        loglevel = logging.ERROR
    elif string == 'CRITICAL':
        loglevel = logging.CRITICAL
    else:
        loglevel = logging.NOTSET

    return loglevel


def make_logger(hgaa_name, service=True, parent=None):
    global SERVICE_LOG, ROOT_LOG, CLIENT_LOG

    hgaa_name = hgaa_name.upper()

    logfile = get_conf('LOG_FILE', service, hgaa_name)
    loglevelstr = get_conf('LOG_LEVEL', service, hgaa_name)
    loglevel = str_to_log_level(loglevelstr)
    logformat = get_conf('LOG_FORMAT', service, hgaa_name)
    logname = get_conf('LOG_NAME', service, hgaa_name)
    dateformat = get_conf('LOG_DATE_FORMAT', service, hgaa_name)
    logstdout = get_conf('LOG_STDOUT', service, hgaa_name)
    clean = get_conf('CLEAN_LOG_ON_START', service, hgaa_name)

    if logfile is not None and logfile.lower() != 'none' and logfile.lower() != 'false' and logfile != '':
        logfile = LOG_DIR + logfile

    if service:
        if SERVICE_LOG is not None:
            SERVICE_LOG.debug("Adding service logger for " + SERVICE_LOG.name + "." + logname)
        else:
            ROOT_LOG.debug("Adding root service logger " + ROOT_LOG.name + "." + logname)
    else:
        if CLIENT_LOG is not None:
            CLIENT_LOG.debug("Adding client logger for " + CLIENT_LOG.name + "." + logname)
        else:
            ROOT_LOG.debug("Adding root client logger " + ROOT_LOG.name + "." + logname)

    if parent is None:
        if service:
            logger = SERVICE_LOG.getChild(logname)
        else:
            logger = CLIENT_LOG.getChild(logname)
    else:
        logger = parent.getChild(logname)

    logger.setLevel(loglevel)

    formatter = logging.Formatter(logformat, dateformat)

    if logfile is not None and logfile.upper() != "NONE" and logfile.upper() != "FALSE":
        if clean.upper() == 'TRUE':
            handler = logging.FileHandler(logfile, mode='w')
        else:
            handler = logging.FileHandler(logfile)

        handler.setFormatter(formatter)
        logger.addHandler(handler)

    if logstdout.upper() == 'TRUE':
        stream = logging.StreamHandler()
        stream.setFormatter(formatter)
        logger.addHandler(stream)

    logger.info('%s log started on %s', logger.name, datetime.datetime.now())
    return logger


def _make_ladon_log():
    global LADON_LOG
    LADON_LOG = logging.getLogger('ladonlogger')

    LADON_LOG.parent = ROOT_LOG
    LADON_LOG.setLevel(str_to_log_level(get_conf('LOG_LEVEL', True, 'LADON')))

    if get_conf('CLEAN_LOG_ON_START', True, 'DEFAULT').upper() == 'TRUE':
        handler = logging.FileHandler(LOG_DIR + get_conf('LOG_FILE', True, 'LADON'), mode='w')
    else:
        handler = logging.FileHandler(LOG_DIR + get_conf('LOG_FILE', True, 'LADON'))

    formatter = logging.Formatter(get_conf('LOG_FORMAT', True, 'LADON'),
                                   get_conf('LOG_DATE_FORMAT', True, 'LADON'))
    handler.setFormatter(formatter)

    LADON_LOG.addHandler(handler)
    if get_conf('LOG_STDOUT', True, 'LADON').upper() == 'TRUE':
        stream = logging.StreamHandler()
        stream.setFormatter(formatter)
        LADON_LOG.addHandler(stream)
    LADON_LOG.info('LADON log started on %s', datetime.datetime.now())


def _make_sql_log():
    global SQL_LOG
    SQL_LOG = logging.getLogger('sqlalchemy')

    SQL_LOG.parent = ROOT_LOG
    SQL_LOG.setLevel(str_to_log_level(get_conf('SQL_LOG_LEVEL', True, 'DEFAULT')))

    if get_conf('CLEAN_LOG_ON_START', True, 'DEFAULT').upper() == 'TRUE':
        handler = logging.FileHandler(LOG_DIR + get_conf('SQL_LOG_FILE', True, 'DEFAULT'), mode='w')
    else:
        handler = logging.FileHandler(LOG_DIR + get_conf('SQL_LOG_FILE', True, 'DEFAULT'))

    formatter = logging.Formatter(get_conf('SQL_LOG_FORMAT', True, 'DEFAULT'),
                                   get_conf('SQL_LOG_DATE_FORMAT', True, 'DEFAULT'))
    handler.setFormatter(formatter)
    SQL_LOG.addHandler(handler)
    if get_conf('SQL_LOG_STDOUT', True, 'DEFAULT').upper() == 'TRUE':
        stream = logging.StreamHandler()
        stream.setFormatter(formatter)
        SQL_LOG.addHandler(stream)
    SQL_LOG.info('SQL log started on %s', datetime.datetime.now())


SERVICE_LOG = make_logger('DEFAULT', True, ROOT_LOG)
CLIENT_LOG = make_logger('DEFAULT', False, ROOT_LOG)
_make_sql_log()
_make_ladon_log()

