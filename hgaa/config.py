import configparser
import os


# TODO: Fix paths in all packages/modules like this?
CONFIG_FILE_DIR = os.path.dirname(os.path.abspath(__file__)) + '/confs/'

DEFAULT_SERVICE_CONFIGS = {
    'DB_TYPE': 'mysql',
    'DB_NAME': 'hgaa',
    'DB_USER': None,
    'DB_PASS': None,
    'DB_PORT': '3306',
    'DB_HOST': 'localhost',
    'LOG_LEVEL': 'ALL',
    'LOG_FILE': 'hgaa_service.log',
    'LOG_FORMAT': '%(asctime)s: [%(levelname)s: %(name)s] %(message)s',
    'LOG_DATE_FORMAT': '%m/%d/%Y %I:%M:%S %p',
    'LOG_NAME': 'services',
    'LOG_STDOUT': 'True',
    'SQL_LOG_LEVEL': 'ALL',
    'SQL_LOG_FILE': 'sql.log',
    'SQL_LOG_FORMAT': '%(asctime)s: [%(levelname)s: %(name)s] %(message)s',
    'SQL_LOG_DATE_FORMAT': '%m/%d/%Y %I:%M:%S %p',
    'SQL_LOG_STDOUT': 'True',
    'CLEAN_LOG_ON_START': 'True',
    'SERVICE_ENABLED': 'True',
    'SERVICE_PORT': '8888',
    'SERVICE_HOST': ''
}

DEFAULT_CLIENT_CONFIGS = {
    'LOG_LEVEL': 'ALL',
    'LOG_FILE': 'hgaa_client.log',
    'LOG_FORMAT': '%(asctime)s: [%(levelname)s: %(name)s] %(message)s',
    'LOG_DATE_FORMAT': '%m/%d/%Y %I:%M:%S %p',
    'LOG_NAME': 'clients',
    'LOG_STDOUT': 'True',
    'CLEAN_LOG_ON_START': 'False'
}

SERVICE_CONFIG = configparser.ConfigParser()
CLIENT_CONFIG = configparser.ConfigParser()

try:
    SERVICE_CONFIG.read(CONFIG_FILE_DIR + 'services.ini')
except Exception as e:
    raise e

try:
    CLIENT_CONFIG.read(CONFIG_FILE_DIR + 'clients.ini')
except Exception as e:
    raise e


def get_conf(val_name, service=True, sect='DEFAULT'):
    global SERVICE_CONFIG, CLIENT_CONFIG

    val_name = val_name.upper()
    sect = sect.upper()

    if service:
        if SERVICE_CONFIG.has_section(sect):
            conf = SERVICE_CONFIG[sect]
        else:
            sect = 'DEFAULT'
            conf = SERVICE_CONFIG['DEFAULT']
    else:

        if CLIENT_CONFIG.has_section(sect):
            conf = CLIENT_CONFIG[sect]
        else:
            sect = 'DEFAULT'
            conf = CLIENT_CONFIG['DEFAULT']

    val = conf.get(val_name, None)

    if val is None:
        if sect == 'DEFAULT':
            if service:
                val = DEFAULT_SERVICE_CONFIGS.get(val_name, None)
            else:
                val = DEFAULT_CLIENT_CONFIGS.get(val_name, None)
        else:
            val = get_conf(val_name, service, 'DEFAULT')

    return val
