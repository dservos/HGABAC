from ladon.server.wsgi import LadonWSGIApplication
import wsgiref.simple_server
from os.path import normpath,abspath,dirname,join
from ladon.tools.log import set_loglevel,set_logfile,set_log_backup_count,set_log_maxsize
import logging

from hgaa.config import get_conf
from hgaa.services import ServiceList
from hgaa.log import str_to_log_level, LADON_LOG


LADON_LOG.info('Setting up Ladon logging.')

#set_logfile(get_conf('LOG_FILE', True, 'LADON'))
set_logfile(None)

log_level = str_to_log_level(get_conf('LOG_LEVEL', True, 'LADON'))
LADON_LOG.debug('Setting Ladon log level to %s.' % logging.getLevelName(log_level))
if log_level == logging.DEBUG:
    set_loglevel(6)
elif log_level == logging.WARN:
    set_loglevel(5)
elif log_level == logging.INFO:
    set_loglevel(4)
elif log_level == logging.ERROR:
    set_loglevel(3)
elif log_level == logging.CRITICAL:
    set_loglevel(1)
elif log_level == logging.NOTSET:
    set_loglevel(0)

set_log_backup_count(50)
set_log_maxsize(50000)

scriptdir = dirname(abspath(__file__))
LADON_LOG.debug('Script dir is ' + scriptdir)

LADON_LOG.info('Finding and adding service modules.')
service_modules = []
for s in ServiceList.keys():
    LADON_LOG.debug('Found service module %(module)s.' % {'module': s})
    if get_conf('SERVICE_ENABLED', True, s).upper() == 'TRUE':
        LADON_LOG.debug('Adding service module %(module)s with class %(class)s.' % {'module': s,
                                                                                            'class': ServiceList[s]})
        service_modules.append(s)
    else:
        LADON_LOG.debug('%(module)s is not enabled.' % {'module': s})


LADON_LOG.info('Making Ladon WSGI Application.')
application = LadonWSGIApplication(
    service_modules,
    join(scriptdir,'services'),
    catalog_name = 'HGABAC Architecture Services',
    catalog_desc = 'Services to support the HGABAC architecture',
    logging=31)

if __name__ == '__main__':
    port = int(get_conf('SERVICE_PORT', True, 'LADON'))
    host = get_conf('SERVICE_HOST', True, 'LADON')
    host_print = 'localhost' if host.strip() == '' else host
    LADON_LOG.info('Making WSGI simple server on port %(port)s at http://%(host)s:%(port)s' %
                           {'port': port,
                            'host': host_print})
    server = wsgiref.simple_server.make_server(host, port, application)
    LADON_LOG.info('Starting WSGI simple server.')
    server.serve_forever()