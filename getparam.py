#!/usr/bin/env python2

import sys, os, time
import logging
import argparse
import r2p
from helpers import *


def _create_argsparser():
    parser = argparse.ArgumentParser(
        description='R2P get app parameter'
    )
    
    parser.add_argument(
        '-v', '--verbose', required=False, action='count', default=0,
        help='verbosity level (default %(default)s): 0=critical, 1=error, 2=warning, 3=info, 4=debug',
        dest='verbosity'
    )
    
    group = parser.add_argument_group('transport setup')
    group.add_argument(
        '-p', '--transport', required=False, nargs='+',
        default=['DebugTransport', 'SerialLineIO', '/dev/ttyUSB0', 115200],
        help='transport parameters',
        dest='transport', metavar='PARAMS'
    )
    group.add_argument(
        '-t', '--boot-topic', required=True,
        help='name of the bootloader topic for the target R2P module; format: "[\\w]{1,%d}"' % r2p.MODULE_NAME_MAX_LENGTH,
        dest='boot_topic_name', metavar='BOOT_TOPIC'
    )
    group.add_argument(
        '-e', '--boot-module', required=True,
        help='name of the target R2P module; format: "[\\w]{1,%d}"' % r2p.MODULE_NAME_MAX_LENGTH,
        dest='boot_module_name', metavar='BOOT_MODULE'
    )
    
    group = parser.add_argument_group('parameter setup')
    group.add_argument(
        '-n', '--app-name', required=True,
        help='name of the app (R2P Node); format: "[\\w]{1,%d}"' % r2p.NODE_NAME_MAX_LENGTH,
        dest='app_name', metavar='APP_NAME'
    )
    group.add_argument(
        '-o', '--param-offset', required=True,
        help='offset of the target parameter, relative to the app config struct',
        dest='offset', metavar='OFFSET'
    )
    group.add_argument(
        '-l', '--param-length', required=True,
        help='parameter size, in bytes',
        dest='length', metavar='SIZE'
    )
        
    return parser


def _force(func):
    try:
        func()
    except:
        pass


def _main():
    parser = _create_argsparser()
    args = parser.parse_args()
    
    logging.basicConfig(stream=sys.stderr, level=verbosity2level(int(args.verbosity)))
    logging.debug('os.chdir(%s)' % repr(os.path.os.getcwd()))
    logging.debug('sys.argv = ' + repr(sys.argv))
    
    # TODO: Automate transport construction from "--transport" args
    assert args.transport[0] == 'DebugTransport'
    assert args.transport[1] == 'SerialLineIO'
    lineio = r2p.SerialLineIO(str(args.transport[2]), int(args.transport[3]))
    transport = r2p.DebugTransport('dbgtra', lineio)
    
    mw = r2p.Middleware.instance()
    
    node = r2p.Node('GETPAR')
    pub = r2p.Publisher()
    sub = r2p.Subscriber(4)
    bootloader = r2p.BootloaderMaster(pub, sub, args.boot_module_name)
    
    try:
        exception = None
        mw.initialize('R2PY')
        transport.open()
        
        node.begin()
        node.advertise(pub, args.boot_topic_name, r2p.Time_INFINITE, r2p.BootMsg)
        node.subscribe(sub, args.boot_topic_name, r2p.BootMsg)
        
        time.sleep(0.200)
        mw.reboot_remote(args.boot_module_name, True)
        time.sleep(2.000)
        bootloader.initialize()
        time.sleep(0.200)
        
        bytes = bootloader.get_parameter(app_name = str(args.app_name),
                                         offset = autoint(args.offset),
                                         length = autoint(args.length))
        
        print str2hexb(bytes)
        
    except KeyboardInterrupt as exception:
        pass
    
    except Exception as exception:
        print '~' * 80
        raise

    finally:
        if exception is not None:
            logging.exception(exception)
        
        logging.debug('Unwinding script initialization')
        node.end()
        mw.uninitialize()
        transport.close()
        
        if exception is not None:
            raise exception


if __name__ == '__main__':
    try:
        _main()
    except Exception as e:
        raise
