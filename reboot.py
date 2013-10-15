#!/usr/bin/env python2

import sys, os, time
import logging
import argparse
import r2p
from helpers import *


def _create_argsparser():
    parser = argparse.ArgumentParser(
        description='R2P module reboot'
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
        '-b' '--boot-mode', required=False, action='store_true',
        help='reboots in bootloader mode',
        dest='boot_mode'
    )
    
    return parser


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
    
    try:
        exception = None
        mw.initialize()
        transport.open()
        transport.notify_stop()
        
        if args.boot_mode:
            transport.notify_bootload()
        else:
            transport.notify_reboot()
        
    except KeyboardInterrupt as exception:
        pass
    
    except Exception as exception:
        print '~' * 80
        raise

    finally:
        if exception is not None:
            logging.critical(exception)
        
        mw.uninitialize()
        transport.close()
        
        if exception is not None:
            raise exception


if __name__ == '__main__':
    try:
        _main()
    except Exception as e:
        raise
