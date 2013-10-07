#!/usr/bin/env python2

import sys, os
import logging
import argparse
import r2p
from helpers import *


def _create_argsparser():
    parser = argparse.ArgumentParser(
        description='R2P app removal'
    )
    
    parser.add_argument(
        '-v', '--verbose', required=False, action='count', default=0,
        help='verbosity level (default %(default)s): 0=critical, 1=error, 2=warning, 3=info, 4=debug',
        dest='verbosity'
    )
    
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument(
        '-l', '--last', required=False, action='store_true',
        help='removes only the last application',
        dest='last'
    )
    group.add_argument(
        '-a', '--all', required=False, action='store_true',
        help='removes all the apps',
        dest='all'
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
        dest='topic', metavar='BOOT_TOPIC'
    )
    
    return parser


def _main():
    parser = _create_argsparser()
    args = parser.parse_args()
    
    logging.basicConfig(stream=sys.stderr, level=verbosity2level(int(args.verbosity)))
    logging.debug('sys.argv = ' + repr(sys.argv))
    
    # TODO: Automate transport construction from "--transport" args
    assert args.transport[0] == 'DebugTransport'
    assert args.transport[1] == 'SerialLineIO'
    lineio = r2p.SerialLineIO(str(args.transport[2]), int(args.transport[3]))
    transport = r2p.DebugTransport('dbgtra', lineio)
    
    mw = r2p.Middleware.instance()
    
    node = r2p.Node('GETPARAM')
    pub = r2p.Publisher()
    sub = r2p.Subscriber(100)
    bootloader = r2p.BootloaderMaster(pub, sub)
    
    rpub = r2p.DebugPublisher(transport)
    rsub = r2p.DebugSubscriber(transport, 100)
    
    try:
        exception = None
        mw.initialize()
        transport.open()
        
        node.begin()
        node.advertise(pub, args.topic, r2p.Time_INFINITE, r2p.BootMsg)
        node.subscribe(sub, args.topic, r2p.BootMsg)
        
        transport.advertise(rpub, args.topic, r2p.Time_INFINITE, r2p.BootMsg) # FIXME: Should be automatic
        transport.subscribe(rsub, args.topic, r2p.BootMsg) # FIXME: Should be automatic
        transport.notify_stop()
        
        bootloader.initialize()
        
        if args.last:
            bootloader.remove_last()
        elif args.all:
            bootloader.remove_all()
        else:
            raise RuntimeException('Missing "remove last/all" action switch')

    except KeyboardInterrupt as exception:
        pass
    
    except Exception as exception:
        print '~' * 80
        raise

    finally:
        if exception is not None:
            logging.critical(exception)
        
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