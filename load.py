#!/usr/bin/env python2

import sys, os, time
import logging
import argparse
import r2p
from helpers import *


def _create_argsparser():
    parser = argparse.ArgumentParser(
        description='R2P app bootloader'
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
    
    group = parser.add_argument_group('app setup')
    group.add_argument(
        '-n', '--app-name', required=True,
        help='name of the app (R2P Node); format: "[\\w]{1,%d}"' % r2p.NODE_NAME_MAX_LENGTH,
        dest='app_name', metavar='APP_NAME'
    )
    group.add_argument(
        '-k', '--app-stack-size', required=True,
        help='size of the stack for the app entry point thread, including the Thread Control Block; format: [\\d]+ or "0x[0-9A-Fa-f]+"',
        dest='app_stack_size', metavar='SIZE'
    )
    group.add_argument(
        '-c', '--app-config-struct', required=False, default='app_config',
        help='name of the app configuration struct',
        dest='app_config_name', metavar='VAR_NAME'
    )
    group.add_argument(
        '-y', '--app-main-name', required=False, default='app_thread',
        help='name of the app thread entry point function',
        dest='app_main_name', metavar='FUNC_NAME'
    )
    
    group = parser.add_argument_group('linker setup')
    group.add_argument(
        '-s', '--sys-elf', required=True,
        help='path of the system ELF file',
        dest='sys_elf_path', metavar='SYS_ELF_PATH'
    )
    group.add_argument(
        '-d', '--app-dir', required=False, default='.',
        help='path of the app Makefile directory',
        dest='app_dir', metavar='APP_MAKE_PATH'
    )
    group.add_argument(
        '-a', '--app-elf', required=True,
        help='path of the app ELF file',
        dest='app_elf_path', metavar='APP_ELF_PATH'
    )
    group.add_argument(
        '-x', '--app-hex', required=True,
        help='path of the app IHEX file',
        dest='app_hex_path', metavar='APP_IHEX_PATH'
    )
    group.add_argument(
        '-l', '--ld-cmd', required=False, default='ld',
        help='linker command name',
        dest='ld_cmd', metavar='LD_CMD'
    )
    group.add_argument(
        '-g', '--ld-use-gcc', required=False, action='store_true',
        help='using GCC as linker instead of LD',
        dest='ld_use_gcc'
    )
    group.add_argument(
        '-r', '--ld-script', required=True,
        help='path of the linker script',
        dest='ld_script_path', metavar='LD_SCRIPT_PATH'
    )
    group.add_argument(
        '-m', '--ld-map', required=False,
        help='path of the linker output MAP file',
        dest='ld_map_path', metavar='LD_MAP_PATH'
    )
    group.add_argument(
        '-o', '--ld-objects', required=True, nargs='+',
        help='list of object files (*.o) to be linked',
        dest='ld_object_paths', metavar='OBJ_PATHS'
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
    
    node = r2p.Node('LOADER')
    pub = r2p.Publisher()
    sub = r2p.Subscriber(4)
    bootloader = r2p.BootloaderMaster(pub, sub)
    
    try:
        exception = None
        mw.initialize('R2PY')
        transport.open()
        
        node.begin()
        node.advertise(pub, args.boot_topic_name, r2p.Time_INFINITE, r2p.BootMsg)
        node.subscribe(sub, args.boot_topic_name, r2p.BootMsg)
        
        time.sleep(1.000)
        transport.notify_bootload()
        bootloader.initialize()
        time.sleep(1.000)
        
        bootloader.load(app_name        = str(args.app_name),
                        app_hex_path    = str(args.app_hex_path),
                        app_stack_size  = autoint(args.app_stack_size),
                        ld_cmd          = str(args.ld_cmd),
                        ld_use_gcc      = bool(args.ld_use_gcc),
                        ld_script_path  = str(args.ld_script_path),
                        sys_elf_path    = str(args.sys_elf_path),
                        ld_map_path     = str(args.ld_map_path),
                        app_elf_path    = str(args.app_elf_path),
                        ld_object_paths = [ str(obj) for obj in args.ld_object_paths ])
        
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
