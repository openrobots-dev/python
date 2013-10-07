#!/usr/bin/env python2

import sys, os, threading, struct
import logging
import argparse
import r2p
from helpers import *
from time import sleep

#==============================================================================

class LedMsg(r2p.Message):
    
    def __init__(self, led=0, value=0):
        self.led = int(led)
        self.value = int(value)
    
    
    def __repr__(self):
        return '%s(led=%d, value=%d)' % (type(self).__name__, self.led, self.value)
    
    
    def marshal(self):
        return struct.pack('<BB', self.led, self.value)
        
        
    def unmarshal(self, data, offset=0):
        self.key, self.value = struct.unpack_from('<BB', data, offset)

#==============================================================================


def _create_argsparser():
    parser = argparse.ArgumentParser(
        description='R2P set app parameter'
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
        '-t', '--led-topic', required=False,
        help='name of the LED topic for the target R2P module; format: "[\\w]{1,%d}"' % r2p.MODULE_NAME_MAX_LENGTH,
        dest='topic', metavar='LED_TOPIC'
    )
    
    group.add_argument(
        '-l', '--param-offset', required=False,
        help='LED number',
        dest='offset', metavar='OFFSET'
    )

    return parser


#==============================================================================


def ledpub_node(mw, transport):
    node = r2p.Node('ledpub')
    node.begin()
    
    pub = r2p.Publisher()
    node.advertise(pub, 'leds', r2p.Time.ms(500), LedMsg)
    
    rsub = r2p.DebugSubscriber(transport, 5)
    transport.subscribe(rsub, "leds", LedMsg)  # FIXME: Should be automatic
    transport.notify_advertisement(rsub.topic)
    
    msg = LedMsg(2, 0)
    
    
    while r2p.ok():
        try:
            pub.publish(msg)
            msg.value = not msg.value
        except IndexError:
            logging.warning('Notify failed (IndexError)')
        
        sleep(1)
    
    node.end()

#==============================================================================

def ledsub_cb(msg):
#    logging.debug('sub["leds"] >>> %s', repr(msg))
    print repr(msg)

def ledsub_node(mw, transport):
    node = r2p.Node('lespub')
    node.begin()
    
    sub = r2p.Subscriber(5, ledsub_cb)
    node.subscribe(sub, 'leds', LedMsg)

    rpub = r2p.DebugPublisher(transport)
    transport.advertise(rpub, "leds", r2p.Time_INFINITE, LedMsg)  # FIXME: Should be automatic
    transport.notify_subscription_request(rpub.topic)
    
    while r2p.ok():
        node.spin(r2p.Time.s(10))
    
    node.end()

#==============================================================================


def _main():
    parser = _create_argsparser()
    args = parser.parse_args()
    
    logging.basicConfig(stream=sys.stderr, level=verbosity2level(int(args.verbosity)))
    logging.debug('sys.argv = ' + repr(sys.argv))
    
    # TODO: Automate transport construction from "--transport" args
    # assert args.transport[0] == 'DebugTransport'
    # assert args.transport[1] == 'SerialLineIO'
    # lineio = r2p.SerialLineIO(str(args.transport[2]), int(args.transport[3]))
    # transport = r2p.DebugTransport('dbgtra', lineio)
    
    lineio = r2p.TCPLineIO("10.0.0.12", 23)
    transport = r2p.DebugTransport("netdbg", lineio)
    
    mw = r2p.Middleware.instance()
    mw.initialize()
    transport.open()
    
    pub_thread = threading.Thread(name='ledpub', target=ledpub_node, args=(mw, transport))
    sub_thread = threading.Thread(name='ledsub', target=ledsub_node, args=(mw, transport))
    pub_thread.start()
    sleep(1)
    sub_thread.start()
    pub_thread.join()
    sub_thread.join()
    
    mw.uninitialize()
    transport.close()
    

if __name__ == '__main__':
    try:
        _main()
    except Exception as e:
        raise
