#!/usr/bin/env python2

import sys, os, io
import collections, struct, string, re, random
import time, threading, Queue, subprocess
import serial
import logging
from helpers import *
import r2p

_mw = r2p.Middleware.instance()

#==============================================================================

class TestMsg(r2p.Message):
    
    def __init__(self, id=0, value=0):
        self.id = int(id)
        self.value = int(value)
    
    
    def __repr__(self):
        return '%s(id=%d, value=%d)' % (type(self).__name__, self.id, self.value)
    
    
    def marshal(self):
        return struct.pack('<ll', self.id, self.value)
        
        
    def unmarshal(self, data, offset=0):
        self.key, self.value = struct.unpack_from('<ll', data, offset)

#==============================================================================

def node1_threadf():
    node = r2p.Node('Node1')
    node.begin()
    
    pub = r2p.LocalPublisher()
    node.advertise(pub, 'test', r2p.Time.ms(500), TestMsg)
    msg = TestMsg(33, 77)
    
    while r2p.ok():
        #logging.debug('Tick: node1_threadf()')
        try:
            node.spin(pub.topic.publish_timeout)
        except r2p.TimeoutError:
            pass
        try:
            pub.publish(msg)
            logging.debug('pub1 <<< %s', repr(msg))
        except IndexError:
            logging.warning('Publisher of "%s/%s/%s" overpublished' % \
                            (_mw.module_name, node.name, pub.topic.name))
    
    node.end()

#==============================================================================

def sub2_cb(msg):
    logging.debug('sub2 >>> %s', repr(msg))
    

def node2_threadf():
    node = r2p.Node('Node2')
    node.begin()
    
    sub = r2p.LocalSubscriber(5, sub2_cb)
    node.subscribe(sub, 'test', TestMsg)
    timeout = r2p.Time.ms(100)
    
    while r2p.ok():
        #logging.debug('Tick: node2_threadf()')
        try:
            node.spin(timeout)
        except r2p.TimeoutError:
            #logging.warning('Subscriber of "%s/%s/%s" timed out after %fs' % \
            #                (_mw.module_name, node.name, sub.topic.name, timeout))
            pass
    
    node.end()

#==============================================================================

def node3_threadf():
    node = r2p.Node('Node3')
    node.begin()
    
    pub = r2p.LocalPublisher()
    node.advertise(pub, 'test', r2p.Time.ms(500), TestMsg)
    msg = TestMsg(33, 77)
    
    while r2p.ok():
        #logging.debug('Tick: node3_threadf()')
        try:
            node.spin(pub.topic.publish_timeout)
        except r2p.TimeoutError:
            pass
        try:
            pub.publish(msg)
            logging.debug('pub3 <<< %s', repr(msg))
        except IndexError:
            logging.warning('Publisher of "%s/%s/%s" overpublished' % \
                            (_mw.module_name, node.name, pub.topic.name))
    
    node.end()

#==============================================================================

def _main():
    logging.basicConfig(stream=sys.stderr, level=verbosity2level(int(4)))
    logging.debug('sys.argv = ' + repr(sys.argv))
    
    dbgtra = r2p.DebugTransport('ttyUSB0', r2p.StdLineIO())
    
    node1_thread = threading.Thread(name='node1', target=node1_threadf)
    node2_thread = threading.Thread(name='node2', target=node2_threadf)
    node3_thread = threading.Thread(name='node3', target=node3_threadf)
    
    try:
        _mw.initialize('R2PY', 'BOOT_R2PY')
        
        dbgtra.open()
        
        node1_thread.start()
        node2_thread.start()
        #node3_thread.start()
        
        while r2p.ok():
            time.sleep(1)
        
    except Exception as e:
        logging.exception(str(e))
        raise
    
    finally:
        _mw._stop()
        time.sleep(1)
        node1_thread.join()
        node2_thread.join()
        #node3_thread.join()
        _mw.uninitialize()
        dbgtra.close()

#==============================================================================

if __name__ == '__main__':
    try:
        _main()
    except KeyboardInterrupt:
        print
        pass
    except:
        raise

