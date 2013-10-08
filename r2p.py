# TODO: Check BootlaoderMsg checksums
# TODO: Add BootlaoderMsg sequence number check

import sys, os, io, socket
import collections, struct, string, re, random
import time, threading, Queue, subprocess
import serial
import logging
from helpers import *

from elftools.elf.elffile import ELFFile
from elftools.construct.macros import FlagsEnum
from elftools.elf.sections import SymbolTableSection

MODULE_NAME_MAX_LENGTH = 7
NODE_NAME_MAX_LENGTH = 8
TOPIC_NAME_MAX_LENGTH = 16
IHEX_MAX_DATA_LENGTH = 16

APP_THREAD_SYMBOL = 'app_main'
THREAD_PC_OFFSET = 1
APP_CONFIG_SYMBOL = 'app_config'

_MODULE_NAME = ''.join([ random.choice(string.ascii_letters + string.digits + '_')
                         for x in xrange(MODULE_NAME_MAX_LENGTH) ])

IDENTIFIER_REGEX_FMT    = '^\\w+$'
MODULE_NAME_REGEX_FMT   = '^\\w{1,%d}$' % MODULE_NAME_MAX_LENGTH
NODE_NAME_REGEX_FMT     = '^\\w{1,%d}$' % NODE_NAME_MAX_LENGTH
TOPIC_NAME_REGEX_FMT    = '^\\w{1,%d}$' % TOPIC_NAME_MAX_LENGTH

_id_regex = re.compile(IDENTIFIER_REGEX_FMT)
_module_regex = re.compile(MODULE_NAME_REGEX_FMT)
_node_regex = re.compile(NODE_NAME_REGEX_FMT)
_topic_regex = re.compile(TOPIC_NAME_REGEX_FMT)

#==============================================================================

def is_identifier(text):
    return bool(_id_regex.match(text))


def is_module_name(text):
    return bool(_module_regex.match(text))


def is_node_name(text):
    return bool(_node_regex.match(text))


def is_topic_name(text):
    return bool(_topic_regex.match(text))


def _get_section_address(elffile, name):
    for section in elffile.iter_sections():
        if section.name == name:
            return section.header['sh_addr']
    raise RuntimeError('Section %s not found' % repr(name))


def _get_function_address(elffile, name):
    dwarfinfo = elffile.get_dwarf_info()
    for CU in dwarfinfo.iter_CUs():
        for DIE in CU.iter_DIEs():
            try:
                if DIE.tag == 'DW_TAG_subprogram' and DIE.attributes['DW_AT_name'].value == name:
                    return int(DIE.attributes['DW_AT_low_pc'].value) + THREAD_PC_OFFSET
            except KeyError: continue
    raise RuntimeError('Symbol %s not found' % repr(name))


def _get_symbol_address(elffile, name):
    for section in elffile.iter_sections():
        if not isinstance(section, SymbolTableSection):
            continue
        for symbol in section.iter_symbols():
            if symbol.name == name:
                return symbol['st_value']
    raise RuntimeError('Symbol %s not found' % repr(name))


def _get_variable_address(elffile, name):
    dwarfinfo = elffile.get_dwarf_info()
    for CU in dwarfinfo.iter_CUs():
        for DIE in CU.iter_DIEs():
            try:
                if DIE.tag == 'DW_TAG_variable' and DIE.attributes['DW_AT_name'].value == name:
                    value = DIE.attributes['DW_AT_location'].value
                    # FIXME: Handmade address conversion (I don't know how to manage this with pyelftools...)
                    assert value[0] == 3
                    return (value[4] << 24) | (value[3] << 16) | (value[2] << 8) | value[1]
            except KeyError: continue
    raise RuntimeError('Symbol %s not found' % repr(name))


def _get_variable_size(elffile, name):
    dwarfinfo = elffile.get_dwarf_info()
    offset = None
    for CU in dwarfinfo.iter_CUs():
        for DIE in CU.iter_DIEs():
            try:
                if DIE.tag == 'DW_TAG_variable' and DIE.attributes['DW_AT_name'].value == name:
                    offset = DIE.attributes['DW_AT_type'].value
                    break
            except KeyError: continue
        else: continue
        break
    else: raise RuntimeError('Symbol %s not found' % repr(name))
    
    for DIE in CU.iter_DIEs():
        try:
            if DIE.tag == 'DW_TAG_const_type' and DIE.offset == offset:
                offset = DIE.attributes['DW_AT_type'].value
                break
        except KeyError: continue
    else: pass # no separate struct/class type definition
    
    for DIE in CU.iter_DIEs():
        try:
            if DIE.tag == 'DW_TAG_typedef' and DIE.offset == offset:
                offset = DIE.attributes['DW_AT_type'].value
                break
        except KeyError: continue
    else: pass # no typedef in C++
    
    for DIE in CU.iter_DIEs():
        try:
            if DIE.tag == 'DW_TAG_structure_type' and DIE.offset == offset:
                size = DIE.attributes['DW_AT_byte_size'].value
                break
        except KeyError: continue
    else: raise RuntimeError('Cannot find structure type of variable %s' % repr(name))
    
    return size


_sys_lock = threading.RLock()

def get_sys_lock():
    global _sys_lock
    return _sys_lock


def ok():
    global _sys_lock
    with _sys_lock:
        return not Middleware.instance().stopped

#==============================================================================

class Checksummer(object):
    def __init__(self):
        self.__accumulator = 0
        
    def __int__(self):
        return self.compute_checksum()
        
    def compute_checksum(self):
        return (0x100 - (self.__accumulator)) & 0xFF
    
    def add_uint(self, value):
        value = int(value)
        while value > 0:
            self.__accumulator = (self.__accumulator + value) & 0xFF
            value >>= 8
    
    def add_int(self, value, size=4):
        assert size > 0
        value = int(value) &  (1 << (8 * size)) - 1
        self.add_uint(value)
    
    def add_bytes(self, chunk):
        for b in chunk:
            self.__accumulator = (self.__accumulator + ord(b)) & 0xFF
            
    def check(self, checksum):
        if checksum != self.compute_checksum():
            raise ValueError('Checksum is 0x%0.2X, expected 0x%0.2X' %
                             (checksum, self.compute_checksum()))
    
#==============================================================================

class Serializable(object):
    
    def __repr(self):
        return str(self.__dict__)
    
    def marshal(self):
        raise NotImplementedError()
        # return 'data'
    
    def unmarshal(self, data, offset=0):
        raise NotImplementedError()
    
#==============================================================================

class ParserError(Exception):
    
    def __init__(self, *args, **kwargs):
        super(ParserError, self).__init__(*args, **kwargs)
    
#==============================================================================

class TimeoutError(Exception):
    
    def __init__(self, now=None, deadline=None, start=None, *args, **kwargs):
        super(TimeoutError, self).__init__(*args, **kwargs)
        self.now = now if now is not None else time.time()
        self.deadline = deadline
        self.start = start
    
#==============================================================================

class Time(object):
    
    RAW_MAX = (1 << 31) - 1
    RAW_MIN = -(1 << 31)
    
    def __init__(self, microseconds=0, seconds=None):
        if seconds is not None:
            microseconds = seconds * 1000000
        self._raw = max(Time.RAW_MIN, min(int(microseconds), Time.RAW_MAX))
    
    
    def __repr__(self):
        assert Time.RAW_MIN <= self._raw <= Time.RAW_MAX
        if self._raw == Time.RAW_MAX:
            return 'Time_INFINITE'
        elif self._raw == Time.RAW_MIN:
            return 'Time_NINFINITE'
        else:
            return 'Time(microseconds=%d, seconds=%f)' % (self._raw, self.to_s())
        
    
    def to_us(self):
        return self._raw
    
    
    def to_ms(self):
        return self._raw / 1000.0
    
    
    def to_s(self):
        return self._raw / 1000000.0
    
    
    def to_m(self):
        return self._raw / 60000000.0
    
    
    def to_hz(self):
        return 1000000.0 / self._raw
    
    
    @staticmethod
    def us(value):
        return Time(value)
        
    
    @staticmethod
    def ms(value):
        return Time(float(value) * 1000.0)
        
    
    @staticmethod
    def s(value):
        return Time(float(value) * 1000000.0)
        
        
    @staticmethod
    def m(value):
        return Time(float(value) * 10000000.0)
        
    
    @staticmethod
    def hz(value):
        return Time(60000000.0 / float(value))

    
    @staticmethod
    def now():
        return Time(time.time() * 1000)

    
    def __cmp__(self, other):
        return self._raw.__cmp__(other._raw)
        
        
    def __add__(self, other):
        return Time(self._raw + other._raw)
        
        
    def __sub__(self, other):
        return Time(self._raw - other._raw)
        
        
    def __iadd__(self, other):
        self.__init__(self._raw + other._raw)
        return self
        
        
    def __isub__(self, other):
        self.__init__(self._raw - other._raw)
        return self
        
        
    def __int__(self):
        return self._raw
        
        
    def __float__(self):
        return self.to_s()
    
    
Time_IMMEDIATE   = Time(0)
Time_INFINITE    = Time(Time.RAW_MAX)
Time_NINFINITE   = Time(Time.RAW_MIN)

#==============================================================================

class MemoryPool(object):
    
    def __init__(self, type):
        self._type = type
        self._free_queue = Queue.LifoQueue()
        self._lock = threading.Lock()
        
        
    def alloc(self):
        item = self._free_queue.get_nowait()
        self._free_queue.task_done()
        return item
        
        
    def free(self, item):
        self._free_queue.put_nowait(item)
    
    
    def extend(self, length, items=[], ctor_args=(), ctor_kwargs={}):
        length = len(items)
        assert length > 0
        lenitems = len(items)
        assert not lenitems > 0 or lenitems == length
        
        if lenitems > 0:
            for item in items:
                self.free(item)
        else:
            for i in xrange(length):
                item = self._type(*ctor_args, **ctor_kwargs)
                self.free(item)
            

#==============================================================================

class ArrayQueue(object):
    
    def __init__(self, length):
        length = int(length)
        assert length > 0
        self.length = length
        self._queue = Queue.Queue(length)
        
        
    def post(self, item):
        self._queue.put_nowait(item)
            
            
    def fetch(self):
        item = self._queue.get_nowait()
        self._queue.task_done()
        return item

#==============================================================================

class EventQueue(object):

    def __init__(self):
        self._queue = Queue.Queue()


    def signal(self, item=None):
        self._queue.put_nowait(item)
    
    
    def wait(self, timeout=Time_INFINITE):
        if timeout == Time_IMMEDIATE:
            item = self._queue.get_nowait()
        elif timeout == Time_INFINITE:
            item = self._queue.get()
        else:
            item = self._queue.get(True, timeout.to_s())
        self._queue.task_done()
        return item

#==============================================================================

class IhexRecord(Serializable):
    MAX_DATA_LENGTH = 16
    
    class TypeEnum:
        DATA                        = 0
        END_OF_FILE                 = 1
        EXTENDED_SEGMENT_ADDRESS    = 2
        START_SEGMENT_ADDRESS       = 3
        EXTENDED_LINEAR_ADDRESS     = 4
        START_LINEAR_ADDRESS        = 5
    
    
    def __init__(self, count=0, offset=0, type=None, data='', checksum=0):
        super(IhexRecord, self).__init__()
        self.count = count
        self.offset = offset
        self.type = type
        self.data = data
        self.checksum = checksum
    
        
    def __repr__(self):
        return '%s(count=0x%0.2X, offset=0x%0.4X, type=%d, data=%s, checksum=0x%0.2X)' % \
               (type(self).__name__, self.count, self.offset, self.type, repr(self.data), self.checksum)
    
        
    def __str__(self):
        return ':%0.2X%0.4X%0.2X%s%0.2X' % \
            (self.count, self.offset, self.type, str2hexb(self.data), self.checksum)


    def compute_checksum(self):
        cs = Checksummer()
        cs.add_uint(self.count)
        cs.add_uint(self.offset)
        cs.add_uint(self.type)
        cs.add_bytes(self.data)
        return cs.compute_checksum()

    
    def check_valid(self):
        if not (0 <= self.count <= 255):
            raise ValueError('not(0 <= count=%d <= 255)' % self.count)
        if self.count != len(self.data):
            raise ValueError('count=%d != len(data)=%d' % (self.count, len(self.data)))
        if not (0 <= self.offset <= 0xFFFF):
            raise ValueError('not(0 <= offset=0x%0.8X <= 0xFFFF)' % self.offset)
        if self.checksum != self.compute_checksum():
            raise ValueError('checksum=%d != expected=%d' % (self.checksum, self.compute_checksum()));
        
        if self.type == self.TypeEnum.DATA:
            pass
        elif self.type == self.TypeEnum.END_OF_FILE:
            if self.count  != 0: raise ValueError('count=%s != 0' % self.count)
        elif self.type == self.TypeEnum.EXTENDED_SEGMENT_ADDRESS:
            if self.count  != 2: raise ValueError('count=%s != 2' % self.count)
            if self.offset != 0: raise ValueError('offset=%s != 0' % self.count)
        elif self.type == self.TypeEnum.START_SEGMENT_ADDRESS:
            if self.count  != 4: raise ValueError('count=%s != 4' % self.count)
            if self.offset != 0: raise ValueError('offset=%s != 0' % self.count)
        elif self.type == self.TypeEnum.EXTENDED_LINEAR_ADDRESS:
            if self.count  != 2: raise ValueError('count=%s != 2' % self.count)
            if self.offset != 0: raise ValueError('offset=%s != 0' % self.count)
        elif self.type == self.TypeEnum.START_LINEAR_ADDRESS:
            if self.count  != 4: raise ValueError('count=%s != 4' % self.count)
            if self.offset != 0: raise ValueError('offset=%s != 0' % self.count)
        else:
            raise ValueError('Unknown type %s' % self.type)
    
    
    def marshal(self):
        return struct.pack('<BHB%dsB' % self.MAX_DATA_LENGTH,
                           self.count, self.offset, self.type, self.data, self.checksum)
    
    
    def unmarshal(self, data, offset=0):
        self.count, self.offset, self.type, self.data, self.checksum = \
            struct.unpack_from('<BHB%dsB' % self.MAX_DATA_LENGTH, data, offset)
        self.data = self.data[:self.count]
    
    
    def parse_ihex(self, entry):
        if entry[0] != ':': raise ValueError("Entry %s does not start with ':'" % repr(entry))
        self.count = int(entry[1:3], 16)
        explen = 1 + 2 * (1 + 2 + 1 + self.count + 1)
        if len(entry) < explen:
            raise ValueError("len(%s) < %d" % (repr(entry), explen))
        self.offset = int(entry[3:7], 16)
        self.type = int(entry[7:9], 16)
        entry = entry[9:]
        self.data = str(bytearray([ int(entry[i : (i + 2)], 16) for i in xrange(0, 2 * self.count, 2) ]))
        self.checksum = int(entry[(2 * self.count) : (2 * self.count + 2)], 16)
        self.check_valid()
        return self

#==============================================================================

class Message(Serializable):
    
    def __init__(self):
        super(Message, self).__init__()

#==============================================================================

class BootMsg(Message):
    
    MAX_PAYLOAD_LENGTH  = 30
    MAX_LENGTH          = 30 + 1 
    
    
    class TypeEnum:
        NACK                =  0
        ACK                 =  1
        BEGIN_LOADER        =  2
        END_LOADER          =  3
        LINKING_SETUP       =  4
        LINKING_ADDRESSES   =  5
        LINKING_OUTCOME     =  6
        IHEX_RECORD         =  7
        REMOVE_LAST         =  8
        REMOVE_ALL          =  9
        BEGIN_APPINFO       = 10
        END_APPINFO         = 11
        APPINFO_SUMMARY     = 12
        BEGIN_SETPARAM      = 13
        END_SETPARAM        = 14
        BEGIN_GETPARAM      = 15
        END_GETPARAM        = 16
        PARAM_REQUEST       = 17
        PARAM_CHUNK         = 18
    
    
    class ErrorInfo(Serializable):
        MAX_TEXT_LENGTH = 20
        
        class ReasonEnum:
            UNKNOWN         = 0
            NO_FREE_MEMORY  = 1
            ZERO_LENGTH     = 2
            OUT_OF_RANGE    = 3
        
        class TypeEnum:
            NONE            = 0
            TEXT            = 1
            INTEGRAL        = 2
            UINTEGRAL       = 3
            ADDRESS         = 4
            LENGTH          = 5
            CHUNK           = 6
        
        def __init__(self, line=0, reason=0, type=0, text='', integral=0, uintegral=0, address=0, length=0):
            super(BootMsg.ErrorInfo, self).__init__()
            self.line = line
            self.reason = reason
            self.type = type
            self.text = text
            self.integral = integral
            self.uintegral = uintegral
            self.address = address
            self.length = length
        
        def __repr__(self):
            e = self.TypeEnum
            if   self.type == e.NONE:       value = 'empty'
            elif self.type == e.TEXT:       value = 'text=%s' % repr(self.text)
            elif self.type == e.INTEGRAL:   value = 'integral=%d' % self.integral
            elif self.type == e.UINTEGRAL:  value = 'uintegral=%d' % self.uintegral
            elif self.type == e.ADDRESS:    value = 'address=0x%0.8X' % self.address
            elif self.type == e.LENGTH:     value = 'length=0x%0.8X' % self.length
            elif self.type == e.CHUNK:      value = 'chunk(address=%d, length=%d)' % (self.address, self.length)
            else: raise ValueError('Unknown error type %d' % self.type)
            return '%s(line=%d, reason=%d, type=%d, text=%s, integral=%d, uintegral=%d, address=0x%0.X, length=%d' % \
                   (type(self).__name__, self.line, self.reason, self.type, repr(self.text), self.integral, self.uintegral, self.address, self.length)
        
        def marshal(self):
            bytes = struct.pack('<HBB', self.line, self.reason, self.type)
            e = self.TypeEnum
            if   self.type == e.NONE:       pass
            elif self.type == e.TEXT:       bytes += struct.pack('%ds' % self.MAX_TEXT_LENGTH)
            elif self.type == e.INTEGRAL:   bytes += struct.pack('<l', self.integral)
            elif self.type == e.UINTEGRAL:  bytes += struct.pack('<L', self.uintegral)
            elif self.type == e.ADDRESS:    bytes += struct.pack('<L', self.address)
            elif self.type == e.LENGTH:     bytes += struct.pack('<L', self.length)
            elif self.type == e.CHUNK:      bytes += struct.pack('<LL', self.address, self.length)
            else: raise ValueError('Unknown error type %d' % self.type)
            return bytes
            
        def unmarshal(self, data, offset=0):
            self.__init__()
            self.line, self.reason, self.type = struct.unpack_from('<HBB', data, offset)
            e = self.TypeEnum
            if   self.type == e.NONE:       pass
            elif self.type == e.TEXT:       self.text = struct.unpack_from('%ds' % self.MAX_TEXT_LENGTH, data, offset)
            elif self.type == e.INTEGRAL:   self.integral = struct.unpack_from('<l', data, offset)
            elif self.type == e.UINTEGRAL:  self.uintegral = struct.unpack_from('<L', data, offset)
            elif self.type == e.ADDRESS:    self.address = struct.unpack_from('<L', data, offset)
            elif self.type == e.LENGTH:     self.length = struct.unpack_from('<L', data, offset)
            elif self.type == e.CHUNK:      self.address, self.length = struct.unpack_from('<LL', data, offset)
            else: raise ValueError('Unknown error type %d' % self.type)
    
    
    class LinkingSetup(Serializable):
        class FlagsEnum:
            ENABLED = (1 << 0)
        
        def __init__(self, pgmlen=0, bsslen=0, datalen=0, stacklen=0, name='', flags=(1 << 0)):
            super(BootMsg.LinkingSetup, self).__init__()
            self.pgmlen = pgmlen
            self.bsslen = bsslen
            self.datalen = datalen
            self.stacklen = stacklen
            self.name = name
            self.flags = self.FlagsEnum.ENABLED
            
            
        def __repr__(self):
            return '%s(pgmlen=0x%0.8X, bsslen=0x%0.8X, datalen=0x%0.8X, stacklen=0x%0.8X, name=%s, flags=0x%0.X)' % \
                   (type(self).__name__, self.pgmlen, self.bsslen, self.datalen, self.stacklen, repr(self.name), self.flags)
            
        
        def marshal(self):
            return struct.pack('<LLLL%dsH' % NODE_NAME_MAX_LENGTH, self.pgmlen, self.bsslen,
                               self.datalen, self.stacklen, self.name, self.flags)
        
        def unmarshal(self, data, offset=0):
            self.__init__()
            self.pgmlen, self.bsslen, self.datalen, self.stacklen, self.name, self.flags = \
                struct.unpack_from('<LLLL%dsH' % NODE_NAME_MAX_LENGTH, data, offset)


    class LinkingAddresses(Serializable):
        def __init__(self, infoadr=0, pgmadr=0, bssadr=0, dataadr=0, datapgmadr=0, nextadr=0):
            super(BootMsg.LinkingAddresses, self).__init__()
            self.infoadr = infoadr
            self.pgmadr = pgmadr
            self.bssadr = bssadr
            self.dataadr = dataadr
            self.datapgmadr = datapgmadr
            self.nextadr = nextadr
        
        def __repr__(self):
            return '%s(infoadr=0x%0.8X, pgmadr=0x%0.8X, bssadr=0x%0.8X, dataadr=0x%0.8X, datapgmadr=0x%0.8X, nextadr=0x%0.8X)' % \
                   (type(self).__name__, self.infoadr, self.pgmadr, self.bssadr, self.dataadr, self.datapgmadr, self.nextadr)
        
        def marshal(self):
            return struct.pack('<LLLLLL', self.infoadr, self.pgmadr, self.bssadr,
                               self.dataadr, self.datapgmadr, self.nextadr)
        
        def unmarshal(self, data, offset=0):
            self.__init__()
            self.infoadr, self.pgmadr, self.bssadr, self.dataadr, self.datapgmadr, self.nextadr = \
                struct.unpack_from('<LLLLLL', data, offset)


    class LinkingOutcome(Serializable):
        def __init__(self, mainadr=0, cfgadr=0, cfglen=0, ctorsadr=0, ctorslen=0, dtorsadr=0, dtorslen=0):
            super(BootMsg.LinkingOutcome, self).__init__()
            self.mainadr = mainadr
            self.cfgadr = cfgadr
            self.cfglen = cfglen
            self.ctorsadr = ctorsadr
            self.ctorslen = ctorslen
            self.dtorsadr = dtorsadr
            self.dtorslen = dtorslen
            
        def __repr__(self):
            return '%s(mainadr=0x%0.8X, cfgadr=0x%0.8X, cfglen=0x%0.8X, ctorsadr=0x%0.8X, ctorslen=0x%0.8X, dtorsadr=0x%0.8X, dtorslen=0x%0.8X)' % \
                   (type(self).__name__, self.mainadr, self.cfgadr, self.cfglen, self.ctorsadr, self.ctorslen, self.dtorsadr, self.dtorslen)
            
        def marshal(self):
            return struct.pack('<LLLLLLL', self.mainadr, self.cfgadr, self.cfglen,
                               self.ctorsadr, self.ctorslen, self.dtorsadr, self.dtorslen)

        def unmarshal(self, data, offset=0):
            self.__init__()
            self.mainadr, self.cfgadr, self.cfglen, self.ctorsadr, self.dtorslen, self.dtorsadr, self.dtorslen = \
                struct.unpack_from('<LLLLLLL', data, offset)


    class AppInfoSummary(Serializable):
        def __init__(self, numapps=0, freeadr=0, pgmstartadr=0, pgmendadr=0, ramstartadr=0, ramendadr=0):
            super(BootMsg.AppInfoSummary, self).__init__()
            self.numapps = numapps
            self.freeadr = freeadr
            self.pgmstartadr = pgmstartadr
            self.pgmendadr = pgmendadr
            self.ramstartadr = ramstartadr
            self.ramendadr = ramendadr
        
        def __repr__(self):
            return '%s(numapps=%d, freeadr=0x%0.8X, pgmstartadr=0x%0.8X, pgmendadr=0x%0.8X, ramstartadr=0x%0.8X, ramendadr=0x%0.8X)' % \
                   (type(self).__name__, self.numapps, self.freeadr, self.pgmstartadr, self.pgmendadr, self.ramstartadr, self.ramendadr)
        
        def marshal(self):
            return struct.pack('<LLLLLL', self.numapps, self.freeadr,
                               self.pgmstartadr, self.pgmendadr,
                               self.ramstartadr, self.ramendadr)
        
        def unmarshal(self, data, offset=0):
            self.__init__()
            self.numapps, self.freeadr, self.pgmstartadr, self.pgmendadr, self.ramstartadr, self.ramendadr = \
                struct.unpack_from('<LLLLLL', data, offset)


    class ParamRequest(Serializable):
        def __init__(self, offset=0, appname='', length=0):
            super(BootMsg.ParamRequest, self).__init__()
            self.offset = offset
            self.appname = appname
            self.length = length
        
        def __repr__(self):
            return '%s(offset=0x%0.8X, appname=%s, length=0x%0.8X)' % \
                   (type(self).__name__, self.offset, repr(self.appname), self.length)
        
        def marshal(self):
            return struct.pack('<L%dsB' % NODE_NAME_MAX_LENGTH,
                               self.offset, self.appname, self.length)
        
        def unmarshal(self, data, offset=0):
            self.__init__()
            self.offset, self.appname, self.length = \
                struct.unpack_from('<L%dsB' % NODE_NAME_MAX_LENGTH, data, offset)


    class ParamChunk(Serializable):
        MAX_DATA_LENGTH = 16

        def __init__(self, data=''):
            super(BootMsg.ParamChunk, self).__init__()
            self.data = data
        
        def __repr__(self):
            return '%s(data=%s)' % (type(self).__name__, repr(self.data))
        
        def marshal(self):
            assert len(self.data) <= self.MAX_DATA_LENGTH
            return self.data

        def unmarshal(self, data, offset=0):
            self.__init__()
            self.data = data[:self.MAX_DATA_LENGTH]


    def __init__(self, type=None):
        super(BootMsg, self).__init__()
        
        self.type = type
        # TODO: Initialize all types to None, and build only when needed
        self.ihex_record = IhexRecord()
        self.error_info = self.ErrorInfo()
        self.linking_setup = self.LinkingSetup()
        self.linking_addresses = self.LinkingAddresses()
        self.linking_outcome = self.LinkingOutcome()
        self.appinfo_summary = self.AppInfoSummary()
        self.param_request = self.ParamRequest()
        self.param_chunk = self.ParamChunk()
        
        if not type is None:
            self.clean(type)
            e = BootMsg.TypeEnum
            if   type == e.NACK:              self.set_error_info(*args, **kwargs)
            elif type == e.LINKING_SETUP:     self.set_linking_setup(*args, **kwargs)
            elif type == e.LINKING_ADDRESSES: self.set_linking_addresses(*args, **kwargs)
            elif type == e.LINKING_OUTCOME:   self.set_linking_outcome(*args, **kwargs)
            elif type == e.IHEX_RECORD:       self.set_ihex_record(*args, **kwargs)
            elif type == e.APPINFO_SUMMARY:   self.set_appinfo_summary(*args, **kwargs)
            elif type == e.PARAM_REQUEST:     self.set_param_request(*args, **kwargs)
            elif type == e.PARAM_CHUNK:       self.set_param_chunk(*args, **kwargs)
            else: raise ValueError('Unknown bootloader message subtype %d' % type)
    
    
    def __repr__(self):
        subtext = ''
        t = self.type
        e = BootMsg.TypeEnum
        if   t == e.NACK:               subtext = ', error_info=' + repr(self.error_info)
        elif t == e.LINKING_SETUP:      subtext = ', linking_setup=' + repr(self.linking_setup)
        elif t == e.LINKING_ADDRESSES:  subtext = ', linking_addresses=' + repr(self.linking_addresses)
        elif t == e.LINKING_OUTCOME:    subtext = ', linking_outcome=' + repr(self.linking_outcome)
        elif t == e.IHEX_RECORD:        subtext = ', ihex_record=' + repr(self.ihex_record)
        elif t == e.APPINFO_SUMMARY:    subtext = ', appinfo_summary=' + repr(self.appinfo_summary)
        elif t == e.PARAM_REQUEST:      subtext = ', param_request=' + repr(self.param_request)
        elif t == e.PARAM_CHUNK:        subtext = ', param_chunk=' + repr(self.param_chunk)
        else: raise ValueError('Unknown bootloader message subtype %d' % t)
        return '%s(type=%d%s)' % (type(self).__name__, self.type, subtext)
    
    
    def check_type(self, type):
        assert not type is None
        if self.type != type:
            raise ValueError('Unknown bootloader message subtype %d' % type)
    
    
    def clean(self, type=None):
        self.__init__()
        self.type = type # TODO: Build only the needed type
    
    
    def set_error_info(self, line, reason, type):
        self.clean(BootMsg.TypeEnum.NACK)
        self.error_info.line = line
        self.error_info.reason = reason
        self.error_info.type = type
    
    
    def set_linking_setup(self, pgmlen, bsslen, datalen, stacklen, name, flags):
        self.clean(BootMsg.TypeEnum.LINKING_SETUP)
        self.linking_setup.pgmlen = pgmlen
        self.linking_setup.bsslen = bsslen
        self.linking_setup.datalen = datalen
        self.linking_setup.stacklen = stacklen
        self.linking_setup.name = name
        self.linking_setup.flags = flags
    
    
    def set_linking_addresses(self, infoadr, pgmadr, bssadr, dataadr, datapgmadr, nextadr):
        self.clean(BootMsg.TypeEnum.LINKING_ADDRESSES)
        self.linking_addresses.infoadr = infoadr
        self.linking_addresses.pgmadr = pgmadr
        self.linking_addresses.bssadr = bssadr
        self.linking_addresses.dataadr = dataadr
        self.linking_addresses.datapgmadr = datapgmadr
        self.linking_addresses.nextadr = nextadr
    
    
    def set_linking_outcome(self, mainadr, cfgadr, cfglen, ctorsadr, ctorslen, dtorsadr, dtorslen):
        self.clean(BootMsg.TypeEnum.LINKING_OUTCOME)
        self.linking_outcome.mainadr = mainadr
        self.linking_outcome.cfgadr = cfgadr
        self.linking_outcome.cfglen = cfglen
        self.linking_outcome.ctorsadr = ctorsadr
        self.linking_outcome.ctorslen = ctorslen
        self.linking_outcome.dtorsadr = dtorsadr
        self.linking_outcome.dtorslen = dtorslen
    
    
    def set_appinfo_summary(self, numapps, freeadr, pgmstartadr, pgmendadr, ramstartadr, ramendadr):
        self.clean(BootMsg.TypeEnum.APPINFO_SUMMARY)
        self.appinfo_summary.numapps = numapps
        self.appinfo_summary.freeadr = freeadr
        self.appinfo_summary.pgmstartadr = pgmstartadr
        self.appinfo_summary.pgmendadr = pgmendadr
        self.appinfo_summary.ramstartadr = ramstartadr
        self.appinfo_summary.ramendadr = ramendadr
        
        
    def set_param_request(self, offset, appname, length):
        self.clean(BootMsg.TypeEnum.PARAM_REQUEST)
        self.param_request.offset = offset
        self.param_request.appname = appname
        self.param_request.length = length
    
    
    def set_ihex(self, ihex_record):
        self.clean(BootMsg.TypeEnum.IHEX_RECORD)
        self.ihex_record = ihex_record
    
    
    def marshal(self):
        t = self.type
        e = BootMsg.TypeEnum
        if t in (e.ACK, e.REMOVE_LAST, e.REMOVE_ALL, e.BEGIN_LOADER, e.END_LOADER,
                 e.BEGIN_APPINFO, e.END_APPINFO, e.BEGIN_SETPARAM, e.END_SETPARAM,
                 e.BEGIN_GETPARAM, e.END_GETPARAM):
            payload = ''
        elif t == e.NACK:               payload = self.error_info.marshal()
        elif t == e.LINKING_SETUP:      payload = self.linking_setup.marshal()
        elif t == e.LINKING_ADDRESSES:  payload = self.linking_addresses.marshal()
        elif t == e.LINKING_OUTCOME:    payload = self.linking_outcome.marshal()
        elif t == e.IHEX_RECORD:        payload = self.ihex_record.marshal()
        elif t == e.APPINFO_SUMMARY:    payload = self.appinfo_summary.marshal()
        elif t == e.PARAM_REQUEST:      payload = self.param_request.marshal()
        elif t == e.PARAM_CHUNK:        payload = self.param_chunk.marshal()
        else: raise ValueError('Unknown bootloader message subtype %d' % self.type)
        return struct.pack('<%dsB' % self.MAX_PAYLOAD_LENGTH, payload, self.type)
    
    
    def unmarshal(self, data, offset=0):
        self.clean()
        if len(data) < self.MAX_LENGTH:
            raise ValueError("len(%s)=%d < %d" % (repr(data), len(data), self.MAX_LENGTH))
        payload, t = struct.unpack_from('<%dsB' % self.MAX_PAYLOAD_LENGTH, data, offset)
        
        e = BootMsg.TypeEnum
        if t in (e.ACK, e.REMOVE_LAST, e.REMOVE_ALL, e.BEGIN_LOADER, e.END_LOADER,
                 e.BEGIN_APPINFO, e.END_APPINFO, e.BEGIN_SETPARAM, e.END_SETPARAM,
                 e.BEGIN_GETPARAM, e.END_GETPARAM):
            pass
        elif t == e.NACK:               self.error_info.unmarshal(payload)
        elif t == e.LINKING_SETUP:      self.linking_setup.unmarshal(payload)
        elif t == e.LINKING_ADDRESSES:  self.linking_addresses.unmarshal(payload)
        elif t == e.LINKING_OUTCOME:    self.linking_outcome.unmarshal(payload)
        elif t == e.IHEX_RECORD:        self.ihex_record.unmarshal(payload)
        elif t == e.APPINFO_SUMMARY:    self.appinfo_summary.unmarshal(payload)
        elif t == e.PARAM_REQUEST:      self.param_request.unmarshal(payload)
        elif t == e.PARAM_CHUNK:        self.param_chunk.unmarshal(payload)
        else: raise ValueError('Unknown bootloader message subtype %d' % t)
        self.type = t

#==============================================================================

class MgmtMsg(Message):
    
    MAX_PAYLOAD_LENGTH = 31


    class TypeEnum:
        RAW                     = 0x00
    
        INFO_MODULE             = 0x10
        INFO_ADVERTISEMENT      = 0x11
        INFO_SUBSCRIPTION       = 0x12
    
        CMD_GET_NETWORK_STATE   = 0x20
        CMD_ADVERTISE           = 0x21
        CMD_SUBSCRIBE_REQUEST   = 0x22
        CMD_SUBSCRIBE_RESPONSE  = 0x23
    
    
    class Path(Serializable):
        def __init__(self, _MgmtMsg, module='', node='', topic=''):
            super(MgmtMsg.Path, self).__init__()
            self._MgmtMsg = _MgmtMsg
            self.module = module
            self.node = node
            self.topic = topic
        
        def __repr__(self):
            return '%s(MgmtMsg, module=%s, node=%s, topic=%s)' % \
                   (type(self).__name__, repr(self.module), repr(self.node), repr(self.topic))
        
        def marshal(self):
            lengths = (MODULE_NAME_MAX_LENGTH, NODE_NAME_MAX_LENGTH, TOPIC_NAME_MAX_LENGTH)
            return struct.pack('<%ds%ds%ds' % lengths, self.module, self.node, self.topic)
        
        def unmarshal(self, data, offset=0):
            lengths = (MODULE_NAME_MAX_LENGTH, NODE_NAME_MAX_LENGTH, TOPIC_NAME_MAX_LENGTH)
            self.module, self.node, self.topic = struct.unpack_from('<%ds%ds%ds' % lengths, data, offset)
    
    
    class PubSub(Serializable):
        def __init__(self, _MgmtMsg, topic='', transport=None, queue_length=0, raw_params=''):
            super(MgmtMsg.PubSub, self).__init__()
            self._MgmtMsg = _MgmtMsg
            self.MAX_RAW_PARAMS_LENGTH = _MgmtMsg.MAX_PAYLOAD_LENGTH - TOPIC_NAME_MAX_LENGTH - 4 - 1
            self.topic = topic
            self.transport = transport
            self.queue_length = queue_length
            self.raw_params = raw_params
        
        def __repr__(self):
            tn = self.transport.name if self.transport is not None else 'None'
            return '%s(MgmtMsg, topic=%s, transport=<%s>, queue_length=%d, raw_params=%s)' % \
                   (type(self).__name__, repr(self.topic), tn, self.queue_length, repr(self.raw_params))
        
        def marshal(self):
            return struct.pack('<%dsB%dsL' % (_MgmtMsg.MAX_PAYLOAD_LENGTH, self.MAX_RAW_PARAMS_LENGTH),
                               self.topic, self.queue_length, self.raw_params, 0xDEADBEEF)
                               
        def unmarshal(self, data, offset=0):
            self.topic, self.queue_length, self.raw_params, self.transport = \
                struct.unpack_from('<%dsB%dsL' % (_MgmtMsg.MAX_PAYLOAD_LENGTH, self.MAX_RAW_PARAMS_LENGTH), data, offset)
    
    
    class Module(Serializable):
        
        class Flags(Serializable):
            def __init__(self, intval=0):
                super(MgmtMsg.Module.Flags, self).__init__()
                self.stopped = bool(intval & (1 << 0))
            
            def __int__(self):
                return int(self.stopped)
            
            def __repr__(self):
                return '%s(intval=0x%0.X)' % (type(self).__name__, self.intval)
            
            def marshal(self):
                return struct.pack('<B', int(self))
                
            def unmarshal(self, data, offset=0):
                self.__init__(struct.unpack_from('<B', data, offset))
        
        def __init__(self, _MgmtMsg, module='', flags=None):
            super(MgmtMsg.Module, self).__init__()
            self._MgmtMsg = _MgmtMsg
            self.module = module
            self.flags = flags if flags is not None else self.Flags()
        
        def __repr__(self):
            return '%s(MgmtMsg, module=%s, flags=%s)' % (type(self).__name__, repr(self.module), repr(self.flags))
        
        def marshal(self):
            return struct.pack('<%ds' % MODULE_NAME_MAX_LENGTH, _MODULE_NAME) + self.flags.marshal()
                               
        def unmarshal(self, data, offset=0):
            self.module = struct.unpack_from('<%ds' % MODULE_NAME_MAX_LENGTH, data, offset)
            self.flags.unmarshal(data, offset + MODULE_NAME_MAX_LENGTH)
    
    
    def __init__(self, type=None):
        super(MgmtMsg, self).__init__()
        self.type = type
        self.path = MgmtMsg.Path(self)
        self.pubsub = MgmtMsg.PubSub(self)
        self.module = MgmtMsg.Module(self)
    
    
    def __repr__(self):
        t = self.type
        e = MgmtMsg.TypeEnum
        if t in (e.RAW, e.CMD_GET_NETWORK_STATE):
            subtext = ''
        if t == e.INFO_MODULE:
            subtext = ', module=' + repr(self.module)
        elif t in (e.INFO_ADVERTISEMENT, e.INFO_SUBSCRIPTION):
            subtext = ', path=' + repr(self.path)
        elif t in (e.CMD_ADVERTISE, e.CMD_SUBSCRIBE_REQUEST, e.CMD_SUBSCRIBE_RESPONSE):
            subtext = ', pubsub=' + repr(self.pubsub)
        else: raise ValueError('Unknown management message subtype %d' % self.type)
        return '%s(type=%d%s)' % (type(self).__name__, self.type, subtext)
    
    
    def check_type(self, type):
        assert not type is None
        if self.type != type:
            raise ValueError('Unknown management message subtype %d' % type)
    
    
    def clean(self, type=None):
        self.__init__()
        self.type = type # TODO: Build only the needed type
        
        
    def marshal(self):
        t = self.type
        e = MgmtMsg.TypeEnum
        if t in (e.RAW, e.CMD_GET_NETWORK_STATE):
            bytes = ''
        if t == e.INFO_MODULE:
            bytes = self.module.marshal()
        elif t in (e.INFO_ADVERTISEMENT, e.INFO_SUBSCRIPTION):
            bytes = self.path.marshal()
        elif t in (e.CMD_ADVERTISE, e.CMD_SUBSCRIBE_REQUEST, e.CMD_SUBSCRIBE_RESPONSE):
            bytes = self.pubsub.marshal()
        else: raise ValueError('Unknown management message subtype %d' % self.type)
        return struct.pack('<B%ds' % (self.MAX_PAYLOAD_LENGTH - 1), self.type, bytes)
        
        
    def unmarshal(self, data, offset=0):
        self.clean()
        t, payload = struct.unpack_from('<B%ds' % (self.MAX_PAYLOAD_LENGTH - 1), data, offset)
        e = MgmtMsg.TypeEnum
        if t in (e.RAW, e.CMD_GET_NETWORK_STATE):
            pass
        if t == e.INFO_MODULE:
            self.module.unmarshal(payload)
        elif t in (e.INFO_ADVERTISEMENT, e.INFO_SUBSCRIPTION):
            self.path.unmarshal(payload)
        elif t in (e.CMD_ADVERTISE, e.CMD_SUBSCRIBE_REQUEST, e.CMD_SUBSCRIBE_RESPONSE):
            self.pubsub.unmarshal(payload)
        else: raise ValueError('Unknown management message subtype %d' % t)
        self.type = t      
        
#==============================================================================

class Topic(object):
    
    def __init__(self, name, msg_type):
        self.name = str(name)
        self.msg_type = msg_type
        self.max_queue_length = 0
        self.publish_timeout = Time_INFINITE
        
        self.local_publishers = []
        self.local_subscribers = []
        self.remote_publishers = []
        self.remote_subscribers = []
        
        self._lock = threading.Lock()
    
    
    def __repr__(self):
        return '%s(name=%s, msg_type=%s, max_queue_length=%d, publish_timeout=%f)' % \
               (type(self).__name__, repr(self.name), self.msg_type.__name__, self.max_queue_length, self.publish_timeout.to_s())
    
    def get_lock(self):
        return self._lock
    
    
    def has_name(self, name):
        return self.name == str(name)
    
    
    def has_local_publishers(self):
        return len(self.local_publishers) > 0
    
    
    def has_local_subscribers(self):
        return len(self.local_subscribers) > 0
    
    
    def has_remote_publishers(self):
        return len(self.remote_publishers) > 0
    
    
    def has_remote_subscribers(self):
        return len(self.remote_subscribers) > 0
    
    
    def is_awaiting_advertisements(self):
        with self._lock:
            return not self.has_local_publishers() and \
                   not self.has_remote_publishers() and \
                       self.has_local_subscribers()
    
        
    def is_awaiting_subscriptions(self):
        with self._lock:
            return not self.has_local_subscribers() and \
                   not self.has_remote_subscribers() and \
                       self.has_local_publishers()
    
    
    def alloc(self):
        return self.msg_type()
    
    
    def release(self, msg):
        pass
    
    
    def free(self, msg):
        pass
    
    
    def extend_pool(self, length):
        length = int(length)
        assert length > 0
        with self._lock:
            self._msg_pool.extend([ self.msg_type() ] * length)
    
    
    def notify_locals(self, msg, timestamp):
        with self._lock:
            for sub in self.local_subscribers:
                sub.notify(msg, timestamp)
    
    
    def notify_remotes(self, msg, timestamp):
        with self._lock:
            for sub in self.remote_subscribers:
                sub.notify(msg, timestamp)
            
            
    def advertise_local(self, pub, publish_timeout):
        with self._lock:
            if self.publish_timeout > publish_timeout:
                self.publish_timeout = publish_timeout
            self.local_publishers.append(pub)
            
            
    def advertise_remote(self, pub, publish_timeout):
        with self._lock:
            if self.publish_timeout > publish_timeout:
                self.publish_timeout = publish_timeout
            self.remote_publishers.append(pub)
        
        
    def subscribe_local(self, sub):
        with self._lock:
            if self.max_queue_length < sub.get_queue_length():
                self.max_queue_length = sub.get_queue_length()
            self.local_subscribers.append(sub)
        
        
    def subscribe_remote(self, sub):
        with self._lock:
            if self.max_queue_length < sub.get_queue_length():
                self.max_queue_length = sub.get_queue_length()
            self.remote_subscribers.append(sub)
    
#==============================================================================

class BasePublisher(object):
    
    def __init__(self):
        self.topic = None
        self._r2p_net_path = '?/?/?'

        
    def __repr__(self):
        return '<%s(path=%s)>' % (type(self).__name__, repr(self._r2p_net_path))


    def has_topic(self, topic_name):
        return self.topic is not None and self.topic.has_name(topic_name)
    
    
    def notify_advertised(self, topic, r2p_net_path=None):
        self.topic = topic
        if r2p_net_path is not None:
            self._r2p_net_path = r2p_net_path
        else:
            self._r2p_net_path = '%s/?/?' % Middleware.instance().module_name
    
    
    def alloc(self):
        return self.topic.alloc()
    
    
    def publish(self, msg):
        deadline = Time.now() + self.topic.publish_timeout
        locals_done = self.topic.notify_locals(msg, deadline)
        remotes_done = self.topic.notify_remotes(msg, deadline)
        return locals_done and remotes_done
    
    
    def publish_locally(self, msg):
        deadline = Time.now() + self.topic.publish_timeout
        return self.topic.notify_locals(msg, deadline)
    
    
    def publish_remotely(self, msg):
        deadline = Time.now() + self.topic.publish_timeout
        return self.topic.notify_remotes(msg, deadline)
        
#==============================================================================

class BaseSubscriber(object):
    
    def __init__(self):
        self.topic = None
        self._r2p_net_path = '?/?/?'

        
    def __repr__(self):
        return '<%s(path=%s)>' % (type(self).__name__, repr(self._r2p_net_path))
        
        
    def get_queue_length(self):
        raise NotImplementedError()
        
    
    def has_topic(self, topic_name):
        return self.topic is not None and self.topic.has_name(topic_name)
    
    
    def notify_subscribed(self, topic, r2p_net_path=None):
        self.topic = topic
        if r2p_net_path is not None:
            self._r2p_net_path = r2p_net_path
        else:
            self._r2p_net_path = '%s/?/?' % Middleware.instance().module_name
    
    
    def notify(self, msg, deadline):
        raise NotImplementedError()
    
    
    def fetch(self):
        raise NotImplementedError()
        # return (msg, deadline) or throw IndexError
        
    
    def release(self, msg):
        pass # gc
    
#==============================================================================

class LocalPublisher(BasePublisher):
    
    def __init__(self):
        super(LocalPublisher, self).__init__()
    
#==============================================================================

class LocalSubscriber(BaseSubscriber):
    
    def __init__(self, queue_length, callback=None):
        super(LocalSubscriber, self).__init__()
        self.queue = ArrayQueue(queue_length)
        self.callback = callback
        self.node = None
    
    
    def get_queue_length(self):
        return self.queue.length
    
    
    def notify(self, msg, deadline):
        self.queue.post((msg, deadline)) # throws IndexError
        self.node.notify(self)
    
    
    def fetch(self):
        return self.queue.fetch() # throws IndexError
    
#==============================================================================

class Publisher(LocalPublisher):
    
    def __init__(self):
        super(Publisher, self).__init__()
    
#==============================================================================

class Subscriber(LocalSubscriber):
    
    def __init__(self, queue_length, callback=None):
        super(Subscriber, self).__init__(queue_length, callback)

#==============================================================================

class RemotePublisher(BasePublisher):
    
    def __init__(self, transport):
        super(RemotePublisher, self).__init__()
        self.transport = transport
    
#==============================================================================

class RemoteSubscriber(BaseSubscriber):
    
    def __init__(self, transport):
        super(RemoteSubscriber, self).__init__()
        self.transport = transport
    
#==============================================================================

class Node(object):
    
    def __init__(self, name):
        self.name = str(name)
        self.publishers = []
        self.subscribers = []
        self._publishers_lock = threading.Lock()
        self._subscribers_lock = threading.Lock()
        self.timeout = Time_INFINITE
        self.notification_queue = EventQueue()
        self.stopped = False
        self._stop_lock = threading.RLock()
        
        
    def begin(self):
        logging.debug('Starting Node %s' % repr(self.name))
        Middleware.instance().add_node(self)
        
        
    def end(self):
        logging.debug('Terminating Node %s' % repr(self.name))
        Middleware.instance().confirm_stop(self)
        
        
    def advertise(self, pub, topic_name, publish_timeout, msg_type):
        logging.debug('Node %s advertising %s, msg_type=%s, timeout=%s' % \
                      (repr(self.name), repr(topic_name), msg_type.__name__, repr(publish_timeout)))
        with self._publishers_lock:
            mw = Middleware.instance()
            mw.advertise_local(pub, topic_name, publish_timeout, msg_type)
            pub.node = self;
            self.publishers.append(pub)
            pub._r2p_net_path = '%s/%s/%s' % (mw.module_name, self.name, topic_name)
        
        
    def subscribe(self, sub, topic_name, msg_type):
        logging.debug('Node %s subscribing %s, msg_type=%s' % \
                      (repr(self.name), repr(topic_name), msg_type.__name__))
        with self._subscribers_lock:
            mw = Middleware.instance()
            mw.subscribe_local(sub, topic_name, msg_type)
            sub.node = self
            self.subscribers.append(sub)
            sub._r2p_net_path = '%s/%s/%s' % (mw.module_name, self.name, topic_name)
        
        
    def publish_publishers(self, info_pub):
        with self._publishers_lock:
            for pub in self.publishers:
                msg = info_pub.alloc()
                msg.type = MgmtMsg.TypeEnum.INFO_ADVERTISEMENT
                msg.path.module = Middleware.instance().module_name
                msg.path.node = self.name
                msg.path.topic = pub.topic.name
                info_pub.publish_remotely(msg)
        
    
    def publish_subscribers(self, info_pub):
        with self._subscribers_lock:
            for pub in self.subscribers:
                msg = info_pub.alloc()
                msg.type = MgmtMsg.TypeEnum.INFO_SUBSCRIPTION
                msg.path.module = Middleware.instance().module_name
                msg.path.node = self.name
                msg.path.topic = pub.topic.name
                info_pub.publish_remotely(msg)


    def notify(self, sub):
        self.notification_queue.signal(sub)
        
        
    def notify_stop(self):
        with self._stop_lock:
            if not self.stopped:
                self.stopped = True
                self.notification_queue.signal(None)
        
        
    def spin(self, timeout=Time_INFINITE):
        try:
            sub = None
            while sub is None:
                sub = self.notification_queue.wait(timeout)
        except Queue.Empty:
            return
        
        with self._subscribers_lock:
            assert sub in self.subscribers
            msg, timestamp = sub.fetch()
            if sub.callback is not None:
                sub.callback(msg)
            sub.release(msg)
       
#==============================================================================

class Transport(object):
    
    class TypeEnum:
        MESSAGE                 = 0
        ADVERTISEMENT           = 1
        SUBSCRIPTION_REQUEST    = 2
        SUBSCRIPTION_RESPONSE   = 3
        STOP                    = 4
        REBOOT                  = 5
    
    
    def __init__(self, name):
        assert is_node_name(name)
        self.name = name
        self.publishers = []
        self.subscribers = []
        self._publishers_lock = threading.RLock()
        self._subscribers_lock = threading.RLock()
        
        
    def open(self):
        raise NotImplementedError()
        
        
    def close(self):
        raise NotImplementedError()
    
        
    def notify_advertisement(self, topic):
        self._send_advertisement(topic)
    
    
    def notify_subscription_request(self, topic):
        self._send_subscription_request(topic)
    
    
    def notify_subscription_response(self, topic):
        self._send_subscription_response(topic)
        
        
    def notify_stop(self):
        self._send_stop()
        
        
    def notify_reboot(self):
        self._send_reboot()
    
    
    def touch_publisher(self, topic):
        with self._publishers_lock:
            for pub in self.publishers:
                if pub.has_topic(topic.name):
                    return pub
            pub = self._create_publisher(topic)
            path = '%s/(%s)/%s' % (Middleware.instance().module_name, self.name, topic.name)
            pub.notify_advertised(topic, path)
            topic.advertise_remote(pub, Time_INFINITE)
            self.publishers.append(pub)
            return pub
        
        
    def touch_subscriber(self, topic, queue_length):
        with self._publishers_lock:
            for sub in self.subscribers:
                if sub.has_topic(topic.name):
                    return sub
            sub = self._create_subscriber(topic, queue_length)
            path = '%s/(%s)/%s' % (Middleware.instance().module_name, self.name, topic.name)
            sub.notify_subscribed(topic, path)
            topic.subscribe_remote(sub)
            self.subscribers.append(sub)
            return sub
    
    
    def _advertise_cb(self, topic, raw_params):
        if topic.has_local_subscribers():
            self.touch_publisher(topic_name)
    
    
    def _subscribe_cb(self, topic, queue_length):
        if topic.has_local_publishers():
            self.touch_subscriber(topic, queue_length)
    
    
    def advertise(self, pub, topic_name, publish_timeout, msg_type):
        with self._publishers_lock:
            Middleware.instance().advertise_remote(pub, topic_name, publish_timeout, msg_type)
            self.publishers.append(pub)
        
        
    def subscribe(self, sub, topic_name, msg_type):
        with self._subscribers_lock:
            Middleware.instance().subscribe_remote(sub, topic_name, msg_type)
            self.subscribers.append(sub)
    
    
    def _send_message(self, topic_name, payload):
        raise NotImplementedError()
    
    
    def _send_advertisement(self, topic):
        raise NotImplementedError()
    
    
    def _send_subscription_request(self, topic):
        raise NotImplementedError()
    
    
    def _send_subscription_response(self, topic):
        raise NotImplementedError()
    
    
    def _send_stop(self):
        raise NotImplementedError()
    
    
    def _send_reboot(self):
        raise NotImplementedError()
    
    
    def _recv(self):
        raise NotImplementedError()
        # return (type \[, 'topic', 'payload'\])
        
        
    def _create_publisher(self, topic):
        raise NotImplementedError()
        # return XxxPublisher<RemotePublisher>()
        
        
    def _create_subscriber(self, topic, queue_length):
        raise NotImplementedError()
        # return XxxSubscriber<RemoteSubscriber>()

#==============================================================================

_Middleware_instance = None

class Middleware(object):

    MGMT_BUFFER_LENGTH      = 5
    MGMT_TIMEOUT_MS         = 20

    BOOT_PAGE_LENGTH        = 1 << 10
    BOOT_BUFFER_LENGTH      = 4

    TOPIC_CHECK_TIMEOUT_MS  = 100
    
    
    @staticmethod
    def instance():
        global _Middleware_instance
        if _Middleware_instance is not None:
            return _Middleware_instance
        else:
            _Middleware_instance = Middleware(_MODULE_NAME, 'BOOT_' + _MODULE_NAME)
            return _Middleware_instance
    
    
    def __init__(self, module_name, bootloader_name):
        self.module_name = str(module_name)
        self.bootloader_name = str(bootloader_name)
        
        assert is_module_name(self.module_name)
        assert is_topic_name(self.bootloader_name)
        
        self.topics = []
        self.nodes = []
        self.transports = []
        
        self._topics_lock = threading.RLock()
        self._nodes_lock = threading.Lock()
        self._transports_lock = threading.Lock()
        
        self.mgmt_topic = Topic('R2P', MgmtMsg)
        self.boot_topic = Topic(self.bootloader_name, MgmtMsg)
        self.mgmt_boot_thread = None
        
        self.stopped = False
        self.num_running_nodes = 0
        
        
    def initialize(self, module_name=None, bootloader_name=None):
        if module_name is not None:
            self.module_name = str(module_name)
            assert is_module_name(module_name)
        
        if bootloader_name is not None:
            self.bootloader_name = str(bootloader_name)
            assert is_topic_name(bootloader_name)
            self.boot_topic.name = self.bootloader_name
        
        logging.info('Initializing middleware %s' % repr(self.module_name))
        
        self.add_topic(self.boot_topic)
        self.add_topic(self.mgmt_topic)
        
        self.mgmt_boot_thread = threading.Thread(name="R2P_MGMT", target=self.mgmt_threadf, args=(self,))
        self.mgmt_boot_thread.start()
        
        ready = False
        while not ready and ok():
            logging.debug('Awaiting mgmt_topic to be advertised and subscribed')
            with self.mgmt_topic.get_lock():
                ready = self.mgmt_topic.has_local_publishers() and self.mgmt_topic.has_local_subscribers()
            if not ready:
                time.sleep(0.5) # TODO: configure
    
    
    def uninitialize(self):
        logging.info('Uninitializing middleware %s' % repr(self.module_name))
        self.stop()
        pass # TODO
    
    
    def _stop(self):
        global _sys_lock
        with _sys_lock:
            if not self.stopped:
                self.stopped = True

            
    def stop(self):
        logging.info('Stopping middleware %s' % repr(self.module_name))
        trigger = False
        with _sys_lock:
            if not self.stopped:
                self.stopped = True
                trigger = True
        
        for transport in self.transports:
            transport.touch_publisher(self.boot_topic)
            transport.touch_subscriber(self.boot_topic, Middleware.MGMT_BUFFER_LENGTH)
        
        if not trigger:
            return
        
        running = True
        while running:
            running = False
            with self._nodes_lock:
                for node in self.nodes:
                    node.notify_stop()
                    running = True
            time.sleep(0.5) # TODO: configure
            
        self.mgmt_boot_thread.join()
        self.mgmt_boot_thread = threading.Thread(name="R2P_BOOT", target=self.boot_threadf, args=(self,))
        self.mgmt_boot_thread.start()
            
        
    def add_node(self, node):
        logging.debug('Adding node %s' % repr(node.name))
        with self._nodes_lock:
            for existing in self.nodes:
                if node is existing or node.name == existing.name:
                    raise KeyError('Node %s already exists' % repr(node.name))
            self.num_running_nodes += 1
            self.nodes.append(node)
        
        
    def add_transport(self, transport):
        logging.debug('Adding transport %s' % repr(transport.name))
        with self._transports_lock:
            for existing in self.transports:
                if transport is existing:
                    raise KeyError('Transport already exists')
            self.transports.append(transport)
            
        
    def add_topic(self, topic):
        logging.debug('Adding topic %s' % repr(topic.name))
        with self._topics_lock:
            for existing in self.topics:
                if topic is existing or topic.name == existing.name:
                    raise KeyError('Topic %s already exists' % repr(topic.name))
            self.topics.append(topic)
        
        
    def advertise_local(self, pub, topic_name, publish_timeout, msg_type):
        with self._topics_lock:
            topic = self.touch_topic(topic_name, msg_type)
            pub.notify_advertised(topic)
            topic.advertise_local(pub, publish_timeout)
            logging.debug('Advertisement of %s by %s' % (repr(topic), repr(pub)))
        
        for transport in self.transports:
            transport.notify_advertisement(topic)
        
    
    def advertise_remote(self, pub, topic_name, publish_timeout, msg_type):
        with self._topics_lock:
            topic = self.touch_topic(topic_name, msg_type)
            pub.notify_advertised(topic)
            topic.advertise_remote(pub, publish_timeout)
            logging.debug('Advertisement of %s by %s' % (repr(topic), repr(pub)))
        
        for transport in self.transports:
            transport.notify_advertisement(topic)
        
        
    def subscribe_local(self, sub, topic_name, msg_type):
        with self._topics_lock:
            topic = self.touch_topic(topic_name, msg_type)
            sub.notify_subscribed(topic)
            topic.subscribe_local(sub)
            logging.debug('Subscription of %s by %s' % (repr(topic), repr(sub)))
        
        for transport in self.transports:
            transport.notify_subscription_request(topic)
    
    
    def subscribe_remote(self, sub, topic_name, msg_type):
        with self._topics_lock:
            topic = self.touch_topic(topic_name, msg_type)
            sub.notify_subscribed(topic)
            topic.subscribe_remote(sub)
            logging.debug('Subscription of %s by %s' % (repr(topic), repr(sub)))


    def confirm_stop(self, node):
        logging.debug('Node %s halted' % repr(node.name))
        with self._nodes_lock:
            assert self.num_running_nodes > 0
            for existing in self.nodes:
                if node is existing:
                    break
            else:
                raise KeyError('Node %s not registered' % repr(node.name))
            self.num_running_nodes -= 1
            self.nodes = [ existing for existing in self.nodes if node is not existing ]

    
    def find_topic(self, topic_name):
        with self._topics_lock:
            for topic in self.topics:
                if topic_name == topic.name:
                    return topic
            return None
    
    
    def find_node(self, node_name):
        with self._nodes_lock:
            for node in self.nodes:
                if node_name == node.name:
                    return node
            return None
    
    
    def touch_topic(self, topic_name, msg_type):
        with self._topics_lock:
            for topic in self.topics:
                if topic_name == topic.name:
                    return topic
            
            topic = Topic(topic_name, msg_type)
            self.topics.append(topic)
            return topic


    def mgmt_cb(self, msg):
        if msg.type == MgmtMsg.TypeEnum.CMD_ADVERTISE:
            logging.debug('CMD_ADVERTISE: %s' % repr(msg))
            topic = self.find_topic(msg.pubsub.topic)
            
            if topic is not None and topic.has_local_subscribers():
                msg.pubsub.transport.notify_subscription_request(topic)
        
        if msg.type == MgmtMsg.TypeEnum.CMD_SUBSCRIBE_REQUEST:
            logging.debug('CMD_SUBSCRIBE_REQUEST: %s' % repr(msg))
            topic = self.find_topic(msg.pubsub.topic)
            
            if topic is not None and topic.has_local_publishers():
                transport = msg.pubsub.transport
                transport._subscribe_cb(topic, msg.pubsub.queue_length)
                transport.notify_subscription_response(topic)
        
        if msg.type == MgmtMsg.TypeEnum.CMD_SUBSCRIBE_RESPONSE:
            logging.debug('CMD_SUBSCRIBE_REPLY: %s' % repr(msg))
            topic = self.find_topic(msg.pubsub.topic)
            transport = msg.pubsub.transport
            transport._advertise_cb(topic, msg.pubsub.raw_params) 
    
    
    def mgmt_threadf(self, thread):
        node = Node('R2P_MGMT')
        pub = Publisher()
        sub = Subscriber(5, self.mgmt_cb) # TODO: configure
        
        node.begin()
        node.advertise(pub, 'R2P', Time.ms(200), MgmtMsg) # TODO: configure
        node.subscribe(sub, 'R2P', MgmtMsg) # TODO: configure
        
        while ok():
            try:
                node.spin(Time.ms(1000)) # TODO: configure
            except TimeoutError:
                pass
            except IndexError: # FIXME: should not happen..
                pass
        
        node.end()
        
        
    def boot_threadf(self):
        pass #  TODO
        
#==============================================================================

class LineIO(object):
    
    def __init__(self):
        pass
    
    
    def open(self):
        raise NotImplementedError()
        
        
    def close(self):
        raise NotImplementedError()
    
    
    def readline(self):
        raise NotImplementedError()
        # return line
    
    
    def writeline(self, line):
        raise NotImplementedError()
        
#==============================================================================

class SerialLineIO(LineIO):
    
    def __init__(self, dev_path, baud_rate):
        super(SerialLineIO, self).__init__()
        self._dev_path = dev_path
        self._baud = baud_rate
        self._ser = None
        self._ti = None
        self._to = None
        self._tmp_in = ''
        self._read_lock = threading.Lock()
        self._write_lock = threading.Lock()
    
    
    def __repr__(self):
        return '%s(dev_path=%s, baud_rate=%d)' % (type(self).__name__, repr(self._dev_path), self._baud)
        
    
    def open(self):
        if self._ser is None:
            self._ser = serial.Serial(port = self._dev_path, baudrate = self._baud, timeout = 3)
            self._ti = io.TextIOWrapper(buffer = io.BufferedReader(self._ser, 1), encoding = 'ascii', newline = '\r\n')
            self._to = io.TextIOWrapper(buffer = io.BufferedWriter(self._ser), encoding = 'ascii', newline = '\r\n')
    
        
    def close(self):
        if self._ser is not None:
            self._ser.close()
            self._ser = None
        self._ti = None
        self._to = None
    
    
    def readline(self):
        while True:
            with self._read_lock:
                try:
                    line = str(self._ti.readline())
                except:
                    continue
                self._tmp_in += line
                if self._tmp_in[-2:] == '\r\n':
                    line = self._tmp_in[:-2]
                    self._tmp_in = ''
                    break
        logging.debug("%s >>> %s" % (self._dev_path, repr(line)))
        return line
    
    
    def writeline(self, line):
        logging.debug("%s <<< %s" % (self._dev_path, repr(line)))
        with self._write_lock:
            self._to.write(unicode(line))
            self._to.write(u'\n')
    
#==============================================================================
    
class StdLineIO(LineIO):
    
    def __init__(self):
        super(StdLineIO, self).__init__()
        self._read_lock = threading.Lock()
        self._write_lock = threading.Lock()
    
    
    def __repr__(self):
        return type(self).__name__ + '()'
    
    
    def open(self):
        pass
    
        
    def close(self):
        pass
    
    
    def readline(self):
        with self._read_lock:
            line = raw_input()
            logging.debug("stdin >>> %s" % repr(line))
        return line
    
    
    def writeline(self, line):
        with self._write_lock:
            logging.debug("stdout <<< %s" % repr(line))
            print line

#==============================================================================

class TCPLineIO(LineIO):
    
    def __init__(self, address_string, port):
        self._socket = None
        self._fp = None
        self._address = address_string
        self._port = port
    
    
    def __repr__(self):
        return '%s(address_string=%s, port=%d)' % (type(self).__name__, repr(self._address), self._port)
    
    
    def open(self):
        self._socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._socket.connect((self._address, self._port))
        self._fp = self._socket.makefile()
        
        time.sleep(1)
    
        
    def close(self):
        self._socket.close()
        self._fp = None
    
    
    def readline(self):
        line = self._fp.readline().rstrip('\r\n')
        logging.debug("%s:%d >>> %s" % (self._address, self._port, repr(line)))
        return line
    
    
    def writeline(self, line):
        logging.debug("%s:%d <<< %s" % (self._address, self._port, repr(line)))
        self._fp.write(line)
        self._fp.write('\r\n')
        self._fp.flush()
        
#==============================================================================

class DebugPublisher(RemotePublisher):
    
    def __init__(self, transport):
        super(DebugPublisher, self).__init__(transport)

#==============================================================================

class DebugSubscriber(RemoteSubscriber):
    
    def __init__(self, transport, queue_length):
        super(DebugSubscriber, self).__init__(transport)
        self.queue = ArrayQueue(queue_length)
        self._lock = threading.Lock()
    
    
    def get_queue_length(self):
        with self._lock:
            return self.queue.length
    
    
    def notify(self, msg, deadline):
        with self._lock:
            try:
                self.queue.post((msg, deadline)) # throws IndexError
                self.transport._sub_queue.signal(self)
            except IndexError:
                logging.warning('Notify failed (IndexError)') # FIXME: Sporadic error, but still works...
                
    
    
    def fetch(self):
        with self._lock:
            return self.queue.fetch() # throws IndexError

#==============================================================================

class DebugTransport(Transport):
    
    MGMT_BUFFER_LENGTH = 100
    
    
    class MsgParser(object):
        def __init__(self, line):
            self._line = str(line)
            self._linelen = len(self._line)
            self._offset = 0
        
        def _check_length(self, length):
            assert length >= 0
            endx = self._offset + length
            if self._linelen < endx:
                raise ParserError("Expected %d chars at %s[%d:%d] == %s (%d chars less)" %
                                  (length, repr(self._line), self._offset, endx,
                                   repr(self._line[self._offset : endx]), endx - self._linelen))
        
        def check_eol(self):
            assert self._linelen >= self._offset
            if self._linelen > self._offset:
                raise ParserError("Expected end of line at %s[%d:] == %s (%d chars more)" %
                                  (repr(self._line), self._offset, repr(self._line[self._offset:]),
                                   self._linelen - self._offset))
        
        def expect_char(self, c): 
            self._check_length(1)
            if self._line[self._offset] != c:
                raise ParserError("Expected %s at %s[%d] == %s" %
                                  (repr(c), repr(self._line), self._offset, repr(self._line[self._offset])))
            self._offset += 1
        
        def read_char(self):
            self._check_length(1)
            c = self._line[self._offset]
            self._offset += 1
            return c
        
        def skip_after_char(self, c):
            try:
                while self.read_char() != c:
                    pass
            except ParserError:
                raise ParserError("Expected %s in %s" % (repr(c), repr(self._line)))
        
        def read_hexb(self):
            self._check_length(2)
            off = self._offset
            try: b = int(self._line[off : off + 2], 16)
            except: raise ParserError("Expected hex byte at %s[%d:%d] == %s" %
                                      (repr(self._line), off, off + 2, repr(self._line[off : off + 2])))
            self._offset += 2
            return b
        
        def read_unsigned(self, size):
            assert size > 0
            self._check_length(2 * size)
            value = 0
            while size > 0:
                value = (value << 8) | self.read_hexb()
                size -= 1
            return value
        
        def read_string(self, length):
            self._check_length(length)
            s = self._line[self._offset : self._offset + length]
            self._offset += length
            return s
        
        def read_bytes(self, length):
            self._check_length(2 * length)
            return ''.join([ chr(self.read_unsigned(1)) for i in xrange(length) ])
    
    
    def __init__(self, name, lineio):
        super(DebugTransport, self).__init__(name)
        self._lineio = lineio
        self._rx_thread = None
        self._tx_thread = None
        self._mgmt_rpub = DebugPublisher(self)
        self._mgmt_rsub = DebugSubscriber(self, self.MGMT_BUFFER_LENGTH)
        self._sub_queue = EventQueue()
        self._running = False
        self._running_lock = threading.Lock()
    
    
    def __repr__(self):
        return '%s(name=%s, lineio=%s)' % (type(self).__name__, repr(self.name), repr(self._lineio))
    
    
    def open(self):
        with self._running_lock:
            if not self._running:
                logging.info('Opening %s' % repr(self))
                self._running = True
                self._lineio.open()
                self._lineio.writeline('')
                self._lineio.writeline('')
                self._lineio.writeline('')
                self._rx_thread = threading.Thread(name=(self.name + "_RX"), target=self._rx_threadf)
                self._tx_thread = threading.Thread(name=(self.name + "_TX"), target=self._tx_threadf)
                self._rx_thread.start()
                self._tx_thread.start()
                self.advertise(self._mgmt_rpub, 'R2P', Time.ms(200), MgmtMsg) #  TODO: configure
                self.subscribe(self._mgmt_rsub, 'R2P', MgmtMsg) #  TODO: configure
                logging.info('%s open' % repr(self))
                Middleware.instance().add_transport(self)
            else:
                raise RuntimeError('%s already open' % repr(self))
    
        
    def close(self):
        with self._running_lock:
            if self._running:
                logging.info('Closing %s' % repr(self))
                self._running = False
                self._rx_thread.join()
                self._tx_thread.join()
                self._rx_thread = None
                self._tx_thread = None
                self._lineio.close()
                logging.info('%s closed' % repr(self))
            else:
                raise RuntimeError('%s already closed' % repr(self))
    
    
    def _send_message(self, topic_name, payload):
        assert is_topic_name(topic_name)
        assert len(payload) < 256
        now = int(time.time()) & 0xFFFFFFFF
        cs = Checksummer()
        cs.add_uint(now)
        cs.add_uint(len(topic_name))
        cs.add_bytes(topic_name)
        cs.add_uint(len(payload))
        cs.add_bytes(payload)
        args = (now, len(topic_name), topic_name,
                len(payload), str2hexb(payload),
                cs.compute_checksum())
        line = '@%.8X:%.2X%s:%.2X%s:%0.2X' % args
        self._lineio.writeline(line)
    
    
    def _send_advertisement(self, topic):
        topic_name = topic.name
        assert is_topic_name(topic_name)
        module_name = Middleware.instance().module_name
        assert is_module_name(module_name)
        now = int(time.time()) & 0xFFFFFFFF
        cs = Checksummer()
        cs.add_uint(now)
        cs.add_uint(len(module_name))
        cs.add_bytes(module_name)
        cs.add_uint(len(topic_name))
        cs.add_bytes(topic_name)
        args = (now, len(module_name), module_name,
                len(topic_name), topic_name,
                cs.compute_checksum())
        line = '@%.8X:00:p:%.2X%s:%.2X%s:%0.2X' % args
        self._lineio.writeline(line)
    
    
    def _send_subscription_request(self, topic):
        topic_name = topic.name
        with topic.get_lock():
            queue_length = topic.max_queue_length
        assert is_topic_name(topic_name)
        assert 0 < queue_length < 256
        module_name = Middleware.instance().module_name
        assert is_module_name(module_name)
        now = int(time.time()) & 0xFFFFFFFF
        cs = Checksummer()
        cs.add_uint(now)
        cs.add_uint(queue_length)
        cs.add_uint(len(module_name))
        cs.add_bytes(module_name)
        args = (now, queue_length,
                len(module_name), module_name,
                len(topic_name), topic_name,
                cs.compute_checksum())
        line = '@%.8X:00:s%.2X:%.2X%s:%.2X%s:%0.2X' % args
        self._lineio.writeline(line)
    
    
    def _send_subscription_response(self, topic):
        topic_name = topic.name
        assert is_topic_name(topic_name)
        assert 0 < len(topic_name) < 256
        module_name = Middleware.instance().module_name
        assert 0 < len(module_name) <= 7
        now = int(time.time()) & 0xFFFFFFFF
        cs = Checksummer()
        cs.add_uint(now)
        cs.add_uint(len(module_name))
        cs.add_bytes(module_name)
        cs.add_uint(len(topic_name))
        cs.add_bytes(topic_name)
        args = (now, len(module_name), module_name,
                len(topic_name), topic_name,
                cs.compute_checksum())
        line = '@%.8X:00:e:%.2X%s:%.2X%s:%0.2X' % args
        self._lineio.writeline(line)
    
    
    def _send_stop(self):
        now = int(time.time()) & 0xFFFFFFFF
        cs = Checksummer()
        cs.add_uint(now)
        cs.add_bytes('t')
        line = '@%.8X:00:t:%0.2X' % (now, cs.compute_checksum())
        self._lineio.writeline(line)
    
    
    def _send_reboot(self):
        now = int(time.time()) & 0xFFFFFFFF
        cs = Checksummer()
        cs.add_uint(now)
        cs.add_bytes('r')
        line = '@%.8X:00:r:%0.2X' % (now, cs.compute_checksum())
        self._lineio.writeline(line)
    
        
    def _recv(self):
        cs = Checksummer()
        while True:
            with self._running_lock:
                if not self._running:
                    return None
            
            # Start parsing the incoming message
            line = self._lineio.readline()
            parser = self.MsgParser(line)
            parser.skip_after_char('@')
            break
        
        deadline = parser.read_unsigned(4)
        cs.add_uint(deadline)
        
        parser.expect_char(':')
        length = parser.read_unsigned(1)
        topic = parser.read_string(length)
        cs.add_uint(length)
        cs.add_bytes(topic)
        
        parser.expect_char(':')
        if length > 0: # Normal message
            length = parser.read_unsigned(1)
            payload = parser.read_bytes(length)
            cs.add_uint(length)
            cs.add_bytes(payload)
            
            parser.expect_char(':')
            checksum = parser.read_unsigned(1)
            cs.check(checksum)
            
            parser.check_eol()
            return (Transport.TypeEnum.MESSAGE, topic, payload)
        
        else: # Management message
            typechar = parser.read_char().lower()
            cs.add_uint(ord(typechar))
            
            if typechar == 'p':
                parser.expect_char(':')
                length = parser.read_unsigned(1)
                module = parser.read_string(length)
                cs.add_uint(length)
                cs.add_bytes(module)
                
                parser.expect_char(':')
                length = parser.read_unsigned(1)
                topic = parser.read_string(length)
                cs.add_uint(length)
                cs.add_bytes(topic)
                
                parser.expect_char(':')
                checksum = parser.read_unsigned(1)
                cs.check(checksum)
                
                parser.check_eol()
                return (Transport.TypeEnum.ADVERTISEMENT, topic)
            
            elif typechar == 's':
                queue_length = parser.read_unsigned(1)
                cs.add_uint(queue_length)
                
                parser.expect_char(':')
                length = parser.read_unsigned(1)
                module = parser.read_string(length)
                cs.add_uint(length)
                cs.add_bytes(module)
                
                parser.expect_char(':')
                length = parser.read_unsigned(1)
                topic = parser.read_string(length)
                cs.add_uint(length)
                cs.add_bytes(topic)
                
                parser.expect_char(':')
                checksum = parser.read_unsigned(1)
                cs.check(checksum)
                
                parser.check_eol()
                return (Transport.TypeEnum.SUBSCRIPTION_REQUEST, topic, queue_length)
            
            elif typechar == 'e':
                parser.expect_char(':')
                length = parser.read_unsigned(1)
                module = parser.read_string(length)
                cs.add_uint(length)
                cs.add_bytes(module)
                
                parser.expect_char(':')
                length = parser.read_unsigned(1)
                topic = parser.read_string(length)
                cs.add_uint(length)
                cs.add_bytes(topic)
                
                parser.expect_char(':')
                checksum = parser.read_unsigned(1)
                cs.check(checksum)
                
                parser.check_eol()
                return (Transport.TypeEnum.SUBSCRIPTION_RESPONSE, topic)
            
            elif typechar == 't':
                parser.expect_char(':')
                checksum = parser.read_unsigned(1)
                cs.check(checksum)
                
                parser.check_eol()
                return (Transport.TypeEnum.STOP,)
            
            elif typechar == 'r':
                parser.expect_char(':')
                checksum = parser.read_unsigned(1)
                cs.check(checksum)
                
                parser.check_eol()
                return (Transport.TypeEnum.REBOOT,)
            
            else:
                raise ValueError("Unknown management message type %s" % repr(typechar))
        
        
    def _create_publisher(self, topic):
        return DebugPublisher(self)
        
        
    def _create_subscriber(self, topic, queue_length):
        return DebugSubscriber(self, queue_length)
    
    
    def _is_running(self):
        with self._running_lock:
            return self._running
    
    
    def _rx_threadf(self):
        try:
            while self._is_running():
                try:
                    fields = self._recv()
                except ParserError as e:
                    logging.debug(str(e))
                    continue
                
                if fields is None:
                    break
                t = fields[0]
                
                if t == Transport.TypeEnum.MESSAGE:
                    topic = Middleware.instance().find_topic(fields[1])
                    if topic is None:
                        continue
                    
                    with self._publishers_lock:
                        for rpub in self.publishers:
                            if rpub.topic is topic:
                                break
                        else:
                            continue
                    
                    msg = rpub.alloc()
                    try:
                        msg.unmarshal(fields[2])
                        rpub.publish_locally(msg)
                    except Exception as e: # suppress errors
                        topic.release(msg) # FIXME: Create BasePublisher.release() like BaseSubscriber.release()
                        logging.warning(e)
                
                elif t == Transport.TypeEnum.ADVERTISEMENT:
                    assert is_topic_name(fields[1])
                    msg = self._mgmt_rpub.alloc()
                    msg.type = MgmtMsg.TypeEnum.CMD_ADVERTISE
                    msg.pubsub.topic = fields[1]
                    msg.pubsub.transport = self
                    self._mgmt_rpub.publish_locally(msg)
                
                elif t == Transport.TypeEnum.SUBSCRIPTION_REQUEST:
                    assert is_topic_name(fields[1])
                    msg = self._mgmt_rpub.alloc()
                    msg.type = MgmtMsg.TypeEnum.CMD_SUBSCRIBE_REQUEST
                    msg.pubsub.topic = fields[1]
                    msg.pubsub.queue_length = fields[2]
                    msg.pubsub.transport = self
                    self._mgmt_rpub.publish_locally(msg)
                
                elif t == Transport.TypeEnum.SUBSCRIPTION_RESPONSE:
                    assert is_topic_name(fields[1])
                    msg = self._mgmt_rpub.alloc()
                    msg.type = MgmtMsg.TypeEnum.CMD_SUBSCRIBE_RESPONSE
                    msg.pubsub.topic = fields[1]
                    msg.pubsub.transport = self
                    self._mgmt_rpub.publish_locally(msg)
                
                elif t == Transport.TypeEnum.STOP:
                    Middleware.instance().stop()
                
                elif t == Transport.TypeEnum.REBOOT:
                    pass
                
                else:
                    raise RuntimeError('Unknown transport message %d' % fields[0])
        
        except Exception as e:
            logging.error(e)
            raise
    
    
    def _tx_threadf(self):
        while self._is_running():
            try:
                sub = self._sub_queue.wait()
            except TimeoutError:
                continue
            if sub is None:
                continue
            
            msg, deadline = sub.fetch()
            try:
                self._send_message(sub.topic.name, msg.marshal())
            finally:
                sub.release(msg)

#==============================================================================

class BootloaderMaster(object):
    
    def __init__(self, boot_pub, boot_sub):
        self._pub = boot_pub
        self._sub = boot_sub
    
    
    def initialize(self):
        
        # Sync with target board
        logging.info('Awaiting target bootloader with topic %s' % repr(self._pub.topic.name))
        try:
            self._alloc_publish(BootMsg.TypeEnum.NACK)
            self._fetch_release(BootMsg.TypeEnum.NACK)
        except Exception as e:
            logging.debug('Ignoring last received message (broken from previous communication?)')
        
        while True:
            try:
                self._alloc_publish(BootMsg.TypeEnum.NACK)
                self._fetch_release(BootMsg.TypeEnum.NACK)
                break
            except ValueError:
                logging.debug('Ignoring last received message (broken from previous communication?)')
            
        logging.info('Target bootloader alive')
    
    
    def load(self, app_name, app_hex_path, app_stack_size, ld_cmd, ld_use_gcc, ld_script_path, sys_elf_path, ld_map_path, app_elf_path, ld_object_paths, *args, **kwargs):
        self._do_wrapper(self._do_load, app_name, app_hex_path, app_stack_size, ld_cmd, ld_use_gcc, ld_script_path, sys_elf_path, ld_map_path, app_elf_path, ld_object_paths, *args, **kwargs)
    
    
    def get_appinfo(self):
        self._do_wrapper(self._do_get_appinfo)
    
    
    def set_parameter(self, app_name, offset, value):
        self._do_wrapper(self._do_set_parameter, app_name, offset, value)
        
        
    def get_parameter(self, app_name, offset, length):
        return self._do_wrapper(self._do_get_parameter, app_name, offset, length)
    
    
    def remove_last(self):
        self._do_wrapper(self._do_remove_last)
    
    
    def remove_all(self):
        self._do_wrapper(self._do_remove_all)
    
    
    def _abort(self):
        logging.warning('Aborting current bootloader procedure')

        while True:
            self._publish(self._alloc(BootMsg.TypeEnum.NACK))
            try:
                self._release(self._fetch(BootMsg.TypeEnum.NACK))
            except ValueError:
                continue
            break
        
        logging.warning('Procedure aborted')
    
    
    def _alloc(self, type_id):
        msg = self._pub.alloc()
        msg.clean(type_id)
        return msg
    
    
    def _release(self, msg):
        self._sub.release(msg)
    
    
    def _publish(self, msg):
        while True:
            try:
                self._pub.publish_remotely(msg)
                break
            except IndexError:
                pass
            except:
                self._release(msg)
                raise
    
    
    def _fetch(self, expected_type_id=None):
        while True:
            try:
                msg, deadline = self._sub.fetch()
                break
            except IndexError:
                time.sleep(0.100) # TODO: configure
        
        if msg.type == expected_type_id:
            return msg
        else:
            self._release(msg)
            raise ValueError('type_id=%s != expected_type_id=%s' % (msg.type, expected_type_id))
    
    
    def _alloc_publish(self, type_id):
        msg = self._alloc(type_id)
        self._publish(msg)
    
    
    def _fetch_release(self, expected_type_id):
        msg = self._fetch(expected_type_id)
        self._release(msg)
    
    
    def _do_wrapper(self, do_function, *args, **kwargs):
        try:
            return do_function(*args, **kwargs)
        
        except KeyboardInterrupt:
            try:
                self._abort()
            except KeyboardInterrupt:
                pass
        
        except Exception as e:
            logging.error(str(e))
            self._abort()
            raise
    
    
    def _do_load(self, app_name, app_hex_path, app_stack_size, ld_cmd, ld_use_gcc, ld_script_path, sys_elf_path, ld_map_path, app_elf_path, ld_object_paths, *args, **kwargs):
        # Begin loading
        logging.info('Initiating bootloading procedure')
        self._alloc_publish(BootMsg.TypeEnum.BEGIN_LOADER)
        self._fetch_release(BootMsg.TypeEnum.ACK)
        
        # Get the length of each section
        logging.info('Reading section lengths from %s' % repr(app_elf_path))
        pgmlen, bsslen, datalen = 0, 0, 0
        with open(app_elf_path, 'rb') as f:
            elffile = ELFFile(f)
            
            text_start  = _get_symbol_address(elffile, '__text_start__')
            text_end    = _get_symbol_address(elffile, '__text_end__')
            pgmlen = text_end - text_start
            
            bss_start   = _get_symbol_address(elffile, '__bss_start__')
            bss_end     = _get_symbol_address(elffile, '__bss_end__')
            bsslen = bss_end - bss_start
            
            data_start  = _get_symbol_address(elffile, '__data_start__')
            data_end    = _get_symbol_address(elffile, '__data_end__')
            datalen = data_end - data_start
        
        appflags = BootMsg.LinkingSetup.FlagsEnum.ENABLED
        logging.info('  pgmlen   = 0x%0.8X (%d)' % (pgmlen, pgmlen))
        logging.info('  bsslen   = 0x%0.8X (%d)' % (bsslen, bsslen))
        logging.info('  datalen  = 0x%0.8X (%d)' % (datalen, datalen))
        logging.info('  stacklen = 0x%0.8X (%d)' % (app_stack_size, app_stack_size))
        logging.info('  appname  = %s' % repr(app_name))
        logging.info('  flags    = 0x%0.4X' % appflags)
        
        # Send the section sizes and app name
        logging.info('Sending section lengths to target module')
        msg = self._alloc(BootMsg.TypeEnum.LINKING_SETUP)
        msg.set_linking_setup(pgmlen, bsslen, datalen, app_stack_size, app_name, appflags)
        linking_setup = msg.linking_setup
        self._publish(msg)
        
        # Receive the allocated addresses
        logging.info('Receiving the allocated addresses from target module')
        msg = self._fetch(BootMsg.TypeEnum.LINKING_ADDRESSES)
        linking_addresses = msg.linking_addresses
        pgmadr     = linking_addresses.pgmadr
        bssadr     = linking_addresses.bssadr
        dataadr    = linking_addresses.dataadr
        datapgmadr = linking_addresses.datapgmadr
        self._release(msg)
        
        logging.info('  pgmadr     = 0x%0.8X' % pgmadr)
        logging.info('  bssadr     = 0x%0.8X' % bssadr)
        logging.info('  dataadr    = 0x%0.8X' % dataadr)
        logging.info('  datapgmadr = 0x%0.8X' % datapgmadr)
        
        # Link to the OS symbols
        args = [
            '--script', ld_script_path,
            '--just-symbols', sys_elf_path,
            '-o', app_elf_path,
            '--section-start', '.text=0x%0.8X' % pgmadr
        ]
        if bssadr:
            args += [ '--section-start', '.bss=0x%0.8X' % bssadr ]
        if dataadr:
            args += [ '--section-start', '.data=0x%0.8X' % dataadr ]
        if ld_map_path:
            args += [ '-Map', ld_map_path ]
        if ld_use_gcc:
            args = [ '-Wl,' + ','.join(args) ]
        args = [ ld_cmd ] + args + list(ld_object_paths)
        logging.debug('Linker command line:')
        logging.debug('  ' + ' '.join([ arg for arg in args ]))
        
        logging.info('Linking object files')
        if 0 != subprocess.call(args):
            raise RuntimeError("Cannot link %s with %s" % (repr(sys_elf_path), repr(app_elf_path)))
        
        logging.info('Generating executable')
        if 0 != subprocess.call(['make']):
            raise RuntimeError("Cannot make the application binary")
        
        logging.info('Reading final ELF file %s' % repr(app_elf_path))
        with open(app_elf_path, 'rb') as f:
            elffile = ELFFile(f)
            
            mainadr = _get_function_address(elffile, APP_THREAD_SYMBOL)
            logging.info('  mainadr   = 0x%0.8X' % mainadr)
            
            config_start  = _get_symbol_address(elffile, '_config_start_')
            config_end    = _get_symbol_address(elffile, '_config_end_')
            cfgadr = config_start
            cfglen = config_end - config_start
            logging.info('  cfgadr    = 0x%0.8X' % cfgadr)
            logging.info('  cfglen    = 0x%0.8X (%d)' % (cfglen, cfglen))
            
            try:
                ctorsadr = _get_symbol_address(elffile, '_init_array_start')
                ctorslen = (_get_symbol_address(elffile, '_init_array_end') - ctorsadr) / 4
            except RuntimeError:
                logging.debug('Section "constructors" looks empty')
                ctorsadr = 0
                ctorslen = 0
            logging.info('  ctorsadr  = 0x%0.8X' % ctorsadr)
            logging.info('  ctorslen  = 0x%0.8X (%d)' % (ctorslen, ctorslen))
            
            try:
                dtorsadr = _get_symbol_address(elffile, '_fini_array_start')
                dtorslen = (_get_symbol_address(elffile, '_fini_array_end') - dtorsadr) / 4
            except RuntimeError:
                logging.debug('Section "destructors" looks empty')
                dtorsadr = 0
                dtorslen = 0
            logging.info('  dtorsadr  = 0x%0.8X' % dtorsadr)
            logging.info('  dtorslen  = 0x%0.8X (%d)' % (dtorslen, dtorslen))
        
        # Send the linking outcome
        self._alloc(BootMsg.TypeEnum.LINKING_OUTCOME)
        msg.set_linking_outcome(mainadr, cfgadr, cfglen, ctorsadr, ctorslen, dtorsadr, dtorslen)
        self._publish(msg)
        self._fetch_release(BootMsg.TypeEnum.ACK)
        
        # Read the generated IHEX file and remove unused records
        logging.info('Reading IHEX file')
        with open(app_hex_path, 'r') as f:
            hexdata = f.readlines()
        
        logging.info('Removing unused IHEX records')
        ihex_records = []
        for line in hexdata:
            line = line.strip()
            if len(line) == 0: continue
            record = IhexRecord()
            record.parse_ihex(line)
            if record.type == IhexRecord.TypeEnum.DATA:
                # Split into smaller packets
                while record.count > IhexRecord.MAX_DATA_LENGTH:
                    bigrecord = IhexRecord()
                    bigrecord.count = IhexRecord.MAX_DATA_LENGTH
                    bigrecord.offset = record.offset
                    bigrecord.type = IhexRecord.TypeEnum.DATA
                    bigrecord.data = record.data[:IhexRecord.MAX_DATA_LENGTH]
                    ihex_records.append(bigrecord)
                    
                    record.count -= IhexRecord.MAX_DATA_LENGTH
                    record.offset += IhexRecord.MAX_DATA_LENGTH
                    record.data = record.data[IhexRecord.MAX_DATA_LENGTH:]
                
                ihex_records.append(record)
                
            elif record.type != IhexRecord.TypeEnum.START_SEGMENT_ADDRESS and \
                 record.type != IhexRecord.TypeEnum.START_LINEAR_ADDRESS:
                ihex_records.append(record)
            else:
                logging.info('  ' + str(record))
        
        # Send IHEX records
        logging.info('Sending IHEX records to target module')
        for i in xrange(len(ihex_records)):
            record = ihex_records[i]
            logging.info('  %s (%d/%d)' % (str(record), i + 1, len(ihex_records)))
            
            msg = self._alloc(BootMsg.TypeEnum.IHEX_RECORD)
            msg.set_ihex(record)
            self._publish(msg)
            self._fetch_release(BootMsg.TypeEnum.ACK)
        
        # End loading
        logging.info('Finalizing bootloading procedure')
        self._alloc_publish(BootMsg.TypeEnum.END_LOADER)
        self._fetch_release(BootMsg.TypeEnum.ACK)
        
        logging.info('Bootloading completed successfully')
        return True


    def _do_get_appinfo(self):
        # Begin appinfo retrieval
        logging.info('Retrieving appinfo')
        self._alloc_publish(BootMsg.TypeEnum.BEGIN_APPINFO)
        summary = msg = self._fetch(BootMsg.TypeEnum.APPINFO_SUMMARY).appinfo_summary
        logging.info('  numapps     = %d' % summary.numapps)
        logging.info('  freeadr     = 0x%0.8X' % summary.freeadr)
        logging.info('  pgmstartadr = 0x%0.8X' % summary.pgmstartadr)
        logging.info('  pgmendadr   = 0x%0.8X' % summary.pgmendadr)
        logging.info('  ramstartadr = 0x%0.8X' % summary.ramstartadr)
        logging.info('  ramendadr   = 0x%0.8X' % summary.ramendadr)
        self._release(msg)
        
        for i in xrange(summary.numapps):
            # Get the linking setup
            self._alloc_publish(BootMsg.TypeEnum.ACK)
            setup = msg = self._fetch(BootMsg.TypeEnum.LINKING_SETUP).linking_setup
            logging.info('Found app %s' % repr(setup.name))
            logging.info('  pgmlen     = 0x%0.8X (%d)' % (setup.pgmlen, setup.pgmlen))
            logging.info('  bsslen     = 0x%0.8X (%d)' % (setup.bsslen, setup.bsslen))
            logging.info('  datalen    = 0x%0.8X (%d)' % (setup.datalen, setup.datalen))
            logging.info('  app_stack_size   = 0x%0.8X (%d)' % (setup.app_stack_size, setup.app_stack_size))
            logging.info('  name       = %s' % repr(setup.name))
            logging.info('  flags      = 0x%0.4X' % setup.flags)
            self._release(msg)
            
            # Get the linking addresses
            self._alloc_publish(BootMsg.TypeEnum.ACK)
            addresses = msg = self._fetch(BootMsg.TypeEnum.LINKING_ADDRESSES).linking_addresses
            logging.info('  pgmadr     = 0x%0.8X' % addresses.pgmadr)
            logging.info('  bssadr     = 0x%0.8X' % addresses.bssadr)
            logging.info('  dataadr    = 0x%0.8X' % addresses.dataadr)
            logging.info('  datapgmadr = 0x%0.8X' % addresses.datapgmadr)
            logging.info('  nextadr    = 0x%0.8X' % addresses.nextadr)
            self._release(msg)
            
            # Get the linking outcome
            self._alloc_publish(BootMsg.TypeEnum.ACK)
            outcome = msg = self._fetch(BootMsg.TypeEnum.LINKING_OUTCOME).linking_outcome
            logging.info('  mainadr    = 0x%0.8X' % outcome.mainadr)
            logging.info('  cfgadr     = 0x%0.8X' % outcome.cfgadr)
            logging.info('  cfglen     = 0x%0.8X (%d)' % (outcome.cfglen, outcome.cfglen))
            logging.info('  ctorsadr   = 0x%0.8X' % outcome.ctorsadr)
            logging.info('  ctorslen   = 0x%0.8X (%d)' % (outcome.ctorslen, outcome.ctorslen))
            logging.info('  dtorsadr   = 0x%0.8X' % outcome.dtorsadr)
            logging.info('  dtorslen   = 0x%0.8X (%d)' % (outcome.dtorslen, outcome.dtorslen))
            self._release(msg)
        
        logging.debug('There should not be more apps')
        self._alloc_publish(BootMsg.TypeEnum.ACK)
        self._release(self._fetch(BootMsg.TypeEnum.END_APPINFO))
        logging.info('Ending appinfo retrieval')
        self._alloc_publish(BootMsg.TypeEnum.ACK)
        self._fetch_release(BootMsg.TypeEnum.ACK)
        logging.info('Appinfo retrieval completed successfully')
        return True
    
    
    def _do_set_parameter(self, app_name, offset, value):
        MAX_LENGTH = BootMsg.ParamChunk.MAX_DATA_LENGTH
        
        if len(value) == 0:
            raise ValueError('Willing to write an empty parameter value')
        
        # Begin parameter set
        logging.info('Beginning parameter set')
        self._alloc_publish(BootMsg.TypeEnum.BEGIN_SETPARAM)
        self._fetch_release(BootMsg.TypeEnum.ACK)
        
        # Send the parameter request
        length = len(value)
        logging.info('Sending parameter request')
        logging.info('  app_name = %s' % repr(app_name))
        logging.info('  offset  = 0x%0.8X (%d)' % (offset, offset))
        logging.info('  length  = 0x%0.8X (%d)' % (length, length))
        
        msg = self._alloc(BootMsg.TypeEnum.PARAM_REQUEST)
        msg.param_request.offset = offset
        msg.param_request.app_name = app_name
        msg.param_request.length = length
        self._publish(msg)
        self._fetch_release(BootMsg.TypeEnum.ACK)
        
        # Send each parameter chunk
        logging.info('Sending parameter chunks')
        pending = value
        while True:
            chunk = pending[:MAX_LENGTH]
            logging.info('  app_config[0x%0.8X : 0x%0.8X] = %s' %
                         (offset, offset + len(chunk), str2hexb(chunk)))
            
            msg = self._alloc(BootMsg.TypeEnum.PARAM_CHUNK)
            msg.param_chunk.data = chunk
            self._publish(msg)
            self._fetch_release(BootMsg.TypeEnum.ACK)
            
            if len(chunk) >= MAX_LENGTH:
                pending = pending[MAX_LENGTH:]
                offset += MAX_LENGTH
            else:
                break
        
        # Finalize
        logging.info('Finalizing parameter')
        self._alloc_publish(BootMsg.TypeEnum.END_SETPARAM)
        self._fetch_release(BootMsg.TypeEnum.ACK)
        logging.info('Parameter set successfully')
        return True
        
        
    def _do_get_parameter(self, app_name, offset, length):
        MAX_LENGTH = BootMsg.ParamChunk.MAX_DATA_LENGTH
        
        if length == 0:
            raise ValueError('Willing to read an empty parameter value')
        
        # Begin parameter get
        logging.info('Beginning parameter get')
        self._alloc_publish(BootMsg.TypeEnum.BEGIN_GETPARAM)
        self._fetch_release(BootMsg.TypeEnum.ACK)
        
        # Send the parameter request
        logging.info('Sending parameter request')
        logging.info('  app_name = %s' % repr(app_name))
        logging.info('  offset  = 0x%0.8X (%d)' % (offset, offset))
        logging.info('  length  = 0x%0.8X (%d)' % (length, length))
        
        msg = self._alloc(BootMsg.TypeEnum.PARAM_REQUEST)
        msg.param_request.offset = offset
        msg.param_request.app_name = app_name
        msg.param_request.length = length
        self._publish(msg)
        
        # Receive each parameter chunk
        logging.info('Receiving parameter chunks')
        value = ''
        while len(value) < length:
            msg = self._fetch(BootMsg.TypeEnum.PARAM_CHUNK)
            
            chunk = msg.param_chunk.data
            if len(chunk) > length - len(value):
                chunk = chunk[:(length - len(value))]
            value += chunk
            logging.info('  app_config[0x%0.8X : 0x%0.8X] = %s' %
                         (offset, offset + len(chunk), str2hexb(chunk)))
            offset += len(chunk)
            
            self._release(msg)
            self._alloc_publish(BootMsg.TypeEnum.ACK)
            
        # Finalize
        logging.info('Finalizing parameter')
        self._alloc_publish(BootMsg.TypeEnum.END_GETPARAM)
        self._fetch_release(BootMsg.TypeEnum.ACK)
        
        logging.info('Parameter got successfully')
        return value
    
    
    def _do_remove_last(self):
        # Begin removal
        logging.info('Initiating removal procedure')
        self._alloc_publish(BootMsg.TypeEnum.BEGIN_LOADER)
        self._fetch_release(BootMsg.TypeEnum.ACK)
        
        # Remove all
        logging.info('Removing last app')
        self._alloc_publish(BootMsg.TypeEnum.REMOVE_LAST)
        try:
            self._fetch_release(BootMsg.TypeEnum.ACK)
        except ValueError:
            raise RuntimeError('Cannot remove last app -- no apps installed?')
        
        # End loading
        logging.info('Finalizing removal procedure')
        self._alloc_publish(BootMsg.TypeEnum.END_LOADER)
        self._fetch_release(BootMsg.TypeEnum.ACK)
        
        logging.info('Removal completed successfully')
        return True
    
    
    def _do_remove_all(self):
        # Begin removal
        logging.info('Initiating removal procedure')
        self._alloc_publish(BootMsg.TypeEnum.BEGIN_LOADER)
        self._fetch_release(BootMsg.TypeEnum.ACK)
        
        # Remove all
        logging.info('Removing all apps')
        self._alloc_publish(BootMsg.TypeEnum.REMOVE_ALL)
        self._fetch_release(BootMsg.TypeEnum.ACK)
        
        # End loading
        logging.info('Finalizing removal procedure')
        self._alloc_publish(BootMsg.TypeEnum.END_LOADER)
        self._fetch_release(BootMsg.TypeEnum.ACK)
        
        logging.info('Removal completed successfully')
        return True
    
#==============================================================================
