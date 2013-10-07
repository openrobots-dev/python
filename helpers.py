import logging
import threading


def verbosity2level(verbosity):
    if   verbosity <= 0: return logging.CRITICAL
    elif verbosity == 1: return logging.ERROR
    elif verbosity == 2: return logging.WARNING
    elif verbosity == 3: return logging.INFO
    elif verbosity >= 4: return logging.DEBUG


def str2hexb(data):
    return ''.join([ ('%.2X' % ord(b)) for b in data ])


def hexb2str(data):
    assert (len(data) & 1) == 0
    return ''.join([ chr(int(data[i : i + 2], 16)) for i in range(0, len(data), 2) ])


def autoint(value):
    value = str(value).strip().lower()
    if value[0:2] == '0x':
        return int(value[2:], 16) 
    else:
        return int(value)


def call_with_timeout(timeout_seconds, invalid_result, function, *args, **kwargs):
    
    class InterruptableThread(threading.Thread):
        def __init__(self):
            threading.Thread.__init__(self)
            self.result = invalid_result
            self.exception = None
        
        def run(self):
            try:
                self.result = function(*args, **kwargs)
            except Exception as e:
                self.exception = e
    
    it = InterruptableThread()
    it.start()
    it.join(timeout_seconds)
    if it.exception is not None:
        raise it.exception
    if it.isAlive():
        return invalid_result
    else:
        return it.result

