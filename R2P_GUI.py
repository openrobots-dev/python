#!/usr/bin/env python2

import sys, os, time, threading
import r2p
import R2P_GUI_ui
from PySide import QtCore, QtGui, QtUiTools


#==============================================================================

class Window(QtGui.QMainWindow):

    def __init__(self, parent=None):  
        super(Window, self).__init__(parent)
        self.transport = None
        self.bootloader = None

        self.ui = R2P_GUI_ui.Ui()
        self.ui.setupUi(self)
    
        self._lock = threading.RLock()
        self.r2p_path = None
        self.chibios_path = None
        self.booting = False
        self.boot_topic = None
        self.valid_boot_topic = None
        self.module_path = None
        self.module_elf = None
        self.app_path = None
        self.app_src_elf = None
        self.app_dst_elf = None
        self.app_name = None
        self.app_stack_size = None

        self.boot_thread = None
        self.mgmt_thread = None
        
        # TODO: Build the transport elsewhere, and with user settings
        self.transport = r2p.DebugTransport(r2p.SerialLineIO('/dev/ttyUSB0', 115200))


    def _create_bootloader(self):
        if self.bootloader is not None:
            self.transport.close()
        
        self.transport.open()
        self.bootloader = r2p.Bootloader(self.transport)
        

    def _start_booting(self):
        if not self.booting:
            mb = QtGui.QMessageBox()
            mb.setIcon(QtGui.QMessageBox.Warning)
            mb.setText("Entering bootloader mode")
            mb.setInformativeText("Bootloader mode stops all the R2P Nodes and Apps on the target module.\nContinue?")
            mb.setStandardButtons(QtGui.QMessageBox.Ok | QtGui.QMessageBox.Cancel)
            mb.setDefaultButton(QtGui.QMessageBox.Cancel)
            ans = mb.exec_()
            if ans == QtGui.QMessageBox.Ok:
                self.valid_boot_topic = self.boot_topic
                self.booting = True
                self._create_bootloader()
                return True
            else:
                return False
        else:
            return True


    def mgmt_cb(self):
        pass


    def mgmt_threadf(self):
        node = r2p.Node('MGMT')
        pub = r2p.Publisher()
        subs = r2p.Subscriber(5, self.mgmt_cb)
        
        node.begin()
        node.advertise(pub, 'R2P', Time.ms(1000), r2p.MgmtMsg)
        node.subscribe(sub, 'R2P', r2p.MgmtMsg)
        
        while r2p.ok():
            node.spin(Time.ms(333))
        
        node.end()
    
    
    def boot_threadf(self):
        node = r2p.Node('LOADER')
        pub = r2p.Publisher()
        subs = r2p.Subscriber(5, self.mgmt_cb)
        
        node.begin()
        with self._lock:
            node.advertise(pub, self.boot_topic, Time.ms(1000), r2p.MgmtMsg)
            node.subscribe(sub, self.boot_topic, r2p.MgmtMsg)
        
        while r2p.ok():
            node.spin(Time.ms(333))
        
        node.end()
        
        
    def bootRefreshApps(self):
        if not self._start_booting():
            return
        pass # TODO


    def bootRemoveAll(self):
        if not self._start_booting():
            return
        pass # TODO


    def bootRemoveLast(self):
        if not self._start_booting():
            return
        pass # TODO


    def bootInstall(self):
        if not self._start_booting():
            return
        pass # TODO


    def bootReboot(self):
        if not self._start_booting():
            return
        pass # TODO
        
        self.booting = False


    def bootChooseAppPath(self):
        pass # TODO


    def settingsChooseR2pPath(self):
        pass # TODO


    def settingsChooseChibiosPath(self):
        pass # TODO


    def bootChooseModulePath(self):
        pass # TODO


    def logicalRefresh(self):
        pass # TODO


    def physicalRefresh(self):
        pass # TODO


    def bootChooseModuleElf(self):
        pass # TODO


    def bootChooseAppSrcElf(self):
        pass # TODO


    def bootChooseAppDstElf(self):
        pass # TODO


    def bootSetAppName(self):
        pass # TODO


    def bootSetStackSize(self):
        pass # TODO


    def bootSetAppDstElf(self):
        pass # TODO


    def bootSetAppSrcElf(self):
        pass # TODO


    def bootSetAppPath(self):
        pass # TODO


    def bootSetMouleElf(self):
        pass # TODO


    def bootSetModulePath(self):
        pass # TODO


    def bootSetBootTopic(self):
        text = self.ui.lineBootTopic.text().strip()
        if not r2p.is_topic_name(text):
            mb = QtGui.QMessageBox()
            mb.setIcon(QtGui.QMessageBox.Critical)
            mb.setText('Invalid topic name')
            mb.setInformativeText('"%s" is not a valid topic name; format: "%s"' % (text, r2p.TOPIC_NAME_REGEX_FMT))
            mb.exec_()
            self.ui.lineBootTopic.setFocus()
        else:
            pass # TODO


    def settingsSetR2pPath(self):
        pass # TODO


    def settingsSetChibiosPath(self):
        pass # TODO

    
#==============================================================================

if __name__ == '__main__':  
   app = QtGui.QApplication(sys.argv)  
   win = Window()  
   win.show()
   app.connect(app, QtCore.SIGNAL("lastWindowClosed()"),
               app, QtCore.SLOT("quit()"))
   app.exec_()


