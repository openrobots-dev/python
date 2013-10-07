#!/usr/bin/env python2

from PySide import QtCore, QtGui
import r2p
from R2P_Window_ui import R2P_Window_ui
from R2P_Window_ctrl import R2P_Window_ctrl


def _main():
    app = QtGui.QApplication(sys.argv)  
    
    ctrl = R2P_Window_ctrl()
    ui = R2P_Window_ui()
    ui.show()
    
    app.connect(app, QtCore.SIGNAL("lastWindowClosed()"),
                app, QtCore.SLOT("quit()"))
    app.exec_()


if __name__ == '__main__':
    _main()


