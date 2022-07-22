import sys
import idaapi
from PyQt5 import QtWidgets
import ida_kernwin 
from Aworkspace import hook 
from Aworkspace import ui 
import ida_typeinf 
import idc 

class WorkSpace(idaapi.plugin_t):
    flags = idaapi.PLUGIN_KEEP
    comment = "workspace"
    help = ""
    wanted_name = "workspace"
    wanted_hotkey = "Alt+F6"
    windows = None
    file = "" 

    def __init__(self):
        self.target = None
        self.file = ""
        self.idb_hook = None
        pass 

    def init(self):
        self.idb_hook = hook.idb_hooks_t(self.file)
        self.idb_hook.hook()
        return idaapi.PLUGIN_KEEP

    def run(self, arg):
        if self.target == None:
            self.target = ui.call()
        print("target :", self.target)
        if self.target == 1:
            # client 
            if self.file == "":
                self.file = ida_kernwin.ask_file(0, "",  "Please enter string")
            print("file: ", self.file)
            ida_typeinf.idc_parse_types(self.file, idc.PT_FILE) 

        if self.target == 2:
            if self.file == "":
                self.file = ida_kernwin.ask_file(0, "",  "Please enter string")
            print("file: ", self.file)
            self.idb_hook.set_file(self.file)
            print("hook done!")

    def term(self):
        return idaapi.PLUGIN_OK


def PLUGIN_ENTRY():
    return WorkSpace()
