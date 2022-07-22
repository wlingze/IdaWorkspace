
from .struct_export import Structs
from .function_export import Funcs

import inspect
import ida_idp


class idb_hooks_t(ida_idp.IDB_Hooks):

    def __init__(self, file):
        ida_idp.IDB_Hooks.__init__(self)
        self.inhibit_log = 0;
        self.file = file 


    def _format_value(self, v):
        return str(v)


    def _log(self, msg=None):
        if self.inhibit_log <= 0:
            if msg:
                print(">>> idb_logger_hooks_t: %s" % msg)
            else:
                stack = inspect.stack()
                frame, _, _, _, _, _ = stack[1]
                args, _, _, values = inspect.getargvalues(frame)
                method_name = inspect.getframeinfo(frame)[2]
                argstrs = []
                for arg in args[1:]:
                    argstrs.append("%s=%s" % (arg, self._format_value(values[arg])))
                print(">>> idb_logger_hooks_t.%s: %s" % (method_name, ", ".join(argstrs)))
        return 0

    def export(self):
        fp = open(self.file, "w")
        func = Funcs(fp.write)
        struct = Structs(fp.write)
        struct.export()
        func.export()
        fp.close()
        print("export!")

    def savebase(self):
        if self.file != "":
            self.export()
        return self._log()

    def set_file(self, file):
        self.file = file