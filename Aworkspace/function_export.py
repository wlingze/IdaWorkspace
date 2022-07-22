
import ida_funcs 
import idautils
import ida_typeinf 
import ida_nalt 
import re 

class Funcs():
    def __init__(self, func):
        self.func = func
        self.function = []
        self.buildin = []
        self.unk = "sub_"
        self.tinfpa = re.compile(r"([\w *]+)\(([\w *,]*)\)")
        self.argspa = re.compile(r"(^\*[\w]*)")
        self.parse_funcs()
    
    def parse_funcs(self):
        funcs = idautils.Functions()
        for func_ea in funcs:
            func = ida_funcs.get_func(func_ea)
            name = ida_funcs.get_func_name(func_ea)
            if name in self.buildin:
                continue
            if self.unk in name:
                continue
            if func.flags == 5136: 
                self.function.append(self.parse_func(func, name))

    def parse_func(self, func, name):
        tif = ida_typeinf.tinfo_t()
        funcdata = ida_typeinf.func_type_data_t()
        if ida_nalt.get_tinfo(tif, func.start_ea):
            match = self.tinfpa.findall(tif.__str__().replace("_BOOL8", "int"))
            if match != []:
                args = match[0][1] 
                match_args = self.argspa.findall(args)
                if match_args != []:
                    args = "void * a1"
                return "{} {}({});\n".format(match[0][0], name, args)
        return "void {}();\n".format(name)


    
    def export(self):
        for func in self.function:
            self.export_func(func)

    def export_func(self, *args):
        self.func(*args)
