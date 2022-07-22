
import ida_struct
import idautils
import ida_typeinf
import re 

def handle_type(size):
    if size == 1:
        return "char"
    if size == 4:
        return "int"
    if size == 8:
        return "__int64"

class Structs():
    def __init__(self, export_func):
        self.structs = {}
        self.func = export_func
        self.buildin = ["JNINativeInterface", "FILE", "JNIInvokeInterface", "Elf64_Sym", "Elf64_Rela", "Elf64_Dyn", "Elf64_Verneed", "Elf64_Vernaux"]
        self.parse_struct()
        self.pfunc = re.compile(r"([\w *]+) \(([\w *]+)\)\(([\w ,*]+)\)")
        self.array = re.compile(r"([\w *]+)\[([0-9]+)\]")

    def parse_struct(self):
        structs = idautils.Structs()
        for item_struct in structs:
            idx, sid, sname = item_struct
            if sname in self.buildin:
                continue
            struc = ida_struct.get_struc(sid)
            members = idautils.StructMembers(sid)
            self.structs[sname] = self.parse_member(struc, members)

    def parse_member(self, struc, members) -> dict:
        member_dict = {}
        for item_member in members:
            offset, name, size = item_member 
            mem = ida_struct.get_member(struc, offset)
            tif = ida_typeinf.tinfo_t() 
            ida_struct.get_member_tinfo(tif, mem)
            member_type = tif.__str__()
            if member_type == "":
                member_type = handle_type(size)
            member_dict[name] = member_type
        return member_dict
            
    
    def export(self):
        for struct in self.structs:
            self.export_struct(struct)
        
    def export_member(self, member_type, name):

        if member_type == None:
            return 
        match = self.pfunc.findall(member_type)
        if match != []:
            self.export_func("\t{} ({} {})({});\n".format(match[0][0], match[0][1], name, match[0][2]))
            return 
        match = self.array.findall(member_type)
        if match != []:
            self.export_func("\t{} {}[{}];\n".format(match[0][0], name, match[0][1]))
            return 

        self.export_func("\t{} {};\n".format(member_type, name))

    def export_struct(self, struct):
        self.export_func("\nstruct {} {{\n".format(struct))
        for member in self.structs[struct]:
            self.export_member(self.structs[struct][member], member)
        self.export_func("};\n\n")
    
    def export_func(self, *args):
        self.func(*args)

