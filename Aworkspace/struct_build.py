import idc
import ida_struct
import ida_bytes
import idaapi
    
def arch():
    if idaapi.BADADDR == 0xffffffffffffffff:
        return 64
    return 32

def build_struct(name , mem_size):
    sid = ida_struct.get_struc_id(name)
    if sid != 0xffffffffffffffff:
        ida_struct.del_struc(ida_struct.get_struc(sid))
    sid = ida_struct.add_struc(-1, name)

    if arch() == 64: 
        member_type = (ida_bytes.FF_QWORD|ida_bytes.FF_DATA )&0xFFFFFFFF
        member_size = 8
    else:
        member_type = (ida_bytes.FF_DWORD|ida_bytes.FF_DATA )&0xFFFFFFFF
        member_size = 4
    
    for i in range(mem_size // member_size):
        idc.add_struc_member(sid, "field_{}".format(i), -1, member_type, -1, member_size)

