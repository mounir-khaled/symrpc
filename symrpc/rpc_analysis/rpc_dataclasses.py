
import logging 
import angr

from .rpc_structs import *

from typing import *
from dataclasses import dataclass
from angr.knowledge_plugins import Function

log = logging.getLogger(__name__)

def arch_endness_to_int_byteorder(endness:str):
    return "little" if endness == archinfo.Endness.LE else "big"

@dataclass
class RpcServerInterfaceFlags:
    FLAG_VALUE_DICT = {
        'RPC_IF_ALLOW_CALLBACKS_WITH_NO_AUTH': 16,
        'RPC_IF_ALLOW_LOCAL_ONLY': 32,
        'RPC_IF_ALLOW_SECURE_ONLY': 8,
        'RPC_IF_ALLOW_UNKNOWN_AUTHORITY': 4,
        'RPC_IF_ASYNC_CALLBACK': 256,
        'RPC_IF_AUTOLISTEN': 1,
        'RPC_IF_OLE': 2,
        'RPC_IF_SEC_CACHE_PER_PROC': 128,
        'RPC_IF_SEC_NO_CACHE': 64
    }

    RPC_IF_AUTOLISTEN: bool
    RPC_IF_OLE: bool
    RPC_IF_ALLOW_UNKNOWN_AUTHORITY: bool
    RPC_IF_ALLOW_SECURE_ONLY: bool
    RPC_IF_ALLOW_CALLBACKS_WITH_NO_AUTH: bool
    RPC_IF_ALLOW_LOCAL_ONLY: bool
    RPC_IF_SEC_NO_CACHE: bool
    RPC_IF_SEC_CACHE_PER_PROC: bool
    RPC_IF_ASYNC_CALLBACK: bool

    @classmethod
    def from_int(cls, flag:int):
        return cls(**{k: flag & v != 0 for k, v in cls.FLAG_VALUE_DICT.items()})

    def to_int(self):
        flag_int = 0
        for flag, value in self.FLAG_VALUE_DICT.items():
            if getattr(self, flag): flag_int |= value
        
        return flag_int

@dataclass
class ExtractedString:
    address:int
    string:Optional[str]=None
    
    @classmethod
    def extract(cls, backer_state:angr.SimState, address:int, char_width=8, byteorder=archinfo.Endness.LE):
        LOAD_BUFFER_SIZE = 1

        reading_string = True
        string = ''
        str_encoding = "ASCII" if char_width in (7, 8) else "UTF-16-LE"
        load_size = LOAD_BUFFER_SIZE * char_width // 8
        current_address = address
        while reading_string:
            
            char_bvs = backer_state.memory.load(current_address, load_size, endness=byteorder)
            if not char_bvs.concrete:
                log.error("Failed to extract string at address %#x", address)
                return cls(address, None)

            char = backer_state.solver.eval(char_bvs)
            if char == 0:
                break

            string += int.to_bytes(char, LOAD_BUFFER_SIZE * char_width//8, byteorder=arch_endness_to_int_byteorder(byteorder)).decode(str_encoding)
            current_address += load_size

        return cls(address, string)

@dataclass
class Uuid:
    uuid:str
    version:str

    @classmethod 
    def from_struct(cls, interface_id:SimStructValue):
        uuid_parts = [None] * 5
        guid = interface_id.SyntaxGUID
        uuid_parts[0] = "%08X" % guid.Data1
        uuid_parts[1] = "%04X" % guid.Data2
        uuid_parts[2] = "%04X" % guid.Data3
        uuid_parts[3] = "".join("%02X" % int.from_bytes(b, byteorder='little') for b in guid.Data4[:2])
        uuid_parts[4] = "".join("%02X" % int.from_bytes(b, byteorder='little') for b in guid.Data4[2:])
        
        uuid = "-".join(uuid_parts)

        syntax_version = interface_id.SyntaxVersion
        version = "%d.%d" % (syntax_version.MajorVersion, syntax_version.MinorVersion)

        return Uuid(uuid, version)

@dataclass
class RpcServerInterface:
    address:int
    struct_values:Optional[SimStructValue]=None
    procedure_functions:Optional[Iterable[Function]]=None
    flags:Optional[RpcServerInterfaceFlags]=None

    @property
    def uuid(self):
        if self.struct_values is None:
            return None

        return Uuid.from_struct(self.struct_values.InterfaceId)

    @classmethod
    def extract(cls, backer_state:angr.SimState, addr:int):
        arch = backer_state.arch

        if_struct = RPC_SERVER_INTERFACE.with_arch(arch)
        server_info_struct = MIDL_SERVER_INFO.with_arch(arch)
        dispatch_table_struct = RPC_DISPATCH_TABLE.with_arch(arch)

        iface = if_struct.extract(backer_state, addr, concrete=True)
        server_info = server_info_struct.extract(backer_state, iface.InterpreterInfo, concrete=True)
        dispatch_table = dispatch_table_struct.extract(backer_state, iface.DispatchTable, concrete=True)

        proc_fns = []
        n_procs = dispatch_table.DispatchTableCount
        dispatch_table_entry_type = server_info_struct.fields["DispatchTable"].pts_to
        ptr_size = dispatch_table_entry_type.size // arch.byte_width
        for i in range(n_procs):
            stub_fn_ptr_addr = server_info.DispatchTable + i * ptr_size
            stub_fn_addr = dispatch_table_entry_type.extract(backer_state, stub_fn_ptr_addr, concrete=True)
            proc_fns.append(backer_state.project.kb.functions.get_by_addr(stub_fn_addr))

        return cls(addr, iface, proc_fns, iface.Flags)


