from dataclasses import dataclass
import logging

from typing import Iterable, Optional

import angr
import archinfo


from angr.analyses.analysis import Analysis
from angr.knowledge_plugins.functions import Function


from .rpc_structs import *
from .callback_analysis.interface_callback_analysis import RpcInterfaceCallbackAnalysis, RpcSimState

from .reaching_arguments import ReachingArgumentsAnalysis

# import angr.procedures.definitions.win32_rpcrt4 as win32_rpcrt4
# ^ PyLance breaks when doing this import so this is here as a workaround
from importlib import import_module
win32_rpcrt4 = import_module("angr.procedures.definitions.win32_rpcrt4")

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


class RpcInterfacesAnalysis(ReachingArgumentsAnalysis):
    def __init__(
            self, 
            register_interface_functions:Optional[Iterable[Function]]=None, 
            use_protseq_functions:Optional[Iterable[Function]]=None,
            register_auth_functions:Optional[Iterable[Function]]=None,
            backer_state:Optional[angr.SimState]=None,
            coerce_argument_values=True,
            symexec_callbacks=True,
            is_multiplexed=True
        ):

        super().__init__(coerce_argument_values)
        self.rpc_register_calls = {}
        self.rpc_use_protseq_calls = {}
        self.rpc_register_auth_calls = {}
        self.possible_callers = defaultdict(list)
        self.rpc_constraints = defaultdict(set)
        # self._symexec_callbacks = symexec_callbacks

        if backer_state is None:
            backer_state:angr.SimState = self.project.factory.blank_state()

        if register_interface_functions is None:
            register_if_functions = [fn for fn in self.kb.functions.values() if fn.name.startswith("RpcServerRegisterIf")]
        
        if use_protseq_functions is None:
            use_protseq_functions = [fn for fn in self.kb.functions.values() if fn.name.startswith("RpcServerUseProtseq")]
        
        if register_auth_functions is None:
            register_auth_functions = [fn for fn in self.kb.functions.values() if fn.name.startswith("RpcServerRegisterAuthInfo")]

        self._recover_registration_args(register_if_functions, use_protseq_functions, register_auth_functions, backer_state)
        if symexec_callbacks:
            self._symexec_callbacks(is_multiplexed=is_multiplexed)

    def _recover_registration_args(
            self, 
            register_if_functions:Iterable[Function], 
            use_protseq_functions:Iterable[Function], 
            register_auth_functions:Iterable[Function], 
            backer_state:angr.SimState
        ):

        for register_fn in register_if_functions:
            callsite_register_args_dict = self.find_all_callsite_args(register_fn, win32_rpcrt4.prototypes[register_fn.name])
            for register_args in callsite_register_args_dict.values():
                register_args["api_function"] = register_fn.name
                interfaces = []
                for if_addr in register_args["IfSpec"]:
                    if isinstance(if_addr, int):
                        interface = RpcServerInterface.extract(backer_state, if_addr)
                    else:
                        interface = RpcServerInterface(if_addr)

                    interfaces.append(interface)
                
                register_args["IfSpec"] = interfaces

                flags_list = []
                for flags_int in register_args["Flags"]:
                    if isinstance(flags_int, int):
                        flags = RpcServerInterfaceFlags.from_int(flags_int)
                    else:
                        flags = None

                    flags_list.append(flags)
                
                register_args["Flags"] = flags_list
            
            self.rpc_register_calls.update(callsite_register_args_dict)

        for fn in use_protseq_functions:
            callsite_useprotseq_args_dict = self.find_all_callsite_args(fn, win32_rpcrt4.prototypes[fn.name])
            char_width = 16 if fn.name.endswith("W") else 8
            for register_args in callsite_useprotseq_args_dict.values():
                register_args["api_function"] = fn.name
                register_args["Protseq"] = [
                    ExtractedString.extract(backer_state, ps_addr, char_width) if isinstance(ps_addr, int) else ExtractedString(ps_addr, None) for ps_addr in register_args["Protseq"] 
                ]

                if "Endpoint" in register_args:
                    register_args["Endpoint"] = [
                        ExtractedString.extract(backer_state, ep_addr, char_width) if isinstance(ep_addr, int) else ExtractedString(ep_addr, None) for ep_addr in register_args["Endpoint"] 
                    ]
                
                if "IfSpec" in register_args:
                    log.info("Unhandled IfSpec in register_args")

            self.rpc_use_protseq_calls.update(callsite_useprotseq_args_dict)

        for fn in register_auth_functions:
            callsite_register_auth_args_dict = self.find_all_callsite_args(fn, win32_rpcrt4.prototypes[fn.name])
            for register_args in callsite_register_auth_args_dict.values():
                register_args["api_function"] = fn.name

            self.rpc_register_auth_calls.update(callsite_register_auth_args_dict)
        

    def _symexec_callbacks(self, is_multiplexed=True):
        auth_svcs = []
        protseqs = []
        if not is_multiplexed:    
            for auth_call in self.rpc_register_auth_calls.values():
                auth_svcs.extend(a if isinstance(a, int) else None for a in auth_call["AuthnSvc"])
            
            for use_protseq_call in self.rpc_use_protseq_calls.values():
                protseqs.extend(p.string for p in use_protseq_call["Protseq"])
        
        for register_interface_args in self.rpc_register_calls.values():
            ifcallbacks = register_interface_args.get("IfCallback", set()) | register_interface_args.get("IfCallbackFn", set())

            flags = register_interface_args["Flags"]
            all_n_opnums = [
                len(ifspec.procedure_functions) for ifspec in register_interface_args["IfSpec"] \
                    if isinstance(ifspec, RpcServerInterface) and ifspec.procedure_functions is not None
            ]

            n_opnums = max(all_n_opnums) if all_n_opnums else 0
            accepted_callers_dict = {}
            register_interface_args["possible_clients"] = accepted_callers_dict

            for ifcallback in ifcallbacks:
                accepted_callers_list = []
                
                if not isinstance(ifcallback, int) or ifcallback == 0:
                    ifcallback = 0
                    s:RpcSimState = self.project.factory.blank_state()
                    s.rpc_call.add_registration_constraints(flags, protseqs, auth_svcs, n_opnums)
                    accepted_callers_list.append({
                        "call_attributes": list(s.rpc_call.evaluate_callers()),
                        "extra_constraints": []
                    })

                else:
                    analysis:'RpcInterfaceCallbackAnalysis' = self.project.analyses.RpcCallbackStates(ifcallback, flags, protseqs, auth_svcs, n_opnums, symbolic_execution_timeout=300)
                    
                    for s in analysis.authorized_callers:
                        accepted_callers_list.append({
                            "call_attributes": list(s.rpc_call.evaluate_callers()),
                            "extra_constraints": s.rpc_call.nonrpc_constraints
                        })

                accepted_callers_dict[ifcallback] = accepted_callers_list
                    

angr.analyses.register_analysis(RpcInterfacesAnalysis, "RpcInterfaces")
