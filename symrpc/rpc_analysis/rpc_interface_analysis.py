from dataclasses import dataclass
import logging

from typing import Iterable, Optional

import angr
import ctypes


from angr.analyses.analysis import Analysis
from angr.knowledge_plugins.functions import Function
from angr.analyses.reaching_definitions import ReachingDefinitionsAnalysis
from angr.knowledge_plugins.key_definitions.key_definition_manager import RDAObserverControl


from .rpc_structs import *
from .callback_analysis.interface_callback_analysis import RpcInterfaceCallbackAnalysis, RpcSimState

from .reaching_arguments import ReachingArgumentsAnalysis

from .rpc_dataclasses import *
from .rd_function_handlers import ConvertStringSecurityDescriptorHandler

# import angr.procedures.definitions.win32_rpcrt4 as win32_rpcrt4
# ^ PyLance breaks when doing this import so this is here as a workaround
from importlib import import_module
win32_rpcrt4 = import_module("angr.procedures.definitions.win32_rpcrt4")

log = logging.getLogger(__name__)

class RpcInterfacesAnalysis(ReachingArgumentsAnalysis):

    RE_SECURITY_DESCRIPTOR = re.compile(r"PSecurityDescriptor\('(?P<sddl>.+)'\)")

    security_descriptor_to_string = ctypes.windll.advapi32.ConvertSecurityDescriptorToStringSecurityDescriptorW
    security_descriptor_to_string.argtypes = [
        ctypes.c_void_p, 
        ctypes.wintypes.DWORD, 
        ctypes.wintypes.DWORD, 
        ctypes.POINTER(ctypes.wintypes.LPWSTR), 
        ctypes.POINTER(ctypes.wintypes.PULONG)
    ]

    security_descriptor_to_string.restype = ctypes.wintypes.BOOL

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
        for cs_addr, register_args in self.rpc_register_calls.items():
            interfaces = register_args["IfSpec"]
            resolved_interfaces = [i for i in interfaces if isinstance(i.address, int)]
            if len(interfaces) == len(resolved_interfaces):
                continue
            
            resolved_interface_addrs = {i.address for i in resolved_interfaces}
            detected_interfaces = resolved_interfaces.copy()
            for addr in self.project.loader.memory.find(b"\x60\x00\x00\x00"):
                try:
                    if addr in resolved_interface_addrs:
                        continue

                    extracted_ifspec = RpcServerInterface.extract(backer_state, addr)
                    if syntax_version["MajorVersion"] > 10:
                        continue

                    if not extracted_ifspec.procedure_functions:
                        continue

                    required_addrs = (
                        extracted_ifspec.struct_values["DispatchTable"], 
                        extracted_ifspec.struct_values["InterpreterInfo"]
                    )

                    if not all(self.project.loader.main_object.contains_addr(a) for a in required_addrs):
                        continue

                    syntax_version = extracted_ifspec.struct_values["InterfaceId"]["SyntaxVersion"]
                    detected_interfaces.append(extracted_ifspec)

                except ValueError:
                    continue

            register_args["IfSpec"] = detected_interfaces.copy()

        if symexec_callbacks:
            self._symexec_callbacks(is_multiplexed=is_multiplexed)

    def _run_and_cache_rda(self, fn:Function):
        # caller_block = fn.get_block(caller_blocknode.addr, fn.get_block_size(caller_blocknode.addr))
        # obs_point = ("insn", caller_block.instruction_addrs[-1], 0)

        # rda = self.project.analyses[ReachingDefinitionsAnalysis].prep()(
        #     fn, 
        #     observation_points=[obs_point], 
        #     function_handler=ConvertStringSecurityDescriptorHandler()
        # )

        # self.kb.defs.model_by_funcaddr[fn.addr] = rda.model

        if fn.is_simprocedure or fn.is_plt or fn.alignment:
            raise ValueError("Function is simprocedure or plt or alignment")

        callsites = list(fn.get_call_sites())
        if not callsites:
            return
        call_insn_addrs = set()
        for block_addr in callsites:
            block = fn._get_block(block_addr)
            if block is None:
                continue
            if not block.instruction_addrs:
                continue
            call_insn_addr = block.instruction_addrs[-1]
            call_insn_addrs.add(call_insn_addr)

        observer = RDAObserverControl(fn.addr, callsites, call_insn_addrs)
        rda = self.project.analyses[ReachingDefinitionsAnalysis].prep(kb=self.kb)(
            subject=fn, observe_callback=observer.rda_observe_callback, function_handler=ConvertStringSecurityDescriptorHandler()
        )
        
        self.kb.defs.model_by_funcaddr[fn.addr] = rda.model

    def _recover_registration_args(
                self, 
                register_if_functions:Iterable[Function], 
                use_protseq_functions:Iterable[Function], 
                register_auth_functions:Iterable[Function], 
                backer_state:angr.SimState
            ):

        for register_fn in register_if_functions:
            for caller_fn, caller_blocknode in self._iter_callers(register_fn):
                if caller_fn.addr in self.kb.defs.model_by_funcaddr:
                    continue
                
                self._run_and_cache_rda(caller_fn)

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
                
                register_args["IfSpec"] = interfaces.copy()

                flags_list = []
                for flags_int in register_args["Flags"]:
                    if isinstance(flags_int, int):
                        flags = RpcServerInterfaceFlags.from_int(flags_int)
                    else:
                        flags = None

                    flags_list.append(flags)
                
                register_args["Flags"] = flags_list.copy()

                security_descriptors = []
                for sd_ptr in register_args["SecurityDescriptor"]:
                    sddl = None
                    try:
                        if isinstance(sd_ptr, int) and sd_ptr == 0:
                            sddl = 0
                        elif isinstance(sd_ptr, int):
                            sddl = self._extract_sddl_from_addr(sd_ptr)
                        elif isinstance(sd_ptr, claripy.ast.bv.BV):
                            sddl = self._extract_sddl_from_bvs(sd_ptr)

                    except Exception:
                        log.error("Failed to extract security descriptor at %#x", sd_ptr)
                        
                    if sddl is None:
                        security_descriptors.append(sd_ptr)
                    else:
                        security_descriptors.append(sddl)
                    
                register_args["SecurityDescriptor"] = security_descriptors.copy()
                    
            
            self.rpc_register_calls.update(callsite_register_args_dict)

        for fn in use_protseq_functions:
            for caller_fn, caller_blocknode in self._iter_callers(register_fn):
                if caller_fn.addr in self.kb.defs.model_by_funcaddr:
                    continue
                
                self._run_and_cache_rda(caller_fn)

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
                
                security_descriptors = []
                for sd_ptr in register_args["SecurityDescriptor"]:
                    sddl = None
                    try:
                        if isinstance(sd_ptr, int) and sd_ptr == 0:
                            sddl = 0
                        elif isinstance(sd_ptr, int):
                            sddl = self._extract_sddl_from_addr(sd_ptr)
                        elif isinstance(sd_ptr, claripy.ast.bv.BV):
                            sddl = self._extract_sddl_from_bvs(sd_ptr)

                    except Exception:
                        log.error("Failed to extract security descriptor at %#x", sd_ptr)
                        
                    if sddl is None:
                        security_descriptors.append(sd_ptr)
                    else:
                        security_descriptors.append(sddl)
                    
                register_args["SecurityDescriptor"] = security_descriptors.copy()

            self.rpc_use_protseq_calls.update(callsite_useprotseq_args_dict)

        for fn in register_auth_functions:
            for caller_fn, caller_blocknode in self._iter_callers(register_fn):
                if caller_fn.addr in self.kb.defs.model_by_funcaddr:
                    continue
                
                self._run_and_cache_rda(caller_fn)

            callsite_register_auth_args_dict = self.find_all_callsite_args(fn, win32_rpcrt4.prototypes[fn.name])
            for register_args in callsite_register_auth_args_dict.values():
                register_args["api_function"] = fn.name

            self.rpc_register_auth_calls.update(callsite_register_auth_args_dict)
        

    def _extract_sddl_from_bvs(self, bvs):
        if not bvs.op == "BVS":
            return None

        name = bvs.args[0]
        match = self.RE_SECURITY_DESCRIPTOR.fullmatch(name)
        if match is None:
            return None

        return match.group("sddl")

    def _extract_sddl_from_addr(self, addr):
        offset = addr - self.project.loader.main_object.mapped_base

        # This won't work with exe files
        loaded_dll = ctypes.windll.LoadLibrary(self.project.filename)
        sd_ptr = ctypes.cast(loaded_dll._handle + offset, ctypes.c_void_p)

        sb = ctypes.c_wchar_p()
        sb_ptr = ctypes.pointer(sb)

        sz = ctypes.wintypes.ULONG(0)
        sz_ptr = ctypes.pointer(sz)

        retval = self.security_descriptor_to_string(sd_ptr, 1, 0xffff_ffff, sb_ptr, sz_ptr)
        if retval == 0:
            raise ValueError("Conversion failed")
        
        sddl = sb.value
        ctypes.windll.kernel32.LocalFree(sb)
        return sddl

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
