
from collections import deque
import itertools
from typing import Iterable, Union, Optional

import angr

from angr.analyses import Analysis
from angr.knowledge_plugins import Function
from angr.exploration_techniques import DFS, Timeout, LocalLoopSeer

from .last_error_plugin import LastErrorPlugin, SetLastError, GetLastError
from .rpc_call_plugin import RpcCallPlugin
from .rpc_sim_procedures import *
from .sim_procedures import *

RE_CONTROL_CHARS = re.compile('[%s]' % re.escape(
    ''.join(map(chr, itertools.chain(range(0x00,0x20), range(0x7f,0xa0))))
))

STRCMP_PROTOTYPE = angr.SIM_LIBRARIES["libc.so"].prototypes["strcmp"]

# Just for type checking 
class RpcSimState(SimState):
    rpc_call:RpcCallPlugin

class HookSet:
    def __init__(self, p:angr.Project, fn_name_hook_pairs:Iterable[Tuple[str, angr.SimProcedure]], *, replace=False) -> None:
        self._project = p
        self._old_hooks = deque()
        self._fn_name_hook_pairs = fn_name_hook_pairs
        self._replace = replace
    
    def hook(self):
        if self._old_hooks:
            raise ValueError("Cannot enter twice, create a new HookSet object")

        for fn_name, hook in self._fn_name_hook_pairs:
            fn:Function = self._project.kb.functions.get(fn_name, None)
            if fn is None:
                continue

            if hook.cc is None:
                hook.cc = fn.calling_convention

            self._old_hooks.append((fn.addr, self._project.hooked_by(fn.addr)))
            self._project.hook(fn.addr, hook, replace=self._replace)

    def restore_hooks(self):
        while self._old_hooks:
            fn_addr, hook = self._old_hooks.pop()
            self._project.hook(fn_addr, hook, replace=True)

    def __enter__(self):
        self.hook()
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        self.restore_hooks()

class SkipUnconstrainAnnotation(claripy.Annotation):
    eliminatable = False
    relocatable = False

def unconstrain_global(state:angr.SimState):
    if not isinstance(state.inspect.mem_read_address, int) and state.inspect.mem_read_address.symbolic:
        return
    
    if any(isinstance(a, SkipUnconstrainAnnotation) for a in state.inspect.mem_read_expr.annotations):
        return

    if not (state.inspect.mem_read_expr.op.startswith("BV") and state.inspect.mem_read_expr.args[0] == 0):
        return

    if isinstance(state.inspect.mem_read_address, int):
        concrete_addr = state.inspect.mem_read_address
    elif state.inspect.mem_read_address.op.startswith("BV"):
        concrete_addr = state.inspect.mem_read_address.args[0]
    else:
        concrete_addr = state.solver.eval_one(state.inspect.mem_read_address)

    section = state.project.loader.find_section_containing(concrete_addr)
    if section is not None and section.is_writable:
        printable_section_name = RE_CONTROL_CHARS.sub('', section.name)
        var_name = "%s_global_%#x" % (printable_section_name, concrete_addr)
        var_size = state.inspect.mem_read_length * state.arch.byte_width

        global_var = state.solver.Unconstrained(var_name, var_size).annotate(SkipUnconstrainAnnotation())
        state.memory.store(state.inspect.mem_read_address, global_var, inspect=False, disable_actions=True)
        state.inspect.mem_read_expr = global_var

def annotate_global_var_write(state:angr.SimState):
    if not isinstance(state.inspect.mem_write_address, int) and state.inspect.mem_write_address.symbolic:
        return

    if isinstance(state.inspect.mem_write_address, int):
        concrete_addr = state.inspect.mem_write_address
    elif state.inspect.mem_write_address.op.startswith("BV"):
        concrete_addr = state.inspect.mem_write_address.args[0]
    else:
        concrete_addr = state.solver.eval_one(state.inspect.mem_write_address)

    section = state.project.loader.find_section_containing(concrete_addr)
    if section is None or not section.is_writable:
        return

    if not any(isinstance(a, SkipUnconstrainAnnotation) for a in state.inspect.mem_write_expr.annotations):
        state.inspect.mem_write_expr = state.inspect.mem_write_expr.annotate(SkipUnconstrainAnnotation())

def assign_prototype(state:angr.SimState):
    simproc:angr.SimProcedure = state.inspect.simprocedure
    charp = SimTypePointer(SimTypeChar())
    if not (simproc.prototype.returnty == charp and \
            all(arg == charp for arg in simproc.prototype.args)):
        return

    prototype = None
    if simproc.library_name and simproc.library_name in angr.SIM_LIBRARIES:
        prototype = angr.SIM_LIBRARIES[simproc.library_name].get_prototype(simproc.display_name, state.arch)

    if prototype is None:
        for lib_name, lib in angr.SIM_LIBRARIES.items():
            prototype = lib.get_prototype(simproc.display_name, state.arch)
            if prototype is not None:
                break

    if prototype is None:
        log.warning("Failed to find prototype for %s", simproc)
    else:
        simproc.prototype = prototype

class RpcInterfaceCallbackAnalysis(Analysis):
    SIMPROC_DICT = {
        "I_RpcBindingIsClientLocal": I_RpcBindingIsClientLocal(),
        "I_RpcBindingInqTransportType": I_RpcBindingInqTransportType(),
        "I_RpcBindingInqLocalClientPID": I_RpcBindingInqLocalClientPID(),
        "RpcBindingInqAuthClientW": RpcBindingInqAuthClient(char_width=2),
        "RpcServerInqCallAttributesW": RpcServerInqCallAttributes(char_width=2),
        "RpcStringBindingParseW": RpcStringBindingParse(char_width=2),
        "PrivilegeCheck": PrivilegeCheck(),
        "GetLastError": GetLastError(),
        "SetLastError": SetLastError(),
        "lstrcmpW": angr.SIM_PROCEDURES["libc"]["strcmp"](wchar=True),
        "wcscmp": angr.SIM_PROCEDURES["libc"]["strcmp"](wchar=True),
        "wcscasecmp": angr.SIM_PROCEDURES["libc"]["strcmp"](wchar=True, ignore_case=True),
        "_wcsicmp": angr.SIM_PROCEDURES["libc"]["strcmp"](wchar=True, ignore_case=True),
        "_stricmp": angr.SIM_PROCEDURES["libc"]["strcmp"](ignore_case=True),
        "TerminateProcess": TerminateProcess()
    }

    def __init__(self, 
                callback_function:Union[str, int, Function], 
                registration_flags:Optional[Iterable['RpcServerInterfaceFlags']]=None,
                protocol_sequences:Optional[Iterable[str]]=None,
                authentication_services:Optional[Iterable[int]]=None,
                n_opnums=0,
                init_state:Optional[angr.SimState]=None,
                symbolic_execution_timeout=None,
                replace_simprocedures=True
            ) -> None:

        super().__init__()

        p = self.project

        self.arch = self.project.arch
        self._default_cc = angr.calling_conventions.SimCCMicrosoftAMD64(p.arch) if p.arch.bits == 64 else angr.calling_conventions.SimCCMicrosoftFastcall

        if not isinstance(callback_function, Function):
            callback_function = self.kb.functions[callback_function]

        if init_state:
            init_state.ip = callback_function.addr
        else:
            if_uuid_ptr = claripy.BVS("InterfaceUuid", p.arch.bits)
            context_ptr = claripy.BVS("Context", p.arch.bits)
            init_state = p.factory.call_state(
                callback_function.addr, 
                if_uuid_ptr, 
                context_ptr,
                cc=self._default_cc,
                add_options={angr.options.UNDER_CONSTRAINED_SYMEXEC}
            )

            concrete_if_uuid_ptr = init_state.heap.allocate(1024)
            concrete_context_ptr = init_state.heap.allocate(1024)

            my_constraints = [
                if_uuid_ptr == concrete_if_uuid_ptr,
                context_ptr == concrete_context_ptr
            ]

            init_state.add_constraints(*my_constraints)
            
            init_state.memory.store(if_uuid_ptr, init_state.solver.Unconstrained("INTERFACE_UUID", 8*1024))
            init_state.memory.store(context_ptr, init_state.solver.Unconstrained("CONTEXT", 8*1024))
        
        # DO NOT DELETE THIS!!
        init_state.last_error
        init_state.rpc_call:RpcCallPlugin
        init_state.rpc_call.add_registration_constraints(registration_flags, protocol_sequences, authentication_services, n_opnums)

        self.rpc_call_info = init_state.rpc_call

        init_state.inspect.b("mem_read", when=angr.BP_AFTER, action=unconstrain_global)
        init_state.inspect.b("mem_write", when=angr.BP_BEFORE, action=annotate_global_var_write)
        init_state.inspect.b("simprocedure", when=angr.BP_BEFORE, action=assign_prototype)

        simgr = p.factory.simulation_manager(init_state)
        simgr.use_technique(DFS())
        simgr.use_technique(Timeout(symbolic_execution_timeout))
        simgr.use_technique(LocalLoopSeer(bound=10))
        
        with HookSet(p, self.SIMPROC_DICT.items(), replace=replace_simprocedures):
            # init_state.inspect.b("constraints", when=angr.BP_BEFORE, action=tag_constraints)
            # init_state.inspect.b("address_concretization", when=angr.BP_BEFORE, action=tag_ac_constraints)
            simgr.run(n=10000)
            
        for state in simgr.deadended:
            if state.history.jumpkind == "Ijk_Ret":
                state.add_constraints(state.regs.eax == 0)

        simgr.move("deadended", "authorized", lambda s: s.history.jumpkind == "Ijk_Ret" and s.satisfiable())

        self.authorized_callers:'list[RpcSimState]' = simgr.authorized

        

angr.SimState.register_default("last_error", LastErrorPlugin)
angr.SimState.register_default("rpc_call", RpcCallPlugin)
angr.analyses.register_analysis(RpcInterfaceCallbackAnalysis, "RpcCallbackStates")
