
import angr
import logging

from angr.knowledge_plugins import Function
from angr.calling_conventions import SimCC

from angr.calling_conventions import *
from angr.knowledge_plugins.key_definitions import *
from angr.knowledge_plugins.key_definitions.atoms import Register, MemoryLocation, SpOffset
from angr.knowledge_plugins.key_definitions.live_definitions import DefinitionAnnotation
from angr.knowledge_plugins.key_definitions.tag import ReturnValueTag

log = logging.getLogger(__name__)

class ReachingArgumentsAnalysis(angr.analyses.Analysis):
    def __init__(self, coerce_values=False) -> None:
        super().__init__()
        self._coerce = coerce_values

    def get_arg_at_callsite(self, caller_fn:Function, callsite_addr:int, callee_cc:SimCC, callee_prototype:SimTypeFunction, arg_ix:int):
        arch = self.project.arch

        rda = self.kb.defs.get_model(caller_fn.addr)
        caller_block = caller_fn.get_block(callsite_addr, caller_fn.get_block_size(callsite_addr))
        obs_point = ("insn", caller_block.instruction_addrs[-1], 0)
        livedefs = rda.observed_results[obs_point]

        arg = callee_cc.arg_locs(callee_prototype)[arg_ix]

        all_values = set()
        
        if isinstance(arg, SimRegArg):
            reg_offset, reg_size = arch.registers[arg.reg_name]
            atoms = [Register(reg_offset, reg_size)]
        elif isinstance(arg, SimStackArg):
            sp_atom = Register(arch.sp_offset, arch.bytes)
            stack_offset = livedefs.get_value_from_atom(sp_atom)
            if stack_offset is None:
                raise ValueError()
            elif 0 not in stack_offset:
                raise ValueError()
            
            atoms = []
            for sp_offset in stack_offset[0]:
                sp_offset = LiveDefinitions.get_stack_offset(sp_offset)
                if sp_offset is None:
                    all_values.add(LiveDefinitions.top(arg.size * arch.byte_width))
                else:
                    arg_sp_offset = SpOffset(arch.bits, arg.stack_offset + sp_offset - callee_cc.STACKARG_SP_DIFF)
                    atoms.append(MemoryLocation(arg_sp_offset, arg.size, arch.memory_endness))

        else:
            raise TypeError()
        
        for atom in atoms:
            mv = livedefs.get_value_from_atom(atom)
            if mv is None or 0 not in mv:
                log.error("Error getting argument %d, failed to get value from atom %s", arg_ix, atom)
                values = {LiveDefinitions.top(arg.size * arch.byte_width)}
            else:
                values = mv[0]

            if isinstance(atom, Register):
                values = set(v[arg.size*arch.byte_width-1:] for v in values)

            all_values.update(values)
            
        return all_values

    
    def _iter_callers(self, fn:Function):
        for caller_addr, _, edge_type in self.kb.callgraph.in_edges(fn.addr, data="type"):
            if edge_type != "call":
                continue

            caller_fn = self.kb.functions.get_by_addr(caller_addr)
            for caller_blocknode, _, tg_edge_type in caller_fn.transition_graph.in_edges(fn, data="type"):
                if tg_edge_type != "call":
                    continue

                yield caller_fn, caller_blocknode


    def find_all_callsite_args(self, fn:Function, proto:SimTypeFunction):
        arch = self.project.arch
        callsite_args = {}
        cc = fn.calling_convention
        if cc is None:
            log.debug("register_if_fn.calling_convention is None")
            if not fn.ran_cca:
                cc = self.project.analyses.CallingConvention(fn).cc
                log.debug("register_if_fn.ran_cca == False")
                
            if cc is None:
                cc = angr.DEFAULT_CC[arch.name](arch)
                log.debug("cc is still None, reverting to DEFAULT")

        for caller_fn, caller_blocknode in self._iter_callers(fn):
            
            register_args = defaultdict(set)
            arg_name_ix_pairs = [(name, i) for i, name in enumerate(proto.arg_names)]
            for arg_name, arg_ix in arg_name_ix_pairs:
                arg_value_set = register_args[arg_name]
                try:
                    arg_mv = self.get_arg_at_callsite(caller_fn, caller_blocknode.addr, cc, proto, arg_ix)
                except ValueError as e:
                    log.error("Error getting argument %d at callsite %#x to %s", arg_ix, caller_blocknode.addr, fn.name)
                    arg_value_set.add(LiveDefinitions.top(proto.args[arg_ix].size * arch.byte_width))
                    continue

                for val in arg_mv:
                    if not val.concrete and self._coerce:
                        leaf_asts = list(val.leaf_asts())
                        any_concrete = False
                        all_symbolic_returnvals = True
                        for v in leaf_asts:
                            if v.concrete:
                                any_concrete = True
                                continue

                            v_defs = [a.definition for a in v.annotations if isinstance(a, DefinitionAnnotation)]
                            for d in v_defs:
                                all_symbolic_returnvals &= any(isinstance(t, ReturnValueTag) for t in d.tags)
                        
                        old_val = val
                        if any_concrete and all_symbolic_returnvals:
                            val = old_val
                            for v in leaf_asts:
                                if v.symbolic:
                                    val = val.replace(v, claripy.BVV(0, v.size()))

                        if val.concrete:
                            log.info("Coerced %s to %s", old_val, val)
                        else:
                            val = old_val
                            log.warning("Failed to coerce value %s", val)
                            
                    if not val.concrete:
                        log.info(
                            "Found non-concrete value for argument '%s' to call to %s at %#x",
                            arg_name,
                            fn.name,
                            caller_blocknode.addr
                        )

                    elif val.op == "BVV":
                        val = val.args[0]
                    else:
                        try:
                            val = claripy.backends.concrete.eval(val, 1)[0]
                        except (IndexError, claripy.ClaripyError):
                            log.error(
                                "Failed to evaluate '%s' for argument '%s' to call to %s at %#x", 
                                val,
                                arg_name,
                                fn.name,
                                caller_blocknode.addr
                            )

                            val = LiveDefinitions.top(proto.args[arg_ix].size * arch.byte_width)

                    arg_value_set.add(val)

            callsite_args[caller_blocknode.addr] = register_args
        
        return callsite_args


angr.analyses.register_analysis(ReachingArgumentsAnalysis, "reaching_args")

