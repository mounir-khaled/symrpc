
import angr
import claripy

from typing import Iterable, Optional, Union

class LastErrorPlugin(angr.SimStatePlugin):
    def __init__(self, value:Optional['claripy.Base']=None):
        super().__init__()
        self.value = value
        self._bp = None
    
    def init_state(self):
        if self.value is None:
            self.value = self.state.solver.Unconstrained(
                "unconstrained_GetLastError", 
                self.state.arch.bits
            )
        
        if self._bp is not None:
            self.state.inspect.remove_breakpoint("simprocedure", self._bp)

        self._bp = self.state.inspect.b(
            "simprocedure", 
            when="after", 
            condition=self._simproc_filter,
            action=self._set_simproc_lasterror
        )

    def _simproc_filter(self, state:angr.SimState):
        return state.inspect.simprocedure_name in {"PrivilegeCheck", "OpenThreadToken"}

    def _set_simproc_lasterror(self, state:angr.SimState):
        self.state.last_error.set_success_condition(
            state.inspect.simprocedure_result[31:0] != 0,
            f"{state.inspect.simprocedure_name}Error"
        )

    def set_success_condition(self, condition:'claripy.Base', error_var: Union[str, 'claripy.Base']):
        if isinstance(error_var, str):
            error_val = self.state.solver.BVS(
                        error_var, 
                        32
                    )
        else:
            error_val = error_var

        self.value = claripy.If(
            condition, 
            claripy.BVV(0, 32),
            error_val
        )

        self.state.add_constraints(error_val != 0)
        return error_val

    @angr.SimStatePlugin.memo
    def copy(self, _memo):
        new_copy = LastErrorPlugin(self.value)
        new_copy._bp = self._bp
        return new_copy

    def merge(self, others:Iterable['LastErrorPlugin'], merge_conditions, common_ancestor=None):
        merged_values = claripy.BVS("Invalid", others[0].value.size())
        for o, c in zip([self] + others, merge_conditions):
            merged_values = claripy.If(c, o.value, merged_values)
        
        return LastErrorPlugin(merged_values)

class GetLastError(angr.SimProcedure):
    def run(self, *args, **kwargs):
        if self.prototype.returnty.size == 64:
            return claripy.Concat(self.state.regs.rax[63:32], self.state.last_error.value[31:0])
        else:
            return self.state.last_error.value

class SetLastError(angr.SimProcedure):
    def run(self, last_error):
        self.state.last_error.value = last_error