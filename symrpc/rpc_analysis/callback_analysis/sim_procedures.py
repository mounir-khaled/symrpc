
import claripy
import angr

class PrivilegeCheck(angr.SimProcedure):
    def run(self, ClientToken:'claripy.Base', RequiredPrivileges:'claripy.Base', pfResult:'claripy.Base'):
        fn_name = "PrivilegeCheck"
        
        return_val = self.state.solver.BVS(
            "unconstrained_ret_%s" % fn_name, 
            self.state.arch.bits
        )

        result = self.state.solver.If(
            return_val == 0, 
            self.state.solver.BVS("%s_unconstrained_result" % fn_name, self.state.arch.bits),
            self.state.solver.BVS("%sResult" % fn_name, self.state.arch.bits)           
        )

        self.state.memory.store(pfResult, result)
        return return_val


class TerminateProcess(angr.SimProcedure):
    NO_RET = True
    def run(self):
        self.exit(0)