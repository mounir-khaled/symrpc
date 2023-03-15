import angr


from angr.analyses.reaching_definitions.function_handler import FunctionHandler
from angr.analyses.reaching_definitions.rd_state import ReachingDefinitionsState
from angr.analyses.reaching_definitions import ReachingDefinitionsAnalysis
from angr.knowledge_plugins.key_definitions.tag import ReturnValueTag

from angr.code_location import CodeLocation
from angr.knowledge_plugins.key_definitions.atoms import *
import archinfo

# BOOL ConvertStringSecurityDescriptorToSecurityDescriptorA(
#   [in]  LPCSTR               StringSecurityDescriptor,
#   [in]  DWORD                StringSDRevision,
#   [out] PSECURITY_DESCRIPTOR *SecurityDescriptor,
#   [out] PULONG               SecurityDescriptorSize
# );

class SddlTag(ReturnValueTag):
    def __init__(self, function: int = None, metadata: object = None):
        super().__init__(function, metadata)

class ConvertStringSecurityDescriptorHandler(FunctionHandler):
    def __init__(self) -> None:
        super().__init__()
        self.rda = None
        self.backing_state = None

    def hook(self, analysis: ReachingDefinitionsAnalysis) -> "FunctionHandler":
        self.rda = analysis
        self.backing_state:angr.SimState = self.rda.project.factory.blank_state()
        return super().hook(analysis)

    def handle_ConvertStringSecurityDescriptorToSecurityDescriptor(
            self,
            state:ReachingDefinitionsState, 
            src_codeloc:CodeLocation,
            *,
            wide_chars):
        
        arch = self.rda.project.arch
        
        str_ptr_atom = Register(arch.registers["rcx"][0], arch.bytes)
        str_ptr = state.live_definitions.get_value_from_atom(str_ptr_atom)

        str_value_set = set()
        for value in str_ptr[0]:
            if isinstance(value, int) or not value.symbolic:
                str_value = self.get_string_value(value, wide=wide_chars)
            else:
                str_value = None

            str_value_set.add(str_value)

        if not str_value_set:
            return False, state
        
        sd_ptr_atom = Register(arch.registers["r8"][0], arch.bytes)
        sd_ptr = state.live_definitions.get_value_from_atom(sd_ptr_atom)
        values = {
            claripy.BVS("PSecurityDescriptor('%s')" % str_value, arch.bits, explicit_name=True) for str_value in str_value_set
        }

        sd_mv = MultiValues(offset_to_values={0: values})
        for value in sd_ptr[0]:
            if not state.is_stack_address(value):
                continue

            offset = state.get_stack_offset(value)
            mloc_atom = MemoryLocation(SpOffset(arch.bits, offset), arch.bytes)
            
            state.kill_and_add_definition(mloc_atom, src_codeloc, sd_mv, endness=archinfo.Endness.LE)
        
        return True, state

    def get_string_value(self, addr, *, wide):
        obj = self.backing_state.mem[addr]
        bv_string = obj.wstring if wide else obj.string

        return bv_string.concrete

    def handle_ConvertStringSecurityDescriptorToSecurityDescriptorA(
            self, 
            state:ReachingDefinitionsState, 
            src_codeloc:CodeLocation):

        return self.handle_ConvertStringSecurityDescriptorToSecurityDescriptor(state, src_codeloc, wide_chars=False)

    def handle_ConvertStringSecurityDescriptorToSecurityDescriptorW(
            self, 
            state:ReachingDefinitionsState, 
            src_codeloc:CodeLocation):
        
        return self.handle_ConvertStringSecurityDescriptorToSecurityDescriptor(state, src_codeloc, wide_chars=True)
    
