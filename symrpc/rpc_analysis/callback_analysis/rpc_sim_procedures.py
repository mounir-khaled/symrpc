import claripy
import angr
import logging
from angr.sim_type import *

from ..rpc_structs import *

log = logging.getLogger(__name__)

def store_ptr_if_notnull(state: angr.SimState, ptr_addr, value):
    if state.solver.is_true(ptr_addr == 0):
        return
    
    arch = state.arch
    ptr = state.solver.BVS("Pointer", arch.bits)
    if isinstance(value, SimStructValue):
        struct:SimStruct = value.struct.with_arch(arch)
        # ptr = claripy.BVV(state.heap.allocate(struct.size // arch.byte_width), arch.bits)
        state.memory.store(ptr_addr, ptr)
        struct.store(state, ptr, value)
    else:
        # ptr = claripy.BVV(state.heap.allocate(value.size() // arch.byte_width), arch.bits)
        state.memory.store(ptr_addr, ptr)
        state.memory.store(ptr, value)

def concat_null_character(string_bvs, char_width):
    return claripy.Concat(string_bvs, claripy.BVV(0, char_width))

class I_RpcBindingIsClientLocal(angr.SimProcedure):
    def run(self, Binding, IsClientLocal):
        self.state.memory.store(IsClientLocal, self.state.rpc_call.call_attributes.IsClientLocal)
        return 0

class I_RpcBindingInqTransportType(angr.SimProcedure):
    def run(self, Binding, Type):
        # self.state.memory.store(Type, claripy.BVS("TransportType", 32))
        self.state.memory.store(Type, self.state.rpc_call.call_attributes.ProtocolSequence)
        return 0

class I_RpcBindingInqLocalClientPID(angr.SimProcedure):
    def run(self, Binding, LocalClientPID):
        self.state.memory.store(LocalClientPID, self.state.rpc_call.call_attributes.ClientPID)
        return 0

class RpcBindingInqAuthClient(angr.SimProcedure):
    def __init__(self, char_width, project=None, cc=None, prototype=None, symbolic_return=None, returns=None, is_syscall=False, is_stub=False, num_args=None, display_name=None, library_name=None, is_function=None, **kwargs):
        super().__init__(project, cc, prototype, symbolic_return, returns, is_syscall, is_stub, num_args, display_name, library_name, is_function, **kwargs)
        self.char_width = char_width

    def run(self, ClientBinding, Privs, ServerPrincName, AuthnLevel, AuthnSvc, AuthzSvc):
        long_size = SimTypeLong(signed=False).with_arch(self.state.arch).size
        store_ptr_if_notnull(self.state, Privs, claripy.BVS("Privs", long_size))
        store_ptr_if_notnull(self.state, ServerPrincName, claripy.BVS("ServerPrincName", long_size))
        
        store_ptr_if_notnull(self.state, AuthnLevel, self.state.rpc_call.call_attributes.AuthenticationLevel)
        store_ptr_if_notnull(self.state, AuthnSvc, self.state.rpc_call.call_attributes.AuthenticationService)
        store_ptr_if_notnull(self.state, AuthzSvc, claripy.BVS("AuthzSvc", long_size))

        return 0

class RpcStringBindingParse(angr.SimProcedure):
    def __init__(self, char_width, project=None, cc=None, prototype=None, symbolic_return=None, returns=None, is_syscall=False, is_stub=False, num_args=None, display_name=None, library_name=None, is_function=None, **kwargs):
        super().__init__(project, cc, prototype, symbolic_return, returns, is_syscall, is_stub, num_args, display_name, library_name, is_function, **kwargs)
        self.char_width = char_width       
            
    def run(self, StringBinding, ObjUuid, Protseq, NetworkAddr, Endpoint, NetworkOptions):
        store_ptr_if_notnull(self.state, ObjUuid, create_symbolic_struct_value(GUID, self.state.arch))
        store_ptr_if_notnull(self.state, Endpoint, claripy.BVS("Endpoint", 12 * self.char_width * self.state.arch.byte_width))

        store_ptr_if_notnull(
            self.state, 
            Protseq, 
            self.state.rpc_call.protseq_string
        )

        return 0

class RpcServerInqCallAttributes(angr.SimProcedure):
    RPC_QUERY_SERVER_PRINCIPAL_NAME                     = 0x02
    RPC_QUERY_CLIENT_PRINCIPAL_NAME                     = 0x04
    RPC_QUERY_CALL_LOCAL_ADDRESS                        = 0x08
    RPC_QUERY_CLIENT_PID                                = 0x10
    # Undocumented:
    RPC_QUERY_IS_CLIENT_LOCAL                           = 0x20
    RPC_QUERY_NO_AUTH_REQUIRED                          = 0x40

    RPC_S_OK = 0
    ERROR_MORE_DATA = 0xea
    ERROR_INVALID_PARAMETER = 0x57

    FIELDS_TO_SET_ALWAYS = ["AuthenticationLevel", "AuthenticationService", "NullSession"]
    FIELDS_TO_SET_V2 = ["KernelModeCaller", "ProtocolSequence", "CallStatus", "CallType", "OpNum", "InterfaceUuid"]

    def __init__(self, char_width, project=None, cc=None, prototype=None, symbolic_return=None, returns=None, is_syscall=False, is_stub=False, num_args=None, display_name=None, library_name=None, is_function=None, **kwargs):
        super().__init__(project, cc, prototype, symbolic_return, returns, is_syscall, is_stub, num_args, display_name, library_name, is_function, **kwargs)
        self.char_width = char_width

    def set_principal_name(self, flags, call_attrs:SimStructValue, return_val, is_server):
        if is_server:
            spn_ptr = call_attrs.ServerPrincipalName
            spn_len = call_attrs.ServerPrincipalNameBufferLength
            flag_cond = flags & self.RPC_QUERY_SERVER_PRINCIPAL_NAME != 0
            principal_name_of = "Server"

        else:
            spn_ptr = call_attrs.ClientPrincipalName
            spn_len = call_attrs.ClientPrincipalNameBufferLength
            flag_cond = flags & self.RPC_QUERY_CLIENT_PRINCIPAL_NAME != 0
            principal_name_of = "Client"

        if self.state.solver.is_false(flag_cond):
            return call_attrs, return_val
        
        spn_len_vals = self.state.solver.eval_upto(spn_len, 2)
        if len(spn_len_vals) != 1:
            # raise ValueError()
            log.warning("Symbolic spn_len %s, setting to 128 (probably should handle this better)", spn_len)
            spn_len_val = 128
        else:
            spn_len_val = spn_len_vals[0]

        old_spn = self.state.memory.load(spn_ptr, spn_len_val)
        spn = claripy.Concat(
            claripy.BVS(f"{principal_name_of}PrincipalName", (spn_len_val - self.char_width) * self.project.arch.byte_width),
            claripy.BVV(0, self.char_width * self.project.arch.byte_width)
        )

        actual_spn_len = self.state.solver.BVS(
            f"Actual{principal_name_of}PrincipalNameBufferLength", 
            call_attrs.struct.fields[f"{principal_name_of}PrincipalNameBufferLength"].size
        )
        # If insufficient, ServerPrincipalName is unchanged, and ServerPrincipalNameBufferLength indicates the required buffer length including the terminating NULL character
        is_insufficient = actual_spn_len > spn_len_val
        new_spn = claripy.If(
            is_insufficient,
            old_spn,
            spn
        )
        
        is_spn_ptr_null = claripy.And(spn_ptr == 0, spn_len_val != 0)
        new_spn = claripy.If(
            is_spn_ptr_null,
            old_spn,
            new_spn
        )

        new_spn = claripy.If(flag_cond, new_spn, old_spn)
        self.state.memory.store(spn_ptr, new_spn)

        call_attrs = self.set_member_to_variable(
            call_attrs, 
            f"{principal_name_of}PrincipalNameBufferLength", 
            claripy.If(claripy.And(flag_cond, claripy.Not(is_spn_ptr_null)), actual_spn_len, spn_len)
        )

        original_return_val = return_val
        return_val = claripy.If(is_insufficient, self.ERROR_MORE_DATA, original_return_val)
        return_val = claripy.If(is_spn_ptr_null, self.ERROR_INVALID_PARAMETER, return_val)
        return_val = claripy.If(flag_cond, return_val, original_return_val)
        return call_attrs, return_val

    def set_member_to_variable(self, struct_val:SimStructValue, field_name:str, value=None):
        field_type:SimType = struct_val.struct.fields[field_name]
        new_values = {}
        for field in struct_val.struct.fields:
            if field == field_name:
                if isinstance(field_type, SimStruct):
                    new_values[field] = create_symbolic_struct_value(field_type, self.arch) if value is None else value
                else:
                    new_values[field] = self.state.solver.BVS(field_name, field_type.size) if value is None else value
            else:
                new_values[field] = struct_val[field]

        return SimStructValue(struct_val.struct, new_values)

    def run(self, ClientBinding:'claripy.Base', RpcCallAttributes:'claripy.Base'):
        # RpcCallAttributes size is 112 (?)
        return_val = claripy.BVV(self.RPC_S_OK, self.arch.bits)
        
        in_call_attrs_type:SimStruct = RPC_CALL_ATTRIBUTES_V1_A.with_arch(self.arch)
        in_call_attrs = in_call_attrs_type.extract(self.state, RpcCallAttributes)

        version = self.state.solver.eval_one(in_call_attrs.Version, default=None)
        if version == 1:
            out_call_attrs_type = RPC_CALL_ATTRIBUTES_V1_A.with_arch(self.arch)
            out_call_attrs = in_call_attrs
        elif version == 2:
            out_call_attrs_type = RPC_CALL_ATTRIBUTES_V2_A.with_arch(self.arch)
            out_call_attrs = out_call_attrs_type.extract(self.state, RpcCallAttributes)
        else:
            out_call_attrs_type = RPC_CALL_ATTRIBUTES_V2_A.with_arch(self.arch)
            out_call_attrs = out_call_attrs_type.extract(self.state, RpcCallAttributes)

        # Fields independent of flags or version
        for fieldname in self.FIELDS_TO_SET_ALWAYS:
            out_call_attrs = self.set_member_to_variable(out_call_attrs, fieldname, self.state.rpc_call.call_attributes[fieldname])

        flags = in_call_attrs.Flags
        # RPC_QUERY_SERVER_PRINCIPAL_NAME
        out_call_attrs, return_val = self.set_principal_name(flags, out_call_attrs, return_val, is_server=True)

        # RPC_QUERY_Client_PRINCIPAL_NAME
        out_call_attrs, return_val = self.set_principal_name(flags, out_call_attrs, return_val, is_server=False)
        
        if version != 1:
            for fieldname in self.FIELDS_TO_SET_V2:
                out_call_attrs = self.set_member_to_variable(out_call_attrs, fieldname, self.state.rpc_call.call_attributes[fieldname])

            # RPC_QUERY_CALL_LOCAL_ADDRESS
            # TODO: Handle insufficient buffer case
            flag_cond = flags & self.RPC_QUERY_CALL_LOCAL_ADDRESS != 0
            cla_type = RPC_CALL_LOCAL_ADDRESS.with_arch(self.arch)
            cla_ptr = out_call_attrs.CallLocalAddress

            old_cla = self.state.memory.load(cla_ptr, cla_type.size // self.arch.byte_width)
            cla = self.state.solver.BVS("CallLocalAddress", cla_type.size)
            is_ptr_null = cla_ptr == 0
            cla = claripy.If(is_ptr_null, old_cla, cla)
            cla = claripy.If(flag_cond, cla, old_cla)

            store_condition = claripy.And(flag_cond, is_ptr_null)
            return_val = claripy.If(store_condition, self.ERROR_INVALID_PARAMETER, return_val)
            self.state.memory.store(cla_ptr, cla, condition=store_condition)
            
            # RPC_QUERY_CLIENT_PID
            flag_cond = flags & self.RPC_QUERY_CLIENT_PID != 0
            # pid = self.state.solver.BVS("ClientPID", out_call_attrs.struct.fields["ClientPID"].size)
            out_call_attrs = self.set_member_to_variable(out_call_attrs,"ClientPID", claripy.If(flag_cond, self.state.rpc_call.call_attributes.ClientPID, out_call_attrs.ClientPID))

            # RPC_QUERY_IS_CLIENT_LOCAL
            flag_cond = flags & self.RPC_QUERY_IS_CLIENT_LOCAL != 0
            # is_client_local = self.state.solver.BVS("IsClientLocal", out_call_attrs.struct.fields["IsClientLocal"].size)
            out_call_attrs = self.set_member_to_variable(out_call_attrs, "IsClientLocal", claripy.If(flag_cond, self.state.rpc_call.call_attributes.IsClientLocal, out_call_attrs.IsClientLocal))

            # TODO: RPC_QUERY_NO_AUTH_REQUIRED but it is undocumented :(
        
        # Workaround for an issue with store
        out_call_attrs_type.store(self.state, RpcCallAttributes, out_call_attrs)
        
        return return_val
