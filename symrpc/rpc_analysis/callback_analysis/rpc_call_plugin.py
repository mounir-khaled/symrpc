from collections import defaultdict
import itertools
from typing import Iterable, Optional, cast
from ..rpc_structs import create_symbolic_struct_value, RPC_CALL_ATTRIBUTES_V2_A

import claripy
import angr
from angr.sim_type import SimStructValue

class RpcConstraint(claripy.SimplificationAvoidanceAnnotation):
    def __init__(self, label=None) -> None:
        super().__init__()
        self.label = label

    def __str__(self):
        return "RpcConstraint(label=%r)" % self.label

class RpcCallPlugin(angr.SimStatePlugin):
    AUTHENTICATION_SERVICE_CONSTANTS = [0, 1, 2, 4, 9, 10, 14, 16, 17, 18, 21, 30, 100, 0xffffffff]
    PROTOCOL_SEQUENCES = {s:s.encode("UTF-16-LE") + b"\x00\x00" for s in [
        "ncacn_nb_tcp", 
        "ncacn_nb_ipx",
        "ncacn_nb_nb",
        "ncacn_ip_tcp",
        "ncacn_np",
        "ncacn_spx",
        "ncacn_dnet_nsp",
        "ncacn_at_dsp",
        "ncacn_vns_spp",
        "ncadg_ip_udp",
        "ncadg_ipx",
        "ncadg_mq",
        "ncacn_http",
        "ncalrpc"
    ]}

    PROTSEQ_STRING_IDS = {
        "ncacn_ip_tcp": 1,
        "ncalrpc": 3,
        "ncacn_http": 4
    }

    def __init__(self):
        super().__init__()
        self.call_attributes = cast(SimStructValue, None)
        self.protseq_string = None
        self.initial_constraint_anno = RpcConstraint("initial")
        self.registration_constraint_anno = RpcConstraint("registration")

    @staticmethod
    def string_equals(symbolic_str:claripy.ast.BV, concrete_str:bytes):
        sym_str_size = symbolic_str.size()
        string_part = symbolic_str[sym_str_size-1:sym_str_size-8*len(concrete_str)]
        return string_part == concrete_str

    def set_state(self, state:angr.SimState):
        super().set_state(state)
        if self.call_attributes is not None:
            return

        solver = state.solver

        protseq_string_size = 8*max(len(s) for s in self.PROTOCOL_SEQUENCES.values())
        self.protseq_string = solver.BVS("ProtseqString", protseq_string_size)
        protseq_string_constraint = []
        for s in self.PROTOCOL_SEQUENCES.values():
            protseq_string_constraint.append(self.string_equals(self.protseq_string, s))
        
        protseq_string_constraint = claripy.Or(*protseq_string_constraint)
        
        call_attributes = create_symbolic_struct_value(RPC_CALL_ATTRIBUTES_V2_A, state.arch)
        self.call_attributes = call_attributes

        protseq_id = call_attributes.ProtocolSequence
        for protseq, id_ in self.PROTSEQ_STRING_IDS.items():
            protseq_id = solver.If(self.string_equals(self.protseq_string, self.PROTOCOL_SEQUENCES[protseq]), solver.BVV(id_, protseq_id.size()), protseq_id)

        constraints = (
            call_attributes.KernelModeCaller[31:1] == 0,
            call_attributes.NullSession[31:1] == 0,
            call_attributes.IsClientLocal >= 0, call_attributes.IsClientLocal <= 3,
            call_attributes.CallStatus >= 1, call_attributes.CallStatus <= 3,
            call_attributes.CallType >= 0, call_attributes.CallType <= 0,
            call_attributes.AuthenticationLevel >= 0, call_attributes.AuthenticationLevel <= 7,
            solver.Or(*[call_attributes.AuthenticationService == a for a in self.AUTHENTICATION_SERVICE_CONSTANTS]),
            protseq_string_constraint,
            call_attributes.IsClientLocal == solver.If(self.string_equals(self.protseq_string, self.PROTOCOL_SEQUENCES["ncalrpc"]), 1, call_attributes.IsClientLocal),
            self.call_attributes.ProtocolSequence == protseq_id,
            self.call_attributes.ProtocolSequence <= 4, self.call_attributes.ProtocolSequence >= 1
        )

        constraints = [c.annotate(self.initial_constraint_anno) for c in solver.simplify(solver.And(*constraints)).split("And")]
        state.add_constraints(*constraints)

    def copy(self, _memo):
        new_copy = super().copy(_memo)
        new_copy.call_attributes = self.call_attributes
        new_copy.initial_constraint_anno = self.initial_constraint_anno
        new_copy.protseq_string = self.protseq_string
        return new_copy

    def satisfiable(self, extra_constraints=None, **caller):
        if extra_constraints is None:
            extra_constraints = []

        extra_constraints = extra_constraints + [
            self.call_attributes[field] == value for field, value in caller.items()
        ]

        return self.state.solver.satisfiable(extra_constraints)

    @property
    def nonrpc_constraints(self):
        rpc_var_names = set()
        for field in ["protseq_string", *list(self.call_attributes.struct.fields)]:
            if field == "protseq_string":
                var = self.protseq_string
            else:
                var = self.call_attributes[field]
                if var.variables is None:
                    continue
                
            rpc_var_names.update(var.variables)

        return [c for c in self.state.solver.constraints if c.variables.isdisjoint(rpc_var_names)]

    def get_field_constraints(self, field:str, *, include_initial=False):
        if field == "protseq_string":
            field_val = self.protseq_string
        else:
            field_val = self.call_attributes[field]
        
        field_var = next(iter(field_val.variables))
        dependency_vars = {field_var}
        new_set = set()
        while len(dependency_vars) != len(new_set):
            dependency_vars.update(new_set)
            for c in self.state.solver.constraints:
                if not include_initial and self.initial_constraint_anno in c.annotations:
                    continue

                c_vars = c.variables
                if dependency_vars.isdisjoint(c_vars):
                    continue

                new_set.update(c_vars)
        
        return [c for c in self.state.solver.constraints \
            if self.initial_constraint_anno not in c.annotations and not dependency_vars.isdisjoint(c.variables)]

    @property
    def constrained_fields(self):
        fields = set()
        var_fields_dict = defaultdict(list)
        for field in self.call_attributes.struct.fields:
            val = self.call_attributes[field]
            if not isinstance(val, claripy.ast.BV):
                continue

            for v in val.variables:
                var_fields_dict[v].append(field)
        
        var_fields_dict[next(iter(self.protseq_string.variables))] = ["protseq_string"]

        for c in self.state.solver.constraints:
            if self.initial_constraint_anno in c.annotations:
                continue

            fields.update(*[var_fields_dict[k] for k in c.variables.intersection(var_fields_dict)])
        
        return fields

    def evaluate_callers(self, fields:Optional[Iterable[str]]=None, extra_constraints=None):
        if fields is None:
            fields = self.constrained_fields
        elif not fields:
            yield {}
            return
        
        constraints = [] if extra_constraints is None else extra_constraints.copy()
        solver = self.state.solver
        while solver.satisfiable(extra_constraints=constraints):
            possible_caller = {}
            current_constraints = []
            for field in fields:
                eval_constraints = constraints + current_constraints
                if field == "protseq_string":
                    val_bytes = solver.eval(self.protseq_string, extra_constraints=eval_constraints, cast_to=bytes)
                    val_byte_part = val_bytes[:val_bytes.find(b"\x00\x00")+1]
                    val = val_byte_part.decode("UTF-16-LE", "replace")
                    current_constraints.append(self.string_equals(self.protseq_string, val_byte_part))
                else:
                    field_var = self.call_attributes[field]
                    val = solver.eval(field_var, extra_constraints=eval_constraints)
                    current_constraints.append(field_var == val)

                possible_caller[field] = val
            
            constraints.append(solver.Not(solver.And(*current_constraints)))
            yield possible_caller


    def add_registration_constraints(self,
                                registration_flags:Optional[Iterable['RpcServerInterfaceFlags']]=None,
                                protocol_sequences:Optional[Iterable[str]]=None,
                                authentication_services:Optional[Iterable[int]]=None,
                                n_opnums=0
                            ):
        
        if not registration_flags or any(f is None for f in registration_flags):
            registration_flags = [None]

        if not protocol_sequences or any(p is None for p in protocol_sequences):
            protocol_sequences = [None]
        
        if not authentication_services or any(a is None for a in authentication_services):
            authentication_services = [None]
        
        solver = self.state.solver

        combinations = itertools.product(registration_flags, protocol_sequences, authentication_services)
        registration_constraints = []
        for registration_flags, protseq, auth_svc in combinations:
            current_constraints = []
            if registration_flags is not None:

                if not registration_flags.RPC_IF_ALLOW_CALLBACKS_WITH_NO_AUTH:
                    if registration_flags.RPC_IF_ALLOW_LOCAL_ONLY:
                        current_constraints.append(self.call_attributes.IsClientLocal == 1)
                        current_constraints.append(solver.Or(
                            self.string_equals(self.protseq_string, self.PROTOCOL_SEQUENCES["ncacn_np"]),
                            self.string_equals(self.protseq_string, self.PROTOCOL_SEQUENCES["ncalrpc"]),
                        ))

                    if registration_flags.RPC_IF_ALLOW_SECURE_ONLY:
                        current_constraints.append(self.call_attributes.AuthenticationLevel > 0)
                
            if protseq is not None:
                current_constraints.append(self.string_equals(self.protseq_string, self.PROTOCOL_SEQUENCES[protseq]))

            if auth_svc is not None:
                current_constraints.append(solver.Or(
                    self.call_attributes.AuthenticationService == auth_svc,
                    solver.And(
                        self.call_attributes.AuthenticationService == 0,
                        self.call_attributes.AuthenticationLevel == 0
                    )
                ))

            registration_constraints.append(solver.And(*current_constraints))

        registration_constraints = solver.simplify(solver.Or(*registration_constraints)).split("And")
        self.state.add_constraints(*[c.annotate(self.registration_constraint_anno) for c in registration_constraints])
        if n_opnums:
            self.state.add_constraints((self.call_attributes.OpNum < n_opnums).annotate(self.initial_constraint_anno))
        
