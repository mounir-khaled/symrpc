
from collections import defaultdict
import json
import claripy

from dataclasses import asdict, is_dataclass
from angr.sim_type import SimStructValue
from rpc_analysis import RpcServerInterface, RpcInterfacesAnalysis

class ValueTypeSorter(json.JSONEncoder):
    TYPE_KEYS = defaultdict(
        lambda: 100,
        {
            int: 0,
            str: 1,
            list: 2,
            dict: 3
        }
    )

    def encode(self, o):
        if isinstance(o, dict):
            o = dict(sorted(o.items(), key=lambda _, v: self.TYPE_KEYS[type(v)]))
        
        return super().encode(o)

class SetJsonEncoder(json.JSONEncoder):
    def default(self, o):
        if isinstance(o, (set, frozenset)):
            return list(o)
        
        return super().default(o)

class BytesToHexJsonEncoder(json.JSONEncoder):
    def default(self, o):
        if isinstance(o, bytes):
            return o.hex(' ')
        
        return super().default(o)

class SimStructJsonEncoder(json.JSONEncoder):
    def default(self, o):
        if isinstance(o, SimStructValue):
            return o._values

        return super().default(o)

class BvJsonEncoder(json.JSONEncoder):
    def default(self, o):
        if isinstance(o, (claripy.ast.BV, claripy.ast.bool.Bool)):
            json_encoded = {"bitvector": str(o)}
            if o.annotations:
                json_encoded["annotations"] = [str(a) for a in o.annotations]

            return json_encoded

        return super().default(o)

class RpcServerInterfaceJsonEncoder(json.JSONEncoder):
    def default(self, o):
        if isinstance(o, RpcServerInterface):
            return {
                "address": o.address,
                "uuid": o.uuid,
                "flags": o.flags,
                "procedure_addresses": 
                    [{"address": fn.addr, "name": fn.name} for fn in o.procedure_functions] 
                    if o.procedure_functions is not None else None,
                "struct_values": o.struct_values
            }

        return super().default(o)

class DataclassJsonEncoder(json.JSONEncoder):
    def default(self, o):
        if is_dataclass(o):
            return asdict(o)

        return super().default(o)

class RpcInterfaceAnalysisJsonEncoder(json.JSONEncoder):
    def _callsite_dict_to_list(self, cs_dict:dict[int]):
        return [{"callsite_address": cs, 'arguments': args} for cs, args in cs_dict.items()]

    def default(self, o):
        if not isinstance(o, RpcInterfacesAnalysis):
            return super().default(o)
        
        return {
            "interface_registration": self._callsite_dict_to_list(o.rpc_register_calls),
            "protseq_usage": self._callsite_dict_to_list(o.rpc_use_protseq_calls),
            "auth_registration": self._callsite_dict_to_list(o.rpc_register_auth_calls)
        }

class AnalysisResultJsonEncoder(
        RpcInterfaceAnalysisJsonEncoder, 
        RpcServerInterfaceJsonEncoder,
        DataclassJsonEncoder, 
        SimStructJsonEncoder, 
        BvJsonEncoder, 
        BytesToHexJsonEncoder,
        SetJsonEncoder,
        # ValueTypeSorter
    ):

    pass