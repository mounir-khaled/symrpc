import angr
import archinfo

from angr.sim_type import *

def create_symbolic_struct_value(struct:SimStruct, arch:archinfo.Arch, struct_name=""):
    values = {}
    struct = struct.with_arch(arch)
    # basic_types = tuple(set(type(t) for t in BASIC_TYPES.values()))
    for field, ty in struct.fields.items():
        ty = ty.with_arch(arch)
        field_name = field if struct_name is None else "%s.%s" % (struct_name, field)
        if isinstance(ty, SimStruct):
            val = create_symbolic_struct_value(ty, arch, field_name)
        elif isinstance(ty, SimTypeFixedSizeArray):
            val = [claripy.BVS("field_%d" % i, ty.elem_type.size) for i in range(ty.length)]
        else:
            val = claripy.BVS(field_name, ty.size)

        values[field] = val
    
    return SimStructValue(struct, values)

class SimTypeVoidPointer(SimTypePointer):
    def __init__(self, void_label=None, label=None, offset=0):
        super().__init__(SimTypeBottom(void_label), label, offset)

RPC_VERSION = SimStruct(
    {
        "MajorVersion": SimTypeNum(16, signed=False, label="USHORT"),
        "MinorVersion": SimTypeNum(16, signed=False, label="USHORT")
    },
    name="RPC_VERSION"
)

GUID = SimStruct(
    {
        "Data1": SimTypeInt(signed=False, label="ULONG"),
        "Data2": SimTypeNum(16, signed=False, label="USHORT"),
        "Data3": SimTypeNum(16, signed=False, label="USHORT"),
        "Data4": SimTypeFixedSizeArray(SimTypeChar(signed=False, label="UCHAR"), 8)
    },
    name="GUID"
)

RPC_SYNTAX_IDENTIFIER = SimStruct(
    {
        "SyntaxGUID": GUID,
        "SyntaxVersion": RPC_VERSION
    },
    name="RPC_SYNTAX_IDENTIFIER"
)

MIDL_STUB_DESC = SimStruct(
    {
        "RpcInterfaceInformation": SimTypeVoidPointer(),
        "pfnAllocate": SimTypeVoidPointer(),
        "pfnFree": SimTypeVoidPointer(),
        "IMPLICIT_HANDLE_INFO": SimStruct({
            "pAutoHandle": SimTypeVoidPointer("handle_t"),
            "pPrimitiveHandle": SimTypeVoidPointer("handle_t"),
            "pGenericBindingInfo": SimTypeVoidPointer(label="PGENERIC_BINDING_INFO"),
        }),
        "apfnNdrRundownRoutines": SimTypeVoidPointer("NDR_RUNDOWN"),
        "aGenericBindingRoutinePairs": SimTypeVoidPointer("GENERIC_BINDING_ROUTINE_PAIR"),
        "apfnExprEval": SimTypeVoidPointer("EXPR_EVAL"),
        "aXmitQuintuple": SimTypeVoidPointer("XMIT_ROUTINE_QUINTUPLE"),
        "pFormatTypes": SimTypePointer(SimTypeChar(signed=False)),
        "fCheckBounds": SimTypeInt(),
        "Version": SimTypeInt(signed=False),
        "pMallocFreeStruct": SimTypeVoidPointer("MALLOC_FREE_STRUCT"),
        "MIDLVersion": SimTypeInt(),
        "CommFaultOffsets": SimTypeVoidPointer("COMM_FAULT_OFFSETS"),
        "aUserMarshalQuadruple": SimTypeVoidPointer("USER_MARSHAL_ROUTINE_QUADRUPLE"),
        "NotifyRoutineTable": SimTypeVoidPointer("NDR_NOTIFY_ROUTINE"),
        "mFlags": SimTypePointer(SimTypeInt(signed=False)),
        "CsRoutineTables": SimTypeVoidPointer("NDR_CS_ROUTINES"),
        "ProxyServerInfo": SimTypeVoidPointer(),
        "pExprInfo": SimTypeVoidPointer("NDR_EXPR_DESC")
    },
    name="MIDL_STUB_DESC"
)

MIDL_SERVER_INFO = SimStruct(
    {
        "pStubDesc": SimTypePointer(MIDL_STUB_DESC),
        "DispatchTable": SimTypePointer(SimTypeVoidPointer("SERVER_ROUTINE")),
        "ProcString": SimTypeVoidPointer("FORMAT_STRING"),
        "FmtStringOffset": SimTypePointer(SimTypeNum(16, signed=False, label="USHORT")),
        "ThunkTable": SimTypeVoidPointer(),
        "pTransferSyntax": SimTypePointer(RPC_SYNTAX_IDENTIFIER),
        "nCount": SimTypeVoidPointer(), 
        "pSyntaxInfo": SimTypeVoidPointer()
    },
    name="MIDL_SERVER_INFO"
)

RPC_DISPATCH_TABLE = SimStruct(
    {
        "DispatchTableCount": SimTypeInt(signed=False),
        "DispatchTable": SimTypeVoidPointer("RPC_DISPATCH_FUNCTION"),
        "LONG_PTR": SimTypeVoidPointer()
    },
    name="RPC_DISPATCH_TABLE"
)

RPC_SERVER_INTERFACE = SimStruct(
    {
        "Length": SimTypeInt(signed=False, label="UINT"),
        "InterfaceId": RPC_SYNTAX_IDENTIFIER,
        "TransferSyntax": RPC_SYNTAX_IDENTIFIER,
        "DispatchTable": SimTypePointer(RPC_DISPATCH_TABLE),
        "RpcProtseqEndpointCount": SimTypeInt(signed=False, label="UINT"),
        "RpcProtseqEndpoint":  SimTypeVoidPointer("PRPC_PROTSEQ_ENDPOINT_T"),
        "DefaultManagerEpv":  SimTypeVoidPointer("RPC_MGR_EPV"),
        "InterpreterInfo":  SimTypePointer(MIDL_SERVER_INFO),
        "Flags": SimTypeInt(signed=False, label="UINT"),
    },
    name="RPC_SERVER_INTERFACE"
)

angr.types.register_types(GUID)

RPC_CALL_LOCAL_ADDRESS:SimStruct = angr.types.define_struct("""struct RPC_CALL_LOCAL_ADDRESS
                                                                {
                                                                    unsigned int Version;
                                                                    void *Buffer;
                                                                    unsigned int BufferSize;
                                                                    unsigned int AddressFormat;
                                                                }
                                                            """)

RPC_CALL_ATTRIBUTES_V1_A:SimStruct = angr.types.define_struct("""struct RPC_CALL_ATTRIBUTES_V1_A
                            {
                                unsigned int Version;
                                unsigned int Flags;
                                unsigned int ServerPrincipalNameBufferLength;
                                unsigned char *ServerPrincipalName;
                                unsigned int ClientPrincipalNameBufferLength;
                                unsigned char *ClientPrincipalName;
                                unsigned int AuthenticationLevel;
                                unsigned int AuthenticationService;
                                unsigned int NullSession;
                            }
                        """)

RPC_CALL_ATTRIBUTES_V2_A:SimStruct = angr.types.define_struct("""struct RPC_CALL_ATTRIBUTES_V2_A
                            {
                                unsigned int              Version;
                                unsigned int             Flags;
                                unsigned int             ServerPrincipalNameBufferLength;
                                unsigned char             * ServerPrincipalName;
                                unsigned int             ClientPrincipalNameBufferLength;
                                unsigned char             * ClientPrincipalName;
                                unsigned int             AuthenticationLevel;
                                unsigned int             AuthenticationService;
                                unsigned int              NullSession;
                                unsigned int              KernelModeCaller;
                                unsigned int             ProtocolSequence;
                                unsigned int             IsClientLocal;
                                void                      * ClientPID;
                                unsigned int             CallStatus;
                                unsigned int              CallType;
                                struct RPC_CALL_LOCAL_ADDRESS * CallLocalAddress;
                                unsigned short            OpNum;
                                struct GUID               InterfaceUuid;
                            }
                        """)
