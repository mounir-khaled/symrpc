

import json
import logging
import os

import angr

from ctypes import *

from rpc_analysis import RpcInterfacesAnalysis
from angrcache import AngrProjectCache

from analysis_json_encoder import AnalysisResultJsonEncoder

from DownloadPDBSymbols import get_pe_debug_infos, download_pdb

log = logging.getLogger(__name__)


class SYMBOL_INFO(Structure):
        _fields_ = [
        ( 'SizeOfStruct', c_ulong ),
        ( 'TypeIndex', c_ulong ),
        ( 'Reserved', c_ulonglong * 2 ),
        ( 'Index', c_ulong ),
        ( 'Size', c_ulong ),
        ( 'ModBase', c_ulonglong ),
        ( 'Flags', c_ulong ),
        ( 'Value', c_ulonglong ),
        ( 'Address', c_ulonglong ),
        ( 'Register', c_ulong ),
        ( 'Scope', c_ulong ),
        ( 'Tag' , c_ulong ),
        ( 'NameLen', c_ulong ),
        ( 'MaxNameLen', c_ulong ),
        ( 'Name', c_char * 2001 )
    ]   


def import_symbols(p:angr.Project, pdb_path:str):
    @CFUNCTYPE(c_bool, POINTER(SYMBOL_INFO), c_ulong, py_object)
    def sym_cb(pSymInfo, SymbolSize:int, p:angr.Project):
        sinfo = pSymInfo.contents
        main_obj = p.loader.main_object
        mapped_address = main_obj.mapped_base + (sinfo.Address - sinfo.ModBase)
        try:
            fn = p.kb.functions.get_by_addr(mapped_address)
            fn.name = sinfo.Name.decode("ascii")
        except KeyError:
            pass

    dbghelp = windll.dbghelp
    k32 = windll.kernel32

    pid = os.getpid()
    hproc = k32.OpenProcess(0x000F0000 | 0x00100000 | 0xFFFF, 1, pid)
    
    dbghelp.SymInitialize(hproc, pdb_path.encode("ascii"), 1)

    obj_size=p.loader.main_object.max_addr - p.loader.main_object.min_addr

    dbghelp.SymLoadModule.restype = c_ulong
    dbghelp.SymLoadModule.argtypes=[c_int, c_int, c_char_p, c_char_p, c_ulong, c_ulong]
    # base = dbghelp.SymLoadModule(hproc, 0, pdb_path.encode("ascii"), None, p.loader.main_object.mapped_base, obj_size)
    base = dbghelp.SymLoadModule(hproc, 0, pdb_path.encode("ascii"), None, p.loader.main_object.mapped_base, obj_size)
    
    dbghelp.SymEnumSymbols(hproc, c_ulonglong(base), None, sym_cb, py_object(p))

    dbghelp.SymCleanup(hproc)
    k32.CloseHandle(hproc)

def find_and_load_symbols(p:angr.Project, symbols_dir):
    dll_path = p.filename
    pdb_name, guid, pdb_age = get_pe_debug_infos(dll_path)
    pdb_path = os.path.join(symbols_dir, pdb_name, guid, pdb_name)
    if not os.path.exists(pdb_path):
        pdb_dir = os.path.dirname(pdb_path)
        os.makedirs(pdb_dir, exist_ok=True)
        download_pdb(pdb_dir, pdb_name, guid, pdb_age)
    
    import_symbols(p, pdb_path)



def analyze_service(cache_filename, service_binpath, output_dir="./reports/", symbols_dir="", is_in_service_group=False):
    metadata = {}
    metadata["binpath"] = service_binpath
    with AngrProjectCache(cache_filename) as cache:
        metadata["is_cached"] = cache.is_cached(service_binpath)
        
        try:
            p = cache.create_if_not_cached(
                service_binpath, 
                auto_load_libs=False
            )
        except Exception as e:
            log.exception("Failed to load project from cache")
            p = angr.Project(service_binpath, auto_load_libs=False)

        p.selfmodifying_code = False

        if not any(
                import_name.startswith("RpcServerRegisterIf") 
                    for import_name in p.loader.main_object.imports
                ):
            
            cache.cache_project(service_binpath, p)
            return

        if symbols_dir:
            try:
                find_and_load_symbols(p, symbols_dir)
            except Exception:
                log.error("Failed to import symbols for project %s", p, exc_info=True)

        if not "CFGFast" in p.kb.cfgs:
            log.info("Building CFG...")
            p.analyses.CFG()
            cache.cache_project(service_binpath, p)
        
        for fn in p.kb.functions.values():
            fn._project = p

        log.info("Starting analysis")
        rpc_ifs:RpcInterfacesAnalysis = p.analyses.RpcInterfaces(coerce_argument_values=True, is_multiplexed=is_in_service_group)
    
    if rpc_ifs.rpc_register_calls:
        os.makedirs(output_dir, exist_ok=True)

        rpc_info_filepath = os.path.join(output_dir, "rpc_server_info.json")
        with open(rpc_info_filepath, 'w') as f:
            json.dump({"analysis_result": rpc_ifs}, f, indent=2, cls=AnalysisResultJsonEncoder, sort_keys=True)

