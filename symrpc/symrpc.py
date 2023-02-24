
import csv
import logging
import os
from typing import Any, Iterable, List, Mapping, Optional, Sequence, Union
import psutil
import argparse
import time
import winreg
import json
import ctypes

import multiprocessing
from psutil._pswindows import WindowsService

from analyze_service import analyze_service

log = logging.getLogger(__name__)

def get_service_binpath(service:WindowsService):
    service_argv = win_CommandLineToArgvW(service.binpath())
    service_binpath = service_argv[0].lower()
    service_args = service_argv[1:]

    if os.path.basename(service_binpath).lower() == "svchost.exe" and "-k" in service_args:
        
        try:
            reg_key =  "SYSTEM\\CurrentControlSet\\Services\\%s\\Parameters" % service.name()
            reg_key = winreg.OpenKeyEx(winreg.HKEY_LOCAL_MACHINE, reg_key)
            service_binpath, t = winreg.QueryValueEx(reg_key, "ServiceDll")
            service_binpath = service_binpath.lower().replace(r"%systemroot%", os.getenv("systemroot"))
        except FileNotFoundError:
            raise NotImplementedError("Unsupported service type")

    return service_binpath

def win_CommandLineToArgvW(cmd:str):
    """ https://stackoverflow.com/questions/33560364/python-windows-parsing-command-lines-with-shlex """
    nargs = ctypes.c_int()
    ctypes.windll.shell32.CommandLineToArgvW.restype = ctypes.POINTER(ctypes.c_wchar_p)
    lpargs = ctypes.windll.shell32.CommandLineToArgvW(cmd, ctypes.byref(nargs))
    args = [lpargs[i] for i in range(nargs.value)]
    if ctypes.windll.kernel32.LocalFree(lpargs):
        raise OSError()
    return args


def analyze_all_services(cache_filename, report_dir="reports", timeout=0, services=None, symexec=False, symbols_dir=""):
    blacklist = set()
    os.makedirs(report_dir, exist_ok=True)

    if services is None:
        services = psutil.win_service_iter()
    elif not services:
        return
    else:
        service_names = set(services)
        services:Iterable[WindowsService] = (psutil.win_service_get(s) for s in service_names)

    for service in services:
        try:
            service_binpath = get_service_binpath(service)
        except NotImplementedError:
            log.error("Failed to find binary path for service %s", service.name())
            continue

        if service_binpath in blacklist:
            continue

        blacklist.add(service_binpath)
        log.info("Loading service: %s (%s)", service.name(), service_binpath)

        start_time = time.time()
        p = None
        output_dir = os.path.join(report_dir, os.path.basename(service_binpath))
        os.makedirs(output_dir, exist_ok=True)
        try:
            if timeout:
                p = multiprocessing.Process(target=analyze_service, args=(cache_filename, service_binpath, output_dir, symbols_dir), daemon=True)
                p.start()
                p.join(timeout)

            else:
                analyze_service(cache_filename, service_binpath, output_dir, symbols_dir)

        except KeyboardInterrupt:
            log.info("Analysis interrupted with KeyboardInterrupt", exc_info=True)
            try:
                termination_reason = "INTERRUPT"
                print("Hit Ctrl+C to stop analysis...")
                time.sleep(3)
            except KeyboardInterrupt:
                log.info("Quitting...")
                return

        except Exception:
            log.error("Exception occurred while analyzing service", exc_info=True)
            termination_reason = "ERROR"

        else:
            if timeout and p is not None and p.is_alive():
                log.error("Timeout analyzing service: %s (%s)", service.name(), service_binpath)
                termination_reason = "TIMEOUT"
            else:
                log.info("Done analyzing service: %s (%s)", service.name(), service_binpath)
                termination_reason = "SUCCESS"

        finally:
            if p is not None and p.is_alive():
                p.terminate()
                p.join()
            
            time_taken = time.time() - start_time

            analysis_metadata = {   
                "name": service.name(), 
                "filepath": service_binpath, 
                "time": time_taken, 
                "termination_reason": termination_reason
            }
            
            result_filepath = os.path.join(output_dir, "rpc_server_info.json")
            result_dict = {"analysis_metadata": analysis_metadata}
            if os.path.exists(result_filepath):
                with open(result_filepath) as f:
                    analysis_result = json.load(f)

                result_dict.update(analysis_result)
                
            with open(result_filepath, 'w') as f:
                json.dump(result_dict, f, indent=2)

if __name__ == "__main__":
    logging.basicConfig()
    default_cache_path = os.path.join("projectcache", "cache")

    parser = argparse.ArgumentParser(description="Statically enumerate RPC interfaces of Windows services")
    parser.add_argument("-t", "--timeout", default=0, type=int, help="Timeout for analyzing each service (default: 0; no timeout)")
    parser.add_argument("-s", "--services", nargs="+", help="Service name(s) or path(s) to analyze (default: all)")
    parser.add_argument("-r", "--report-dir", default="reports", help="Directory to store analysis results (default: reports)")
    parser.add_argument("-c", "--cache-name", default=default_cache_path, help="Path to store cached analysis results (default: %s)" % default_cache_path)
    parser.add_argument("-l", "--logging-level", default="INFO", help="Logging level (default: INFO)")
    parser.add_argument("-p", "--symbols-dir", default="")

    args = parser.parse_args()

    log.setLevel(logging.getLevelName(args.logging_level))
    logging.getLogger("rpc_interface_analysis").setLevel(args.logging_level)
    analyze_all_services(args.cache_name, args.report_dir, args.timeout, args.services, True, args.symbols_dir)