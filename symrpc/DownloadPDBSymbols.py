
# -*- coding: utf-8 -*-
# File name          : DownloadPDBSymbols.py
# Author             : Podalirius (@podalirius_)
# Date created       : 8 Feb 2022

import binascii
import os
import pefile
import argparse
import requests
from rich import progress


VERSION = "1.1"


def download_pdb(download_dir, pdbname, guid, pdbage, verbose=False):
    download_url = "https://msdl.microsoft.com/download/symbols/%s/%s/%s" % (pdbname, guid.upper(), pdbname)
    print("[>] Downloading %s" % download_url)
    r = requests.head(
        download_url,
        headers={"User-Agent": "Microsoft-Symbol-Server/10.0.10036.206"},
        allow_redirects=True
    )
    if r.status_code == 200:
        target_file = download_dir + os.path.sep + pdbname
        with progress.Progress() as p:
            progress_bar, csize = p.add_task("[cyan]Downloading %s" % pdbname, total=int(r.headers["Content-Length"])), 1024*16
            pdb = requests.get(r.url, headers={"User-Agent": "Microsoft-Symbol-Server/10.0.10036.206"}, stream=True)
            with open(target_file, "wb") as f:
                for chunk in pdb.iter_content(chunk_size=csize):
                    f.write(chunk)
                    p.update(progress_bar, advance=len(chunk))
    else:
        print("[!] (HTTP %d) Could not find %s " % (r.status_code, download_url))


def get_pe_debug_infos(pathtopefile):
    p = pefile.PE(pathtopefile, fast_load=False)
    pedata = {d.name: d for d in p.OPTIONAL_HEADER.DATA_DIRECTORY}
    raw_debug_data = [e for e in p.parse_debug_directory(pedata["IMAGE_DIRECTORY_ENTRY_DEBUG"].VirtualAddress, pedata["IMAGE_DIRECTORY_ENTRY_DEBUG"].Size) if e.entry is not None]
    raw_debug_data = raw_debug_data[0].entry

    guid = raw_debug_data.Signature_String
    return raw_debug_data.PdbFileName.strip(b'\x00').decode("utf-8"), guid, raw_debug_data.Age


def parseArgs():
    print("DownloadPDBSymbols v%s - by @podalirius_\n" % VERSION)
    
    parser = argparse.ArgumentParser(description="A Python script to download PDB files associated with a Portable Executable (PE).")

    group_pesource = parser.add_mutually_exclusive_group(required=True)
    group_pesource.add_argument("-f", "--pe-file", default=None, help='')
    group_pesource.add_argument("-d", "--pe-dir", default=None, help='')

    parser.add_argument("-S", "--symbols-dir", default="./symbols/", required=False, help='Output dir where symbols will be downloaded.')
    parser.add_argument("-v", "--verbose", default=False, action="store_true", help='Verbose mode. (default: False)')
    return parser.parse_args()


if __name__ == '__main__':
    options = parseArgs()

    if not os.path.exists(options.symbols_dir):
        if options.verbose:
            print("[>] Creating '%s'" % options.symbols_dir)
        os.makedirs(options.symbols_dir, exist_ok=True)

    if options.pe_dir is not None:
        list_of_pe_files = []

        if options.verbose:
            print("[debug] Searching for PE files in '%s' ..." % options.pe_dir)
        for root, dirs, files in os.walk(options.pe_dir):
            for filepath in files:
                if filepath.lower().endswith(".exe") or filepath.lower().endswith(".dll"):
                    name = os.path.join(root, filepath)
                    list_of_pe_files.append(name)

        for pef in list_of_pe_files:
            if options.verbose:
                print("[>] Reading PE file '%s'" % pef)
            pdbname, guid, pdbage = get_pe_debug_infos(pef)
            if options.verbose:
                print("  | PdbName '%s'" % pdbname)
                print("  | GUID    %s" % guid)
                print("  | Age     0x%x" % pdbage)
            download_pdb(options.symbols_dir, pdbname, guid, pdbage)

    elif options.pe_file is not None:
        if options.verbose:
            print("[>] Reading PE file '%s'" % options.pe_file)
        pdbname, guid, pdbage = get_pe_debug_infos(options.pe_file)
        if options.verbose:
            print("  | PdbName '%s'" % pdbname)
            print("  | GUID    %s" % guid)
            print("  | Age     0x%x" % pdbage)
        download_pdb(options.symbols_dir, pdbname, guid, pdbage)

