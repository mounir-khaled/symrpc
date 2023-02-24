
# SymRPC

## Usage

```
symrpc.py [-h] [-t TIMEOUT] [-s SERVICES [SERVICES ...]] [-r REPORT_DIR] [-c CACHE_NAME] [-l LOGGING_LEVEL] [-e]
                 [-p SYMBOLS_DIR]

Statically enumerate RPC interfaces of Windows services

optional arguments:
  -h, --help            show this help message and exit
  -t TIMEOUT, --timeout TIMEOUT
                        Timeout for analyzing each service (default: 0; no timeout)
  -s SERVICES [SERVICES ...], --services SERVICES [SERVICES ...]
                        Service name(s) or path(s) to analyze (default: all)
  -r REPORT_DIR, --report-dir REPORT_DIR
                        Directory to store analysis results (default: reports)
  -c CACHE_NAME, --cache-name CACHE_NAME
                        Path to store cached analysis results (default: projectcache\cache)
  -l LOGGING_LEVEL, --logging-level LOGGING_LEVEL
                        Logging level (default: INFO)
  -e, --symexec         Symbolically execute interface callbacks
  -p SYMBOLS_DIR, --symbols-dir SYMBOLS_DIR
```

---
   Copyright 2023 Mounir Elgharabawy

   Licensed under the Apache License, Version 2.0 (the "License");
   you may not use this file except in compliance with the License.
   You may obtain a copy of the License at

       http://www.apache.org/licenses/LICENSE-2.0

   Unless required by applicable law or agreed to in writing, software
   distributed under the License is distributed on an "AS IS" BASIS,
   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
   See the License for the specific language governing permissions and
   limitations under the License.