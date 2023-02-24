Some queries written in jq to find interesting targets. Usage example:

Find all RPC services that allow remote clients:
```
cat ./reports/*/rpc_server_info.json | jq -f .\results_analysis_scripts\find_remote.jq | jq .analysis_metadata
```