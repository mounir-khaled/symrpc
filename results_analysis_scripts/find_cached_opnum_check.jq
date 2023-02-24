select(.analysis_result != null) | select(.analysis_result.interface_registration | any( 
    (.arguments.Flags | arrays | any(.RPC_IF_SEC_CACHE_PER_PROC == false and .RPC_IF_SEC_NO_CACHE == false)) 
    and 
    (.arguments.possible_callers | arrays | any(.OpNum != null))
)
) | objects | .analysis_metadata