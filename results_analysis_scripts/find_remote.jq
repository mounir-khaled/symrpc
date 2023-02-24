select(.analysis_result != null) | select(.analysis_result.interface_registration | any( 
    (.arguments.possible_clients[][] | .call_attributes | arrays | 
        any((.IsClientLocal == 1 or .protseq_string == "ncalrpc") | not))
)) | objects