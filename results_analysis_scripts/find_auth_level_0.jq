select(.analysis_result != null) | select(.analysis_result.interface_registration | any( 
    (.arguments.possible_clients[][] | .call_attributes | arrays | 
        any(.AuthenticationLevel == 0) ))
) | objects

# https://github.com/fortra/impacket/pull/857