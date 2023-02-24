select(.analysis_result != null) | select(.analysis_result.interface_registration | any( 
    (.arguments.possible_clients[][] | .call_attributes | arrays | 
        any(.AuthenticationService % 10 == 0 ) | not))
) | objects