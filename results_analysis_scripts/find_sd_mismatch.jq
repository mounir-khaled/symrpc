select(.analysis_result != null) | select(([.analysis_result.protseq_usage[] | .arguments.SecurityDescriptor] | unique | length) != 1) | {"metadata": .analysis_metadata, "protseq_usage": .analysis_result.protseq_usage}