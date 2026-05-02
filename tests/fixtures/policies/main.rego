package bifrost.security

import future.keywords.contains
import future.keywords.if

# Main policy for integration testing
default allow = false

# Allow if no violations detected
allow if {
	not contains_pii
	not suspicious_patterns
}

# PII Detection
contains_pii if {
	regex.match(`\d{3}-\d{2}-\d{4}`, input.messages[_].content)
}

contains_pii if {
	regex.match(`\d{4}[-\s]?\d{4}[-\s]?\d{4}[-\s]?\d{4}`, input.messages[_].content)
}

# Suspicious patterns (basic prompt injection indicators)
suspicious_patterns if {
	lower(input.messages[_].content) contains "ignore previous"
}

suspicious_patterns if {
	lower(input.messages[_].content) contains "disregard all"
}

suspicious_patterns if {
	lower(input.messages[_].content) contains "reveal secrets"
}

# Helper function
lower(s) = result {
	result := lower(s)
}
