package bifrost.security

import future.keywords.contains
import future.keywords.if

# Block requests containing PII patterns
default allow = false

allow if {
	not contains_pii
}

contains_pii if {
	# SSN pattern: XXX-XX-XXXX
	regex.match(`\d{3}-\d{2}-\d{4}`, input.messages[_].content)
}

contains_pii if {
	# Credit card pattern
	regex.match(`\d{4}[-\s]?\d{4}[-\s]?\d{4}[-\s]?\d{4}`, input.messages[_].content)
}

contains_pii if {
	# Email pattern
	regex.match(`[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}`, input.messages[_].content)
}
