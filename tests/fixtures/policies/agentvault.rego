package agentvault

import future.keywords.contains
import future.keywords.if
import future.keywords.in

default decision := {
  "action": "allow",
  "allowed": true,
  "risk": "low",
  "score": 0,
  "reason": "none",
  "violations": [],
}

score_candidates contains 0 if { true }

has_allowed_action(action) if {
  some allowed in input.signals.auth.allowed_actions
  allowed == action
}

has_allowed_data_object(obj) if {
  some allowed in input.signals.auth.allowed_data_objects
  allowed == obj
}

contains_sensitive_object if {
  some obj in input.signals.intent.data_objects
  obj == "credentials"
}

contains_sensitive_object if {
  some obj in input.signals.intent.data_objects
  obj == "government_ids"
}

contains_sensitive_object if {
  some obj in input.signals.intent.data_objects
  obj == "payroll"
}

contains_sensitive_object if {
  some obj in input.signals.intent.data_objects
  obj == "system_internals"
}

contains_disallowed_data_object if {
  some obj in input.signals.intent.data_objects
  not has_allowed_data_object(obj)
}

privileged_sensitive_transfer if {
  input.signals.auth.can_send_external
  input.signals.auth.can_access_sensitive_data
  input.signals.auth.approved
}

violations contains {"type": "prompt_injection", "reason": "prompt_injection", "layer": "opa"} if {
  input.signals.prompt_injection
}
score_candidates contains 95 if { input.signals.prompt_injection }

violations contains {"type": "memory_context_poisoning", "reason": "untrusted_context_influence", "layer": "opa"} if {
  input.signals.context.poisoned
}
score_candidates contains 91 if { input.signals.context.poisoned }

violations contains {"type": "untrusted_context", "reason": "instructional_untrusted_context", "layer": "opa"} if {
  input.signals.context.risky_instructional_count > 0
}
score_candidates contains 89 if { input.signals.context.risky_instructional_count > 0 }

violations contains {"type": "agent_goal_hijack", "reason": "goal_scope_change", "layer": "opa"} if {
  input.signals.intent.goal_scope_change
}
score_candidates contains 88 if { input.signals.intent.goal_scope_change }

violations contains {"type": "identity_privilege_abuse", "reason": "action_not_permitted", "layer": "opa"} if {
  input.signals.intent.high_impact_action
  not has_allowed_action(input.signals.intent.requested_action)
}
score_candidates contains 89 if {
  input.signals.intent.high_impact_action
  not has_allowed_action(input.signals.intent.requested_action)
}

violations contains {"type": "identity_privilege_abuse", "reason": "external_delivery_not_permitted", "layer": "opa"} if {
  input.signals.intent.requested_action == "external_delivery"
  not input.signals.auth.can_send_external
}
score_candidates contains 90 if {
  input.signals.intent.requested_action == "external_delivery"
  not input.signals.auth.can_send_external
}

violations contains {"type": "identity_privilege_abuse", "reason": "code_execution_not_permitted", "layer": "opa"} if {
  input.signals.intent.requested_action == "code_execution"
  not input.signals.auth.can_execute_code
}
score_candidates contains 92 if {
  input.signals.intent.requested_action == "code_execution"
  not input.signals.auth.can_execute_code
}

violations contains {"type": "identity_privilege_abuse", "reason": "destructive_change_not_permitted", "layer": "opa"} if {
  input.signals.intent.destructive_action
  not input.signals.auth.can_mutate_state
}
score_candidates contains 90 if {
  input.signals.intent.destructive_action
  not input.signals.auth.can_mutate_state
}

violations contains {"type": "identity_privilege_abuse", "reason": "sensitive_data_not_permitted", "layer": "opa"} if {
  contains_sensitive_object
  input.signals.intent.high_impact_action
  not input.signals.auth.can_access_sensitive_data
}
score_candidates contains 90 if {
  contains_sensitive_object
  input.signals.intent.high_impact_action
  not input.signals.auth.can_access_sensitive_data
}

violations contains {"type": "identity_privilege_abuse", "reason": "data_scope_not_permitted", "layer": "opa"} if {
  count(input.signals.intent.data_objects) > 0
  input.signals.intent.high_impact_action
  contains_disallowed_data_object
  input.signals.auth.actor_role != "admin"
}
score_candidates contains 88 if {
  count(input.signals.intent.data_objects) > 0
  input.signals.intent.high_impact_action
  contains_disallowed_data_object
  input.signals.auth.actor_role != "admin"
}

violations contains {"type": "identity_privilege_abuse", "reason": "approval_required", "layer": "opa"} if {
  input.signals.intent.requires_human_approval
  not input.signals.auth.approved
}
score_candidates contains 86 if {
  input.signals.intent.requires_human_approval
  not input.signals.auth.approved
}

violations contains {"type": "blocked_term", "reason": "policy_violation", "layer": "opa"} if {
  count(input.signals.blocked_terms) > 0
}
score_candidates contains 85 if { count(input.signals.blocked_terms) > 0 }

violations contains {"type": "resource_abuse", "reason": "resource_abuse", "layer": "opa"} if {
  input.signals.resource_abuse
}
score_candidates contains 90 if { input.signals.resource_abuse }

violations contains {"type": "instruction_smuggling", "reason": "encoded_instruction_smuggling", "layer": "opa"} if {
  input.signals.encoded_instruction
}
score_candidates contains 89 if { input.signals.encoded_instruction }

violations contains {"type": "tool_misuse", "reason": "tool_call_smuggling", "layer": "opa"} if {
  input.signals.tool_call_smuggling
  input.signals.external_destination
}
violations contains {"type": "tool_misuse", "reason": "tool_call_smuggling", "layer": "opa"} if {
  input.signals.tool_call_smuggling
  input.signals.sensitive_domain
}
violations contains {"type": "tool_misuse", "reason": "tool_call_smuggling", "layer": "opa"} if {
  input.signals.tool_call_smuggling
  input.signals.bulk_data_request
}
score_candidates contains 88 if {
  input.signals.tool_call_smuggling
  input.signals.external_destination
}
score_candidates contains 88 if {
  input.signals.tool_call_smuggling
  input.signals.sensitive_domain
}
score_candidates contains 88 if {
  input.signals.tool_call_smuggling
  input.signals.bulk_data_request
}

violations contains {"type": "tool_misuse", "reason": "browser_action_hijack", "layer": "opa"} if {
  input.signals.browser_action
  input.signals.external_destination
}
violations contains {"type": "tool_misuse", "reason": "browser_action_hijack", "layer": "opa"} if {
  input.signals.browser_action
  input.signals.sensitive_domain
}
score_candidates contains 86 if {
  input.signals.browser_action
  input.signals.external_destination
}
score_candidates contains 86 if {
  input.signals.browser_action
  input.signals.sensitive_domain
}

violations contains {"type": "identity_privilege_abuse", "reason": "oauth_consent_abuse", "layer": "opa"} if {
  input.signals.oauth_consent
}
score_candidates contains 87 if { input.signals.oauth_consent }

violations contains {"type": "instruction_smuggling", "reason": "multilingual_instruction_smuggling", "layer": "opa"} if {
  input.signals.multilingual_instruction
  input.signals.intent.high_impact_action
}
violations contains {"type": "instruction_smuggling", "reason": "multilingual_instruction_smuggling", "layer": "opa"} if {
  input.signals.multilingual_instruction
  input.signals.sensitive_domain
}
score_candidates contains 86 if {
  input.signals.multilingual_instruction
  input.signals.intent.high_impact_action
}
score_candidates contains 86 if {
  input.signals.multilingual_instruction
  input.signals.sensitive_domain
}

violations contains {"type": "tool_misuse", "reason": "private_network_fetch", "layer": "opa"} if {
  input.signals.private_network_destination
}
score_candidates contains 88 if { input.signals.private_network_destination }

violations contains {"type": "tool_misuse", "reason": "approval_bypass_attempt", "layer": "opa"} if {
  input.signals.intent.approval_bypass_attempt
  input.signals.intent.requires_human_approval
}
score_candidates contains 87 if {
  input.signals.intent.approval_bypass_attempt
  input.signals.intent.requires_human_approval
}

violations contains {"type": "tool_misuse", "reason": "unexpected_code_execution", "layer": "opa"} if {
  input.signals.intent.requested_action == "code_execution"
}
score_candidates contains 92 if { input.signals.intent.requested_action == "code_execution" }

violations contains {"type": "tool_misuse", "reason": "destructive_tool_misuse", "layer": "opa"} if {
  input.signals.intent.destructive_action
  input.signals.intent.requires_human_approval
}
score_candidates contains 90 if {
  input.signals.intent.destructive_action
  input.signals.intent.requires_human_approval
}

violations contains {"type": "unsafe_output_handling", "reason": "unsafe_html_write", "layer": "opa"} if {
  input.signals.unsafe_html
  input.signals.write_action
}
score_candidates contains 85 if {
  input.signals.unsafe_html
  input.signals.write_action
}

violations contains {"type": "data_exfiltration", "reason": "external_sensitive_transfer", "layer": "opa"} if {
  input.signals.external_destination
  input.signals.write_action
  input.signals.bulk_data_request
  not privileged_sensitive_transfer
}
score_candidates contains 90 if {
  input.signals.external_destination
  input.signals.write_action
  input.signals.bulk_data_request
  not privileged_sensitive_transfer
}

violations contains {"type": "data_exfiltration", "reason": "external_sensitive_transfer", "layer": "opa"} if {
  input.signals.external_destination
  input.signals.write_action
  input.signals.sensitive_domain
  not privileged_sensitive_transfer
}
score_candidates contains 90 if {
  input.signals.external_destination
  input.signals.write_action
  input.signals.sensitive_domain
  not privileged_sensitive_transfer
}

violations contains {"type": "data_exfiltration", "reason": "external_sensitive_transfer", "layer": "opa"} if {
  input.signals.external_destination
  input.signals.write_action
  input.signals.presidio.has_pii
  not privileged_sensitive_transfer
}
score_candidates contains 90 if {
  input.signals.external_destination
  input.signals.write_action
  input.signals.presidio.has_pii
  not privileged_sensitive_transfer
}

violations contains {"type": "social_engineering", "reason": "coerced_sensitive_transfer", "layer": "opa"} if {
  input.signals.social_engineering
  input.signals.external_destination
  input.signals.sensitive_domain
}
score_candidates contains 80 if {
  input.signals.social_engineering
  input.signals.external_destination
  input.signals.sensitive_domain
}

deny if { count(violations) > 0 }

violation_reasons := [v.reason | some v in violations]

score := max(score_candidates)

risk := "critical" if {
  score >= 90
}
risk := "high" if {
  score >= 70
  score < 90
}
risk := "medium" if {
  score >= 35
  score < 70
}
risk := "low" if {
  score < 35
}

action := "block" if { deny }
action := "scrub" if {
  not deny
  input.signals.presidio.has_pii
}
action := "allow" if {
  not deny
  not input.signals.presidio.has_pii
}

allowed := false if { deny }
allowed := true if { not deny }

reason := violation_reasons[0] if {
  deny
  count(violation_reasons) > 0
}
reason := "pii_redaction_required" if {
  not deny
  input.signals.presidio.has_pii
}
reason := "none" if {
  not deny
  not input.signals.presidio.has_pii
}

decision := {
  "action": action,
  "allowed": allowed,
  "risk": risk,
  "score": score,
  "reason": reason,
  "violations": violations,
}
