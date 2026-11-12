package erasure

default decision := "reject"
default justification := []
default actions := {}

# -------------------------
# Bindings
# -------------------------
erasure := input.request.erasure
target_user_id := erasure.target_user_id
requester_user_id := erasure.user_id
requested_fields := erasure.fields

target_user := u if {
  u := input.users[_]
  u.id == target_user_id
}

# -------------------------
# Decision
# -------------------------
decision := "accept" if {
  valid_request
  reason_allows
  not exception_blocks
}

# -------------------------
# Justification (sets -> arrays -> concat)
# -------------------------
justification := js if {
  a := [x | x := req_validation_reasons[_]]
  b := [x | x := reason_reject_reasons[_]]
  c := [x | x := exception_reject_reasons[_]]
  js := array.concat(a, array.concat(b, c))
}

# -------------------------
# Actions
# -------------------------
actions := out if {
  base := {
    "log_audit": audit_event,
    "notify_storage_period_and_criteria": {
      "period": input.storage.period,
      "criteria": input.storage.criteria
    }
  }

  decision == "accept"

  accept_actions := {
    "delete": delete_plan,
    "notify_data_subject": {
      "decision": "accept",
      "request_id": erasure.request_id,
      "details": {"fields": erasure.fields}
    },
    "notify_third_parties": third_party_notifications
  }

  out := object.union(base, accept_actions)
} else := out if {
  base := {
    "log_audit": audit_event,
    "notify_storage_period_and_criteria": {
      "period": input.storage.period,
      "criteria": input.storage.criteria
    }
  }

  decision == "reject"

  reject_actions := {
    "notify_data_subject": {
      "decision": "reject",
      "request_id": erasure.request_id,
      "justification": justification
    }
  }

  out := object.union(base, reject_actions)
}

# =========================
# (1) Validate request
# =========================
valid_request if {
  erasure.user_id != ""
  erasure.target_user_id != ""
  erasure.request_id != ""
  count(erasure.fields) > 0
  requester_user_id == target_user_id
}

req_validation_reasons contains r if {
  not (erasure.user_id != "")
  r := "Missing erasure.user_id"
}

req_validation_reasons contains r if {
  not (erasure.target_user_id != "")
  r := "Missing erasure.target_user_id"
}

req_validation_reasons contains r if {
  not (erasure.request_id != "")
  r := "Missing erasure.request_id"
}

req_validation_reasons contains r if {
  not (count(erasure.fields) > 0)
  r := "No fields requested for erasure"
}

req_validation_reasons contains r if {
  erasure.user_id != ""
  erasure.target_user_id != ""
  erasure.user_id != erasure.target_user_id
  r := "Requester not authorized to erase another user's data"
}

# =========================
# (2) Reason checks
# =========================
reason_allows if { erasure.reason == "withdrawn_consent" }
reason_allows if { erasure.reason == "unlawfully_processed" }

reason_allows if {
  erasure.reason == "objection_processing"
  not processing_necessary_for_requested_fields
}

reason_allows if {
  erasure.reason == "purpose_updated"
  not all_fields_mapped_and_purpose_valid
}

supported_reason if { erasure.reason == "objection_processing" }
supported_reason if { erasure.reason == "withdrawn_consent" }
supported_reason if { erasure.reason == "unlawfully_processed" }
supported_reason if { erasure.reason == "purpose_updated" }

reason_reject_reasons contains r if {
  valid_request
  erasure.reason == "objection_processing"
  processing_necessary_for_requested_fields
  r := "Rejected: processing is necessary for the requested data."
}

reason_reject_reasons contains r if {
  valid_request
  erasure.reason == "purpose_updated"
  all_fields_mapped_and_purpose_valid
  r := "Rejected: data is mapped to a still-valid purpose."
}

reason_reject_reasons contains r if {
  valid_request
  not supported_reason
  r := sprintf("Rejected: unsupported erasure reason '%v'.", [erasure.reason])
}

# (2a)(i) necessary processing (no inline 'or')
processing_necessary_for_requested_fields if {
  fld := requested_fields[_]
  item := data_item_for_field(fld)
  item.purpose == "contract"
}

processing_necessary_for_requested_fields if {
  fld := requested_fields[_]
  item := data_item_for_field(fld)
  item.purpose == "legal_obligation"
}

# (2d)(i) purpose updated check
all_fields_mapped_and_purpose_valid if {
  not exists_invalid_purpose_mapping
}

exists_invalid_purpose_mapping if {
  fld := requested_fields[_]
  not field_mapped_to_valid_purpose(fld)
}

field_mapped_to_valid_purpose(field_name) if {
  item := data_item_for_field(field_name)
  item.purpose != ""
  check_expiry(item.purpose)
}

check_expiry(purpose) if {
  purpose == input.lawful_purposes[_]
}

# =========================
# (3) Exceptions override
# =========================
exception_blocks if { retention_required_legal_obligation }
exception_blocks if { retention_required_public_interest }
exception_blocks if { retention_required_legal_claims }

retention_required_legal_obligation if {
  fld := requested_fields[_]
  fld == input.exceptions.legal_obligation[_]
}

retention_required_public_interest if {
  fld := requested_fields[_]
  fld == input.exceptions.public_interest[_]
}

retention_required_legal_claims if {
  fld := requested_fields[_]
  fld == input.exceptions.legal_claims[_]
}

exception_reject_reasons contains r if {
  valid_request
  reason_allows
  retention_required_legal_obligation
  r := "Rejected: retention required by legal obligation."
}

exception_reject_reasons contains r if {
  valid_request
  reason_allows
  retention_required_public_interest
  r := "Rejected: retention required for public interest."
}

exception_reject_reasons contains r if {
  valid_request
  reason_allows
  retention_required_legal_claims
  r := "Rejected: retention needed to defend legal claims."
}

# =========================
# (6) Audit event
# =========================
audit_event := {
  "type": "erasure_request",
  "request_id": erasure.request_id,
  "requester_user_id": requester_user_id,
  "target_user_id": target_user_id,
  "reason": erasure.reason,
  "fields": erasure.fields,
  "decision": decision,
  "justification": justification
}

# =========================
# (7) Third party notifications
# =========================
third_party_notifications := notes if {
  decision == "accept"
  notes := [n |
    tp := input.third_parties[_]
    n := {
      "third_party_id": tp.id,
      "third_party_name": tp.name,
      "request_id": erasure.request_id,
      "target_user_id": target_user_id,
      "fields": erasure.fields
    }
  ]
} else := [] if {
  decision != "accept"
}

# =========================
# Delete plan
# =========================
delete_plan := plan if {
  decision == "accept"
  plan := {
    "target_user_id": target_user_id,
    "fields": [x | x := requested_fields[_]]
  }
} else := {} if {
  decision != "accept"
}

data_item_for_field(field_name) := item if {
  item := target_user.data_items[_]
  item.field == field_name
}
