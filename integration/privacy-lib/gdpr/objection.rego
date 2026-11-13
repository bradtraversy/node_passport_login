package objection

default decision := "reject"
default actions := {}
default justification := []

# -------------------------
# Bindings
# -------------------------
objection := input.request.objection

target_user_id := objection.target_user_id
requester_user_id := objection.user_id
requested_fields := objection.fields

target_user := u if {
  u := input.users[_]
  u.id == target_user_id
}

# -------------------------
# (1) Validate request from user
# -------------------------
valid_request if {
  objection.user_id != ""
  objection.target_user_id != ""
  objection.request_id != ""
  count(objection.fields) > 0

  # self-only (same model as your other rights)
  requester_user_id == target_user_id
}

validation_reasons contains r if {
  not (objection.user_id != "")
  r := "Missing objection.user_id"
}
validation_reasons contains r if {
  not (objection.target_user_id != "")
  r := "Missing objection.target_user_id"
}
validation_reasons contains r if {
  not (objection.request_id != "")
  r := "Missing objection.request_id"
}
validation_reasons contains r if {
  not (count(objection.fields) > 0)
  r := "No fields requested for objection"
}
validation_reasons contains r if {
  objection.user_id != ""
  objection.target_user_id != ""
  objection.user_id != objection.target_user_id
  r := "Requester not authorized to object for another user"
}

# -------------------------
# (2) Identify purpose and legal basis of processing for specified data
# (purpose = data_item.purpose; legal_basis derived from purpose)
# -------------------------
present_processing_context := ctx if {
  ctx := [{
    "field": fld,
    "purpose": item.purpose,
    "legal_basis": legal_basis_for_purpose(item.purpose)
  } |
    fld := requested_fields[_]
    item := data_item_for_field(fld)
  ]
} else := [] if { true }

legal_basis_for_purpose(p) := "contract" if { p == "contract" }
legal_basis_for_purpose(p) := "legal_obligation" if { p == "legal_obligation" }
legal_basis_for_purpose(p) := "legitimate_interest" if { p == "legitimate_interest" }
legal_basis_for_purpose(p) := "public_interest" if { p == "public_interest" }
legal_basis_for_purpose(p) := "consent" if { p == "marketing" }
legal_basis_for_purpose(p) := "unknown" if { not known_purpose(p) }

known_purpose(p) if { p == "contract" }
known_purpose(p) if { p == "legal_obligation" }
known_purpose(p) if { p == "marketing" }
known_purpose(p) if { p == "legitimate_interest" }
known_purpose(p) if { p == "public_interest" }

# -------------------------
# (3) Check reason for objection request
# Supported objection reasons:
# - "marketing"
# - "legitimate_interest"
# - "public_interest"
# -------------------------
supported_reason if { objection.reason == "marketing" }
supported_reason if { objection.reason == "legitimate_interest" }
supported_reason if { objection.reason == "public_interest" }

# (3a) Marketing: always accept and stop processing
accept_reason if {
  objection.reason == "marketing"
}

# (3b) Legitimate/public interest:
# We require a check result from the app/system:
#   objection.checks.processing_is_necessary == true/false
#
# Interpretation:
# - If processing IS necessary -> reject the objection
# - If processing is NOT necessary -> accept and stop processing
accept_reason if {
  objection.reason == "legitimate_interest"
  objection.checks.processing_is_necessary == false
}

accept_reason if {
  objection.reason == "public_interest"
  objection.checks.processing_is_necessary == false
}

reject_reasons contains r if {
  valid_request
  not supported_reason
  r := sprintf("Rejected: unsupported objection reason '%v'.", [objection.reason])
}

reject_reasons contains r if {
  valid_request
  objection.reason == "legitimate_interest"
  objection.checks.processing_is_necessary == true
  r := "Rejected: processing is necessary and overrides the objection (legitimate interest assessment)."
}

reject_reasons contains r if {
  valid_request
  objection.reason == "public_interest"
  objection.checks.processing_is_necessary == true
  r := "Rejected: processing is necessary and overrides the objection (public interest assessment)."
}

# -------------------------
# Decision
# -------------------------
decision := "accept" if {
  valid_request
  accept_reason
}

decision := "reject" if {
  not valid_request
} else := "reject" if {
  valid_request
  not accept_reason
}

# -------------------------
# (4) If rejected, notify user they can complain to DPA
# -------------------------
complaint_info := info if {
  info := {
    "message": "If you disagree with this outcome, you can lodge a complaint with your Data Protection Authority (DPA)."
  }
}

# -------------------------
# (5) Audit log
# -------------------------
audit_event := evt if {
  evt := {
    "type": "objection_request",
    "request_id": objection.request_id,
    "requester_user_id": requester_user_id,
    "target_user_id": target_user_id,
    "reason": objection.reason,
    "fields": objection.fields,
    "decision": decision,
    "justification": justification
  }
}

# -------------------------
# Justification
# -------------------------
justification := js if {
  a := [x | x := validation_reasons[_]]
  b := [x | x := reject_reasons[_]]
  js := array.concat(a, b)
}

# -------------------------
# Actions
# -------------------------
actions := out if {
  base := {
    "present_processing_context": present_processing_context,
    "log_audit": audit_event
  }

  decision == "accept"

  out := object.union(base, {
    "stop_processing": {
      "target_user_id": target_user_id,
      "fields": objection.fields,
      "mode": "stop"
    },
    "notify_user": {
      "decision": "accept",
      "request_id": objection.request_id,
      "message": "Objection accepted. Processing will be stopped for the specified personal data."
    }
  })
} else := out if {
  base := {
    "present_processing_context": present_processing_context,
    "log_audit": audit_event
  }

  decision == "reject"

  out := object.union(base, {
    "notify_user": {
      "decision": "reject",
      "request_id": objection.request_id,
      "justification": justification,
      "complaint": complaint_info
    }
  })
}

# -------------------------
# Helper: lookup data_item by field
# -------------------------
data_item_for_field(field_name) := item if {
  item := target_user.data_items[_]
  item.field == field_name
}
