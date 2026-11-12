package restriction

default decision := "reject"
default actions := {}
default justification := []

# Bindings
restriction := input.request.restriction

requested_fields := restriction.fields
target_user_id := restriction.target_user_id
requester_user_id := restriction.user_id

target_user := u if {
  u := input.users[_]
  u.id == target_user_id
}

# (1) Present purpose to user
present_purposes := purposes if {
  purposes := [{"field": fld, "purpose": item.purpose} |
    fld := requested_fields[_]
    item := data_item_for_field(fld)
  ]
} else := [] if {
  true
}

# (2) Validate request
valid_request if {
  restriction.user_id != ""
  restriction.target_user_id != ""
  restriction.request_id != ""
  count(restriction.fields) > 0

  # self-only restriction - validation oti to request erxete apo ton idio xristi
  requester_user_id == target_user_id
}

validation_reasons contains r if {
  not (restriction.user_id != "")
  r := "Missing restriction.user_id"
}
validation_reasons contains r if {
  not (restriction.target_user_id != "")
  r := "Missing restriction.target_user_id"
}
validation_reasons contains r if {
  not (restriction.request_id != "")
  r := "Missing restriction.request_id"
}
validation_reasons contains r if {
  not (count(restriction.fields) > 0)
  r := "No fields requested for restriction"
}
validation_reasons contains r if {
  restriction.user_id != ""
  restriction.target_user_id != ""
  restriction.user_id != restriction.target_user_id
  r := "Requester not authorized to restrict another user's processing"
}

# -------------------------
# (3) Reason checks
# Supported:
# - data_inaccuracy_suspicion
# - invalid_purpose
# - objection_art21
# - unlawfulness
# -------------------------
supported_reason if { restriction.reason == "data_inaccuracy_suspicion" }
supported_reason if { restriction.reason == "invalid_purpose" }
supported_reason if { restriction.reason == "objection_art21" }
supported_reason if { restriction.reason == "unlawfulness" }

# Accept conditions:
accept_reason if {
  restriction.reason == "data_inaccuracy_suspicion"
  restriction.checks.data_correct == false
}

accept_reason if {
  restriction.reason == "invalid_purpose"
  restriction.checks.purpose_valid == false
}

accept_reason if {
  restriction.reason == "objection_art21"
  restriction.checks.legitimate_interest_overrides == false
}

accept_reason if {
  restriction.reason == "unlawfulness"
}

# Reject reasons:
reject_reasons contains r if {
  valid_request
  not supported_reason
  r := sprintf("Rejected: unsupported restriction reason '%v'.", [restriction.reason])
}

reject_reasons contains r if {
  valid_request
  restriction.reason == "data_inaccuracy_suspicion"
  restriction.checks.data_correct == true
  r := "Rejected: data was verified as correct."
}

reject_reasons contains r if {
  valid_request
  restriction.reason == "invalid_purpose"
  restriction.checks.purpose_valid == true
  r := "Rejected: purpose is still valid."
}

reject_reasons contains r if {
  valid_request
  restriction.reason == "objection_art21"
  restriction.checks.legitimate_interest_overrides == true
  r := "Rejected: controller's legitimate interests override the objection."
}

# Decision
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

# (4) Justification if rejected
justification := js if {
  a := [x | x := validation_reasons[_]]
  b := [x | x := reject_reasons[_]]
  js := array.concat(a, b)
}

# (6) Audit log
audit_event := evt if {
  evt := {
    "type": "restriction_request",
    "request_id": restriction.request_id,
    "requester_user_id": requester_user_id,
    "target_user_id": target_user_id,
    "reason": restriction.reason,
    "fields": restriction.fields,
    "decision": decision,
    "justification": justification
  }
}

# -------------------------
# Actions
# -------------------------
actions := out if {
  base := {
    "present_purposes": present_purposes,
    "log_audit": audit_event
  }

  decision == "accept"

  out := object.union(base, {
    "stop_processing": {
      "target_user_id": target_user_id,
      "fields": restriction.fields,
      "mode": "restrict"
    },
    "notify_user": {
      "decision": "accept",
      "request_id": restriction.request_id,
      "message": "Processing restricted for requested data. You will be notified of the result and before restriction is lifted."
    }
  })
} else := out if {
  base := {
    "present_purposes": present_purposes,
    "log_audit": audit_event
  }

  decision == "reject"

  out := object.union(base, {
    "notify_user": {
      "decision": "reject",
      "request_id": restriction.request_id,
      "justification": justification
    }
  })
}

# Helper
data_item_for_field(field_name) := item if {
  item := target_user.data_items[_]
  item.field == field_name
}
