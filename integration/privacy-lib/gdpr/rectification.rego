package rectification

# (1) Validate request by user
req := input.request.rectification

valid_request if {
  req.user_id == req.target_user_id
  req.user_id != ""
}

valid_request_value := true if {
  valid_request
} else := false if {
  true
}

# -----------------------------
# Helpers
# -----------------------------

# Single-valued user lookup (prevents eval_conflict_error)
user_obj(user_id) := u if {
  matches := [x |
    some i
    x := input.users[i]
    x.id == user_id
  ]
  count(matches) == 1
  u := matches[0]
}

# Flatten user data_items into a map field -> di
user_data_map(user_id) := m if {
  u := user_obj(user_id)
  m := {di.field: di | di := u.data_items[_]}
}

# Current value for a field (optional; if missing, null)
old_value(di) := v if { v := di.value }
old_value(di) := null if { not di.value }

# Editable if collected from user
editable(di) if { di.source == "user" }

# -----------------------------
# (2) Present user data for review
# -----------------------------
present_data(user_id) := details if {
  u := user_obj(user_id)
  details := [x |
    di := u.data_items[_]
    x := {
      "field": di.field,
      "purpose": di.purpose,
      "source": di.source,
      "purpose_presented": di.purpose_presented,
      "current_value": old_value(di)
    }
  ]
}

# -----------------------------
# (3) Proposed updates
# -----------------------------
updates := req.updates

# -----------------------------
# Accepted updates
# -----------------------------
accepted_updates(user_id) := acc if {
  m := user_data_map(user_id)
  acc := [u |
    some field
    newv := updates[field]

    di := m[field]
    editable(di)

    u := {
      "field": field,
      "old_value": old_value(di),
      "new_value": newv
    }
  ]
}

# -----------------------------
# Rejected updates (deterministic; no "or" in comprehension)
# -----------------------------
rejected_updates(user_id) := rej if {
  m := user_data_map(user_id)

  # Missing field rejections
  missing := [r |
    some field
    newv := updates[field]
    not m[field]

    r := {
      "field": field,
      "new_value": newv,
      "reason": "Field does not exist for this user."
    }
  ]

  # Not editable rejections
  not_editable := [r |
    some field
    newv := updates[field]
    di := m[field]
    not editable(di)

    r := {
      "field": field,
      "new_value": newv,
      "reason": "Field is not editable (not collected directly from user)."
    }
  ]

  # Combine without ++ (OPA in your setup is picky)
  rej := array.concat(missing, not_editable)
}

# -----------------------------
# (4) DB update plan
# -----------------------------
db_update_plan(user_id) := plan if {
  acc := accepted_updates(user_id)
  plan := [p |
    a := acc[_]
    p := {
      "user_id": user_id,
      "field": a.field,
      "old_value": a.old_value,
      "new_value": a.new_value
    }
  ]
}

# -----------------------------
# (5) Audit record
# -----------------------------
audit_record(user_id) := rec if {
  rec := {
    "event": "RIGHT_TO_RECTIFICATION",
    "request_id": req.request_id,
    "requester_user_id": req.user_id,
    "target_user_id": user_id,
    "validated": valid_request_value,
    "accepted_count": count(accepted_updates(user_id)),
    "rejected_count": count(rejected_updates(user_id))
  }
}

# -----------------------------
# (6) Confirmation email instruction
# -----------------------------
confirmation_email(user_id) := email if {
  email := {
    "send": true,
    "template": "rectification_confirmation",
    "to_user_id": user_id,
    "subject": "Your data has been updated",
    "body_hint": "Confirm we have rectified the requested personal data fields."
  }
}

# -----------------------------
# Main response
# -----------------------------
rectification_response(user_id) := result if {
  valid_request
  req.target_user_id == user_id
  _ := user_obj(user_id)

  result := {
    "request": {
      "user_id": req.user_id,
      "target_user_id": req.target_user_id,
      "validated": true
    },
    "present_data": present_data(user_id),
    "accepted_updates": accepted_updates(user_id),
    "rejected_updates": rejected_updates(user_id),
    "db_update_plan": db_update_plan(user_id),
    "audit": audit_record(user_id),
    "confirmation_email": confirmation_email(user_id)
  }
}

# Invalid request safe response
rectification_response(user_id) := result if {
  not valid_request

  result := {
    "request": {
      "user_id": req.user_id,
      "target_user_id": req.target_user_id,
      "validated": false
    },
    "error": "Invalid request: requester does not match target user.",
    "audit": audit_record(user_id),
    "confirmation_email": {
      "send": false
    }
  }
}
