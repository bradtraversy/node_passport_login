package complaint

default decision := "reject"
default actions := {}
default justification := []

c := input.request.complaint

# (1) Validate user (simple version: user exists)
valid_user if {
  c.user_id != ""
  u := input.users[_]
  u.id == c.user_id
}

# (1) Validate request payload
valid_request if {
  valid_user
  c.request_id != ""
  c.description != ""
  c.authority_id != ""
}

reasons contains r if {
  not (c.user_id != "")
  r := "Missing complaint.user_id"
}
reasons contains r if {
  c.user_id != ""
  not valid_user
  r := "Unknown user_id"
}
reasons contains r if {
  not (c.request_id != "")
  r := "Missing complaint.request_id"
}
reasons contains r if {
  not (c.description != "")
  r := "Missing complaint.description"
}
reasons contains r if {
  not (c.authority_id != "")
  r := "Missing complaint.authority_id"
}

# (4) Present list of supervisory authorities
authorities := [a | a := input.supervisory_authorities[_]]

selected_authority := a if {
  a := input.supervisory_authorities[_]
  a.id == c.authority_id
}

authority_valid if {
  selected_authority.id == c.authority_id
}

reasons contains r if {
  valid_user
  c.authority_id != ""
  not authority_valid
  r := "Selected supervisory authority not found"
}

# -------------------------
# Decision
# Accept only if request valid AND authority exists.
# -------------------------
decision := "accept" if {
  valid_request
  authority_valid
}

decision := "reject" if {
  not valid_request
}

decision := "reject" if {
  valid_request
  not authority_valid
}

# Justification (array)
justification := [x | x := reasons[_]]

# (5) Log complaint for auditing
audit_event := evt if {
  evt := {
    "type": "supervisory_authority_complaint",
    "request_id": object.get(c, "request_id", ""),
    "user_id": object.get(c, "user_id", ""),
    "authority_id": object.get(c, "authority_id", ""),
    "authority_name": object.get(selected_authority, "name", ""),
    "description": object.get(c, "description", ""),
    "decision": decision
  }
}

# (2)(3) UI hint: show option + prompt
ui_hint := {
  "show_complaint_option": true,
  "prompt": "You may lodge a complaint with a supervisory authority.",
  "input_fields": ["description", "authority_id"]
}

# (6) Forward complaint to selected authority (action for app)
forward_action := fwd if {
  decision == "accept"
  fwd := {
    "authority": selected_authority,
    "payload": {
      "request_id": c.request_id,
      "user_id": c.user_id,
      "description": c.description
    }
  }
} else := {} if {
  true
}

# (7) Notify user complaint recorded (or rejected)
actions := out if {
  decision == "accept"
  out := {
    "ui": ui_hint,
    "authorities": authorities,
    "log_audit": audit_event,
    "forward": forward_action,
    "notify_user": {
      "decision": "accept",
      "request_id": c.request_id,
      "message": "Your complaint has been recorded and will be forwarded to the selected supervisory authority."
    }
  }
} else := out if {
  decision == "reject"
  out := {
    "ui": ui_hint,
    "authorities": authorities,
    "log_audit": audit_event,
    "notify_user": {
      "decision": "reject",
      "request_id": object.get(c, "request_id", ""),
      "justification": justification,
      "message": "Your complaint could not be recorded because required information is missing or invalid."
    }
  }
}
