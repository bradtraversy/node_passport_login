package access

#
# Right to Access (GDPR Art. 15)
# Returns a structured object for the application to:
#  - show data in UI
#  - generate a downloadable JSON
#  - log/audit the request
#

# (1) Validate request by user
valid_request(user_id) if {
  input.request.access.user_id == user_id
}

valid_request_value(user_id) := true if {
  valid_request(user_id)
} else := false if {
  true
}

# Find user object by id
user_obj(user_id) := user if {
  some i
  user := input.users[i]
  user.id == user_id
}

# Third party lookup by id
third_party_by_id(tp_id) := tp if {
  some k
  tp := input.third_parties[k]
  tp.id == tp_id
}

# Classify data items
is_first_party(di) if { di.source == "user" }
is_third_party(di) if { di.source != "user" }

# (2) Retrieve user personal data collected by this.system
first_party_items(user_id) := items if {
  u := user_obj(user_id)
  items := [di |
    di := u.data_items[_]
    is_first_party(di)
  ]
}

# (3) Retrieve user personal data sent to third parties
third_party_items(user_id) := items if {
  u := user_obj(user_id)
  items := [di |
    di := u.data_items[_]
    is_third_party(di)
  ]
}

# (4) Format personal data
format_item(di) := out if {
  out := {
    "field": di.field,
    "purpose": di.purpose,
    "source": di.source,
    "purpose_presented": di.purpose_presented
  }
}

format_tp_item(di) := out if {
  tp := third_party_by_id(di.source)
  out := {
    "field": di.field,
    "purpose": di.purpose,
    "third_party_id": tp.id,
    "third_party_name": tp.name,
    "legitimate_interest": tp.legitimate_interest,
    "purpose_presented": di.purpose_presented
  }
}

# Inform third parties of the access request after retrieving data linked to them.
third_party_access_notifications(user_id) := notes if {
  valid_request(user_id)
  notes := [n |
    tp := input.third_parties[_]
    fields := [format_tp_item(di) |
      di := third_party_items(user_id)[_]
      di.source == tp.id
    ]
    count(fields) > 0
    n := {
      "third_party_id": tp.id,
      "third_party_name": tp.name,
      "request_type": "right_to_access",
      "target_user_id": user_id,
      "message": "User has submitted a right of access request involving personal data linked to this third party.",
      "data_items": fields
    }
  ]
} else := [] if {
  true
}

# (5) Create downloadable format (stringified JSON)
download_payload(user_id) := payload if {
  payload := {
    "user_id": user_id,
    "controller": input.controller,
    "dpo": input.dpo,
    "storage": input.storage,

    "data_collected_from_user": [format_item(di) |
      di := first_party_items(user_id)[_]
    ],

    "data_from_third_parties": [format_tp_item(di) |
      di := third_party_items(user_id)[_]
    ],

    "data_sent_to_third_parties": [format_tp_item(di) |
      di := third_party_items(user_id)[_]
    ],

    "rights_notice": {
      "access": true,
      "rectification": true,
      "erasure": true,
      "restriction": true,
      "objection": true,
      "data_portability": true,
      "withdraw_consent_any_time": true
    }
  }
}

download_object(user_id) := dl if {
  payload := download_payload(user_id)
  dl := {
    "filename": sprintf("access_%v.json", [user_id]),
    "mime": "application/json",
    "content": json.marshal(payload)
  }
}

# (7) Audit record
audit_record(user_id) := rec if {
  rec := {
    "event": "RIGHT_TO_ACCESS_REQUEST",
    "user_id": user_id,
    "validated": valid_request_value(user_id),
    "has_download_payload": valid_request_value(user_id)
  }
}

# (6) Main response returned to the app
access_response(user_id) := result if {
  valid_request(user_id)
  _ := user_obj(user_id)

  first := [format_item(di) | di := first_party_items(user_id)[_]]
  third := [format_tp_item(di) | di := third_party_items(user_id)[_]]
  third_party_notifications := third_party_access_notifications(user_id)
  dl := download_object(user_id)

  result := {
    "request": {
      "user_id": user_id,
      "validated": true
    },
    "controller": input.controller,
    "dpo": input.dpo,
    "storage": input.storage,

    "personal_data": {
      "collected_from_user": first,
      "from_third_parties": third,
      "sent_to_third_parties": third
    },

    "inform_third_parties_of_access_request": third_party_notifications,

    "download": dl,

    "deliver_to_user": {
      "include_in_response": true,
      "include_download": true
    },

    "rights_notice": {
      "access": true,
      "rectification": true,
      "erasure": true,
      "restriction": true,
      "objection": true,
      "data_portability": true,
      "withdraw_consent_any_time": true
    },

    "audit": audit_record(user_id)
  }
}

# Invalid request branch (still returns a safe object)
access_response(user_id) := result if {
  not valid_request(user_id)
  result := {
    "request": {
      "user_id": user_id,
      "validated": false
    },
    "error": "Invalid request: request.access.user_id does not match the requested user_id.",
    "audit": audit_record(user_id)
  }
}
