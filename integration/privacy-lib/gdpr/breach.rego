package breach

default decision := "no_notify"
default actions := {}
default justification := []

# Bindings
b := input.breach

# (1) Detect and Identify data breach
breach_detected if {
  b.detected == true
  b.incident_id != ""
}

detect_reasons contains r if {
  not (b.detected == true)
  r := "No breach detected."
}

detect_reasons contains r if {
  b.detected == true
  not (b.incident_id != "")
  r := "Missing breach.incident_id"
}

# (2) Compose notification message within 72 hours
# We rely on numeric hours_since_detected to avoid time parsing issues.
within_72_hours if {
  breach_detected
  b.hours_since_detected <= 72
}

timing_reasons contains r if {
  breach_detected
  not within_72_hours
  r := "Notification window exceeded (more than 72 hours since detection)."
}

plain_text_message := msg if {
  msg := sprintf(
    "Data breach notification (Incident %v)\n\nSummary: %v\nCategories of data: %v\nWhen detected: %v hours ago\nWhat we are doing: %v\nWhat you can do: %v\nContact: %v",
    [
      b.incident_id,
      object.get(b, "summary", "N/A"),
      object.get(b, "categories", []),
      object.get(b, "hours_since_detected", "N/A"),
      object.get(b, "mitigations", "We are investigating and mitigating the issue."),
      object.get(b, "user_actions", "Monitor your accounts and be alert for suspicious activity."),
      object.get(input, "dpo", {"email": "N/A"}).email
    ]
  )
}

# (3) Assess risk to individuals
# Risk input is expected as:
# b.risks = ["rights_freedoms", "identity_theft", "discrimination"]
high_risk if { "rights_freedoms" == b.risks[_] }
high_risk if { "identity_theft" == b.risks[_] }
high_risk if { "discrimination" == b.risks[_] }
high_risk if { "financial_loss" == b.risks[_] }
high_risk if { "reputational_damage" == b.risks[_] }

risk_reasons contains r if {
  breach_detected
  not high_risk
  r := "Risk assessment does not indicate high risk to individuals' rights and freedoms."
}

# Decision
# Notify users only if:
# - breach detected
# - within 72 hours
# - high risk
decision := "notify_users" if {
  breach_detected
  within_72_hours
  high_risk
}

decision := "no_notify" if {
  not breach_detected
} else := "no_notify" if {
  breach_detected
  not within_72_hours
} else := "no_notify" if {
  breach_detected
  within_72_hours
  not high_risk
}

# Justification
justification := js if {
  a := [x | x := detect_reasons[_]]
  b := [x | x := timing_reasons[_]]
  c := [x | x := risk_reasons[_]]
  js := array.concat(a, array.concat(b, c))
}

# Actions
# If notify_users, return message + target list
actions := out if {
  decision == "notify_users"

  out := {
    "compose_message": {
      "incident_id": b.incident_id,
      "plain_text": plain_text_message
    },
    "notify_users": {
      "incident_id": b.incident_id,
      "users": object.get(b, "affected_users", []),
      "message": plain_text_message
    },
    "log_audit": audit_event
  }
} else := out if {
  decision == "no_notify"
  out := {
    "log_audit": audit_event,
    "justification": justification
  }
}

# Audit log (always)
audit_event := evt if {
  evt := {
    "type": "data_breach_assessment",
    "incident_id": object.get(b, "incident_id", ""),
    "detected": object.get(b, "detected", false),
    "hours_since_detected": object.get(b, "hours_since_detected", null),
    "risks": object.get(b, "risks", []),
    "decision": decision,
    "justification": justification
  }
}
