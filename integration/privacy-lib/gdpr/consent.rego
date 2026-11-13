package consent

#
# Helper: get consent record for a user
#
consent_record(user_id) := rec if {
  key := sprintf("%v", [user_id])
  rec := input.consents[key]
  rec != null
}


#
# (1) User must have given consent
#
has_given_consent(user_id) if {
    rec := consent_record(user_id)
    rec.value == "yes"
}

#
# (2) Consent is withdrawn
#
consent_withdrawn(user_id) if {
    rec := consent_record(user_id)
    rec.withdrawn == true
}

#
# FINAL DECISION
#
may_process_or_store(user_id) := true if {
    has_given_consent(user_id)
    not consent_withdrawn(user_id)
}

may_process_or_store(user_id) := false if {
    not has_given_consent(user_id)
}

may_process_or_store(user_id) := false if {
    consent_withdrawn(user_id)
}

# Confirm withdrawal completion
withdrawal_confirmation(user_id) := confirmation if {
    consent_withdrawn(user_id)
    confirmation := {
        "status": "completed",
        "user_id": user_id,
        "message": "Consent withdrawal completed."
    }
} else := confirmation if {
    not consent_withdrawn(user_id)
    confirmation := {
        "status": "not_withdrawn",
        "user_id": user_id,
        "message": "Consent has not been withdrawn."
    }
}

# Action output for app
actions(user_id) := out if {
    out := {
        "confirm_withdrawal_completion": withdrawal_confirmation(user_id)
    }
}
