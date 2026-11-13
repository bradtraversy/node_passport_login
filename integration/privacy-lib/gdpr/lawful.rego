package lawful

#
# (1) Obtain consent from the user
# We reuse your existing consent policy:
#   data.consent.may_process_or_store(user_id)
#

consent_ok(user_id) if {
    data.consent.may_process_or_store(user_id)
}

#
# (2) Ensure the processing is lawful
#  -> the purpose must be in the list of lawful purposes
#
lawful_purpose(purpose) if {
    some i
    input.lawful_purposes[i] == purpose
}

#
# (3) check if system has presented the purpose of processing to the user
# We assume each data item has "purpose_presented": true
# di stands for data item. A data item could be' email, age etc.'
purpose_presented(di) if {
    di.purpose_presented == true
}

#
# (4) Gather the data from the user
# We assume each data item has "source": "user" when it comes directly from the user
#
data_from_user(di) if {
    di.source == "user"
}

#
# Helper: all data items for a given user
#
user_data_item(user_id, di) if {
    some i, j
    u := input.users[i]
    u.id == user_id
    d := u.data_items[j]   # local variable
    di == d                # unify di with d (no reassign)
}

#
# A single data item is processed lawfully if:
#   - its purpose is lawful
#   - the purpose was presented to the user
#   - the data was gathered from the user
#
data_item_lawful(di) if {
    lawful_purpose(di.purpose)
    purpose_presented(di)
    data_from_user(di)
}

#
# check if there is any data item for this user that is NOT lawful
#
exists_unlawful_data(user_id) if {
    some i, j
    u := input.users[i]
    u.id == user_id
    di := u.data_items[j]
    not data_item_lawful(di)
}

#
# FINAL DECISION:
# Lawful processing for this user iff:
#   (1) consent_ok
#   AND
#   (2-4) no unlawful data items
#
lawful_processing(user_id) := true if {
    consent_ok(user_id)
    not exists_unlawful_data(user_id)
}

lawful_processing(user_id) := false if {
    not consent_ok(user_id)
}

lawful_processing(user_id) := false if {
    exists_unlawful_data(user_id)
}

# Audit log
audit_event(user_id) := evt if {
    lawful_request := object.get(input.request, "lawful", {})
    request_user_id := object.get(lawful_request, "user_id", user_id)

    evt := {
        "type": "lawfulness_check_request",
        "request_user_id": request_user_id,
        "target_user_id": user_id,
        "lawful_processing": lawful_processing(user_id)
    }
}

# Action output for app/logging
actions(user_id) := out if {
    out := {
        "log_audit": audit_event(user_id)
    }
}
