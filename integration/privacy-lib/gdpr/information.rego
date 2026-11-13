package information

third_party_by_id(tp_id) := tp if {
    some k
    tp := input.third_parties[k]
    tp.id == tp_id
}

information(user_id) := result if {

    # -----------------------------
    # Find the user
    # -----------------------------
    some i
    user := input.users[i]
    user.id == user_id

    data_items := user.data_items

    # -----------------------------
    # Data details
    # -----------------------------
    details := [d |
        di := data_items[_]
        d := {
            "field": di.field,
            "purpose": di.purpose,
            "purpose_presented": di.purpose_presented
        }
    ]

    # -----------------------------
    # DPO details
    # -----------------------------
    dpo_details := {
        "name": input.dpo.name,
        "email": input.dpo.email
    }
    
    # -----------------------------
    # controller details
    # -----------------------------
    controller_details := {
        "name": input.controller.name,
        "address": input.controller.address,
        "email": input.controller.email
    }

    



    # -----------------------------
    # Third-party data + legitimate interests
    # -----------------------------
    third_party_items := [di |
        di := data_items[_]
        di.source != "user"
    ]

    third_party_required := count(third_party_items) > 0

    third_party_notice_data := [x |
        di := third_party_items[_]
        tp := third_party_by_id(di.source)

        x := {
            "field": di.field,
            "purpose": di.purpose,
            "source_id": tp.id,
            "source_name": tp.name,
            "legitimate_interest": tp.legitimate_interest
        }
    ]

  

    # -----------------------------
    # Violations (MINIMAL + SAFE)
    # -----------------------------
    violations := [v |
        di := data_items[_]
        not data.lawful.lawful_purpose(di.purpose)
        v := sprintf("Unlawful purpose: %s for field %s", [di.purpose, di.field])
    ]

    # -----------------------------
    # Final result
    # -----------------------------
    result := {
        "user_id": user_id,
        "storage": {
            "period": input.storage.period,
            "criteria": input.storage.criteria
        },
        "lawful_processing": data.lawful.lawful_processing(user_id),
        "consent_valid": data.consent.may_process_or_store(user_id),

        "controller_identity": controller_details,
        "show_dpo_identity": dpo_details,

        "my_data_details": details,

        "third_party_notice": {
            "required": third_party_required,
            "data": third_party_notice_data
        },

        "user_rights": [
            "access",
            "rectification",
            "erasure",
            "restriction",
            "objection",
            "data_portability",
            "consent_withdrawal"
        ],

        "withdraw_consent": data.consent.may_process_or_store(user_id),

        "violations": violations
    }
}
