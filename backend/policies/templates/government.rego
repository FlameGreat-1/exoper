package government.template

import future.keywords.if
import future.keywords.in
import future.keywords.every
import future.keywords.contains

default allow := false
default deny := true
default security_clearance_verified := false
default classification_handling_compliant := false
default government_compliance_met := false

metadata := {
    "policy_id": "government-template",
    "version": "1.0.0",
    "description": "Government-grade authorization template with security clearance and classification controls",
    "priority": 11,
    "effect": "allow",
    "created_by": "system",
    "tags": ["government", "security_clearance", "classification", "national_security", "federal", "compliance"]
}

allow if {
    security_clearance_verified
    classification_handling_compliant
    government_compliance_met
    not national_security_violations_detected
    federal_regulations_enforced
    security_protocols_implemented
    access_need_to_know_verified
    compartmentalized_access_controlled
}

deny if {
    national_security_violations_detected
}

deny if {
    not security_clearance_verified
}

deny if {
    classification_level_insufficient
}

security_clearance_verified if {
    subject_clearance_valid
    clearance_level_sufficient
    clearance_status_current
    polygraph_requirements_met
    background_investigation_current
    continuous_monitoring_active
}

subject_clearance_valid if {
    subject_id := input.context.security.subject_id
    subject_clearance := data.subjects[subject_id].security_clearance
    
    subject_clearance.active == true
    subject_clearance.verified == true
    subject_clearance.adjudicated == true
}

clearance_level_sufficient if {
    subject_id := input.context.security.subject_id
    subject_clearance_level := data.subjects[subject_id].security_clearance.level
    required_clearance_level := determine_required_clearance_level
    
    clearance_hierarchy[subject_clearance_level] >= clearance_hierarchy[required_clearance_level]
}

clearance_hierarchy := {
    "unclassified": 0,
    "confidential": 1,
    "secret": 2,
    "top_secret": 3,
    "top_secret_sci": 4,
    "top_secret_sap": 5
}

determine_required_clearance_level := required_level if {
    resource_classification := input.resource.classification.level
    action := input.action
    
    required_level := classification_access_matrix[resource_classification][action]
}

classification_access_matrix := {
    "unclassified": {
        "read": "unclassified",
        "create": "unclassified",
        "update": "unclassified",
        "delete": "unclassified",
        "share": "unclassified"
    },
    "confidential": {
        "read": "confidential",
        "create": "confidential",
        "update": "confidential",
        "delete": "confidential",
        "share": "secret"
    },
    "secret": {
        "read": "secret",
        "create": "secret",
        "update": "secret",
        "delete": "secret",
        "share": "top_secret"
    },
    "top_secret": {
        "read": "top_secret",
        "create": "top_secret",
        "update": "top_secret",
        "delete": "top_secret",
        "share": "top_secret_sci"
    },
    "top_secret_sci": {
        "read": "top_secret_sci",
        "create": "top_secret_sci",
        "update": "top_secret_sci",
        "delete": "top_secret_sci",
        "share": "top_secret_sap"
    },
    "top_secret_sap": {
        "read": "top_secret_sap",
        "create": "top_secret_sap",
        "update": "top_secret_sap",
        "delete": "top_secret_sap",
        "share": "top_secret_sap"
    }
}

clearance_status_current if {
    subject_id := input.context.security.subject_id
    subject_clearance := data.subjects[subject_id].security_clearance
    
    current_time := time.now_ns()
    expiry_time := time.parse_rfc3339_ns(subject_clearance.expiry_date)
    
    current_time < expiry_time
}

polygraph_requirements_met if {
    subject_id := input.context.security.subject_id
    subject_clearance := data.subjects[subject_id].security_clearance
    required_clearance_level := determine_required_clearance_level
    
    not polygraph_required(required_clearance_level)
}

polygraph_requirements_met if {
    subject_id := input.context.security.subject_id
    subject_clearance := data.subjects[subject_id].security_clearance
    required_clearance_level := determine_required_clearance_level
    
    polygraph_required(required_clearance_level)
    subject_clearance.polygraph.completed == true
    subject_clearance.polygraph.current == true
    subject_clearance.polygraph.type == polygraph_type_required(required_clearance_level)
}

polygraph_required(clearance_level) if {
    clearance_level in {"top_secret_sci", "top_secret_sap"}
}

polygraph_type_required("top_secret_sci") := "lifestyle"

polygraph_type_required("top_secret_sap") := "full_scope"

background_investigation_current if {
    subject_id := input.context.security.subject_id
    subject_clearance := data.subjects[subject_id].security_clearance
    
    investigation := subject_clearance.background_investigation
    investigation.completed == true
    investigation.current == true
    investigation.type == investigation_type_required(subject_clearance.level)
}

investigation_type_required("confidential") := "naclc"

investigation_type_required("secret") := "naclc"

investigation_type_required("top_secret") := "ssbi"

investigation_type_required("top_secret_sci") := "ssbi_pr"

investigation_type_required("top_secret_sap") := "ssbi_pr"

continuous_monitoring_active if {
    subject_id := input.context.security.subject_id
    subject_clearance := data.subjects[subject_id].security_clearance
    
    monitoring := subject_clearance.continuous_monitoring
    monitoring.enrolled == true
    monitoring.active == true
    monitoring.last_update_within_threshold == true
}

classification_handling_compliant if {
    resource_properly_classified
    marking_requirements_met
    handling_procedures_followed
    storage_requirements_satisfied
    transmission_security_enforced
    destruction_procedures_compliant
}

resource_properly_classified if {
    resource_classification := input.resource.classification
    
    resource_classification.level
    resource_classification.authority
    resource_classification.date
    resource_classification.reason
}

marking_requirements_met if {
    resource_classification := input.resource.classification
    classification_level := resource_classification.level
    
    required_markings := classification_marking_requirements[classification_level]
    actual_markings := resource_classification.markings
    
    every required_marking in required_markings {
        required_marking in actual_markings
    }
}

classification_marking_requirements := {
    "unclassified": ["UNCLASSIFIED"],
    "confidential": ["CONFIDENTIAL"],
    "secret": ["SECRET"],
    "top_secret": ["TOP SECRET"],
    "top_secret_sci": ["TOP SECRET//SCI"],
    "top_secret_sap": ["TOP SECRET//SAP"]
}

handling_procedures_followed if {
    resource_classification := input.resource.classification
    classification_level := resource_classification.level
    action := input.action
    
    handling_requirements := classification_handling_matrix[classification_level][action]
    actual_handling := input.context.classification.handling
    
    handling_requirements_satisfied(handling_requirements, actual_handling)
}

classification_handling_matrix := {
    "unclassified": {
        "read": {
            "location_restrictions": false,
            "escort_required": false,
            "secure_facility": false,
            "two_person_integrity": false
        },
        "create": {
            "location_restrictions": false,
            "approval_required": false,
            "secure_facility": false,
            "classification_review": false
        },
        "update": {
            "location_restrictions": false,
            "approval_required": false,
            "secure_facility": false,
            "classification_review": false
        },
        "delete": {
            "location_restrictions": false,
            "approval_required": false,
            "secure_destruction": false,
            "witness_required": false
        }
    },
    "confidential": {
        "read": {
            "location_restrictions": true,
            "escort_required": false,
            "secure_facility": false,
            "two_person_integrity": false
        },
        "create": {
            "location_restrictions": true,
            "approval_required": true,
            "secure_facility": false,
            "classification_review": true
        },
        "update": {
            "location_restrictions": true,
            "approval_required": true,
            "secure_facility": false,
            "classification_review": true
        },
        "delete": {
            "location_restrictions": true,
            "approval_required": true,
            "secure_destruction": true,
            "witness_required": false
        }
    },
    "secret": {
        "read": {
            "location_restrictions": true,
            "escort_required": false,
            "secure_facility": true,
            "two_person_integrity": false
        },
        "create": {
            "location_restrictions": true,
            "approval_required": true,
            "secure_facility": true,
            "classification_review": true
        },
        "update": {
            "location_restrictions": true,
            "approval_required": true,
            "secure_facility": true,
            "classification_review": true
        },
        "delete": {
            "location_restrictions": true,
            "approval_required": true,
            "secure_destruction": true,
            "witness_required": true
        }
    },
    "top_secret": {
        "read": {
            "location_restrictions": true,
            "escort_required": true,
            "secure_facility": true,
            "two_person_integrity": true
        },
        "create": {
            "location_restrictions": true,
            "approval_required": true,
            "secure_facility": true,
            "classification_review": true
        },
        "update": {
            "location_restrictions": true,
            "approval_required": true,
            "secure_facility": true,
            "classification_review": true
        },
        "delete": {
            "location_restrictions": true,
            "approval_required": true,
            "secure_destruction": true,
            "witness_required": true
        }
    },
    "top_secret_sci": {
        "read": {
            "location_restrictions": true,
            "escort_required": true,
            "secure_facility": true,
            "two_person_integrity": true,
            "scif_required": true
        },
        "create": {
            "location_restrictions": true,
            "approval_required": true,
            "secure_facility": true,
            "classification_review": true,
            "scif_required": true
        },
        "update": {
            "location_restrictions": true,
            "approval_required": true,
            "secure_facility": true,
            "classification_review": true,
            "scif_required": true
        },
        "delete": {
            "location_restrictions": true,
            "approval_required": true,
            "secure_destruction": true,
            "witness_required": true,
            "scif_required": true
        }
    },
    "top_secret_sap": {
        "read": {
            "location_restrictions": true,
            "escort_required": true,
            "secure_facility": true,
            "two_person_integrity": true,
            "scif_required": true,
            "sap_facility_required": true
        },
        "create": {
            "location_restrictions": true,
            "approval_required": true,
            "secure_facility": true,
            "classification_review": true,
            "scif_required": true,
            "sap_facility_required": true
        },
        "update": {
            "location_restrictions": true,
            "approval_required": true,
            "secure_facility": true,
            "classification_review": true,
            "scif_required": true,
            "sap_facility_required": true
        },
        "delete": {
            "location_restrictions": true,
            "approval_required": true,
            "secure_destruction": true,
            "witness_required": true,
            "scif_required": true,
            "sap_facility_required": true
        }
    }
}

handling_requirements_satisfied(requirements, actual) if {
    every requirement, value in requirements {
        not value
    }
}

handling_requirements_satisfied(requirements, actual) if {
    every requirement, value in requirements {
        value
        actual[requirement] == true
    }
}

storage_requirements_satisfied if {
    resource_classification := input.resource.classification
    classification_level := resource_classification.level
    
    storage_requirements := classification_storage_matrix[classification_level]
    actual_storage := input.context.classification.storage
    
    storage_requirements_met(storage_requirements, actual_storage)
}

classification_storage_matrix := {
    "unclassified": {
        "physical_security": false,
        "access_control": true,
        "encryption_at_rest": false,
        "secure_container": false,
        "facility_clearance": false,
        "backup_security": true
    },
    "confidential": {
        "physical_security": true,
        "access_control": true,
        "encryption_at_rest": true,
        "secure_container": true,
        "facility_clearance": false,
        "backup_security": true
    },
    "secret": {
        "physical_security": true,
        "access_control": true,
        "encryption_at_rest": true,
        "secure_container": true,
        "facility_clearance": true,
        "backup_security": true,
        "vault_storage": true
    },
    "top_secret": {
        "physical_security": true,
        "access_control": true,
        "encryption_at_rest": true,
        "secure_container": true,
        "facility_clearance": true,
        "backup_security": true,
        "vault_storage": true,
        "alarmed_storage": true
    },
    "top_secret_sci": {
        "physical_security": true,
        "access_control": true,
        "encryption_at_rest": true,
        "secure_container": true,
        "facility_clearance": true,
        "backup_security": true,
        "vault_storage": true,
        "alarmed_storage": true,
        "scif_storage": true
    },
    "top_secret_sap": {
        "physical_security": true,
        "access_control": true,
        "encryption_at_rest": true,
        "secure_container": true,
        "facility_clearance": true,
        "backup_security": true,
        "vault_storage": true,
        "alarmed_storage": true,
        "scif_storage": true,
        "sap_storage": true
    }
}

storage_requirements_met(requirements, actual) if {
    every requirement, value in requirements {
        not value
    }
}

storage_requirements_met(requirements, actual) if {
    every requirement, value in requirements {
        value
        actual[requirement] == true
    }
}

transmission_security_enforced if {
    resource_classification := input.resource.classification
    classification_level := resource_classification.level
    action := input.action
    
    action != "transmit"
}

transmission_security_enforced if {
    resource_classification := input.resource.classification
    classification_level := resource_classification.level
    action := input.action
    
    action == "transmit"
    
    transmission_requirements := classification_transmission_matrix[classification_level]
    actual_transmission := input.context.classification.transmission
    
    transmission_requirements_met(transmission_requirements, actual_transmission)
}

classification_transmission_matrix := {
    "unclassified": {
        "encryption_in_transit": false,
        "secure_network": false,
        "vpn_required": false,
        "end_to_end_encryption": false,
        "transmission_approval": false,
        "recipient_verification": true
    },
    "confidential": {
        "encryption_in_transit": true,
        "secure_network": true,
        "vpn_required": false,
        "end_to_end_encryption": false,
        "transmission_approval": true,
        "recipient_verification": true
    },
    "secret": {
        "encryption_in_transit": true,
        "secure_network": true,
        "vpn_required": true,
        "end_to_end_encryption": true,
        "transmission_approval": true,
        "recipient_verification": true,
        "secure_phone": false
    },
    "top_secret": {
        "encryption_in_transit": true,
        "secure_network": true,
        "vpn_required": true,
        "end_to_end_encryption": true,
        "transmission_approval": true,
        "recipient_verification": true,
        "secure_phone": true,
        "classified_network": true
    },
    "top_secret_sci": {
        "encryption_in_transit": true,
        "secure_network": true,
        "vpn_required": true,
        "end_to_end_encryption": true,
        "transmission_approval": true,
        "recipient_verification": true,
        "secure_phone": true,
        "classified_network": true,
        "jwics_network": true
    },
    "top_secret_sap": {
        "encryption_in_transit": true,
        "secure_network": true,
        "vpn_required": true,
        "end_to_end_encryption": true,
        "transmission_approval": true,
        "recipient_verification": true,
        "secure_phone": true,
        "classified_network": true,
        "jwics_network": true,
        "sap_network": true
    }
}

transmission_requirements_met(requirements, actual) if {
    every requirement, value in requirements {
        not value
    }
}

transmission_requirements_met(requirements, actual) if {
    every requirement, value in requirements {
        value
        actual[requirement] == true
    }
}

destruction_procedures_compliant if {
    action := input.action
    action != "delete"
}

destruction_procedures_compliant if {
    action := input.action
    action == "delete"
    
    resource_classification := input.resource.classification
    classification_level := resource_classification.level
    
    destruction_requirements := classification_destruction_matrix[classification_level]
    actual_destruction := input.context.classification.destruction
    
    destruction_requirements_met(destruction_requirements, actual_destruction)
}

classification_destruction_matrix := {
    "unclassified": {
        "secure_deletion": false,
        "witness_required": false,
        "certificate_of_destruction": false,
        "physical_destruction": false,
        "degaussing_required": false,
        "overwrite_passes": 1
    },
    "confidential": {
        "secure_deletion": true,
        "witness_required": false,
        "certificate_of_destruction": true,
        "physical_destruction": false,
        "degaussing_required": false,
        "overwrite_passes": 3
    },
    "secret": {
        "secure_deletion": true,
        "witness_required": true,
        "certificate_of_destruction": true,
        "physical_destruction": true,
        "degaussing_required": true,
        "overwrite_passes": 7
    },
    "top_secret": {
        "secure_deletion": true,
        "witness_required": true,
        "certificate_of_destruction": true,
        "physical_destruction": true,
        "degaussing_required": true,
        "overwrite_passes": 7,
        "disintegration_required": true
    },
    "top_secret_sci": {
        "secure_deletion": true,
        "witness_required": true,
        "certificate_of_destruction": true,
        "physical_destruction": true,
        "degaussing_required": true,
        "overwrite_passes": 7,
        "disintegration_required": true,
        "pulverization_required": true
    },
    "top_secret_sap": {
        "secure_deletion": true,
        "witness_required": true,
        "certificate_of_destruction": true,
        "physical_destruction": true,
        "degaussing_required": true,
        "overwrite_passes": 7,
        "disintegration_required": true,
        "pulverization_required": true,
        "incineration_required": true
    }
}

destruction_requirements_met(requirements, actual) if {
    every requirement, value in requirements {
        not value
    }
}

destruction_requirements_met(requirements, actual) if {
    every requirement, value in requirements {
        value
        actual[requirement] == true
    }
}

government_compliance_met if {
    federal_information_security_management_act_compliant
    privacy_act_compliant
    freedom_of_information_act_compliant
    records_management_compliant
    cybersecurity_framework_implemented
    continuous_diagnostics_mitigation_active
}

federal_information_security_management_act_compliant if {
    fisma := input.context.government_compliance.fisma
    fisma.security_categorization_completed == true
    fisma.security_controls_implemented == true
    fisma.security_assessment_conducted == true
    fisma.authorization_to_operate_current == true
    fisma.continuous_monitoring_active == true
}

privacy_act_compliant if {
    privacy_act := input.context.government_compliance.privacy_act
    
    not privacy_act_applicable
}

privacy_act_compliant if {
    privacy_act := input.context.government_compliance.privacy_act
    privacy_act_applicable
    
    privacy_act.system_of_records_notice_published == true
    privacy_act.privacy_impact_assessment_completed == true
    privacy_act.individual_rights_procedures_established == true
    privacy_act.data_sharing_agreements_documented == true
}

privacy_act_applicable if {
    resource_type := input.resource.type
    resource_type == "dataset"
    
    dataset_contains_pii := input.context.data.contains_pii
    dataset_contains_pii == true
}

freedom_of_information_act_compliant if {
    foia := input.context.government_compliance.foia
    foia.exemption_review_completed == true
    foia.release_procedures_established == true
    foia.redaction_procedures_documented == true
    foia.response_time_procedures == true
}

records_management_compliant if {
    records_mgmt := input.context.government_compliance.records_management
    records_mgmt.records_schedule_approved == true
    records_mgmt.retention_periods_defined == true
    records_mgmt.disposition_procedures_established == true
    records_mgmt.electronic_records_management == true
}

cybersecurity_framework_implemented if {
    csf := input.context.government_compliance.cybersecurity_framework
    csf.nist_framework_implemented == true
    csf.identify_function_operational == true
    csf.protect_function_operational == true
    csf.detect_function_operational == true
    csf.respond_function_operational == true
    csf.recover_function_operational == true
}

continuous_diagnostics_mitigation_active if {
    cdm := input.context.government_compliance.cdm
    cdm.asset_management_deployed == true
    cdm.identity_management_deployed == true
    cdm.network_security_management_deployed == true
    cdm.data_protection_management_deployed == true
}

federal_regulations_enforced if {
    nist_800_53_controls_implemented
    fips_140_2_compliance_verified
    common_criteria_evaluation_completed
    itar_compliance_enforced
    ear_compliance_enforced
}

nist_800_53_controls_implemented if {
    nist_controls := input.context.federal_regulations.nist_800_53
    nist_controls.access_control_family == true
    nist_controls.awareness_training_family == true
    nist_controls.audit_accountability_family == true
    nist_controls.security_assessment_family == true
    nist_controls.configuration_management_family == true
    nist_controls.contingency_planning_family == true
    nist_controls.identification_authentication_family == true
    nist_controls.incident_response_family == true
    nist_controls.maintenance_family == true
    nist_controls.media_protection_family == true
    nist_controls.physical_protection_family == true
    nist_controls.planning_family == true
    nist_controls.personnel_security_family == true
    nist_controls.risk_assessment_family == true
    nist_controls.system_services_acquisition_family == true
    nist_controls.system_communications_protection_family == true
    nist_controls.system_information_integrity_family == true
}

fips_140_2_compliance_verified if {
    fips := input.context.federal_regulations.fips_140_2
    fips.cryptographic_modules_validated == true
    fips.security_level_appropriate == true
    fips.key_management_compliant == true
    fips.physical_security_verified == true
}

common_criteria_evaluation_completed if {
    cc := input.context.federal_regulations.common_criteria
    
    not cc_evaluation_required
}

common_criteria_evaluation_completed if {
    cc := input.context.federal_regulations.common_criteria
    cc_evaluation_required
    
    cc.evaluation_completed == true
    cc.certification_current == true
    cc.protection_profile_appropriate == true
    cc.security_target_approved == true
}

cc_evaluation_required if {
    resource_classification := input.resource.classification
    classification_level := resource_classification.level
    
    classification_level in {"top_secret", "top_secret_sci", "top_secret_sap"}
}

itar_compliance_enforced if {
    itar := input.context.federal_regulations.itar
    
    not itar_controlled_technology
}

itar_compliance_enforced if {
    itar := input.context.federal_regulations.itar
    itar_controlled_technology
    
    itar.export_license_current == true
    itar.foreign_person_access_controlled == true
    itar.technical_data_protected == true
    itar.defense_services_authorized == true
}

itar_controlled_technology if {
    resource_type := input.resource.type
    resource_type == "model"
    
    model_category := input.resource.category
    model_category in itar_controlled_categories
}

itar_controlled_categories := {
    "defense",
    "military",
    "weapons",
    "surveillance",
    "cryptographic",
    "dual_use"
}

ear_compliance_enforced if {
    ear := input.context.federal_regulations.ear
    
    not ear_controlled_technology
}

ear_compliance_enforced if {
    ear := input.context.federal_regulations.ear
    ear_controlled_technology
    
    ear.export_control_classification_number_assigned == true
    ear.license_exception_applicable == true
    ear.end_user_screening_completed == true
    ear.destination_control_verified == true
}

ear_controlled_technology if {
    resource_type := input.resource.type
    resource_type == "model"
    
    model_category := input.resource.category
    model_category in ear_controlled_categories
}

ear_controlled_categories := {
    "encryption",
    "telecommunications",
    "information_security",
    "sensors",
    "navigation",
    "aerospace",
    "marine",
    "propulsion"
}

security_protocols_implemented if {
    physical_security_protocols_active
    personnel_security_protocols_enforced
    information_security_protocols_operational
    communications_security_protocols_implemented
    operations_security_protocols_maintained
}

physical_security_protocols_active if {
    physical_security := input.context.security_protocols.physical_security
    physical_security.perimeter_security == true
    physical_security.access_control_systems == true
    physical_security.visitor_control == true
    physical_security.surveillance_systems == true
    physical_security.intrusion_detection == true
    physical_security.security_guards == true
    physical_security.emergency_procedures == true
}

personnel_security_protocols_enforced if {
    personnel_security := input.context.security_protocols.personnel_security
    personnel_security.background_investigations == true
    personnel_security.security_briefings == true
    personnel_security.debriefings == true
    personnel_security.insider_threat_program == true
    personnel_security.security_violations_reporting == true
    personnel_security.foreign_contacts_reporting == true
    personnel_security.travel_security_briefings == true
}

information_security_protocols_operational if {
    info_security := input.context.security_protocols.information_security
    info_security.data_classification_program == true
    info_security.marking_procedures == true
    info_security.handling_procedures == true
    info_security.storage_procedures == true
    info_security.transmission_procedures == true
    info_security.destruction_procedures == true
    info_security.incident_response_procedures == true
}

communications_security_protocols_implemented if {
    comms_security := input.context.security_protocols.communications_security
    comms_security.secure_communications == true
    comms_security.encryption_standards == true
    comms_security.key_management == true
    comms_security.emanations_security == true
    comms_security.transmission_security == true
    comms_security.communications_intelligence == true
}

operations_security_protocols_maintained if {
    ops_security := input.context.security_protocols.operations_security
    ops_security.critical_information_identification == true
    ops_security.threat_assessment == true
    ops_security.vulnerability_analysis == true
    ops_security.risk_assessment == true
    ops_security.countermeasures_implementation == true
}

access_need_to_know_verified if {
    subject_id := input.context.security.subject_id
    resource_id := input.resource.id
    action := input.action
    
    need_to_know_justified
    official_duties_require_access
    minimum_access_principle_applied
    access_purpose_documented
}

need_to_know_justified if {
    justification := input.context.access_control.need_to_know_justification
    justification.business_purpose
    justification.official_duties
    justification.mission_requirements
    justification.supervisor_approval == true
}

official_duties_require_access if {
    subject_id := input.context.security.subject_id
    subject_duties := data.subjects[subject_id].official_duties
    resource_type := input.resource.type
    action := input.action
    
    duties_resource_matrix[subject_duties][resource_type][action] == true
}

duties_resource_matrix := {
    "intelligence_analyst": {
        "dataset": {
            "read": true,
            "analyze": true,
            "report": true
        },
        "model": {
            "read": true,
            "infer": true,
            "evaluate": true
        }
    },
    "data_scientist": {
        "dataset": {
            "read": true,
            "create": true,
            "update": true,
            "analyze": true
        },
        "model": {
            "read": true,
            "create": true,
            "train": true,
            "evaluate": true
        }
    },
    "security_officer": {
        "dataset": {
            "read": true,
            "audit": true,
            "monitor": true
        },
        "model": {
            "read": true,
            "audit": true,
            "monitor": true
        }
    },
    "system_administrator": {
        "dataset": {
            "read": true,
            "backup": true,
            "restore": true
        },
        "model": {
            "read": true,
            "deploy": true,
            "monitor": true
        }
    }
}

minimum_access_principle_applied if {
    requested_access := input.context.access_control.requested_access
    minimum_required_access := determine_minimum_required_access
    
    access_level_appropriate(requested_access, minimum_required_access)
}

determine_minimum_required_access := minimum_access if {
    subject_id := input.context.security.subject_id
    resource_type := input.resource.type
    action := input.action
    subject_role := data.subjects[subject_id].role
    
    minimum_access := role_minimum_access_matrix[subject_role][resource_type][action]
}

role_minimum_access_matrix := {
    "analyst": {
        "dataset": {
            "read": "read_only",
            "analyze": "read_only"
        },
        "model": {
            "read": "read_only",
            "infer": "execute_only"
        }
    },
    "researcher": {
        "dataset": {
            "read": "read_write",
            "create": "create_only"
        },
        "model": {
            "read": "read_write",
            "train": "execute_only"
        }
    },
    "administrator": {
        "dataset": {
            "read": "full_access",
            "create": "full_access",
            "update": "full_access",
            "delete": "full_access"
        },
        "model": {
            "read": "full_access",
            "create": "full_access",
            "deploy": "full_access",
            "delete": "full_access"
        }
    }
}

access_level_appropriate(requested, minimum) if {
    access_hierarchy[requested] <= access_hierarchy[minimum]
}

access_hierarchy := {
    "read_only": 1,
    "execute_only": 2,
    "read_write": 3,
    "create_only": 4,
    "full_access": 5
}

access_purpose_documented if {
    access_purpose := input.context.access_control.access_purpose
    access_purpose.documented == true
    access_purpose.approved == true
    access_purpose.reviewed_date
    access_purpose.next_review_date
}

compartmentalized_access_controlled if {
    compartment_access_verified
    special_access_program_compliance
    sensitive_compartmented_information_controls
    foreign_government_information_controls
}

compartment_access_verified if {
    resource_compartments := input.resource.classification.compartments
    
    count(resource_compartments) == 0
}

compartment_access_verified if {
    resource_compartments := input.resource.classification.compartments
    subject_id := input.context.security.subject_id
    subject_compartments := data.subjects[subject_id].security_clearance.compartments
    
    count(resource_compartments) > 0
    
    every compartment in resource_compartments {
        compartment in subject_compartments
    }
}

special_access_program_compliance if {
    resource_sap := input.resource.classification.special_access_program
    
    not resource_sap
}

special_access_program_compliance if {
    resource_sap := input.resource.classification.special_access_program
    resource_sap
    
    subject_id := input.context.security.subject_id
    subject_sap_access := data.subjects[subject_id].security_clearance.special_access_programs
    
    resource_sap in subject_sap_access
    sap_access_current(subject_id, resource_sap)
    sap_briefing_current(subject_id, resource_sap)
}

sap_access_current(subject_id, sap) if {
    sap_access := data.subjects[subject_id].security_clearance.sap_details[sap]
    current_time := time.now_ns()
    expiry_time := time.parse_rfc3339_ns(sap_access.expiry_date)
    
    current_time < expiry_time
}

sap_briefing_current(subject_id, sap) if {
    sap_briefing := data.subjects[subject_id].security_clearance.sap_briefings[sap]
    current_time := time.now_ns()
    briefing_time := time.parse_rfc3339_ns(sap_briefing.date)
    
    time_since_briefing := current_time - briefing_time
    max_briefing_age := 365 * 24 * 3600 * 1000000000
    
    time_since_briefing <= max_briefing_age
}

sensitive_compartmented_information_controls if {
    resource_sci := input.resource.classification.sci_controls
    
    count(resource_sci) == 0
}

sensitive_compartmented_information_controls if {
    resource_sci := input.resource.classification.sci_controls
    subject_id := input.context.security.subject_id
    subject_sci := data.subjects[subject_id].security_clearance.sci_access
    
    count(resource_sci) > 0
    
    every sci_control in resource_sci {
        sci_control in subject_sci
    }
    
    sci_indoctrination_current(subject_id)
    sci_polygraph_current(subject_id)
}

sci_indoctrination_current(subject_id) if {
    indoctrination := data.subjects[subject_id].security_clearance.sci_indoctrination
    current_time := time.now_ns()
    indoctrination_time := time.parse_rfc3339_ns(indoctrination.date)
    
    time_since_indoctrination := current_time - indoctrination_time
    max_indoctrination_age := 5 * 365 * 24 * 3600 * 1000000000
    
    time_since_indoctrination <= max_indoctrination_age
}

sci_polygraph_current(subject_id) if {
    polygraph := data.subjects[subject_id].security_clearance.polygraph
    polygraph.type == "lifestyle"
    
    current_time := time.now_ns()
    polygraph_time := time.parse_rfc3339_ns(polygraph.date)
    
    time_since_polygraph := current_time - polygraph_time
    max_polygraph_age := 5 * 365 * 24 * 3600 * 1000000000
    
    time_since_polygraph <= max_polygraph_age
}

foreign_government_information_controls if {
    resource_fgi := input.resource.classification.foreign_government_information
    
    not resource_fgi
}

foreign_government_information_controls if {
    resource_fgi := input.resource.classification.foreign_government_information
    resource_fgi
    
    fgi_handling_authorized
    fgi_dissemination_controls_enforced
    fgi_third_party_rule_respected
}

fgi_handling_authorized if {
    subject_id := input.context.security.subject_id
    subject_fgi_authorization := data.subjects[subject_id].security_clearance.fgi_authorization
    
    subject_fgi_authorization.authorized == true
    subject_fgi_authorization.current == true
    subject_fgi_authorization.countries_authorized
}

fgi_dissemination_controls_enforced if {
    dissemination_controls := input.context.classification.fgi_dissemination
    dissemination_controls.originator_control == true
    dissemination_controls.dissemination_list_maintained == true
    dissemination_controls.third_party_consent == true
}

fgi_third_party_rule_respected if {
    third_party_rule := input.context.classification.fgi_third_party
    third_party_rule.consent_obtained == true
    third_party_rule.limitations_respected == true
    third_party_rule.disclosure_restrictions == true
}

national_security_violations_detected if {
    unauthorized_disclosure_detected
}

national_security_violations_detected if {
    classification_violations_detected
}

national_security_violations_detected if {
    foreign_influence_detected
}

national_security_violations_detected if {
    insider_threat_indicators_present
}

unauthorized_disclosure_detected if {
    disclosure_violations := input.context.violations.unauthorized_disclosure
    count(disclosure_violations) > 0
}

classification_violations_detected if {
    classification_violations := input.context.violations.classification
    critical_violations := [violation | violation := classification_violations[_]; violation.severity == "critical"]
    count(critical_violations) > 0
}

foreign_influence_detected if {
    foreign_influence := input.context.security.foreign_influence_indicators
    foreign_influence.suspicious_contacts == true
}

foreign_influence_detected if {
    foreign_influence := input.context.security.foreign_influence_indicators
    foreign_influence.unexplained_wealth == true
}

foreign_influence_detected if {
    foreign_influence := input.context.security.foreign_influence_indicators
    foreign_influence.foreign_travel_unreported == true
}

insider_threat_indicators_present if {
    insider_threat := input.context.security.insider_threat_indicators
    
    behavioral_indicators := count([indicator | indicator := insider_threat.behavioral[_]; indicator == true])
    technical_indicators := count([indicator | indicator := insider_threat.technical[_]; indicator == true])
    
    behavioral_indicators >= 2
    technical_indicators >= 1
}

classification_level_insufficient if {
    subject_id := input.context.security.subject_id
    subject_clearance_level := data.subjects[subject_id].security_clearance.level
    required_clearance_level := determine_required_clearance_level
    
    clearance_hierarchy[subject_clearance_level] < clearance_hierarchy[required_clearance_level]
}


government_audit_log_entry := {
    "policy_id": metadata.policy_id,
    "tenant_id": input.tenant_id,
    "subject_id": input.context.security.subject_id,
    "resource": input.resource,
    "action": input.action,
    "decision": allow,
    "timestamp": time.now_ns(),
    "request_id": input.context.request_id,
    "trace_id": input.context.trace_id,
    "security_clearance_status": security_clearance_status,
    "classification_handling_status": classification_handling_status,
    "government_compliance_status": government_compliance_status,
    "access_control_status": access_control_status,
    "national_security_assessment": national_security_assessment,
    "compartment_access_status": compartment_access_status,
    "violation_summary": government_violation_summary
}

security_clearance_status := {
    "clearance_verified": security_clearance_verified,
    "clearance_level": data.subjects[input.context.security.subject_id].security_clearance.level,
    "required_level": determine_required_clearance_level,
    "clearance_current": clearance_status_current,
    "polygraph_status": {
        "required": polygraph_required(determine_required_clearance_level),
        "completed": data.subjects[input.context.security.subject_id].security_clearance.polygraph.completed,
        "current": data.subjects[input.context.security.subject_id].security_clearance.polygraph.current,
        "type": data.subjects[input.context.security.subject_id].security_clearance.polygraph.type
    },
    "background_investigation": {
        "completed": data.subjects[input.context.security.subject_id].security_clearance.background_investigation.completed,
        "current": data.subjects[input.context.security.subject_id].security_clearance.background_investigation.current,
        "type": data.subjects[input.context.security.subject_id].security_clearance.background_investigation.type
    },
    "continuous_monitoring": {
        "enrolled": data.subjects[input.context.security.subject_id].security_clearance.continuous_monitoring.enrolled,
        "active": data.subjects[input.context.security.subject_id].security_clearance.continuous_monitoring.active
    }
}

classification_handling_status := {
    "resource_classification": input.resource.classification,
    "marking_compliant": marking_requirements_met,
    "handling_compliant": handling_procedures_followed,
    "storage_compliant": storage_requirements_satisfied,
    "transmission_compliant": transmission_security_enforced,
    "destruction_compliant": destruction_procedures_compliant,
    "required_markings": classification_marking_requirements[input.resource.classification.level],
    "actual_markings": input.resource.classification.markings
}

government_compliance_status := {
    "fisma_compliant": federal_information_security_management_act_compliant,
    "privacy_act_compliant": privacy_act_compliant,
    "foia_compliant": freedom_of_information_act_compliant,
    "records_management_compliant": records_management_compliant,
    "cybersecurity_framework": cybersecurity_framework_implemented,
    "cdm_active": continuous_diagnostics_mitigation_active,
    "nist_800_53_implemented": nist_800_53_controls_implemented,
    "fips_140_2_verified": fips_140_2_compliance_verified,
    "common_criteria_evaluated": common_criteria_evaluation_completed,
    "itar_compliant": itar_compliance_enforced,
    "ear_compliant": ear_compliance_enforced
}

access_control_status := {
    "need_to_know_verified": access_need_to_know_verified,
    "official_duties_verified": official_duties_require_access,
    "minimum_access_applied": minimum_access_principle_applied,
    "access_purpose_documented": access_purpose_documented,
    "requested_access": input.context.access_control.requested_access,
    "minimum_required": determine_minimum_required_access,
    "justification": input.context.access_control.need_to_know_justification
}

national_security_assessment := {
    "risk_level": calculate_national_security_risk_level,
    "threat_indicators": {
        "unauthorized_disclosure": unauthorized_disclosure_detected,
        "classification_violations": classification_violations_detected,
        "foreign_influence": foreign_influence_detected,
        "insider_threat": insider_threat_indicators_present
    },
    "security_protocols": {
        "physical_security": physical_security_protocols_active,
        "personnel_security": personnel_security_protocols_enforced,
        "information_security": information_security_protocols_operational,
        "communications_security": communications_security_protocols_implemented,
        "operations_security": operations_security_protocols_maintained
    },
    "mitigation_measures": national_security_mitigation_measures
}

calculate_national_security_risk_level := "low" if {
    security_clearance_verified
    classification_handling_compliant
    not national_security_violations_detected
    access_need_to_know_verified
}

calculate_national_security_risk_level := "medium" if {
    security_clearance_verified
    classification_handling_compliant
    national_security_violations_detected
    access_need_to_know_verified
}

calculate_national_security_risk_level := "high" if {
    not security_clearance_verified
    classification_handling_compliant
    access_need_to_know_verified
}

calculate_national_security_risk_level := "critical" if {
    not security_clearance_verified
    not classification_handling_compliant
}

national_security_mitigation_measures := {
    "enhanced_monitoring": calculate_national_security_risk_level in {"medium", "high", "critical"},
    "additional_oversight": calculate_national_security_risk_level in {"high", "critical"},
    "immediate_review": calculate_national_security_risk_level == "critical",
    "access_suspension": national_security_violations_detected,
    "security_briefing": insider_threat_indicators_present,
    "counterintelligence_referral": foreign_influence_detected
}

compartment_access_status := {
    "compartment_access_verified": compartment_access_verified,
    "sap_compliance": special_access_program_compliance,
    "sci_controls": sensitive_compartmented_information_controls,
    "fgi_controls": foreign_government_information_controls,
    "resource_compartments": input.resource.classification.compartments,
    "subject_compartments": data.subjects[input.context.security.subject_id].security_clearance.compartments,
    "sap_programs": {
        "resource_sap": input.resource.classification.special_access_program,
        "subject_sap_access": data.subjects[input.context.security.subject_id].security_clearance.special_access_programs
    },
    "sci_details": {
        "resource_sci": input.resource.classification.sci_controls,
        "subject_sci": data.subjects[input.context.security.subject_id].security_clearance.sci_access,
        "indoctrination_current": sci_indoctrination_current(input.context.security.subject_id),
        "polygraph_current": sci_polygraph_current(input.context.security.subject_id)
    }
}

government_violation_summary := {
    "total_violations": count(input.context.violations.government_violations),
    "national_security_violations": count([v | v := input.context.violations.government_violations[_]; v.category == "national_security"]),
    "classification_violations": count([v | v := input.context.violations.government_violations[_]; v.category == "classification"]),
    "clearance_violations": count([v | v := input.context.violations.government_violations[_]; v.category == "clearance"]),
    "compliance_violations": count([v | v := input.context.violations.government_violations[_]; v.category == "compliance"]),
    "critical_violations": count([v | v := input.context.violations.government_violations[_]; v.severity == "critical"]),
    "violation_trends": analyze_violation_trends,
    "remediation_status": government_remediation_status
}

analyze_violation_trends := {
    "increasing": violation_trend_analysis.direction == "increasing",
    "stable": violation_trend_analysis.direction == "stable",
    "decreasing": violation_trend_analysis.direction == "decreasing",
    "trend_period_days": violation_trend_analysis.period_days,
    "trend_confidence": violation_trend_analysis.confidence
}

violation_trend_analysis := {
    "direction": input.context.violations.trend_analysis.direction,
    "period_days": input.context.violations.trend_analysis.period_days,
    "confidence": input.context.violations.trend_analysis.confidence
}

government_remediation_status := {
    "open_violations": count([v | v := input.context.violations.government_violations[_]; v.status == "open"]),
    "in_progress_violations": count([v | v := input.context.violations.government_violations[_]; v.status == "in_progress"]),
    "resolved_violations": count([v | v := input.context.violations.government_violations[_]; v.status == "resolved"]),
    "overdue_violations": count([v | v := input.context.violations.government_violations[_]; v.overdue == true]),
    "escalated_violations": count([v | v := input.context.violations.government_violations[_]; v.escalated == true])
}

security_incident_reporting := {
    "incident_detected": national_security_violations_detected,
    "incident_type": determine_incident_type,
    "incident_severity": determine_incident_severity,
    "reporting_required": incident_reporting_required,
    "reporting_timeline": determine_reporting_timeline,
    "notification_authorities": determine_notification_authorities
}

determine_incident_type := "unauthorized_disclosure" if {
    unauthorized_disclosure_detected
}

determine_incident_type := "classification_violation" if {
    classification_violations_detected
    not unauthorized_disclosure_detected
}

determine_incident_type := "foreign_influence" if {
    foreign_influence_detected
    not unauthorized_disclosure_detected
    not classification_violations_detected
}

determine_incident_type := "insider_threat" if {
    insider_threat_indicators_present
    not unauthorized_disclosure_detected
    not classification_violations_detected
    not foreign_influence_detected
}

determine_incident_severity := "critical" if {
    unauthorized_disclosure_detected
    input.resource.classification.level in {"top_secret", "top_secret_sci", "top_secret_sap"}
}

determine_incident_severity := "high" if {
    classification_violations_detected
    input.resource.classification.level in {"secret", "top_secret"}
}

determine_incident_severity := "medium" if {
    foreign_influence_detected
}

determine_incident_severity := "low" if {
    insider_threat_indicators_present
    not foreign_influence_detected
}

incident_reporting_required if {
    national_security_violations_detected
}

determine_reporting_timeline := "immediate" if {
    determine_incident_severity == "critical"
}

determine_reporting_timeline := "within_24_hours" if {
    determine_incident_severity == "high"
}

determine_reporting_timeline := "within_72_hours" if {
    determine_incident_severity == "medium"
}

determine_reporting_timeline := "within_7_days" if {
    determine_incident_severity == "low"
}

determine_notification_authorities := authorities if {
    incident_type := determine_incident_type
    incident_severity := determine_incident_severity
    
    authorities := notification_matrix[incident_type][incident_severity]
}

notification_matrix := {
    "unauthorized_disclosure": {
        "critical": ["fbi", "cia", "nsa", "dod_ig", "congress"],
        "high": ["fbi", "agency_ig", "security_office"],
        "medium": ["agency_ig", "security_office"],
        "low": ["security_office"]
    },
    "classification_violation": {
        "critical": ["security_office", "agency_ig", "isoo"],
        "high": ["security_office", "agency_ig"],
        "medium": ["security_office"],
        "low": ["security_office"]
    },
    "foreign_influence": {
        "critical": ["fbi", "ci_office", "security_office"],
        "high": ["fbi", "ci_office", "security_office"],
        "medium": ["ci_office", "security_office"],
        "low": ["security_office"]
    },
    "insider_threat": {
        "critical": ["fbi", "insider_threat_office", "security_office"],
        "high": ["insider_threat_office", "security_office"],
        "medium": ["insider_threat_office", "security_office"],
        "low": ["security_office"]
    }
}

final_government_decision := {
    "allow": allow,
    "deny": deny,
    "tenant_id": input.tenant_id,
    "resource": input.resource,
    "action": input.action,
    "security_clearance_status": security_clearance_status,
    "classification_handling_status": classification_handling_status,
    "government_compliance_status": government_compliance_status,
    "access_control_status": access_control_status,
    "national_security_assessment": national_security_assessment,
    "compartment_access_status": compartment_access_status,
    "violation_summary": government_violation_summary,
    "security_incident_reporting": security_incident_reporting,
    "audit_log": government_audit_log_entry,
    "recommendations": government_recommendations,
    "evaluation_time_ms": (time.now_ns() - time.parse_rfc3339_ns(input.context.timestamp)) / 1000000
}

government_recommendations := {
    "clearance_improvements": clearance_improvement_recommendations,
    "classification_enhancements": classification_enhancement_recommendations,
    "compliance_strengthening": compliance_strengthening_recommendations,
    "security_protocol_updates": security_protocol_recommendations
}

clearance_improvement_recommendations := [recommendation |
    not security_clearance_verified
    recommendation := "Update security clearance and complete required investigations"
]

clearance_improvement_recommendations := [recommendation |
    not polygraph_requirements_met
    recommendation := "Complete required polygraph examination"
]

classification_enhancement_recommendations := [recommendation |
    not marking_requirements_met
    recommendation := "Ensure proper classification markings are applied"
]

classification_enhancement_recommendations := [recommendation |
    not handling_procedures_followed
    recommendation := "Implement proper classification handling procedures"
]

compliance_strengthening_recommendations := [recommendation |
    not federal_information_security_management_act_compliant
    recommendation := "Strengthen FISMA compliance framework"
]

compliance_strengthening_recommendations := [recommendation |
    not nist_800_53_controls_implemented
    recommendation := "Implement missing NIST 800-53 security controls"
]

security_protocol_recommendations := [recommendation |
    not physical_security_protocols_active
    recommendation := "Enhance physical security protocols and procedures"
]

security_protocol_recommendations := [recommendation |
    insider_threat_indicators_present
    recommendation := "Implement enhanced insider threat monitoring"
]

allow if {
    security_clearance_verified
    classification_handling_compliant
    government_compliance_met
    not national_security_violations_detected
    federal_regulations_enforced
    security_protocols_implemented
    access_need_to_know_verified
    compartmentalized_access_controlled
    calculate_national_security_risk_level in {"low", "medium"}
}
