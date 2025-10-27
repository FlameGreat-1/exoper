package healthcare.template

import future.keywords.if
import future.keywords.in
import future.keywords.every
import future.keywords.contains

default allow := false
default deny := true
default hipaa_compliance_verified := false
default patient_privacy_protected := false
default healthcare_compliance_met := false

metadata := {
    "policy_id": "healthcare-template",
    "version": "1.0.0",
    "description": "Healthcare-grade authorization template with HIPAA compliance and patient privacy protection",
    "priority": 10,
    "effect": "allow",
    "created_by": "system",
    "tags": ["healthcare", "hipaa", "patient_privacy", "medical_data", "clinical", "phi"]
}

allow if {
    hipaa_compliance_verified
    patient_privacy_protected
    healthcare_compliance_met
    not patient_safety_violations_detected
    clinical_workflows_authorized
    medical_data_governance_enforced
    healthcare_security_standards_met
    provider_credentials_validated
}

deny if {
    patient_safety_violations_detected
}

deny if {
    not hipaa_compliance_verified
}

deny if {
    unauthorized_phi_access_attempt
}

hipaa_compliance_verified if {
    hipaa_administrative_safeguards_implemented
    hipaa_physical_safeguards_implemented
    hipaa_technical_safeguards_implemented
    hipaa_breach_notification_procedures_established
    hipaa_business_associate_agreements_current
    hipaa_risk_assessment_completed
}

hipaa_administrative_safeguards_implemented if {
    admin_safeguards := input.context.hipaa.administrative_safeguards
    admin_safeguards.security_officer_assigned == true
    admin_safeguards.workforce_training_completed == true
    admin_safeguards.access_management_procedures == true
    admin_safeguards.information_access_management == true
    admin_safeguards.security_awareness_training == true
    admin_safeguards.security_incident_procedures == true
    admin_safeguards.contingency_plan_exists == true
    admin_safeguards.regular_security_evaluations == true
    admin_safeguards.business_associate_contracts == true
}

hipaa_physical_safeguards_implemented if {
    physical_safeguards := input.context.hipaa.physical_safeguards
    physical_safeguards.facility_access_controls == true
    physical_safeguards.workstation_use_restrictions == true
    physical_safeguards.device_media_controls == true
    physical_safeguards.workstation_security == true
    physical_safeguards.device_controls == true
    physical_safeguards.media_reuse_controls == true
    physical_safeguards.data_backup_storage == true
    physical_safeguards.data_disposal_procedures == true
}

hipaa_technical_safeguards_implemented if {
    technical_safeguards := input.context.hipaa.technical_safeguards
    technical_safeguards.access_control == true
    technical_safeguards.audit_controls == true
    technical_safeguards.integrity == true
    technical_safeguards.person_authentication == true
    technical_safeguards.transmission_security == true
    technical_safeguards.automatic_logoff == true
    technical_safeguards.encryption_decryption == true
}

hipaa_breach_notification_procedures_established if {
    breach_procedures := input.context.hipaa.breach_notification
    breach_procedures.detection_procedures == true
    breach_procedures.assessment_procedures == true
    breach_procedures.notification_procedures == true
    breach_procedures.documentation_procedures == true
    breach_procedures.patient_notification_procedures == true
    breach_procedures.hhs_notification_procedures == true
    breach_procedures.media_notification_procedures == true
    breach_procedures.business_associate_notification == true
}

hipaa_business_associate_agreements_current if {
    baa := input.context.hipaa.business_associate_agreements
    baa.agreements_in_place == true
    baa.agreements_current == true
    baa.compliance_monitoring == true
    baa.breach_notification_requirements == true
    baa.data_return_destruction_procedures == true
}

hipaa_risk_assessment_completed if {
    risk_assessment := input.context.hipaa.risk_assessment
    risk_assessment.conducted_annually == true
    risk_assessment.documented == true
    risk_assessment.vulnerabilities_identified == true
    risk_assessment.mitigation_plans_implemented == true
    risk_assessment.regular_updates == true
}

patient_privacy_protected if {
    phi_access_controls_enforced
    minimum_necessary_standard_applied
    patient_consent_management_compliant
    patient_rights_procedures_established
    privacy_notice_requirements_met
    marketing_communications_controlled
}

phi_access_controls_enforced if {
    phi_access := input.context.patient_privacy.phi_access_controls
    phi_access.role_based_access == true
    phi_access.user_authentication == true
    phi_access.access_logging == true
    phi_access.session_management == true
    phi_access.data_encryption == true
    phi_access.audit_trails == true
    phi_access.access_termination_procedures == true
}

minimum_necessary_standard_applied if {
    action := input.action
    resource_type := input.resource.type
    subject_role := data.subjects[input.context.security.subject_id].healthcare_role
    
    access_level_appropriate := minimum_necessary_matrix[subject_role][resource_type][action]
    access_level_appropriate == true
    
    data_minimization_applied
    purpose_limitation_enforced
}

minimum_necessary_matrix := {
    "physician": {
        "patient_record": {
            "read": true,
            "create": true,
            "update": true,
            "delete": false
        },
        "medical_image": {
            "read": true,
            "create": true,
            "update": false,
            "delete": false
        },
        "lab_result": {
            "read": true,
            "create": true,
            "update": true,
            "delete": false
        },
        "prescription": {
            "read": true,
            "create": true,
            "update": true,
            "delete": false
        }
    },
    "nurse": {
        "patient_record": {
            "read": true,
            "create": false,
            "update": true,
            "delete": false
        },
        "medical_image": {
            "read": true,
            "create": false,
            "update": false,
            "delete": false
        },
        "lab_result": {
            "read": true,
            "create": false,
            "update": false,
            "delete": false
        },
        "prescription": {
            "read": true,
            "create": false,
            "update": false,
            "delete": false
        }
    },
    "pharmacist": {
        "patient_record": {
            "read": false,
            "create": false,
            "update": false,
            "delete": false
        },
        "medical_image": {
            "read": false,
            "create": false,
            "update": false,
            "delete": false
        },
        "lab_result": {
            "read": false,
            "create": false,
            "update": false,
            "delete": false
        },
        "prescription": {
            "read": true,
            "create": false,
            "update": true,
            "delete": false
        }
    },
    "lab_technician": {
        "patient_record": {
            "read": false,
            "create": false,
            "update": false,
            "delete": false
        },
        "medical_image": {
            "read": false,
            "create": false,
            "update": false,
            "delete": false
        },
        "lab_result": {
            "read": true,
            "create": true,
            "update": true,
            "delete": false
        },
        "prescription": {
            "read": false,
            "create": false,
            "update": false,
            "delete": false
        }
    },
    "radiologist": {
        "patient_record": {
            "read": true,
            "create": false,
            "update": false,
            "delete": false
        },
        "medical_image": {
            "read": true,
            "create": true,
            "update": true,
            "delete": false
        },
        "lab_result": {
            "read": false,
            "create": false,
            "update": false,
            "delete": false
        },
        "prescription": {
            "read": false,
            "create": false,
            "update": false,
            "delete": false
        }
    },
    "administrator": {
        "patient_record": {
            "read": false,
            "create": false,
            "update": false,
            "delete": false
        },
        "medical_image": {
            "read": false,
            "create": false,
            "update": false,
            "delete": false
        },
        "lab_result": {
            "read": false,
            "create": false,
            "update": false,
            "delete": false
        },
        "prescription": {
            "read": false,
            "create": false,
            "update": false,
            "delete": false
        }
    },
    "researcher": {
        "patient_record": {
            "read": true,
            "create": false,
            "update": false,
            "delete": false
        },
        "medical_image": {
            "read": true,
            "create": false,
            "update": false,
            "delete": false
        },
        "lab_result": {
            "read": true,
            "create": false,
            "update": false,
            "delete": false
        },
        "prescription": {
            "read": true,
            "create": false,
            "update": false,
            "delete": false
        }
    }
}

data_minimization_applied if {
    data_scope := input.context.data_access.scope
    data_scope.limited_to_necessary_fields == true
    data_scope.time_limited_access == true
    data_scope.purpose_specific == true
}

purpose_limitation_enforced if {
    access_purpose := input.context.data_access.purpose
    access_purpose in valid_healthcare_purposes
    purpose_documented_and_approved(access_purpose)
}

valid_healthcare_purposes := {
    "treatment",
    "payment",
    "healthcare_operations",
    "public_health",
    "research",
    "quality_assurance",
    "patient_safety",
    "compliance",
    "emergency_care"
}

purpose_documented_and_approved(purpose) if {
    purpose_documentation := input.context.data_access.purpose_documentation
    purpose_documentation.documented == true
    purpose_documentation.approved == true
    purpose_documentation.approval_date
    purpose_documentation.approver_authorized == true
}

patient_consent_management_compliant if {
    consent_requirements := determine_consent_requirements
    consent_obtained_appropriately(consent_requirements)
    consent_current_and_valid
    consent_withdrawal_procedures_available
}

determine_consent_requirements := requirements if {
    access_purpose := input.context.data_access.purpose
    data_sensitivity := input.resource.sensitivity_level
    
    requirements := consent_requirements_matrix[access_purpose][data_sensitivity]
}

consent_requirements_matrix := {
    "treatment": {
        "low": "implied_consent",
        "medium": "implied_consent",
        "high": "explicit_consent"
    },
    "payment": {
        "low": "implied_consent",
        "medium": "implied_consent",
        "high": "explicit_consent"
    },
    "healthcare_operations": {
        "low": "implied_consent",
        "medium": "explicit_consent",
        "high": "explicit_consent"
    },
    "research": {
        "low": "explicit_consent",
        "medium": "explicit_consent",
        "high": "irb_approval"
    },
    "public_health": {
        "low": "no_consent_required",
        "medium": "no_consent_required",
        "high": "explicit_consent"
    },
    "quality_assurance": {
        "low": "implied_consent",
        "medium": "explicit_consent",
        "high": "explicit_consent"
    }
}

consent_obtained_appropriately(requirements) if {
    requirements == "no_consent_required"
}

consent_obtained_appropriately(requirements) if {
    requirements == "implied_consent"
    patient_consent := input.context.patient_consent
    patient_consent.general_consent_on_file == true
}

consent_obtained_appropriately(requirements) if {
    requirements == "explicit_consent"
    patient_consent := input.context.patient_consent
    patient_consent.specific_consent_obtained == true
    patient_consent.informed_consent == true
    patient_consent.voluntary_consent == true
}

consent_obtained_appropriately(requirements) if {
    requirements == "irb_approval"
    irb_approval := input.context.research.irb_approval
    irb_approval.approved == true
    irb_approval.current == true
    irb_approval.waiver_of_consent_granted == true
}

consent_current_and_valid if {
    patient_consent := input.context.patient_consent
    current_time := time.now_ns()
    consent_date := time.parse_rfc3339_ns(patient_consent.consent_date)
    
    time_since_consent := current_time - consent_date
    max_consent_age := 365 * 24 * 3600 * 1000000000
    
    time_since_consent <= max_consent_age
    patient_consent.consent_valid == true
    not patient_consent.consent_withdrawn
}

consent_withdrawal_procedures_available if {
    withdrawal_procedures := input.context.patient_consent.withdrawal_procedures
    withdrawal_procedures.procedures_documented == true
    withdrawal_procedures.easily_accessible == true
    withdrawal_procedures.no_penalty_for_withdrawal == true
    withdrawal_procedures.partial_withdrawal_supported == true
}

patient_rights_procedures_established if {
    patient_rights := input.context.patient_privacy.patient_rights
    patient_rights.right_to_access == true
    patient_rights.right_to_amend == true
    patient_rights.right_to_accounting_of_disclosures == true
    patient_rights.right_to_request_restrictions == true
    patient_rights.right_to_request_confidential_communications == true
    patient_rights.right_to_complain == true
    patient_rights.procedures_documented == true
    patient_rights.staff_trained == true
}

privacy_notice_requirements_met if {
    privacy_notice := input.context.patient_privacy.privacy_notice
    privacy_notice.provided_to_patients == true
    privacy_notice.comprehensive == true
    privacy_notice.plain_language == true
    privacy_notice.updated_when_required == true
    privacy_notice.acknowledgment_obtained == true
    privacy_notice.posted_prominently == true
}

marketing_communications_controlled if {
    marketing := input.context.patient_privacy.marketing
    marketing.authorization_required == true
    marketing.opt_out_procedures == true
    marketing.financial_remuneration_disclosed == true
    marketing.treatment_communications_exempt == true
}

healthcare_compliance_met if {
    hitech_act_compliance_verified
    fda_regulations_compliant
    dea_regulations_compliant
    state_medical_board_requirements_met
    joint_commission_standards_met
    cms_conditions_of_participation_satisfied
    oig_compliance_program_implemented
}

hitech_act_compliance_verified if {
    hitech := input.context.healthcare_compliance.hitech_act
    hitech.breach_notification_enhanced == true
    hitech.business_associate_liability == true
    hitech.audit_controls_strengthened == true
    hitech.access_controls_enhanced == true
    hitech.integrity_controls_implemented == true
    hitech.transmission_security_enhanced == true
    hitech.meaningful_use_requirements == true
}

fda_regulations_compliant if {
    fda := input.context.healthcare_compliance.fda
    
    not fda_regulated_activity
}

fda_regulations_compliant if {
    fda := input.context.healthcare_compliance.fda
    fda_regulated_activity
    
    fda.good_clinical_practice == true
    fda.clinical_trial_regulations == true
    fda.medical_device_regulations == true
    fda.drug_safety_reporting == true
    fda.quality_system_regulation == true
    fda.validation_requirements == true
}

fda_regulated_activity if {
    activity_type := input.context.clinical.activity_type
    activity_type in fda_regulated_activities
}

fda_regulated_activities := {
    "clinical_trial",
    "medical_device_testing",
    "drug_development",
    "diagnostic_testing",
    "medical_software_validation"
}

dea_regulations_compliant if {
    dea := input.context.healthcare_compliance.dea
    
    not controlled_substance_involved
}

dea_regulations_compliant if {
    dea := input.context.healthcare_compliance.dea
    controlled_substance_involved
    
    dea.registration_current == true
    dea.security_requirements_met == true
    dea.record_keeping_compliant == true
    dea.inventory_controls == true
    dea.prescription_monitoring == true
    dea.theft_loss_reporting == true
}

controlled_substance_involved if {
    resource_type := input.resource.type
    resource_type == "prescription"
    
    medication_schedule := input.resource.medication.schedule
    medication_schedule in controlled_schedules
}

controlled_schedules := {"I", "II", "III", "IV", "V"}

state_medical_board_requirements_met if {
    medical_board := input.context.healthcare_compliance.state_medical_board
    medical_board.licensing_current == true
    medical_board.continuing_education_current == true
    medical_board.disciplinary_actions_clear == true
    medical_board.scope_of_practice_compliant == true
    medical_board.supervision_requirements_met == true
}

joint_commission_standards_met if {
    joint_commission := input.context.healthcare_compliance.joint_commission
    joint_commission.patient_safety_goals == true
    joint_commission.performance_improvement == true
    joint_commission.leadership_standards == true
    joint_commission.human_resources_standards == true
    joint_commission.information_management_standards == true
    joint_commission.infection_prevention_control == true
    joint_commission.medication_management == true
}

cms_conditions_of_participation_satisfied if {
    cms := input.context.healthcare_compliance.cms
    cms.governing_body_requirements == true
    cms.medical_staff_requirements == true
    cms.nursing_services_requirements == true
    cms.medical_record_services == true
    cms.pharmaceutical_services == true
    cms.radiology_services == true
    cms.laboratory_services == true
    cms.food_dietetic_services == true
    cms.utilization_review == true
    cms.quality_assurance_performance_improvement == true
}

oig_compliance_program_implemented if {
    oig := input.context.healthcare_compliance.oig
    oig.compliance_program_established == true
    oig.compliance_officer_designated == true
    oig.training_education_program == true
    oig.effective_communication == true
    oig.auditing_monitoring == true
    oig.response_to_violations == true
    oig.corrective_action_procedures == true
}

clinical_workflows_authorized if {
    clinical_role_authorization_verified
    clinical_competency_validated
    clinical_supervision_requirements_met
    clinical_documentation_standards_enforced
    clinical_decision_support_compliant
    medication_administration_controls_active
}

clinical_role_authorization_verified if {
    subject_id := input.context.security.subject_id
    healthcare_role := data.subjects[subject_id].healthcare_role
    clinical_privileges := data.subjects[subject_id].clinical_privileges
    
    role_authorized_for_action(healthcare_role, input.action, input.resource.type)
    privileges_current_and_valid(clinical_privileges)
    scope_of_practice_compliant(healthcare_role, input.action)
}

role_authorized_for_action(role, action, resource_type) if {
    authorization_matrix[role][resource_type][action] == true
}

authorization_matrix := {
    "attending_physician": {
        "patient_record": {
            "read": true,
            "create": true,
            "update": true,
            "delete": false,
            "sign": true,
            "cosign": true
        },
        "prescription": {
            "read": true,
            "create": true,
            "update": true,
            "delete": true,
            "sign": true
        },
        "lab_order": {
            "read": true,
            "create": true,
            "update": true,
            "delete": true,
            "sign": true
        },
        "imaging_order": {
            "read": true,
            "create": true,
            "update": true,
            "delete": true,
            "sign": true
        }
    },
    "resident_physician": {
        "patient_record": {
            "read": true,
            "create": true,
            "update": true,
            "delete": false,
            "sign": false,
            "cosign": false
        },
        "prescription": {
            "read": true,
            "create": true,
            "update": true,
            "delete": false,
            "sign": false
        },
        "lab_order": {
            "read": true,
            "create": true,
            "update": true,
            "delete": false,
            "sign": false
        },
        "imaging_order": {
            "read": true,
            "create": true,
            "update": true,
            "delete": false,
            "sign": false
        }
    },
    "nurse_practitioner": {
        "patient_record": {
            "read": true,
            "create": true,
            "update": true,
            "delete": false,
            "sign": true,
            "cosign": false
        },
        "prescription": {
            "read": true,
            "create": true,
            "update": true,
            "delete": true,
            "sign": true
        },
        "lab_order": {
            "read": true,
            "create": true,
            "update": true,
            "delete": true,
            "sign": true
        },
        "imaging_order": {
            "read": true,
            "create": false,
            "update": false,
            "delete": false,
            "sign": false
        }
    },
    "registered_nurse": {
        "patient_record": {
            "read": true,
            "create": false,
            "update": true,
            "delete": false,
            "sign": false,
            "cosign": false
        },
        "prescription": {
            "read": true,
            "create": false,
            "update": false,
            "delete": false,
            "sign": false
        },
        "medication_administration": {
            "read": true,
            "create": true,
            "update": true,
            "delete": false,
            "sign": true
        }
    }
}

privileges_current_and_valid(privileges) if {
    privileges.active == true
    privileges.current == true
    privileges.credentialing_complete == true
    privileges.peer_review_current == true
    
    current_time := time.now_ns()
    expiry_time := time.parse_rfc3339_ns(privileges.expiry_date)
    current_time < expiry_time
}

scope_of_practice_compliant(role, action) if {
    scope_requirements := scope_of_practice_matrix[role]
    action_requirements := scope_requirements[action]
    
    not action_requirements
}

scope_of_practice_compliant(role, action) if {
    scope_requirements := scope_of_practice_matrix[role]
    action_requirements := scope_requirements[action]
    action_requirements
    
    requirements_met(action_requirements)
}

scope_of_practice_matrix := {
    "resident_physician": {
        "prescribe_controlled_substances": {
            "supervision_required": true,
            "dea_registration": false,
            "attending_cosign": true
        },
        "perform_procedures": {
            "supervision_required": true,
            "competency_validated": true,
            "attending_oversight": true
        }
    },
    "nurse_practitioner": {
        "prescribe_controlled_substances": {
            "supervision_required": false,
            "dea_registration": true,
            "state_authorization": true
        },
        "diagnose_conditions": {
            "scope_limitations": true,
            "collaborative_agreement": true
        }
    }
}

requirements_met(requirements) if {
    every requirement, value in requirements {
        not value
    }
}

requirements_met(requirements) if {
    every requirement, value in requirements {
        value
        input.context.clinical[requirement] == true
    }
}

clinical_competency_validated if {
    subject_id := input.context.security.subject_id
    competency_records := data.subjects[subject_id].competency_records
    action := input.action
    resource_type := input.resource.type
    
    competency_required := competency_requirements_matrix[action][resource_type]
    
    not competency_required
}

clinical_competency_validated if {
    subject_id := input.context.security.subject_id
    competency_records := data.subjects[subject_id].competency_records
    action := input.action
    resource_type := input.resource.type
    
    competency_required := competency_requirements_matrix[action][resource_type]
    competency_required
    
    competency_validated(competency_records, action, resource_type)
}

competency_requirements_matrix := {
    "administer_medication": {
        "high_risk_medication": true,
        "controlled_substance": true,
        "chemotherapy": true,
        "blood_products": true
    },
    "perform_procedure": {
        "invasive_procedure": true,
        "surgical_procedure": true,
        "diagnostic_procedure": true
    },
    "operate_equipment": {
        "life_support_equipment": true,
        "imaging_equipment": true,
        "monitoring_equipment": true
    }
}

competency_validated(records, action, resource_type) if {
    competency_key := sprintf("%s_%s", [action, resource_type])
    competency_record := records[competency_key]
    
    competency_record.validated == true
    competency_record.current == true
    competency_record.assessment_passed == true
    
    current_time := time.now_ns()
    validation_date := time.parse_rfc3339_ns(competency_record.validation_date)
    time_since_validation := current_time - validation_date
    max_validation_age := 365 * 24 * 3600 * 1000000000
    
    time_since_validation <= max_validation_age
}

clinical_supervision_requirements_met if {
    supervision_required := determine_supervision_requirements
    
    not supervision_required
}

clinical_supervision_requirements_met if {
    supervision_required := determine_supervision_requirements
    supervision_required
    
    supervision_provided_appropriately
}

determine_supervision_requirements := required if {
    subject_id := input.context.security.subject_id
    healthcare_role := data.subjects[subject_id].healthcare_role
    action := input.action
    resource_type := input.resource.type
    
    required := supervision_matrix[healthcare_role][action][resource_type]
}

supervision_matrix := {
    "medical_student": {
        "create": {
            "patient_record": true,
            "prescription": true,
            "lab_order": true
        },
        "update": {
            "patient_record": true,
            "prescription": true
        }
    },
    "resident_physician": {
        "create": {
            "prescription": true,
            "surgical_order": true
        },
        "perform": {
            "major_procedure": true,
            "surgery": true
        }
    },
    "physician_assistant": {
        "create": {
            "controlled_substance_prescription": true
        },
        "perform": {
            "complex_procedure": true
        }
    }
}

supervision_provided_appropriately if {
    supervision := input.context.clinical.supervision
    supervision.supervisor_present == true
    supervision.supervisor_qualified == true
    supervision.supervision_documented == true
    supervision.real_time_oversight == true
}

clinical_documentation_standards_enforced if {
    documentation := input.context.clinical.documentation
    documentation.timely_documentation == true
    documentation.accurate_documentation == true
    documentation.complete_documentation == true
    documentation.legible_documentation == true
    documentation.authenticated_documentation == true
    documentation.error_correction_procedures == true
    documentation.retention_requirements_met == true
}

clinical_decision_support_compliant if {
    cds := input.context.clinical.decision_support
    cds.drug_interaction_checking == true
    cds.allergy_checking == true
    cds.dosage_checking == true
    cds.clinical_guidelines_integration == true
    cds.evidence_based_recommendations == true
    cds.alert_fatigue_management == true
}

medication_administration_controls_active if {
    medication_controls := input.context.clinical.medication_controls
    medication_controls.five_rights_verification == true
    medication_controls.barcode_scanning == true
    medication_controls.double_verification_high_risk == true
    medication_controls.allergy_verification == true
    medication_controls.contraindication_checking == true
    medication_controls.administration_documentation == true
    medication_controls.adverse_event_monitoring == true
}

medical_data_governance_enforced if {
    medical_data_classification_implemented
    clinical_data_quality_standards_met
    medical_record_lifecycle_management_active
    research_data_governance_compliant
    medical_device_data_governance_enforced
    interoperability_standards_implemented
}

medical_data_classification_implemented if {
    data_classification := input.context.medical_data_governance.classification
    data_classification.phi_identified == true
    data_classification.sensitivity_levels_assigned == true
    data_classification.handling_instructions_defined == true
    data_classification.access_controls_mapped == true
    data_classification.retention_periods_defined == true
    data_classification.disposal_procedures_established == true
}

clinical_data_quality_standards_met if {
    data_quality := input.context.medical_data_governance.data_quality
    data_quality.accuracy_validation == true
    data_quality.completeness_checking == true
    data_quality.consistency_verification == true
    data_quality.timeliness_monitoring == true
    data_quality.validity_checking == true
    data_quality.uniqueness_verification == true
    data_quality.integrity_controls == true
}

medical_record_lifecycle_management_active if {
    lifecycle_mgmt := input.context.medical_data_governance.lifecycle_management
    lifecycle_mgmt.creation_standards == true
    lifecycle_mgmt.maintenance_procedures == true
    lifecycle_mgmt.access_controls == true
    lifecycle_mgmt.retention_schedules == true
    lifecycle_mgmt.archival_procedures == true
    lifecycle_mgmt.destruction_procedures == true
    lifecycle_mgmt.legal_hold_procedures == true
}

research_data_governance_compliant if {
    research_governance := input.context.medical_data_governance.research_governance
    
    not research_data_involved
}

research_data_governance_compliant if {
    research_governance := input.context.medical_data_governance.research_governance
    research_data_involved
    
    research_governance.irb_approval_current == true
    research_governance.informed_consent_obtained == true
    research_governance.data_use_agreements == true
    research_governance.de_identification_procedures == true
    research_governance.data_sharing_controls == true
    research_governance.publication_review_procedures == true
}

research_data_involved if {
    data_purpose := input.context.data_access.purpose
    data_purpose == "research"
}

medical_device_data_governance_enforced if {
    device_governance := input.context.medical_data_governance.device_governance
    
    not medical_device_data_involved
}

medical_device_data_governance_enforced if {
    device_governance := input.context.medical_data_governance.device_governance
    medical_device_data_involved
    
    device_governance.device_validation == true
    device_governance.data_integrity_controls == true
    device_governance.cybersecurity_controls == true
    device_governance.interoperability_standards == true
    device_governance.maintenance_procedures == true
    device_governance.incident_response_procedures == true
}

medical_device_data_involved if {
    resource_type := input.resource.type
    resource_type in medical_device_types
}

medical_device_types := {
    "medical_image",
    "monitoring_data",
    "diagnostic_data",
    "therapeutic_data",
    "implant_data",
    "wearable_data"
}

interoperability_standards_implemented if {
    interoperability := input.context.medical_data_governance.interoperability
    interoperability.hl7_fhir_compliance == true
    interoperability.dicom_compliance == true
    interoperability.ihe_profiles_implemented == true
    interoperability.terminology_standards == true
    interoperability.data_exchange_agreements == true
    interoperability.semantic_interoperability == true
}

healthcare_security_standards_met if {
    nist_cybersecurity_framework_healthcare_implemented
    healthcare_specific_security_controls_active
    medical_device_cybersecurity_enforced
    cloud_security_healthcare_compliant
    incident_response_healthcare_specific
    business_continuity_healthcare_focused
}

nist_cybersecurity_framework_healthcare_implemented if {
    nist_healthcare := input.context.healthcare_security.nist_framework
    nist_healthcare.identify_function_healthcare == true
    nist_healthcare.protect_function_healthcare == true
    nist_healthcare.detect_function_healthcare == true
    nist_healthcare.respond_function_healthcare == true
    nist_healthcare.recover_function_healthcare == true
    nist_healthcare.healthcare_sector_guidance == true
}

healthcare_specific_security_controls_active if {
    security_controls := input.context.healthcare_security.specific_controls
    security_controls.patient_matching_controls == true
    security_controls.clinical_decision_support_security == true
    security_controls.medication_management_security == true
    security_controls.medical_imaging_security == true
    security_controls.laboratory_information_security == true
    security_controls.telehealth_security == true
    security_controls.mobile_health_security == true
}

medical_device_cybersecurity_enforced if {
    device_security := input.context.healthcare_security.medical_device_security
    device_security.device_inventory_maintained == true
    device_security.vulnerability_management == true
    device_security.patch_management == true
    device_security.network_segmentation == true
    device_security.access_controls == true
    device_security.monitoring_logging == true
    device_security.incident_response == true
}

cloud_security_healthcare_compliant if {
    cloud_security := input.context.healthcare_security.cloud_security
    cloud_security.hipaa_compliant_cloud == true
    cloud_security.business_associate_agreements == true
    cloud_security.data_encryption == true
    cloud_security.access_controls == true
    cloud_security.audit_logging == true
    cloud_security.backup_recovery == true
    cloud_security.geographic_restrictions == true
}

incident_response_healthcare_specific if {
    incident_response := input.context.healthcare_security.incident_response
    incident_response.healthcare_incident_types == true
    incident_response.patient_safety_considerations == true
    incident_response.clinical_operations_continuity == true
    incident_response.regulatory_notification_procedures == true
    incident_response.media_communication_procedures == true
    incident_response.patient_notification_procedures == true
}

business_continuity_healthcare_focused if {
    business_continuity := input.context.healthcare_security.business_continuity
    business_continuity.clinical_operations_continuity == true
    business_continuity.patient_care_continuity == true
    business_continuity.emergency_procedures == true
    business_continuity.disaster_recovery == true
    business_continuity.backup_systems == true
    business_continuity.communication_procedures == true
}

provider_credentials_validated if {
    medical_license_verification_current
    board_certification_validated
    hospital_privileges_current
    malpractice_insurance_verified
    background_check_completed
    continuing_education_current
    peer_review_satisfactory
}

medical_license_verification_current if {
    subject_id := input.context.security.subject_id
    medical_license := data.subjects[subject_id].medical_license
    
    medical_license.active == true
    medical_license.verified == true
    medical_license.state_issued == true
    medical_license.unrestricted == true
    
    current_time := time.now_ns()
    expiry_time := time.parse_rfc3339_ns(medical_license.expiry_date)
    current_time < expiry_time
    
    license_verification_current(medical_license)
}

license_verification_current(license) if {
    verification := license.verification
    current_time := time.now_ns()
    verification_date := time.parse_rfc3339_ns(verification.last_verified_date)
    
    time_since_verification := current_time - verification_date
    max_verification_age := 30 * 24 * 3600 * 1000000000
    
    time_since_verification <= max_verification_age
}

board_certification_validated if {
    subject_id := input.context.security.subject_id
    board_certification := data.subjects[subject_id].board_certification
    
    not board_certification_required
}

board_certification_validated if {
    subject_id := input.context.security.subject_id
    board_certification := data.subjects[subject_id].board_certification
    board_certification_required
    
    board_certification.certified == true
    board_certification.current == true
    board_certification.specialty_appropriate == true
    
    current_time := time.now_ns()
    expiry_time := time.parse_rfc3339_ns(board_certification.expiry_date)
    current_time < expiry_time
}

board_certification_required if {
    subject_id := input.context.security.subject_id
    healthcare_role := data.subjects[subject_id].healthcare_role
    
    healthcare_role in roles_requiring_board_certification
}

roles_requiring_board_certification := {
    "attending_physician",
    "specialist_physician",
    "surgeon",
    "anesthesiologist",
    "radiologist",
    "pathologist"
}

hospital_privileges_current if {
    subject_id := input.context.security.subject_id
    hospital_privileges := data.subjects[subject_id].hospital_privileges
    
    hospital_privileges.active == true
    hospital_privileges.current == true
    hospital_privileges.credentialing_complete == true
    
    current_time := time.now_ns()
    expiry_time := time.parse_rfc3339_ns(hospital_privileges.expiry_date)
    current_time < expiry_time
    
    privileges_scope_appropriate(hospital_privileges)
}

privileges_scope_appropriate(privileges) if {
    action := input.action
    resource_type := input.resource.type
    
    privilege_scope := privileges.scope
    action_authorized := privilege_scope[resource_type][action]
    action_authorized == true
}

malpractice_insurance_verified if {
    subject_id := input.context.security.subject_id
    malpractice_insurance := data.subjects[subject_id].malpractice_insurance
    
    malpractice_insurance.active == true
    malpractice_insurance.coverage_adequate == true
    malpractice_insurance.carrier_approved == true
    
    current_time := time.now_ns()
    expiry_time := time.parse_rfc3339_ns(malpractice_insurance.expiry_date)
    current_time < expiry_time
}

background_check_completed if {
    subject_id := input.context.security.subject_id
    background_check := data.subjects[subject_id].background_check
    
    background_check.completed == true
    background_check.cleared == true
    background_check.comprehensive == true
    
    current_time := time.now_ns()
    check_date := time.parse_rfc3339_ns(background_check.completion_date)
    time_since_check := current_time - check_date
    max_check_age := 2 * 365 * 24 * 3600 * 1000000000
    
    time_since_check <= max_check_age
}

continuing_education_current if {
    subject_id := input.context.security.subject_id
    continuing_education := data.subjects[subject_id].continuing_education
    
    continuing_education.requirements_met == true
    continuing_education.credits_current == true
    continuing_education.reporting_period_current == true
    continuing_education.specialty_requirements_met == true
}

peer_review_satisfactory if {
    subject_id := input.context.security.subject_id
    peer_review := data.subjects[subject_id].peer_review
    
    peer_review.completed == true
    peer_review.satisfactory == true
    peer_review.no_adverse_actions == true
    peer_review.quality_indicators_met == true
    
    current_time := time.now_ns()
    review_date := time.parse_rfc3339_ns(peer_review.last_review_date)
    time_since_review := current_time - review_date
    max_review_age := 365 * 24 * 3600 * 1000000000
    
    time_since_review <= max_review_age
}

patient_safety_violations_detected if {
    medication_safety_violations_detected
}

patient_safety_violations_detected if {
    clinical_safety_violations_detected
}

patient_safety_violations_detected if {
    data_safety_violations_detected
}

patient_safety_violations_detected if {
    device_safety_violations_detected
}

medication_safety_violations_detected if {
    medication_violations := input.context.violations.medication_safety
    critical_violations := [violation | violation := medication_violations[_]; violation.severity == "critical"]
    count(critical_violations) > 0
}

clinical_safety_violations_detected if {
    clinical_violations := input.context.violations.clinical_safety
    patient_harm_violations := [violation | violation := clinical_violations[_]; violation.patient_harm_potential == "high"]
    count(patient_harm_violations) > 0
}

data_safety_violations_detected if {
    data_violations := input.context.violations.data_safety
    phi_breach_violations := [violation | violation := data_violations[_]; violation.type == "phi_breach"]
    count(phi_breach_violations) > 0
}

device_safety_violations_detected if {
    device_violations := input.context.violations.device_safety
    safety_critical_violations := [violation | violation := device_violations[_]; violation.safety_critical == true]
    count(safety_critical_violations) > 0
}

unauthorized_phi_access_attempt if {
    phi_access_violations := input.context.violations.phi_access
    unauthorized_attempts := [violation | violation := phi_access_violations[_]; violation.unauthorized == true]
    count(unauthorized_attempts) > 0
}

healthcare_audit_log_entry := {
    "policy_id": metadata.policy_id,
    "tenant_id": input.tenant_id,
    "subject_id": input.context.security.subject_id,
    "resource": input.resource,
    "action": input.action,
    "decision": allow,
    "timestamp": time.now_ns(),
    "request_id": input.context.request_id,
    "trace_id": input.context.trace_id,
    "hipaa_compliance_status": hipaa_compliance_status,
    "patient_privacy_status": patient_privacy_status,
    "healthcare_compliance_status": healthcare_compliance_status,
    "clinical_workflow_status": clinical_workflow_status,
    "provider_credentials_status": provider_credentials_status,
    "patient_safety_assessment": patient_safety_assessment,
    "medical_data_governance_status": medical_data_governance_status
}

hipaa_compliance_status := {
    "administrative_safeguards": hipaa_administrative_safeguards_implemented,
    "physical_safeguards": hipaa_physical_safeguards_implemented,
    "technical_safeguards": hipaa_technical_safeguards_implemented,
    "breach_notification": hipaa_breach_notification_procedures_established,
    "business_associates": hipaa_business_associate_agreements_current,
    "risk_assessment": hipaa_risk_assessment_completed,
    "overall_compliant": hipaa_compliance_verified
}

patient_privacy_status := {
    "phi_access_controls": phi_access_controls_enforced,
    "minimum_necessary": minimum_necessary_standard_applied,
    "consent_management": patient_consent_management_compliant,
    "patient_rights": patient_rights_procedures_established,
    "privacy_notice": privacy_notice_requirements_met,
    "marketing_controls": marketing_communications_controlled,
    "overall_protected": patient_privacy_protected
}

healthcare_compliance_status := {
    "hitech_act": hitech_act_compliance_verified,
    "fda_regulations": fda_regulations_compliant,
    "dea_regulations": dea_regulations_compliant,
    "state_medical_board": state_medical_board_requirements_met,
    "joint_commission": joint_commission_standards_met,
    "cms_conditions": cms_conditions_of_participation_satisfied,
    "oig_compliance": oig_compliance_program_implemented,
    "overall_compliant": healthcare_compliance_met
}

clinical_workflow_status := {
    "role_authorization": clinical_role_authorization_verified,
    "competency_validation": clinical_competency_validated,
    "supervision_requirements": clinical_supervision_requirements_met,
    "documentation_standards": clinical_documentation_standards_enforced,
    "decision_support": clinical_decision_support_compliant,
    "medication_controls": medication_administration_controls_active,
    "workflows_authorized": clinical_workflows_authorized
}

provider_credentials_status := {
    "medical_license": medical_license_verification_current,
    "board_certification": board_certification_validated,
    "hospital_privileges": hospital_privileges_current,
    "malpractice_insurance": malpractice_insurance_verified,
    "background_check": background_check_completed,
    "continuing_education": continuing_education_current,
    "peer_review": peer_review_satisfactory,
    "credentials_validated": provider_credentials_validated
}

patient_safety_assessment := {
    "safety_risk_level": calculate_patient_safety_risk_level,
    "violation_indicators": {
        "medication_safety": medication_safety_violations_detected,
        "clinical_safety": clinical_safety_violations_detected,
        "data_safety": data_safety_violations_detected,
        "device_safety": device_safety_violations_detected
    },
    "safety_controls": {
        "medication_controls": medication_administration_controls_active,
        "clinical_controls": clinical_documentation_standards_enforced,
        "data_controls": phi_access_controls_enforced,
        "device_controls": medical_device_cybersecurity_enforced
    },
    "mitigation_measures": patient_safety_mitigation_measures
}

calculate_patient_safety_risk_level := "low" if {
    not patient_safety_violations_detected
    provider_credentials_validated
    clinical_workflows_authorized
    hipaa_compliance_verified
}

calculate_patient_safety_risk_level := "medium" if {
    patient_safety_violations_detected
    provider_credentials_validated
    clinical_workflows_authorized
}

calculate_patient_safety_risk_level := "high" if {
    patient_safety_violations_detected
    not provider_credentials_validated
}

calculate_patient_safety_risk_level := "critical" if {
    patient_safety_violations_detected
    not provider_credentials_validated
    not clinical_workflows_authorized
}

patient_safety_mitigation_measures := {
    "enhanced_monitoring": calculate_patient_safety_risk_level in {"medium", "high", "critical"},
    "additional_supervision": calculate_patient_safety_risk_level in {"high", "critical"},
    "immediate_intervention": calculate_patient_safety_risk_level == "critical",
    "incident_reporting": patient_safety_violations_detected,
    "quality_review": medication_safety_violations_detected,
    "peer_consultation": clinical_safety_violations_detected,
    "system_alert": device_safety_violations_detected
}

medical_data_governance_status := {
    "data_classification": medical_data_classification_implemented,
    "data_quality": clinical_data_quality_standards_met,
    "lifecycle_management": medical_record_lifecycle_management_active,
    "research_governance": research_data_governance_compliant,
    "device_governance": medical_device_data_governance_enforced,
    "interoperability": interoperability_standards_implemented,
    "governance_enforced": medical_data_governance_enforced
}

healthcare_incident_reporting := {
    "incident_detected": patient_safety_violations_detected,
    "incident_type": determine_healthcare_incident_type,
    "incident_severity": determine_healthcare_incident_severity,
    "reporting_required": healthcare_incident_reporting_required,
    "reporting_timeline": determine_healthcare_reporting_timeline,
    "notification_authorities": determine_healthcare_notification_authorities,
    "patient_notification": patient_notification_required
}

determine_healthcare_incident_type := "medication_error" if {
    medication_safety_violations_detected
    not clinical_safety_violations_detected
    not data_safety_violations_detected
}

determine_healthcare_incident_type := "clinical_incident" if {
    clinical_safety_violations_detected
    not medication_safety_violations_detected
}

determine_healthcare_incident_type := "data_breach" if {
    data_safety_violations_detected
    not medication_safety_violations_detected
    not clinical_safety_violations_detected
}

determine_healthcare_incident_type := "device_malfunction" if {
    device_safety_violations_detected
    not medication_safety_violations_detected
    not clinical_safety_violations_detected
    not data_safety_violations_detected
}

determine_healthcare_incident_type := "multiple_incidents" if {
    medication_safety_violations_detected
    clinical_safety_violations_detected
}

determine_healthcare_incident_severity := "critical" if {
    calculate_patient_safety_risk_level == "critical"
}

determine_healthcare_incident_severity := "high" if {
    calculate_patient_safety_risk_level == "high"
}

determine_healthcare_incident_severity := "medium" if {
    calculate_patient_safety_risk_level == "medium"
}

determine_healthcare_incident_severity := "low" if {
    calculate_patient_safety_risk_level == "low"
    patient_safety_violations_detected
}

healthcare_incident_reporting_required if {
    patient_safety_violations_detected
}

determine_healthcare_reporting_timeline := "immediate" if {
    determine_healthcare_incident_severity == "critical"
}

determine_healthcare_reporting_timeline := "within_24_hours" if {
    determine_healthcare_incident_severity == "high"
}

determine_healthcare_reporting_timeline := "within_72_hours" if {
    determine_healthcare_incident_severity == "medium"
}

determine_healthcare_reporting_timeline := "within_30_days" if {
    determine_healthcare_incident_severity == "low"
}

determine_healthcare_notification_authorities := authorities if {
    incident_type := determine_healthcare_incident_type
    incident_severity := determine_healthcare_incident_severity
    
    authorities := healthcare_notification_matrix[incident_type][incident_severity]
}

healthcare_notification_matrix := {
    "medication_error": {
        "critical": ["fda", "state_board_pharmacy", "hospital_administration", "risk_management"],
        "high": ["state_board_pharmacy", "hospital_administration", "risk_management"],
        "medium": ["hospital_administration", "risk_management"],
        "low": ["risk_management"]
    },
    "clinical_incident": {
        "critical": ["state_medical_board", "hospital_administration", "risk_management", "quality_committee"],
        "high": ["hospital_administration", "risk_management", "quality_committee"],
        "medium": ["risk_management", "quality_committee"],
        "low": ["quality_committee"]
    },
    "data_breach": {
        "critical": ["hhs_ocr", "state_attorney_general", "fbi", "hospital_administration"],
        "high": ["hhs_ocr", "state_attorney_general", "hospital_administration"],
        "medium": ["hhs_ocr", "hospital_administration"],
        "low": ["hospital_administration"]
    },
    "device_malfunction": {
        "critical": ["fda", "device_manufacturer", "hospital_administration", "biomedical_engineering"],
        "high": ["fda", "device_manufacturer", "hospital_administration"],
        "medium": ["device_manufacturer", "hospital_administration"],
        "low": ["biomedical_engineering"]
    }
}

patient_notification_required if {
    data_safety_violations_detected
    phi_breach_significant
}

patient_notification_required if {
    medication_safety_violations_detected
    patient_harm_occurred
}

patient_notification_required if {
    clinical_safety_violations_detected
    patient_harm_occurred
}

phi_breach_significant if {
    breach_details := input.context.violations.data_safety
    affected_patients := count([violation | violation := breach_details[_]; violation.type == "phi_breach"])
    affected_patients >= 500
}

patient_harm_occurred if {
    safety_violations := input.context.violations.patient_safety
    harm_violations := [violation | violation := safety_violations[_]; violation.patient_harm == true]
    count(harm_violations) > 0
}

quality_assurance_requirements := {
    "quality_metrics_monitoring": quality_metrics_monitoring_active,
    "performance_improvement": performance_improvement_programs_active,
    "patient_satisfaction": patient_satisfaction_monitoring_active,
    "clinical_outcomes": clinical_outcomes_tracking_active,
    "safety_indicators": safety_indicators_monitoring_active
}

quality_metrics_monitoring_active if {
    quality_metrics := input.context.quality_assurance.metrics_monitoring
    quality_metrics.core_measures_tracked == true
    quality_metrics.benchmarking_active == true
    quality_metrics.trend_analysis == true
    quality_metrics.reporting_current == true
}

performance_improvement_programs_active if {
    performance_improvement := input.context.quality_assurance.performance_improvement
    performance_improvement.programs_established == true
    performance_improvement.multidisciplinary_teams == true
    performance_improvement.data_driven_decisions == true
    performance_improvement.action_plans_implemented == true
}

patient_satisfaction_monitoring_active if {
    patient_satisfaction := input.context.quality_assurance.patient_satisfaction
    patient_satisfaction.surveys_conducted == true
    patient_satisfaction.feedback_analyzed == true
    patient_satisfaction.improvement_actions == true
    patient_satisfaction.communication_enhanced == true
}

clinical_outcomes_tracking_active if {
    clinical_outcomes := input.context.quality_assurance.clinical_outcomes
    clinical_outcomes.outcome_measures_defined == true
    clinical_outcomes.data_collection_systematic == true
    clinical_outcomes.analysis_regular == true
    clinical_outcomes.improvement_initiatives == true
}

safety_indicators_monitoring_active if {
    safety_indicators := input.context.quality_assurance.safety_indicators
    safety_indicators.never_events_tracking == true
    safety_indicators.adverse_events_monitoring == true
    safety_indicators.near_miss_reporting == true
    safety_indicators.safety_culture_assessment == true
}

research_ethics_compliance := {
    "irb_oversight": irb_oversight_active,
    "informed_consent": informed_consent_procedures_compliant,
    "data_protection": research_data_protection_enforced,
    "publication_ethics": publication_ethics_maintained
}

irb_oversight_active if {
    irb := input.context.research_ethics.irb_oversight
    
    not research_involving_human_subjects
}

irb_oversight_active if {
    irb := input.context.research_ethics.irb_oversight
    research_involving_human_subjects
    
    irb.approval_obtained == true
    irb.approval_current == true
    irb.continuing_review_current == true
    irb.adverse_event_reporting == true
}

research_involving_human_subjects if {
    data_purpose := input.context.data_access.purpose
    data_purpose == "research"
    
    human_subjects := input.context.research.human_subjects_involved
    human_subjects == true
}

informed_consent_procedures_compliant if {
    consent_procedures := input.context.research_ethics.informed_consent
    
    not research_involving_human_subjects
}

informed_consent_procedures_compliant if {
    consent_procedures := input.context.research_ethics.informed_consent
    research_involving_human_subjects
    
    consent_procedures.procedures_documented == true
    consent_procedures.consent_forms_approved == true
    consent_procedures.voluntary_participation == true
    consent_procedures.withdrawal_procedures == true
}

research_data_protection_enforced if {
    data_protection := input.context.research_ethics.data_protection
    data_protection.de_identification_procedures == true
    data_protection.data_security_measures == true
    data_protection.access_controls == true
    data_protection.data_sharing_agreements == true
}

publication_ethics_maintained if {
    publication_ethics := input.context.research_ethics.publication_ethics
    publication_ethics.authorship_guidelines == true
    publication_ethics.conflict_of_interest_disclosure == true
    publication_ethics.data_sharing_policies == true
    publication_ethics.peer_review_integrity == true
}


telehealth_compliance_requirements := {
    "platform_security": telehealth_platform_security_verified,
    "patient_consent": telehealth_patient_consent_obtained,
    "provider_licensing": telehealth_provider_licensing_verified,
    "documentation_standards": telehealth_documentation_compliant,
    "privacy_protections": telehealth_privacy_protections_enforced
}

telehealth_platform_security_verified if {
    platform_security := input.context.telehealth.platform_security
    platform_security.end_to_end_encryption == true
    platform_security.access_controls == true
    platform_security.audit_logging == true
    platform_security.session_management == true
    platform_security.data_retention_controls == true
}

telehealth_patient_consent_obtained if {
    telehealth_consent := input.context.telehealth.patient_consent
    telehealth_consent.informed_consent == true
    telehealth_consent.technology_consent == true
    telehealth_consent.recording_consent == true
    telehealth_consent.data_sharing_consent == true
}

telehealth_provider_licensing_verified if {
    provider_licensing := input.context.telehealth.provider_licensing
    provider_licensing.state_licensing_verified == true
    provider_licensing.cross_state_authorization == true
    provider_licensing.telehealth_training_completed == true
    provider_licensing.malpractice_coverage_telehealth == true
}

telehealth_documentation_compliant if {
    telehealth_documentation := input.context.telehealth.documentation
    telehealth_documentation.encounter_documented == true
    telehealth_documentation.technology_platform_noted == true
    telehealth_documentation.patient_location_documented == true
    telehealth_documentation.clinical_decision_rationale == true
}

telehealth_privacy_protections_enforced if {
    privacy_protections := input.context.telehealth.privacy_protections
    privacy_protections.private_location_verified == true
    privacy_protections.unauthorized_access_prevented == true
    privacy_protections.recording_controls == true
    privacy_protections.data_transmission_secure == true
}

emergency_access_procedures := {
    "emergency_override": emergency_override_authorized,
    "break_glass_access": break_glass_access_controlled,
    "emergency_documentation": emergency_access_documented,
    "post_emergency_review": post_emergency_review_required
}

emergency_override_authorized if {
    emergency_context := input.context.emergency
    
    not emergency_context.emergency_declared
}

emergency_override_authorized if {
    emergency_context := input.context.emergency
    emergency_context.emergency_declared == true
    
    emergency_context.authorized_by_physician == true
    emergency_context.patient_safety_justification == true
    emergency_context.alternative_access_unavailable == true
    emergency_context.emergency_code_valid == true
}

break_glass_access_controlled if {
    break_glass := input.context.emergency.break_glass
    break_glass.justification_documented == true
    break_glass.supervisor_notification == true
    break_glass.audit_trail_maintained == true
    break_glass.time_limited_access == true
}

emergency_access_documented if {
    emergency_documentation := input.context.emergency.documentation
    emergency_documentation.access_reason_documented == true
    emergency_documentation.patient_condition_documented == true
    emergency_documentation.actions_taken_documented == true
    emergency_documentation.outcome_documented == true
}

post_emergency_review_required if {
    emergency_context := input.context.emergency
    emergency_context.emergency_declared == true
    
    review_procedures := input.context.emergency.post_review
    review_procedures.review_scheduled == true
    review_procedures.multidisciplinary_review == true
    review_procedures.appropriateness_assessment == true
    review_procedures.process_improvement == true
}

final_healthcare_decision := {
    "allow": allow,
    "deny": deny,
    "tenant_id": input.tenant_id,
    "resource": input.resource,
    "action": input.action,
    "hipaa_compliance_status": hipaa_compliance_status,
    "patient_privacy_status": patient_privacy_status,
    "healthcare_compliance_status": healthcare_compliance_status,
    "clinical_workflow_status": clinical_workflow_status,
    "provider_credentials_status": provider_credentials_status,
    "patient_safety_assessment": patient_safety_assessment,
    "medical_data_governance_status": medical_data_governance_status,
    "healthcare_incident_reporting": healthcare_incident_reporting,
    "quality_assurance_status": quality_assurance_requirements,
    "research_ethics_status": research_ethics_compliance,
    "telehealth_compliance_status": telehealth_compliance_requirements,
    "emergency_access_status": emergency_access_procedures,
    "audit_log": healthcare_audit_log_entry,
    "evaluation_time_ms": (time.now_ns() - time.parse_rfc3339_ns(input.context.timestamp)) / 1000000
}

healthcare_violation_summary := {
    "total_violations": count(input.context.violations.healthcare_violations),
    "patient_safety_violations": count([v | v := input.context.violations.healthcare_violations[_]; v.category == "patient_safety"]),
    "hipaa_violations": count([v | v := input.context.violations.healthcare_violations[_]; v.category == "hipaa"]),
    "clinical_violations": count([v | v := input.context.violations.healthcare_violations[_]; v.category == "clinical"]),
    "data_violations": count([v | v := input.context.violations.healthcare_violations[_]; v.category == "data"]),
    "critical_violations": count([v | v := input.context.violations.healthcare_violations[_]; v.severity == "critical"]),
    "remediation_status": healthcare_remediation_status
}

healthcare_remediation_status := {
    "open_violations": count([v | v := input.context.violations.healthcare_violations[_]; v.status == "open"]),
    "in_progress_violations": count([v | v := input.context.violations.healthcare_violations[_]; v.status == "in_progress"]),
    "resolved_violations": count([v | v := input.context.violations.healthcare_violations[_]; v.status == "resolved"]),
    "overdue_violations": count([v | v := input.context.violations.healthcare_violations[_]; v.overdue == true])
}

allow if {
    hipaa_compliance_verified
    patient_privacy_protected
    healthcare_compliance_met
    not patient_safety_violations_detected
    clinical_workflows_authorized
    medical_data_governance_enforced
    healthcare_security_standards_met
    provider_credentials_validated
    calculate_patient_safety_risk_level in {"low", "medium"}
}

allow if {
    emergency_override_authorized
    break_glass_access_controlled
    emergency_access_documented
    post_emergency_review_required
}
