package model.permissions

import future.keywords.if
import future.keywords.in
import future.keywords.every
import future.keywords.contains

default allow := false
default deny := true
default model_accessible := false
default operation_permitted := false
default resource_constraints_met := false

metadata := {
    "policy_id": "model-permissions-base",
    "version": "1.0.0", 
    "description": "AI/ML model access control and permissions policy",
    "priority": 14,
    "effect": "allow",
    "created_by": "system",
    "tags": ["model", "ai", "ml", "permissions", "inference", "training"]
}

allow if {
    model_accessible
    operation_permitted
    resource_constraints_met
    not explicitly_denied
    model_security_validated
    computational_limits_respected
    data_access_authorized
}

deny if {
    not model_accessible
}

deny if {
    explicitly_denied
}

deny if {
    model_security_violation
}

model_accessible if {
    input.resource.type == "model"
    model_exists
    model_belongs_to_tenant
    model_status_valid
    model_version_accessible
    model_license_valid
}

model_exists if {
    input.resource.id
    data.models[input.resource.id]
}

model_belongs_to_tenant if {
    model := data.models[input.resource.id]
    model.tenant_id == input.tenant_id
}

model_status_valid if {
    model := data.models[input.resource.id]
    model.status in valid_model_statuses
}

valid_model_statuses := {
    "active",
    "deployed", 
    "training",
    "ready",
    "published"
}

model_version_accessible if {
    model := data.models[input.resource.id]
    requested_version := input.context.model.version
    
    not requested_version
}

model_version_accessible if {
    model := data.models[input.resource.id]
    requested_version := input.context.model.version
    requested_version in model.available_versions
}

model_license_valid if {
    model := data.models[input.resource.id]
    license := model.license
    license_active(license)
}

license_active(license) if {
    license.status == "active"
    license_not_expired(license)
}

license_not_expired(license) if {
    current_time := time.now_ns()
    expiry_time := time.parse_rfc3339_ns(license.expires_at)
    current_time < expiry_time
}

operation_permitted if {
    input.action in valid_model_operations
    operation_context_valid
    operation_authorization_valid
    operation_scope_appropriate
}

valid_model_operations := {
    "create",
    "read",
    "update", 
    "delete",
    "list",
    "train",
    "infer",
    "deploy",
    "undeploy",
    "version",
    "publish",
    "unpublish",
    "clone",
    "export",
    "import",
    "monitor",
    "evaluate",
    "optimize",
    "quantize",
    "compress",
    "validate",
    "test",
    "benchmark"
}

operation_context_valid if {
    action := input.action
    model := data.models[input.resource.id]
    operation_model_type_compatible(action, model.type)
}

operation_model_type_compatible("train", model_type) if {
    model_type in trainable_model_types
}

operation_model_type_compatible("infer", model_type) if {
    model_type in inference_model_types
}

operation_model_type_compatible("deploy", model_type) if {
    model_type in deployable_model_types
}

operation_model_type_compatible(action, model_type) if {
    action in {"create", "read", "update", "delete", "list", "monitor", "evaluate"}
}

trainable_model_types := {
    "neural_network",
    "transformer",
    "cnn",
    "rnn", 
    "lstm",
    "gru",
    "autoencoder",
    "gan",
    "vae",
    "reinforcement_learning",
    "decision_tree",
    "random_forest",
    "gradient_boosting",
    "svm",
    "linear_regression",
    "logistic_regression",
    "clustering",
    "ensemble"
}

inference_model_types := {
    "neural_network",
    "transformer", 
    "cnn",
    "rnn",
    "lstm",
    "gru",
    "autoencoder",
    "decision_tree",
    "random_forest",
    "gradient_boosting",
    "svm",
    "linear_regression",
    "logistic_regression",
    "clustering",
    "ensemble",
    "pre_trained",
    "fine_tuned"
}

deployable_model_types := {
    "neural_network",
    "transformer",
    "cnn", 
    "rnn",
    "lstm",
    "gru",
    "decision_tree",
    "random_forest",
    "gradient_boosting",
    "svm",
    "linear_regression",
    "logistic_regression",
    "pre_trained",
    "fine_tuned",
    "ensemble"
}

operation_authorization_valid if {
    action := input.action
    subject_id := input.context.security.subject_id
    subject_permissions := data.subjects[subject_id].model_permissions
    
    subject_permissions[action] == true
}

operation_scope_appropriate if {
    action := input.action
    model := data.models[input.resource.id]
    model_scope := model.scope
    
    scope_action_matrix[model_scope][action] == true
}

scope_action_matrix := {
    "private": {
        "create": true,
        "read": true,
        "update": true,
        "delete": true,
        "list": true,
        "train": true,
        "infer": true,
        "deploy": true,
        "undeploy": true,
        "version": true,
        "clone": true,
        "export": true,
        "import": true,
        "monitor": true,
        "evaluate": true,
        "optimize": true,
        "quantize": true,
        "compress": true,
        "validate": true,
        "test": true,
        "benchmark": true
    },
    "shared": {
        "read": true,
        "list": true,
        "infer": true,
        "clone": true,
        "monitor": true,
        "evaluate": true,
        "test": true,
        "benchmark": true
    },
    "public": {
        "read": true,
        "list": true,
        "infer": true,
        "clone": true,
        "monitor": true,
        "evaluate": true,
        "test": true,
        "benchmark": true
    },
    "restricted": {
        "read": true,
        "infer": true,
        "monitor": true
    }
}

resource_constraints_met if {
    computational_resources_available
    memory_requirements_satisfied
    storage_requirements_satisfied
    network_bandwidth_adequate
    gpu_requirements_met
}

computational_resources_available if {
    action := input.action
    model := data.models[input.resource.id]
    required_compute := model.resource_requirements.compute
    available_compute := input.context.resources.available_compute
    
    required_compute <= available_compute
}

memory_requirements_satisfied if {
    action := input.action
    model := data.models[input.resource.id]
    required_memory := model.resource_requirements.memory_gb
    available_memory := input.context.resources.available_memory_gb
    
    required_memory <= available_memory
}

storage_requirements_satisfied if {
    action := input.action
    model := data.models[input.resource.id]
    required_storage := model.resource_requirements.storage_gb
    available_storage := input.context.resources.available_storage_gb
    
    required_storage <= available_storage
}

network_bandwidth_adequate if {
    action := input.action
    model := data.models[input.resource.id]
    required_bandwidth := model.resource_requirements.bandwidth_mbps
    available_bandwidth := input.context.resources.available_bandwidth_mbps
    
    required_bandwidth <= available_bandwidth
}

gpu_requirements_met if {
    action := input.action
    model := data.models[input.resource.id]
    
    not model.resource_requirements.gpu_required
}

gpu_requirements_met if {
    action := input.action
    model := data.models[input.resource.id]
    model.resource_requirements.gpu_required
    
    required_gpu_memory := model.resource_requirements.gpu_memory_gb
    available_gpu_memory := input.context.resources.available_gpu_memory_gb
    
    required_gpu_memory <= available_gpu_memory
}

explicitly_denied if {
    model_deprecated
}

explicitly_denied if {
    model_security_flagged
}

explicitly_denied if {
    computational_quota_exceeded
}

explicitly_denied if {
    model_access_suspended
}

model_deprecated if {
    model := data.models[input.resource.id]
    model.status == "deprecated"
}

model_security_flagged if {
    model := data.models[input.resource.id]
    model.security_flags.blocked == true
}

computational_quota_exceeded if {
    tenant_quotas := data.tenants[input.tenant_id].model_quotas
    action := input.action
    current_usage := input.context.usage.models[action]
    quota_limit := tenant_quotas[action]
    
    current_usage >= quota_limit
}

model_access_suspended if {
    model := data.models[input.resource.id]
    model.access_control.suspended == true
}

model_security_validated if {
    model_integrity_verified
    model_provenance_validated
    model_vulnerability_scan_passed
    model_compliance_verified
}

model_integrity_verified if {
    model := data.models[input.resource.id]
    expected_hash := model.integrity.hash
    actual_hash := input.context.model.computed_hash
    
    expected_hash == actual_hash
}

model_provenance_validated if {
    model := data.models[input.resource.id]
    provenance := model.provenance
    provenance_chain_valid(provenance)
}

provenance_chain_valid(provenance) if {
    provenance.verified == true
    provenance.source_verified == true
    provenance.training_data_verified == true
}

model_vulnerability_scan_passed if {
    model := data.models[input.resource.id]
    scan_results := model.security.vulnerability_scan
    scan_results.status == "passed"
    scan_results.critical_vulnerabilities == 0
}

model_compliance_verified if {
    model := data.models[input.resource.id]
    compliance := model.compliance
    all_compliance_checks_passed(compliance)
}

all_compliance_checks_passed(compliance) if {
    compliance.ai_ethics_approved == true
    compliance.bias_testing_passed == true
    compliance.fairness_validated == true
    compliance.explainability_verified == true
}

computational_limits_respected if {
    inference_rate_limit_respected
    training_time_limit_respected
    concurrent_operations_limit_respected
    resource_utilization_within_bounds
}

inference_rate_limit_respected if {
    action := input.action
    action != "infer"
}

inference_rate_limit_respected if {
    action := input.action
    action == "infer"
    
    model := data.models[input.resource.id]
    rate_limit := model.limits.inference_rate_per_minute
    current_rate := input.context.usage.inference_rate
    
    current_rate <= rate_limit
}

training_time_limit_respected if {
    action := input.action
    action != "train"
}

training_time_limit_respected if {
    action := input.action
    action == "train"
    
    model := data.models[input.resource.id]
    max_training_hours := model.limits.max_training_hours
    requested_training_hours := input.context.training.estimated_hours
    
    requested_training_hours <= max_training_hours
}

concurrent_operations_limit_respected if {
    tenant_limits := data.tenants[input.tenant_id].model_limits
    current_operations := input.context.usage.concurrent_model_operations
    max_concurrent := tenant_limits.max_concurrent_operations
    
    current_operations < max_concurrent
}

resource_utilization_within_bounds if {
    action := input.action
    model := data.models[input.resource.id]
    
    cpu_utilization_acceptable(action, model)
    memory_utilization_acceptable(action, model)
    gpu_utilization_acceptable(action, model)
}

cpu_utilization_acceptable(action, model) if {
    max_cpu_percent := model.limits.max_cpu_utilization_percent
    current_cpu_percent := input.context.resources.cpu_utilization_percent
    
    current_cpu_percent <= max_cpu_percent
}

memory_utilization_acceptable(action, model) if {
    max_memory_percent := model.limits.max_memory_utilization_percent
    current_memory_percent := input.context.resources.memory_utilization_percent
    
    current_memory_percent <= max_memory_percent
}

gpu_utilization_acceptable(action, model) if {
    not model.resource_requirements.gpu_required
}

gpu_utilization_acceptable(action, model) if {
    model.resource_requirements.gpu_required
    max_gpu_percent := model.limits.max_gpu_utilization_percent
    current_gpu_percent := input.context.resources.gpu_utilization_percent
    
    current_gpu_percent <= max_gpu_percent
}

data_access_authorized if {
    training_data_access_valid
    inference_data_access_valid
    model_artifacts_access_valid
}

training_data_access_valid if {
    action := input.action
    action != "train"
}

training_data_access_valid if {
    action := input.action
    action == "train"
    
    model := data.models[input.resource.id]
    training_datasets := model.training.datasets
    
    every dataset in training_datasets {
        dataset_accessible(dataset)
    }
}

dataset_accessible(dataset) if {
    dataset_exists(dataset)
    dataset_belongs_to_tenant(dataset)
    dataset_permissions_valid(dataset)
}

dataset_exists(dataset) if {
    data.datasets[dataset.id]
}

dataset_belongs_to_tenant(dataset) if {
    dataset_info := data.datasets[dataset.id]
    dataset_info.tenant_id == input.tenant_id
}

dataset_permissions_valid(dataset) if {
    dataset_info := data.datasets[dataset.id]
    subject_id := input.context.security.subject_id
    subject_permissions := data.subjects[subject_id].dataset_permissions
    
    subject_permissions.read == true
}

inference_data_access_valid if {
    action := input.action
    action != "infer"
}

inference_data_access_valid if {
    action := input.action
    action == "infer"
    
    input_data_schema_valid
    input_data_size_within_limits
    input_data_format_supported
}

input_data_schema_valid if {
    model := data.models[input.resource.id]
    expected_schema := model.input_schema
    actual_schema := input.context.inference.input_schema
    
    schemas_compatible(expected_schema, actual_schema)
}

schemas_compatible(expected, actual) if {
    expected.type == actual.type
    expected.shape == actual.shape
    expected.dtype == actual.dtype
}

input_data_size_within_limits if {
    model := data.models[input.resource.id]
    max_input_size := model.limits.max_input_size_mb
    actual_input_size := input.context.inference.input_size_mb
    
    actual_input_size <= max_input_size
}

input_data_format_supported if {
    model := data.models[input.resource.id]
    supported_formats := model.supported_input_formats
    actual_format := input.context.inference.input_format
    
    actual_format in supported_formats
}

model_artifacts_access_valid if {
    model := data.models[input.resource.id]
    artifacts := model.artifacts
    
    every artifact in artifacts {
        artifact_accessible(artifact)
    }
}

artifact_accessible(artifact) if {
    artifact_exists(artifact)
    artifact_integrity_valid(artifact)
    artifact_permissions_valid(artifact)
}

artifact_exists(artifact) if {
    data.artifacts[artifact.id]
}

artifact_integrity_valid(artifact) if {
    artifact_info := data.artifacts[artifact.id]
    expected_checksum := artifact_info.checksum
    actual_checksum := input.context.artifacts[artifact.id].checksum
    
    expected_checksum == actual_checksum
}

artifact_permissions_valid(artifact) if {
    artifact_info := data.artifacts[artifact.id]
    subject_id := input.context.security.subject_id
    subject_permissions := data.subjects[subject_id].artifact_permissions
    
    subject_permissions.read == true
}

model_deployment_constraints if {
    action := input.action
    action != "deploy"
}

model_deployment_constraints if {
    action := input.action
    action == "deploy"
    
    deployment_environment_valid
    deployment_resources_available
    deployment_security_requirements_met
}

deployment_environment_valid if {
    target_environment := input.context.deployment.target_environment
    model := data.models[input.resource.id]
    supported_environments := model.deployment.supported_environments
    
    target_environment in supported_environments
}

deployment_resources_available if {
    target_environment := input.context.deployment.target_environment
    environment_resources := data.environments[target_environment].available_resources
    model := data.models[input.resource.id]
    required_resources := model.resource_requirements
    
    resources_sufficient(environment_resources, required_resources)
}

resources_sufficient(available, required) if {
    available.compute >= required.compute
    available.memory_gb >= required.memory_gb
    available.storage_gb >= required.storage_gb
}

deployment_security_requirements_met if {
    target_environment := input.context.deployment.target_environment
    environment_security := data.environments[target_environment].security
    model := data.models[input.resource.id]
    required_security := model.security_requirements
    
    security_requirements_satisfied(environment_security, required_security)
}

security_requirements_satisfied(env_security, required_security) if {
    env_security.encryption_at_rest >= required_security.encryption_at_rest
    env_security.encryption_in_transit >= required_security.encryption_in_transit
    env_security.network_isolation >= required_security.network_isolation
}

model_security_violation if {
    unauthorized_model_modification_attempt
}

model_security_violation if {
    model_poisoning_detected
}

model_security_violation if {
    adversarial_attack_detected
}

unauthorized_model_modification_attempt if {
    action := input.action
    action in {"update", "train", "optimize", "quantize"}
    
    model := data.models[input.resource.id]
    model.protection.immutable == true
}

model_poisoning_detected if {
    action := input.action
    action == "train"
    
    training_data_anomalies := input.context.training.data_anomalies
    anomaly_threshold := data.security_thresholds.training_data_anomaly_threshold
    
    training_data_anomalies > anomaly_threshold
}

adversarial_attack_detected if {
    action := input.action
    action == "infer"
    
    input_adversarial_score := input.context.inference.adversarial_score
    adversarial_threshold := data.security_thresholds.adversarial_detection_threshold
    
    input_adversarial_score > adversarial_threshold
}

model_audit_log_entry := {
    "policy_id": metadata.policy_id,
    "tenant_id": input.tenant_id,
    "subject_id": input.context.security.subject_id,
    "model": {
        "id": input.resource.id,
        "name": data.models[input.resource.id].name,
        "type": data.models[input.resource.id].type,
        "version": data.models[input.resource.id].version,
        "status": data.models[input.resource.id].status
    },
    "action": input.action,
    "decision": allow,
    "timestamp": time.now_ns(),
    "request_id": input.context.request_id,
    "trace_id": input.context.trace_id,
    "operation_context": operation_context,
    "resource_usage": resource_usage_snapshot,
    "security_assessment": security_assessment,
    "compliance_status": compliance_status,
    "performance_metrics": performance_metrics
}

operation_context := {
    "operation_type": input.action,
    "model_scope": data.models[input.resource.id].scope,
    "computational_requirements": data.models[input.resource.id].resource_requirements,
    "estimated_duration": input.context.operation.estimated_duration_minutes,
    "priority": input.context.operation.priority,
    "batch_size": input.context.operation.batch_size
}

resource_usage_snapshot := {
    "cpu_utilization": input.context.resources.cpu_utilization_percent,
    "memory_utilization": input.context.resources.memory_utilization_percent,
    "gpu_utilization": input.context.resources.gpu_utilization_percent,
    "storage_utilization": input.context.resources.storage_utilization_percent,
    "network_bandwidth_usage": input.context.resources.network_bandwidth_usage_mbps,
    "concurrent_operations": input.context.usage.concurrent_model_operations
}

security_assessment := {
    "model_integrity_verified": model_integrity_verified,
    "provenance_validated": model_provenance_validated,
    "vulnerability_scan_status": data.models[input.resource.id].security.vulnerability_scan.status,
    "adversarial_protection_enabled": data.models[input.resource.id].security.adversarial_protection,
    "encryption_status": data.models[input.resource.id].security.encryption_enabled,
    "access_control_enforced": true
}

compliance_status := {
    "ai_ethics_compliance": data.models[input.resource.id].compliance.ai_ethics_approved,
    "bias_testing_status": data.models[input.resource.id].compliance.bias_testing_passed,
    "fairness_validation": data.models[input.resource.id].compliance.fairness_validated,
    "explainability_requirements": data.models[input.resource.id].compliance.explainability_verified,
    "data_privacy_compliance": data_privacy_compliance_check,
    "regulatory_compliance": regulatory_compliance_check
}

performance_metrics := {
    "inference_latency_ms": input.context.performance.inference_latency_ms,
    "throughput_requests_per_second": input.context.performance.throughput_rps,
    "accuracy_score": data.models[input.resource.id].metrics.accuracy,
    "f1_score": data.models[input.resource.id].metrics.f1_score,
    "model_size_mb": data.models[input.resource.id].metrics.size_mb,
    "training_time_hours": data.models[input.resource.id].metrics.training_time_hours
}

data_privacy_compliance_check if {
    model := data.models[input.resource.id]
    privacy_requirements := model.privacy_requirements
    
    privacy_requirements.pii_handling_compliant == true
    privacy_requirements.data_anonymization_verified == true
    privacy_requirements.consent_management_enabled == true
}

regulatory_compliance_check if {
    model := data.models[input.resource.id]
    regulatory_status := model.regulatory_compliance
    
    regulatory_status.gdpr_compliant == true
    regulatory_status.ccpa_compliant == true
    regulatory_status.hipaa_compliant == true
}

model_lifecycle_stage_permissions if {
    model := data.models[input.resource.id]
    lifecycle_stage := model.lifecycle.stage
    action := input.action
    
    lifecycle_action_matrix[lifecycle_stage][action] == true
}

lifecycle_action_matrix := {
    "development": {
        "create": true,
        "read": true,
        "update": true,
        "delete": true,
        "train": true,
        "evaluate": true,
        "test": true,
        "validate": true,
        "optimize": true,
        "version": true
    },
    "testing": {
        "read": true,
        "evaluate": true,
        "test": true,
        "validate": true,
        "benchmark": true,
        "infer": true
    },
    "staging": {
        "read": true,
        "deploy": true,
        "undeploy": true,
        "infer": true,
        "monitor": true,
        "evaluate": true,
        "test": true
    },
    "production": {
        "read": true,
        "infer": true,
        "monitor": true,
        "evaluate": true,
        "clone": true,
        "export": true
    },
    "deprecated": {
        "read": true,
        "export": true,
        "delete": true
    },
    "archived": {
        "read": true,
        "export": true
    }
}

model_sharing_permissions if {
    action := input.action
    action != "share"
}

model_sharing_permissions if {
    action := input.action
    action == "share"
    
    model := data.models[input.resource.id]
    sharing_policy := model.sharing_policy
    target_tenant := input.context.sharing.target_tenant_id
    
    sharing_allowed(sharing_policy, target_tenant)
}

sharing_allowed(sharing_policy, target_tenant) if {
    sharing_policy.enabled == true
    sharing_policy.allowed_tenants[target_tenant] == true
}

model_versioning_permissions if {
    action := input.action
    action != "version"
}

model_versioning_permissions if {
    action := input.action
    action == "version"
    
    model := data.models[input.resource.id]
    versioning_policy := model.versioning_policy
    
    versioning_allowed(versioning_policy)
}

versioning_allowed(versioning_policy) if {
    versioning_policy.enabled == true
    current_versions := versioning_policy.current_version_count
    max_versions := versioning_policy.max_versions
    
    current_versions < max_versions
}

model_export_permissions if {
    action := input.action
    action != "export"
}

model_export_permissions if {
    action := input.action
    action == "export"
    
    model := data.models[input.resource.id]
    export_policy := model.export_policy
    export_format := input.context.export.format
    
    export_allowed(export_policy, export_format)
}

export_allowed(export_policy, export_format) if {
    export_policy.enabled == true
    export_format in export_policy.allowed_formats
    export_policy.data_residency_compliant == true
}

model_monitoring_permissions if {
    action := input.action
    action != "monitor"
}

model_monitoring_permissions if {
    action := input.action
    action == "monitor"
    
    monitoring_scope := input.context.monitoring.scope
    monitoring_scope in allowed_monitoring_scopes
}

allowed_monitoring_scopes := {
    "performance",
    "accuracy",
    "drift",
    "bias",
    "fairness",
    "explainability",
    "resource_usage",
    "security",
    "compliance"
}

final_model_decision := {
    "allow": allow,
    "deny": deny,
    "tenant_id": input.tenant_id,
    "model_id": input.resource.id,
    "action": input.action,
    "model_metadata": data.models[input.resource.id],
    "operation_context": operation_context,
    "resource_constraints": resource_usage_snapshot,
    "security_validation": security_assessment,
    "compliance_validation": compliance_status,
    "audit_log": model_audit_log_entry,
    "lifecycle_stage": data.models[input.resource.id].lifecycle.stage,
    "evaluation_time_ms": (time.now_ns() - time.parse_rfc3339_ns(input.context.timestamp)) / 1000000
}

allow if {
    model_accessible
    operation_permitted
    resource_constraints_met
    not explicitly_denied
    model_security_validated
    computational_limits_respected
    data_access_authorized
    model_lifecycle_stage_permissions
    model_sharing_permissions
    model_versioning_permissions
    model_export_permissions
    model_monitoring_permissions
}
