package tenant.access

import future.keywords.if
import future.keywords.in
import future.keywords.every
import future.keywords.contains

default allow := false
default deny := true
default tenant_isolated := false
default resource_accessible := false
default action_permitted := false

metadata := {
    "policy_id": "tenant-access-base",
    "version": "1.0.0",
    "description": "Core tenant isolation and access control policy",
    "priority": 15,
    "effect": "allow",
    "created_by": "system",
    "tags": ["tenant", "isolation", "access", "security"]
}

allow if {
    tenant_isolated
    resource_accessible
    action_permitted
    not explicitly_denied
    rate_limit_check
    security_context_valid
}

deny if {
    not tenant_isolated
}

deny if {
    explicitly_denied
}

deny if {
    not rate_limit_check
}

tenant_isolated if {
    input.tenant_id
    input.tenant_id != ""
    valid_tenant_format
    tenant_exists
    tenant_active
    tenant_context_match
}

valid_tenant_format if {
    regex.match("^[a-f0-9]{8}-[a-f0-9]{4}-4[a-f0-9]{3}-[89ab][a-f0-9]{3}-[a-f0-9]{12}$", input.tenant_id)
}

tenant_exists if {
    data.tenants[input.tenant_id]
}

tenant_active if {
    data.tenants[input.tenant_id].status == "active"
}

tenant_context_match if {
    input.context.tenant_id == input.tenant_id
}

resource_accessible if {
    resource_exists
    resource_belongs_to_tenant
    resource_not_deleted
    resource_permissions_valid
}

resource_exists if {
    input.resource
    input.resource.type
    input.resource.id
}

resource_belongs_to_tenant if {
    input.resource.tenant_id == input.tenant_id
}

resource_not_deleted if {
    not input.resource.deleted
}

resource_permissions_valid if {
    resource_type := input.resource.type
    allowed_resource_types[resource_type]
}

allowed_resource_types := {
    "model",
    "dataset", 
    "inference",
    "training",
    "deployment",
    "pipeline",
    "experiment",
    "workspace",
    "project",
    "api_key",
    "webhook",
    "log",
    "metric",
    "alert",
    "backup"
}

action_permitted if {
    input.action
    input.action in valid_actions
    action_scope_valid
    action_context_valid
}

valid_actions := {
    "create",
    "read", 
    "update",
    "delete",
    "list",
    "execute",
    "deploy",
    "train",
    "infer",
    "monitor",
    "backup",
    "restore",
    "share",
    "export",
    "import"
}

action_scope_valid if {
    action := input.action
    resource_type := input.resource.type
    action_resource_matrix[action][resource_type]
}

action_resource_matrix := {
    "create": {
        "model": true,
        "dataset": true,
        "inference": true,
        "training": true,
        "deployment": true,
        "pipeline": true,
        "experiment": true,
        "workspace": true,
        "project": true,
        "api_key": true,
        "webhook": true,
        "backup": true
    },
    "read": {
        "model": true,
        "dataset": true,
        "inference": true,
        "training": true,
        "deployment": true,
        "pipeline": true,
        "experiment": true,
        "workspace": true,
        "project": true,
        "api_key": true,
        "webhook": true,
        "log": true,
        "metric": true,
        "alert": true,
        "backup": true
    },
    "update": {
        "model": true,
        "dataset": true,
        "deployment": true,
        "pipeline": true,
        "experiment": true,
        "workspace": true,
        "project": true,
        "webhook": true
    },
    "delete": {
        "model": true,
        "dataset": true,
        "deployment": true,
        "pipeline": true,
        "experiment": true,
        "workspace": true,
        "project": true,
        "api_key": true,
        "webhook": true,
        "backup": true
    },
    "list": {
        "model": true,
        "dataset": true,
        "inference": true,
        "training": true,
        "deployment": true,
        "pipeline": true,
        "experiment": true,
        "workspace": true,
        "project": true,
        "api_key": true,
        "webhook": true,
        "log": true,
        "metric": true,
        "alert": true,
        "backup": true
    },
    "execute": {
        "inference": true,
        "training": true,
        "pipeline": true,
        "experiment": true
    },
    "deploy": {
        "model": true,
        "pipeline": true
    },
    "train": {
        "model": true,
        "experiment": true
    },
    "infer": {
        "model": true,
        "inference": true
    },
    "monitor": {
        "model": true,
        "deployment": true,
        "pipeline": true,
        "training": true,
        "inference": true
    },
    "backup": {
        "model": true,
        "dataset": true,
        "workspace": true,
        "project": true
    },
    "restore": {
        "model": true,
        "dataset": true,
        "workspace": true,
        "project": true,
        "backup": true
    },
    "share": {
        "model": true,
        "dataset": true,
        "experiment": true,
        "workspace": true
    },
    "export": {
        "model": true,
        "dataset": true,
        "experiment": true,
        "log": true,
        "metric": true
    },
    "import": {
        "model": true,
        "dataset": true
    }
}

action_context_valid if {
    input.context.action_context
    action_context_secure
}

action_context_secure if {
    not input.context.action_context.bypass_security
}

action_context_secure if {
    not input.context.action_context.elevated_privileges
}

explicitly_denied if {
    input.context.security_flags.blocked
}

explicitly_denied if {
    input.context.security_flags.suspended
}

explicitly_denied if {
    tenant_quota_exceeded
}

explicitly_denied if {
    security_violation_detected
}

explicitly_denied if {
    cross_tenant_access_attempt
}

rate_limit_check if {
    not rate_limit_exceeded
}

rate_limit_exceeded if {
    tenant_rate_limits := data.tenants[input.tenant_id].rate_limits
    action := input.action
    resource_type := input.resource.type
    
    current_usage := input.context.rate_limit.current_usage[action][resource_type]
    limit := tenant_rate_limits[action][resource_type]
    
    current_usage >= limit
}

security_context_valid if {
    input.context.security
    authentication_valid
    authorization_headers_valid
    request_integrity_valid
    timestamp_valid
}

authentication_valid if {
    input.context.security.authenticated == true
}

authentication_valid if {
    input.context.security.subject_id
    input.context.security.subject_id != ""
}

authorization_headers_valid if {
    input.context.security.headers.authorization
}

authorization_headers_valid if {
    input.context.security.headers.tenant_id == input.tenant_id
}

request_integrity_valid if {
    input.context.security.request_hash
    input.context.security.signature
}

timestamp_valid if {
    request_time := time.parse_rfc3339_ns(input.context.timestamp)
    current_time := time.now_ns()
    time_diff := current_time - request_time
    
    time_diff <= 300000000000
}

tenant_quota_exceeded if {
    tenant_quotas := data.tenants[input.tenant_id].quotas
    resource_type := input.resource.type
    action := input.action
    
    current_usage := input.context.usage[resource_type]
    quota_limit := tenant_quotas[resource_type]
    
    current_usage >= quota_limit
}

security_violation_detected if {
    suspicious_activity_patterns
}

security_violation_detected if {
    malicious_payload_detected
}

security_violation_detected if {
    anomalous_access_pattern
}

suspicious_activity_patterns if {
    request_frequency := input.context.security.request_frequency
    request_frequency > data.security_thresholds.max_request_frequency
}

suspicious_activity_patterns if {
    failed_attempts := input.context.security.failed_attempts
    failed_attempts > data.security_thresholds.max_failed_attempts
}

malicious_payload_detected if {
    payload_size := input.context.security.payload_size
    payload_size > data.security_thresholds.max_payload_size
}

malicious_payload_detected if {
    contains(input.context.security.payload_content, "script")
}

malicious_payload_detected if {
    contains(input.context.security.payload_content, "eval")
}

anomalous_access_pattern if {
    geo_location := input.context.security.geo_location
    allowed_locations := data.tenants[input.tenant_id].security.allowed_locations
    
    count([location | location := allowed_locations[_]; location == geo_location]) == 0
}

anomalous_access_pattern if {
    access_time := time.parse_rfc3339_ns(input.context.timestamp)
    hour := time.weekday(access_time)
    
    not business_hours_access(hour)
}

business_hours_access(hour) if {
    hour >= 8
    hour <= 18
}

cross_tenant_access_attempt if {
    input.resource.tenant_id != input.tenant_id
}

cross_tenant_access_attempt if {
    input.context.target_tenant_id
    input.context.target_tenant_id != input.tenant_id
}

tenant_permissions := data.tenants[input.tenant_id].permissions

resource_permission_check if {
    resource_type := input.resource.type
    action := input.action
    
    tenant_permissions[resource_type][action] == true
}

subject_permissions := data.subjects[input.context.security.subject_id].permissions

subject_permission_check if {
    resource_type := input.resource.type
    action := input.action
    
    subject_permissions[resource_type][action] == true
}

role_based_access if {
    subject_roles := data.subjects[input.context.security.subject_id].roles
    required_role := resource_role_requirements[input.resource.type][input.action]
    
    required_role in subject_roles
}

resource_role_requirements := {
    "model": {
        "create": "model_creator",
        "read": "model_viewer", 
        "update": "model_editor",
        "delete": "model_admin",
        "deploy": "model_deployer",
        "train": "model_trainer"
    },
    "dataset": {
        "create": "data_creator",
        "read": "data_viewer",
        "update": "data_editor", 
        "delete": "data_admin",
        "import": "data_importer",
        "export": "data_exporter"
    },
    "inference": {
        "create": "inference_creator",
        "read": "inference_viewer",
        "execute": "inference_executor",
        "monitor": "inference_monitor"
    },
    "training": {
        "create": "training_creator",
        "read": "training_viewer",
        "execute": "training_executor",
        "monitor": "training_monitor"
    },
    "deployment": {
        "create": "deployment_creator",
        "read": "deployment_viewer",
        "update": "deployment_editor",
        "delete": "deployment_admin",
        "monitor": "deployment_monitor"
    }
}

time_based_access if {
    current_time := time.now_ns()
    tenant_schedule := data.tenants[input.tenant_id].access_schedule
    
    time_within_schedule(current_time, tenant_schedule)
}

time_within_schedule(current_time, schedule) if {
    start_time := time.parse_rfc3339_ns(schedule.start_time)
    end_time := time.parse_rfc3339_ns(schedule.end_time)
    
    current_time >= start_time
    current_time <= end_time
}

ip_whitelist_check if {
    client_ip := input.context.security.client_ip
    allowed_ips := data.tenants[input.tenant_id].security.allowed_ips
    
    client_ip in allowed_ips
}

compliance_check if {
    tenant_compliance := data.tenants[input.tenant_id].compliance
    resource_type := input.resource.type
    action := input.action
    
    compliance_requirements_met(tenant_compliance, resource_type, action)
}

compliance_requirements_met(compliance, resource_type, action) if {
    compliance.gdpr_enabled
    gdpr_compliant(resource_type, action)
}

compliance_requirements_met(compliance, resource_type, action) if {
    compliance.hipaa_enabled  
    hipaa_compliant(resource_type, action)
}

compliance_requirements_met(compliance, resource_type, action) if {
    compliance.sox_enabled
    sox_compliant(resource_type, action)
}

gdpr_compliant(resource_type, action) if {
    resource_type != "dataset"
}

gdpr_compliant("dataset", action) if {
    action in {"read", "list"}
    input.context.gdpr.consent_given == true
}

hipaa_compliant(resource_type, action) if {
    input.context.hipaa.phi_access_logged == true
}

sox_compliant(resource_type, action) if {
    input.context.sox.audit_trail_enabled == true
}

audit_log_entry := {
    "policy_id": metadata.policy_id,
    "tenant_id": input.tenant_id,
    "subject_id": input.context.security.subject_id,
    "resource": {
        "type": input.resource.type,
        "id": input.resource.id,
        "tenant_id": input.resource.tenant_id
    },
    "action": input.action,
    "decision": allow,
    "timestamp": time.now_ns(),
    "request_id": input.context.request_id,
    "trace_id": input.context.trace_id,
    "client_ip": input.context.security.client_ip,
    "user_agent": input.context.security.user_agent,
    "geo_location": input.context.security.geo_location,
    "evaluation_time_ns": evaluation_duration,
    "policy_version": metadata.version,
    "compliance_flags": compliance_flags,
    "security_flags": security_flags,
    "rate_limit_status": rate_limit_status,
    "quota_status": quota_status
}

evaluation_duration := time.now_ns() - time.parse_rfc3339_ns(input.context.timestamp)

compliance_flags := {
    "gdpr_applicable": data.tenants[input.tenant_id].compliance.gdpr_enabled,
    "hipaa_applicable": data.tenants[input.tenant_id].compliance.hipaa_enabled,
    "sox_applicable": data.tenants[input.tenant_id].compliance.sox_enabled,
    "gdpr_compliant": gdpr_compliant(input.resource.type, input.action),
    "hipaa_compliant": hipaa_compliant(input.resource.type, input.action),
    "sox_compliant": sox_compliant(input.resource.type, input.action)
}

security_flags := {
    "tenant_isolated": tenant_isolated,
    "authentication_valid": authentication_valid,
    "authorization_valid": authorization_headers_valid,
    "request_integrity_valid": request_integrity_valid,
    "timestamp_valid": timestamp_valid,
    "ip_whitelisted": ip_whitelist_check,
    "geo_location_allowed": not anomalous_access_pattern,
    "suspicious_activity": suspicious_activity_patterns,
    "malicious_payload": malicious_payload_detected,
    "cross_tenant_attempt": cross_tenant_access_attempt
}

rate_limit_status := {
    "exceeded": rate_limit_exceeded,
    "current_usage": input.context.rate_limit.current_usage,
    "limits": data.tenants[input.tenant_id].rate_limits,
    "reset_time": input.context.rate_limit.reset_time
}

quota_status := {
    "exceeded": tenant_quota_exceeded,
    "current_usage": input.context.usage,
    "quotas": data.tenants[input.tenant_id].quotas,
    "reset_time": input.context.quota.reset_time
}

decision_metadata := {
    "policy_evaluation": {
        "tenant_isolated": tenant_isolated,
        "resource_accessible": resource_accessible,
        "action_permitted": action_permitted,
        "explicitly_denied": explicitly_denied,
        "rate_limit_check": rate_limit_check,
        "security_context_valid": security_context_valid
    },
    "tenant_validation": {
        "valid_format": valid_tenant_format,
        "exists": tenant_exists,
        "active": tenant_active,
        "context_match": tenant_context_match
    },
    "resource_validation": {
        "exists": resource_exists,
        "belongs_to_tenant": resource_belongs_to_tenant,
        "not_deleted": resource_not_deleted,
        "permissions_valid": resource_permissions_valid
    },
    "action_validation": {
        "valid_action": input.action in valid_actions,
        "scope_valid": action_scope_valid,
        "context_valid": action_context_valid
    },
    "security_validation": {
        "authentication": authentication_valid,
        "authorization": authorization_headers_valid,
        "integrity": request_integrity_valid,
        "timestamp": timestamp_valid,
        "ip_whitelist": ip_whitelist_check,
        "compliance": compliance_check
    },
    "rbac_validation": {
        "resource_permission": resource_permission_check,
        "subject_permission": subject_permission_check,
        "role_based_access": role_based_access
    }
}

emergency_access if {
    input.context.emergency.enabled == true
    input.context.emergency.authorized_by
    input.context.emergency.reason
    input.context.emergency.approval_code
    emergency_approval_valid
}

emergency_approval_valid if {
    approval_code := input.context.emergency.approval_code
    expected_code := data.emergency_codes[input.tenant_id].current_code
    approval_code == expected_code
}

emergency_access_logged if {
    emergency_access
    input.context.emergency.audit_logged == true
}

maintenance_mode_check if {
    not data.system.maintenance_mode.enabled
}

maintenance_mode_check if {
    data.system.maintenance_mode.enabled
    input.context.security.subject_id in data.system.maintenance_mode.allowed_subjects
}

system_health_check if {
    data.system.health.status == "healthy"
}

system_health_check if {
    data.system.health.status == "degraded"
    input.action in {"read", "list"}
}

tenant_subscription_valid if {
    subscription := data.tenants[input.tenant_id].subscription
    subscription.status == "active"
    subscription_not_expired
}

subscription_not_expired if {
    subscription := data.tenants[input.tenant_id].subscription
    current_time := time.now_ns()
    expiry_time := time.parse_rfc3339_ns(subscription.expires_at)
    current_time < expiry_time
}

feature_flag_check if {
    resource_type := input.resource.type
    action := input.action
    feature_key := sprintf("%s_%s", [resource_type, action])
    
    tenant_features := data.tenants[input.tenant_id].features
    tenant_features[feature_key] == true
}

data_residency_check if {
    tenant_region := data.tenants[input.tenant_id].region
    resource_region := input.resource.region
    tenant_region == resource_region
}

encryption_requirement_check if {
    resource_type := input.resource.type
    encryption_required := data.security_policies.encryption_requirements[resource_type]
    
    not encryption_required
}

encryption_requirement_check if {
    resource_type := input.resource.type
    encryption_required := data.security_policies.encryption_requirements[resource_type]
    encryption_required
    input.context.security.encryption_enabled == true
}

final_decision := {
    "allow": allow,
    "deny": deny,
    "tenant_id": input.tenant_id,
    "resource": input.resource,
    "action": input.action,
    "metadata": decision_metadata,
    "audit_log": audit_log_entry,
    "compliance": compliance_flags,
    "security": security_flags,
    "emergency_access": emergency_access,
    "maintenance_mode": data.system.maintenance_mode.enabled,
    "system_health": data.system.health.status,
    "evaluation_time_ms": evaluation_duration / 1000000
}

allow if {
    tenant_isolated
    resource_accessible  
    action_permitted
    not explicitly_denied
    rate_limit_check
    security_context_valid
    maintenance_mode_check
    system_health_check
    tenant_subscription_valid
    feature_flag_check
    data_residency_check
    encryption_requirement_check
}

allow if {
    emergency_access
    emergency_access_logged
    maintenance_mode_check
}
