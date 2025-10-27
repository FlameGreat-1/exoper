package rate.limits

import future.keywords.if
import future.keywords.in
import future.keywords.every
import future.keywords.contains

default allow := false
default deny := true
default rate_limit_exceeded := false
default quota_exceeded := false
default throttling_required := false

metadata := {
    "policy_id": "rate-limits-base",
    "version": "1.0.0",
    "description": "Rate limiting and throttling policy for API and resource access",
    "priority": 13,
    "effect": "deny",
    "created_by": "system",
    "tags": ["rate_limit", "throttling", "quota", "performance", "protection"]
}

allow if {
    not rate_limit_exceeded
    not quota_exceeded
    not throttling_required
    not burst_limit_exceeded
    not concurrent_limit_exceeded
    rate_limit_window_valid
    tenant_limits_respected
    resource_limits_respected
}

deny if {
    rate_limit_exceeded
}

deny if {
    quota_exceeded
}

deny if {
    burst_limit_exceeded
}

rate_limit_exceeded if {
    tenant_rate_limit_exceeded
}

rate_limit_exceeded if {
    subject_rate_limit_exceeded
}

rate_limit_exceeded if {
    resource_rate_limit_exceeded
}

rate_limit_exceeded if {
    action_rate_limit_exceeded
}

tenant_rate_limit_exceeded if {
    tenant_limits := data.tenants[input.tenant_id].rate_limits
    action := input.action
    resource_type := input.resource.type
    
    current_usage := input.context.rate_limit.tenant_usage[action][resource_type]
    limit := tenant_limits[action][resource_type]
    window := tenant_limits.window_seconds
    
    usage_exceeds_limit(current_usage, limit, window)
}

subject_rate_limit_exceeded if {
    subject_id := input.context.security.subject_id
    subject_limits := data.subjects[subject_id].rate_limits
    action := input.action
    resource_type := input.resource.type
    
    current_usage := input.context.rate_limit.subject_usage[action][resource_type]
    limit := subject_limits[action][resource_type]
    window := subject_limits.window_seconds
    
    usage_exceeds_limit(current_usage, limit, window)
}

resource_rate_limit_exceeded if {
    resource_id := input.resource.id
    resource_limits := data.resources[resource_id].rate_limits
    action := input.action
    
    current_usage := input.context.rate_limit.resource_usage[action]
    limit := resource_limits[action]
    window := resource_limits.window_seconds
    
    usage_exceeds_limit(current_usage, limit, window)
}

action_rate_limit_exceeded if {
    action := input.action
    global_limits := data.system.rate_limits.actions
    
    current_usage := input.context.rate_limit.global_usage[action]
    limit := global_limits[action].requests_per_window
    window := global_limits[action].window_seconds
    
    usage_exceeds_limit(current_usage, limit, window)
}

usage_exceeds_limit(current_usage, limit, window) if {
    current_time := time.now_ns()
    window_start := current_time - (window * 1000000000)
    
    requests_in_window := count([req | req := current_usage[_]; req.timestamp >= window_start])
    requests_in_window >= limit
}

quota_exceeded if {
    tenant_quota_exceeded
}

quota_exceeded if {
    subject_quota_exceeded
}

quota_exceeded if {
    resource_quota_exceeded
}

tenant_quota_exceeded if {
    tenant_quotas := data.tenants[input.tenant_id].quotas
    resource_type := input.resource.type
    action := input.action
    
    current_usage := input.context.quota.tenant_usage[resource_type][action]
    quota_limit := tenant_quotas[resource_type][action]
    quota_period := tenant_quotas.period_hours
    
    quota_limit_reached(current_usage, quota_limit, quota_period)
}

subject_quota_exceeded if {
    subject_id := input.context.security.subject_id
    subject_quotas := data.subjects[subject_id].quotas
    resource_type := input.resource.type
    action := input.action
    
    current_usage := input.context.quota.subject_usage[resource_type][action]
    quota_limit := subject_quotas[resource_type][action]
    quota_period := subject_quotas.period_hours
    
    quota_limit_reached(current_usage, quota_limit, quota_period)
}

resource_quota_exceeded if {
    resource_id := input.resource.id
    resource_quotas := data.resources[resource_id].quotas
    action := input.action
    
    current_usage := input.context.quota.resource_usage[action]
    quota_limit := resource_quotas[action]
    quota_period := resource_quotas.period_hours
    
    quota_limit_reached(current_usage, quota_limit, quota_period)
}

quota_limit_reached(current_usage, quota_limit, quota_period) if {
    current_time := time.now_ns()
    period_start := current_time - (quota_period * 3600 * 1000000000)
    
    usage_in_period := sum([usage.amount | usage := current_usage[_]; usage.timestamp >= period_start])
    usage_in_period >= quota_limit
}

burst_limit_exceeded if {
    tenant_burst_limit_exceeded
}

burst_limit_exceeded if {
    subject_burst_limit_exceeded
}

burst_limit_exceeded if {
    global_burst_limit_exceeded
}

tenant_burst_limit_exceeded if {
    tenant_limits := data.tenants[input.tenant_id].burst_limits
    action := input.action
    resource_type := input.resource.type
    
    current_burst := input.context.burst.tenant_burst[action][resource_type]
    burst_limit := tenant_limits[action][resource_type]
    burst_window := tenant_limits.burst_window_seconds
    
    burst_exceeds_limit(current_burst, burst_limit, burst_window)
}

subject_burst_limit_exceeded if {
    subject_id := input.context.security.subject_id
    subject_limits := data.subjects[subject_id].burst_limits
    action := input.action
    resource_type := input.resource.type
    
    current_burst := input.context.burst.subject_burst[action][resource_type]
    burst_limit := subject_limits[action][resource_type]
    burst_window := subject_limits.burst_window_seconds
    
    burst_exceeds_limit(current_burst, burst_limit, burst_window)
}

global_burst_limit_exceeded if {
    global_limits := data.system.burst_limits
    action := input.action
    
    current_burst := input.context.burst.global_burst[action]
    burst_limit := global_limits[action].max_burst
    burst_window := global_limits[action].burst_window_seconds
    
    burst_exceeds_limit(current_burst, burst_limit, burst_window)
}

burst_exceeds_limit(current_burst, burst_limit, burst_window) if {
    current_time := time.now_ns()
    window_start := current_time - (burst_window * 1000000000)
    
    requests_in_burst_window := count([req | req := current_burst[_]; req.timestamp >= window_start])
    requests_in_burst_window >= burst_limit
}

concurrent_limit_exceeded if {
    tenant_concurrent_limit_exceeded
}

concurrent_limit_exceeded if {
    subject_concurrent_limit_exceeded
}

concurrent_limit_exceeded if {
    resource_concurrent_limit_exceeded
}

tenant_concurrent_limit_exceeded if {
    tenant_limits := data.tenants[input.tenant_id].concurrent_limits
    resource_type := input.resource.type
    action := input.action
    
    current_concurrent := input.context.concurrent.tenant_concurrent[resource_type][action]
    concurrent_limit := tenant_limits[resource_type][action]
    
    current_concurrent >= concurrent_limit
}

subject_concurrent_limit_exceeded if {
    subject_id := input.context.security.subject_id
    subject_limits := data.subjects[subject_id].concurrent_limits
    resource_type := input.resource.type
    action := input.action
    
    current_concurrent := input.context.concurrent.subject_concurrent[resource_type][action]
    concurrent_limit := subject_limits[resource_type][action]
    
    current_concurrent >= concurrent_limit
}

resource_concurrent_limit_exceeded if {
    resource_id := input.resource.id
    resource_limits := data.resources[resource_id].concurrent_limits
    action := input.action
    
    current_concurrent := input.context.concurrent.resource_concurrent[action]
    concurrent_limit := resource_limits[action]
    
    current_concurrent >= concurrent_limit
}

throttling_required if {
    adaptive_throttling_triggered
}

throttling_required if {
    priority_based_throttling_required
}

throttling_required if {
    system_load_throttling_required
}

adaptive_throttling_triggered if {
    tenant_id := input.tenant_id
    action := input.action
    resource_type := input.resource.type
    
    recent_error_rate := input.context.metrics.recent_error_rate
    error_threshold := data.throttling.adaptive.error_rate_threshold
    
    recent_error_rate > error_threshold
}

priority_based_throttling_required if {
    request_priority := input.context.priority
    system_load := input.context.system.load_percentage
    
    priority_threshold := data.throttling.priority_thresholds[request_priority]
    system_load > priority_threshold
}

system_load_throttling_required if {
    system_metrics := input.context.system
    
    cpu_overloaded := system_metrics.cpu_utilization > data.throttling.system_thresholds.max_cpu_percent
    memory_overloaded := system_metrics.memory_utilization > data.throttling.system_thresholds.max_memory_percent
    
    cpu_overloaded
}

system_load_throttling_required if {
    system_metrics := input.context.system
    memory_overloaded := system_metrics.memory_utilization > data.throttling.system_thresholds.max_memory_percent
    
    memory_overloaded
}

rate_limit_window_valid if {
    current_time := time.now_ns()
    request_timestamp := time.parse_rfc3339_ns(input.context.timestamp)
    time_diff := current_time - request_timestamp
    
    max_window_drift := data.rate_limits.max_window_drift_seconds * 1000000000
    time_diff <= max_window_drift
}

tenant_limits_respected if {
    tenant_subscription_limits_respected
    tenant_tier_limits_respected
    tenant_custom_limits_respected
}

tenant_subscription_limits_respected if {
    tenant_subscription := data.tenants[input.tenant_id].subscription
    subscription_tier := tenant_subscription.tier
    action := input.action
    resource_type := input.resource.type
    
    tier_limits := data.subscription_tiers[subscription_tier].rate_limits
    current_usage := input.context.rate_limit.tenant_usage[action][resource_type]
    
    subscription_limit := tier_limits[action][resource_type]
    window := tier_limits.window_seconds
    
    not usage_exceeds_limit(current_usage, subscription_limit, window)
}

tenant_tier_limits_respected if {
    tenant_tier := data.tenants[input.tenant_id].tier
    tier_config := data.tenant_tiers[tenant_tier]
    action := input.action
    resource_type := input.resource.type
    
    tier_rate_limits := tier_config.rate_limits
    current_usage := input.context.rate_limit.tenant_usage[action][resource_type]
    
    tier_limit := tier_rate_limits[action][resource_type]
    window := tier_rate_limits.window_seconds
    
    not usage_exceeds_limit(current_usage, tier_limit, window)
}

tenant_custom_limits_respected if {
    tenant_custom_limits := data.tenants[input.tenant_id].custom_rate_limits
    
    not tenant_custom_limits
}

tenant_custom_limits_respected if {
    tenant_custom_limits := data.tenants[input.tenant_id].custom_rate_limits
    action := input.action
    resource_type := input.resource.type
    
    custom_limit := tenant_custom_limits[action][resource_type]
    current_usage := input.context.rate_limit.tenant_usage[action][resource_type]
    window := tenant_custom_limits.window_seconds
    
    not usage_exceeds_limit(current_usage, custom_limit, window)
}

resource_limits_respected if {
    model_specific_limits_respected
    inference_limits_respected
    training_limits_respected
    deployment_limits_respected
}

model_specific_limits_respected if {
    input.resource.type != "model"
}

model_specific_limits_respected if {
    input.resource.type == "model"
    model_id := input.resource.id
    model_limits := data.models[model_id].rate_limits
    action := input.action
    
    current_usage := input.context.rate_limit.resource_usage[action]
    model_limit := model_limits[action]
    window := model_limits.window_seconds
    
    not usage_exceeds_limit(current_usage, model_limit, window)
}

inference_limits_respected if {
    action := input.action
    action != "infer"
}

inference_limits_respected if {
    action := input.action
    action == "infer"
    
    inference_rate_limit_respected
    inference_throughput_limit_respected
    inference_latency_requirement_met
}

inference_rate_limit_respected if {
    model_id := input.resource.id
    model_inference_limits := data.models[model_id].inference_limits
    
    current_inference_rate := input.context.inference.current_rate_per_minute
    max_inference_rate := model_inference_limits.max_requests_per_minute
    
    current_inference_rate <= max_inference_rate
}

inference_throughput_limit_respected if {
    model_id := input.resource.id
    model_inference_limits := data.models[model_id].inference_limits
    
    current_throughput := input.context.inference.current_throughput_rps
    max_throughput := model_inference_limits.max_throughput_rps
    
    current_throughput <= max_throughput
}

inference_latency_requirement_met if {
    model_id := input.resource.id
    model_inference_limits := data.models[model_id].inference_limits
    
    expected_latency := input.context.inference.expected_latency_ms
    max_latency := model_inference_limits.max_latency_ms
    
    expected_latency <= max_latency
}

training_limits_respected if {
    action := input.action
    action != "train"
}

training_limits_respected if {
    action := input.action
    action == "train"
    
    training_job_limit_respected
    training_resource_limit_respected
    training_duration_limit_respected
}

training_job_limit_respected if {
    tenant_id := input.tenant_id
    tenant_training_limits := data.tenants[tenant_id].training_limits
    
    current_training_jobs := input.context.training.current_jobs
    max_concurrent_jobs := tenant_training_limits.max_concurrent_training_jobs
    
    current_training_jobs < max_concurrent_jobs
}

training_resource_limit_respected if {
    tenant_id := input.tenant_id
    tenant_training_limits := data.tenants[tenant_id].training_limits
    
    requested_gpu_hours := input.context.training.requested_gpu_hours
    available_gpu_hours := tenant_training_limits.available_gpu_hours
    
    requested_gpu_hours <= available_gpu_hours
}

training_duration_limit_respected if {
    model_id := input.resource.id
    model_training_limits := data.models[model_id].training_limits
    
    estimated_duration_hours := input.context.training.estimated_duration_hours
    max_duration_hours := model_training_limits.max_training_duration_hours
    
    estimated_duration_hours <= max_duration_hours
}

deployment_limits_respected if {
    action := input.action
    action != "deploy"
}

deployment_limits_respected if {
    action := input.action
    action == "deploy"
    
    deployment_count_limit_respected
    deployment_resource_limit_respected
    deployment_environment_limit_respected
}

deployment_count_limit_respected if {
    tenant_id := input.tenant_id
    tenant_deployment_limits := data.tenants[tenant_id].deployment_limits
    
    current_deployments := input.context.deployment.current_count
    max_deployments := tenant_deployment_limits.max_concurrent_deployments
    
    current_deployments < max_deployments
}

deployment_resource_limit_respected if {
    tenant_id := input.tenant_id
    tenant_deployment_limits := data.tenants[tenant_id].deployment_limits
    
    requested_compute_units := input.context.deployment.requested_compute_units
    available_compute_units := tenant_deployment_limits.available_compute_units
    
    requested_compute_units <= available_compute_units
}

deployment_environment_limit_respected if {
    target_environment := input.context.deployment.target_environment
    environment_limits := data.environments[target_environment].deployment_limits
    
    current_deployments_in_env := input.context.deployment.current_count_in_environment
    max_deployments_in_env := environment_limits.max_deployments
    
    current_deployments_in_env < max_deployments_in_env
}

advanced_throttling_mechanisms if {
    exponential_backoff_applied
    circuit_breaker_respected
    load_shedding_applied
}

exponential_backoff_applied if {
    recent_failures := input.context.failures.recent_count
    backoff_threshold := data.throttling.exponential_backoff.failure_threshold
    
    recent_failures < backoff_threshold
}

exponential_backoff_applied if {
    recent_failures := input.context.failures.recent_count
    backoff_threshold := data.throttling.exponential_backoff.failure_threshold
    last_request_time := input.context.failures.last_request_timestamp
    
    recent_failures >= backoff_threshold
    
    current_time := time.now_ns()
    time_since_last_request := current_time - time.parse_rfc3339_ns(last_request_time)
    
    required_backoff := calculate_exponential_backoff(recent_failures)
    time_since_last_request >= required_backoff
}

calculate_exponential_backoff(failure_count) := backoff_time if {
    base_delay := data.throttling.exponential_backoff.base_delay_ms
    max_delay := data.throttling.exponential_backoff.max_delay_ms
    multiplier := data.throttling.exponential_backoff.multiplier
    
    calculated_delay := base_delay * (multiplier ^ (failure_count - 1))
    backoff_time := min(calculated_delay, max_delay) * 1000000
}

circuit_breaker_respected if {
    circuit_breaker_state := input.context.circuit_breaker.state
    circuit_breaker_state != "open"
}

circuit_breaker_respected if {
    circuit_breaker_state := input.context.circuit_breaker.state
    circuit_breaker_state == "open"
    
    circuit_opened_time := input.context.circuit_breaker.opened_timestamp
    current_time := time.now_ns()
    time_since_opened := current_time - time.parse_rfc3339_ns(circuit_opened_time)
    
    recovery_timeout := data.throttling.circuit_breaker.recovery_timeout_ms * 1000000
    time_since_opened >= recovery_timeout
}

load_shedding_applied if {
    system_load := input.context.system.load_percentage
    load_shedding_threshold := data.throttling.load_shedding.threshold_percentage
    
    system_load <= load_shedding_threshold
}

load_shedding_applied if {
    system_load := input.context.system.load_percentage
    load_shedding_threshold := data.throttling.load_shedding.threshold_percentage
    request_priority := input.context.priority
    
    system_load > load_shedding_threshold
    priority_allowed_during_shedding(request_priority, system_load)
}

priority_allowed_during_shedding(priority, system_load) if {
    priority_thresholds := data.throttling.load_shedding.priority_thresholds
    threshold := priority_thresholds[priority]
    
    system_load <= threshold
}

geographic_rate_limiting if {
    client_region := input.context.security.geo_location.region
    regional_limits := data.rate_limits.geographic[client_region]
    action := input.action
    resource_type := input.resource.type
    
    current_regional_usage := input.context.rate_limit.regional_usage[client_region][action][resource_type]
    regional_limit := regional_limits[action][resource_type]
    window := regional_limits.window_seconds
    
    not usage_exceeds_limit(current_regional_usage, regional_limit, window)
}

time_based_rate_limiting if {
    current_hour := time.weekday(time.now_ns())
    time_based_limits := data.rate_limits.time_based
    action := input.action
    resource_type := input.resource.type
    
    hourly_limit := time_based_limits[current_hour][action][resource_type]
    current_hourly_usage := input.context.rate_limit.hourly_usage[action][resource_type]
    
    current_hourly_usage < hourly_limit
}

api_key_rate_limiting if {
    api_key := input.context.security.api_key
    
    not api_key
}

api_key_rate_limiting if {
    api_key := input.context.security.api_key
    api_key_limits := data.api_keys[api_key].rate_limits
    action := input.action
    resource_type := input.resource.type
    
    current_api_key_usage := input.context.rate_limit.api_key_usage[action][resource_type]
    api_key_limit := api_key_limits[action][resource_type]
    window := api_key_limits.window_seconds
    
    not usage_exceeds_limit(current_api_key_usage, api_key_limit, window)
}

rate_limit_audit_log_entry := {
    "policy_id": metadata.policy_id,
    "tenant_id": input.tenant_id,
    "subject_id": input.context.security.subject_id,
    "resource": {
        "type": input.resource.type,
        "id": input.resource.id
    },
    "action": input.action,
    "decision": allow,
    "timestamp": time.now_ns(),
    "request_id": input.context.request_id,
    "trace_id": input.context.trace_id,
    "rate_limit_status": rate_limit_status,
    "quota_status": quota_status,
    "throttling_status": throttling_status,
    "enforcement_actions": enforcement_actions,
    "limit_violations": limit_violations,
    "performance_impact": performance_impact
}

rate_limit_status := {
    "tenant_rate_limit_exceeded": tenant_rate_limit_exceeded,
    "subject_rate_limit_exceeded": subject_rate_limit_exceeded,
    "resource_rate_limit_exceeded": resource_rate_limit_exceeded,
    "action_rate_limit_exceeded": action_rate_limit_exceeded,
    "burst_limit_exceeded": burst_limit_exceeded,
    "concurrent_limit_exceeded": concurrent_limit_exceeded,
    "current_usage": current_usage_summary,
    "applied_limits": applied_limits_summary
}

quota_status := {
    "tenant_quota_exceeded": tenant_quota_exceeded,
    "subject_quota_exceeded": subject_quota_exceeded,
    "resource_quota_exceeded": resource_quota_exceeded,
    "current_quotas": current_quota_summary,
    "quota_reset_times": quota_reset_times
}

throttling_status := {
    "adaptive_throttling_triggered": adaptive_throttling_triggered,
    "priority_based_throttling_required": priority_based_throttling_required,
    "system_load_throttling_required": system_load_throttling_required,
    "exponential_backoff_applied": exponential_backoff_applied,
    "circuit_breaker_state": input.context.circuit_breaker.state,
    "load_shedding_applied": load_shedding_applied
}

enforcement_actions := {
    "request_blocked": deny,
    "throttling_delay_ms": calculate_throttling_delay,
    "retry_after_seconds": calculate_retry_after,
    "circuit_breaker_action": circuit_breaker_action,
    "load_shedding_action": load_shedding_action,
    "priority_adjustment": priority_adjustment
}

limit_violations := {
    "violation_type": violation_type,
    "violation_severity": violation_severity,
    "violation_count": violation_count,
    "first_violation_time": first_violation_time,
    "consecutive_violations": consecutive_violations
}

performance_impact := {
    "expected_delay_ms": expected_delay_ms,
    "resource_utilization_impact": resource_utilization_impact,
    "system_load_impact": system_load_impact,
    "user_experience_impact": user_experience_impact
}

current_usage_summary := {
    "tenant_usage": input.context.rate_limit.tenant_usage,
    "subject_usage": input.context.rate_limit.subject_usage,
    "resource_usage": input.context.rate_limit.resource_usage,
    "global_usage": input.context.rate_limit.global_usage,
    "concurrent_operations": input.context.concurrent
}

applied_limits_summary := {
    "tenant_limits": data.tenants[input.tenant_id].rate_limits,
    "subject_limits": data.subjects[input.context.security.subject_id].rate_limits,
    "resource_limits": data.resources[input.resource.id].rate_limits,
    "global_limits": data.system.rate_limits,
    "subscription_limits": data.subscription_tiers[data.tenants[input.tenant_id].subscription.tier].rate_limits
}

current_quota_summary := {
    "tenant_quotas": input.context.quota.tenant_usage,
    "subject_quotas": input.context.quota.subject_usage,
    "resource_quotas": input.context.quota.resource_usage,
    "subscription_quotas": input.context.quota.subscription_usage
}

quota_reset_times := {
    "tenant_reset": data.tenants[input.tenant_id].quotas.reset_time,
    "subject_reset": data.subjects[input.context.security.subject_id].quotas.reset_time,
    "resource_reset": data.resources[input.resource.id].quotas.reset_time,
    "subscription_reset": data.subscription_tiers[data.tenants[input.tenant_id].subscription.tier].quotas.reset_time
}

calculate_throttling_delay := delay_ms if {
    throttling_required
    base_delay := data.throttling.base_delay_ms
    load_multiplier := input.context.system.load_percentage / 100
    priority_factor := data.throttling.priority_factors[input.context.priority]
    
    delay_ms := base_delay * load_multiplier * priority_factor
}

calculate_throttling_delay := 0 if {
    not throttling_required
}

calculate_retry_after := retry_seconds if {
    rate_limit_exceeded
    window_seconds := data.tenants[input.tenant_id].rate_limits.window_seconds
    current_time := time.now_ns()
    window_start := current_time - (window_seconds * 1000000000)
    
    retry_seconds := window_seconds - ((current_time - window_start) / 1000000000)
}

calculate_retry_after := 0 if {
    not rate_limit_exceeded
}

circuit_breaker_action := "open" if {
    input.context.circuit_breaker.failure_rate > data.throttling.circuit_breaker.failure_threshold
}

circuit_breaker_action := "half_open" if {
    input.context.circuit_breaker.state == "open"
    circuit_opened_time := input.context.circuit_breaker.opened_timestamp
    current_time := time.now_ns()
    time_since_opened := current_time - time.parse_rfc3339_ns(circuit_opened_time)
    recovery_timeout := data.throttling.circuit_breaker.recovery_timeout_ms * 1000000
    
    time_since_opened >= recovery_timeout
}

circuit_breaker_action := "close" if {
    input.context.circuit_breaker.state == "half_open"
    input.context.circuit_breaker.success_rate > data.throttling.circuit_breaker.success_threshold
}

load_shedding_action := "shed_low_priority" if {
    system_load := input.context.system.load_percentage
    system_load > data.throttling.load_shedding.threshold_percentage
    input.context.priority in {"low", "normal"}
}

load_shedding_action := "shed_normal_priority" if {
    system_load := input.context.system.load_percentage
    system_load > data.throttling.load_shedding.critical_threshold_percentage
    input.context.priority == "normal"
}

load_shedding_action := "none" if {
    system_load := input.context.system.load_percentage
    system_load <= data.throttling.load_shedding.threshold_percentage
}

priority_adjustment := "downgrade" if {
    rate_limit_exceeded
    input.context.priority in {"normal", "high"}
}

priority_adjustment := "maintain" if {
    not rate_limit_exceeded
}

violation_type := "rate_limit" if {
    rate_limit_exceeded
    not quota_exceeded
}

violation_type := "quota" if {
    quota_exceeded
    not rate_limit_exceeded
}

violation_type := "combined" if {
    rate_limit_exceeded
    quota_exceeded
}

violation_type := "none" if {
    not rate_limit_exceeded
    not quota_exceeded
}

violation_severity := "critical" if {
    burst_limit_exceeded
    concurrent_limit_exceeded
}

violation_severity := "high" if {
    rate_limit_exceeded
    quota_exceeded
    not burst_limit_exceeded
}

violation_severity := "medium" if {
    rate_limit_exceeded
    not quota_exceeded
    not burst_limit_exceeded
}

violation_severity := "low" if {
    throttling_required
    not rate_limit_exceeded
    not quota_exceeded
}

violation_count := input.context.violations.total_count

first_violation_time := input.context.violations.first_violation_timestamp

consecutive_violations := input.context.violations.consecutive_count

expected_delay_ms := calculate_throttling_delay

resource_utilization_impact := {
    "cpu_impact": input.context.system.cpu_utilization,
    "memory_impact": input.context.system.memory_utilization,
    "network_impact": input.context.system.network_utilization,
    "storage_impact": input.context.system.storage_utilization
}

system_load_impact := {
    "current_load": input.context.system.load_percentage,
    "projected_load": input.context.system.projected_load_percentage,
    "load_trend": input.context.system.load_trend
}

user_experience_impact := {
    "expected_latency_increase_ms": calculate_throttling_delay,
    "service_degradation_level": service_degradation_level,
    "user_notification_required": user_notification_required
}

service_degradation_level := "none" if {
    not throttling_required
    not rate_limit_exceeded
}

service_degradation_level := "minimal" if {
    throttling_required
    not rate_limit_exceeded
    calculate_throttling_delay < 1000
}

service_degradation_level := "moderate" if {
    rate_limit_exceeded
    not quota_exceeded
    calculate_throttling_delay < 5000
}

service_degradation_level := "severe" if {
    quota_exceeded
    burst_limit_exceeded
}

user_notification_required if {
    service_degradation_level in {"moderate", "severe"}
}

dynamic_rate_limit_adjustment := {
    "adjustment_factor": adjustment_factor,
    "new_limits": new_limits,
    "adjustment_reason": adjustment_reason,
    "adjustment_duration": adjustment_duration
}

adjustment_factor := 0.8 if {
    input.context.system.load_percentage > 80
    input.context.metrics.error_rate > 0.05
}

adjustment_factor := 1.2 if {
    input.context.system.load_percentage < 50
    input.context.metrics.error_rate < 0.01
}

adjustment_factor := 1.0 if {
    input.context.system.load_percentage >= 50
    input.context.system.load_percentage <= 80
}

new_limits := {
    "rate_limit": data.tenants[input.tenant_id].rate_limits[input.action][input.resource.type] * adjustment_factor,
    "burst_limit": data.tenants[input.tenant_id].burst_limits[input.action][input.resource.type] * adjustment_factor,
    "concurrent_limit": data.tenants[input.tenant_id].concurrent_limits[input.resource.type][input.action] * adjustment_factor
}

adjustment_reason := "high_load_error_rate" if {
    adjustment_factor == 0.8
}

adjustment_reason := "low_load_good_performance" if {
    adjustment_factor == 1.2
}

adjustment_reason := "stable_conditions" if {
    adjustment_factor == 1.0
}

adjustment_duration := 300 if {
    adjustment_factor != 1.0
}

adjustment_duration := 0 if {
    adjustment_factor == 1.0
}

final_rate_limit_decision := {
    "allow": allow,
    "deny": deny,
    "tenant_id": input.tenant_id,
    "resource": input.resource,
    "action": input.action,
    "rate_limit_status": rate_limit_status,
    "quota_status": quota_status,
    "throttling_status": throttling_status,
    "enforcement_actions": enforcement_actions,
    "audit_log": rate_limit_audit_log_entry,
    "dynamic_adjustments": dynamic_rate_limit_adjustment,
    "retry_after_seconds": calculate_retry_after,
    "throttling_delay_ms": calculate_throttling_delay,
    "evaluation_time_ms": (time.now_ns() - time.parse_rfc3339_ns(input.context.timestamp)) / 1000000
}

allow if {
    not rate_limit_exceeded
    not quota_exceeded
    not throttling_required
    not burst_limit_exceeded
    not concurrent_limit_exceeded
    rate_limit_window_valid
    tenant_limits_respected
    resource_limits_respected
    advanced_throttling_mechanisms
    geographic_rate_limiting
    time_based_rate_limiting
    api_key_rate_limiting
}
