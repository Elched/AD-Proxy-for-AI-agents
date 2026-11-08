export interface CommandMeta {
  name: string;
  description: string;
  category: 'read' | 'write' | 'admin' | 'system';
  risk_level: 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';
  required_params: string[];
  optional_params: string[];
}

export interface ProxyExecutionResult {
  success: boolean;
  status_code: string;
  message: string;
  data?: any;
  request_id?: string;
  duration_ms?: number;
  siem_event?: SiemEvent;
}

export interface SiemEvent {
  event_id: string;
  timestamp: string;
  caller_account: string;
  client_ip: string;
  command: string;
  target_dn?: string;
  filter_string?: string;
  outcome: 'SUCCESS' | 'AUTH_FAILED' | 'FORBIDDEN_CALLER' | 'FORBIDDEN_COMMAND' | 'RESTRICTED_TARGET' | 'VALIDATION_ERROR' | 'UPSTREAM_ERROR';
  status_code: string;
  message: string;
  duration_ms: number;
  parameters: Record<string, any>;
  details: Record<string, any>;
  domain: string;
  raw?: string;
}

export interface ServiceAccountPolicy {
  account_identifier: string;
  description: string;
  permitted_commands: string[];
  denied_commands?: string[];
  rules?: Array<{
    command: string;
    allowed_groups?: string[];
    restricted_groups?: string[];
    allowed_ous?: string[];
    allowed_attributes?: string[];
    max_search_results?: number;
    require_approval_ticket?: boolean;
  }>;
}
