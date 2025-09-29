variable "backend_lambda_arn" {
  type        = string
  description = "Existing backend Lambda ARN (Lambda proxy integration target)"
  default     = "arn:aws:lambda:us-east-1:179072210594:function:nodejs_backend"
}

variable "tenant_id" {
  type        = string
  description = "Azure AD (Entra ID) tenant ID (GUID)"
}

variable "audience" {
  type        = string
  description = "Expected audience for tokens (e.g., api://<app-id> or the API app's client ID). For multiple, comma-separate."
}

variable "create_lambda_permission" {
  type        = bool
  default     = true
  description = "If true, grant API Gateway permission to invoke the existing backend Lambda"
}