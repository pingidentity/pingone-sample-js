variable "admin_environment_id" {
  type = string
}

variable "environment_name" {
  type = string
  default = "PingOne Sample JS Demonstration"
}

variable "license_name" {
  type = string
  default = null
}

variable "license_id" {
  type = string
  default = null
}

variable "application_name" {
  type = string
  default = "Sample JS Application SPA"
}

variable "deployment_url" {
  type = string
  default = "http://localhost:8080"
}

variable "openid_scopes" {
    type = list(string)
    default = [
        "profile", "email", "address"
    ]
}
