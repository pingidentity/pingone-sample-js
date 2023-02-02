provider "pingone" {}

locals {
  use_license_id_var = (var.license_id != null && var.license_id != "")
  license_id = var.license_id != null && var.license_id != "" ? var.license_id : data.pingone_licenses.org_licenses[0].ids[0]
}

#########################################################################
# PineOne Admin Environment
#########################################################################
data "pingone_environment" "administrators" {
  environment_id = var.admin_environment_id
}

#########################################################################
# PingOne License ID
#########################################################################
data "pingone_licenses" "org_licenses" {
  count = !local.use_license_id_var ? 1 : 0

  organization_id = data.pingone_environment.administrators.organization_id

  data_filter {
    name   = "name"
    values = [var.license_name]
  }

  data_filter {
    name   = "status"
    values = ["ACTIVE"]
  }
}

resource "pingone_environment" "my_environment" {
  name        = var.environment_name
  description = "An environment created from Terraform to showcase the PingOne Sample JS application"
  type        = "SANDBOX"
  license_id  = local.license_id

  lifecycle {
    precondition {
      condition     = (var.license_id != null && var.license_id != "") || ((var.license_name != null && var.license_name != "") && length(data.pingone_licenses.org_licenses) == 1)
      error_message = "Ensure one of `license_id` or `license_name` is set in the module parameters.  If using `license_name`, only one license of the same name should exist in the environment.  Licenses can be individually named in the admin console."
    }
  }

  default_population {}

  service {
    type = "SSO"
  }
}

resource "pingone_application" "single_page_app" {
  environment_id = pingone_environment.my_environment.id
  name           = "Sample JS Application SPA"
  enabled        = true

  oidc_options {
    type                        = "SINGLE_PAGE_APP"
    grant_types                 = ["IMPLICIT"]
    response_types              = ["TOKEN", "ID_TOKEN"]
    token_endpoint_authn_method = "NONE"
    redirect_uris               = [var.deployment_url]
    post_logout_redirect_uris   = [var.deployment_url]
  }
}

data "pingone_resource" "openid" {
  environment_id = pingone_environment.my_environment.id

  name = "openid"
}

data "pingone_resource_scope" "openid" {
    for_each = toset(var.openid_scopes)

  environment_id = pingone_environment.my_environment.id
  resource_id    = data.pingone_resource.openid.id

  name = each.key
}

resource "pingone_application_resource_grant" "openid" {
  environment_id = pingone_environment.my_environment.id
  application_id = pingone_application.single_page_app.id

  resource_id = data.pingone_resource.openid.id

  scopes = [for r in data.pingone_resource_scope.openid : r.id]
}
