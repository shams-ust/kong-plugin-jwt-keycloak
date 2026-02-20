local typedefs = require "kong.db.schema.typedefs"

return {
  name = "jwt-keycloak",
  fields = {
    { protocols = typedefs.protocols_http },
    { config = {
        type = "record",
        fields = {
          -- Essential: The list of allowed issuers
          { allowed_iss = { 
              type = "array", 
              required = true, 
              elements = { type = "string" },
              default = {} 
          } },
          -- Essential: The URL template for Keycloak discovery
          { well_known_template = { 
              type = "string", 
              default = "%s/.well-known/openid-configuration" 
          } },
          -- Security: Algorithms allowed for validation
          { algorithms = { 
              type = "array", 
              default = { "RS256" }, 
              elements = { type = "string", one_of = { "RS256", "RS512" } } 
          } },
          -- Cache/Rotation: Grace period for refreshing keys (seconds)
          { iss_key_grace_period = { 
              type = "number", 
              default = 10, 
              gt = 0 
          } },
          -- Gateway Logic: Run on CORS preflight requests
          { run_on_preflight = { 
              type = "boolean", 
              default = true 
          } },
          -- Headers to check for tokens
          { header_names = { 
              type = "array", 
              default = { "authorization" }, 
              elements = typedefs.header_name 
          } },
          -- URI params to check for tokens
          { uri_param_names = { 
              type = "array", 
              default = { "jwt" }, 
              elements = { type = "string" } 
          } },
          -- Cookie names to check for tokens
          { cookie_names = { 
              type = "array", 
              default = {}, 
              elements = { type = "string" } 
          } },
          -- Claim verification (e.g., exp, nbf)
          { claims_to_verify = { 
              type = "array", 
              default = { "exp" }, 
              elements = { type = "string", one_of = { "exp", "nbf" } } 
          } },
        },
    }, },
  },
}
