package = "kong-plugin-jwt-keycloak"
version = "1.1.0-1"

source = {
  url = "git://://github.com/shams-ust/kong-plugin-jwt-keycloak",
  tag = "master"
}

description = {
  summary = "A Kong plugin that will validate tokens issued by Keycloak",
  license = "Apache 2.0"
}

dependencies = {
  "lua ~> 5.1",
  -- FIX: Added requirement for Kong's native HTTP client
  "lua-resty-http >= 0.11"
}

build = {
  type = "builtin",
  modules = {
    ["kong.plugins.jwt-keycloak.handler"] = "src/handler.lua",
    ["kong.plugins.jwt-keycloak.schema"] = "src/schema.lua",
    ["kong.plugins.jwt-keycloak.keycloak_keys"] = "src/keycloak_keys.lua",
    ["kong.plugins.jwt-keycloak.key_conversion"] = "src/key_conversion.lua",
    ["kong.plugins.jwt-keycloak.validators.issuers"] = "src/validators/issuers.lua",
    -- Include other validators if you have them in your src folder
    ["kong.plugins.jwt-keycloak.validators.scope"] = "src/validators/scope.lua",
    ["kong.plugins.jwt-keycloak.validators.roles"] = "src/validators/roles.lua"
  }
}
