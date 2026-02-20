local constants = require "kong.constants"
local jwt_decoder = require "kong.plugins.jwt.jwt_parser"
local kong_meta = require "kong.meta"
local keycloak_keys = require("kong.plugins.jwt-keycloak.keycloak_keys")

-- Validators
local validate_issuer = require("kong.plugins.jwt-keycloak.validators.issuers").validate_issuer
local validate_scope = require("kong.plugins.jwt-keycloak.validators.scope").validate_scope
local validate_roles = require("kong.plugins.jwt-keycloak.validators.roles").validate_roles
local validate_realm_roles = require("kong.plugins.jwt-keycloak.validators.roles").validate_realm_roles
local validate_client_roles = require("kong.plugins.jwt-keycloak.validators.roles").validate_client_roles

local re_gmatch = ngx.re.gmatch

-- Priority handling for Kong 3.x
local priority_env_var = "JWT_KEYCLOAK_PRIORITY"
local priority = tonumber(os.getenv(priority_env_var)) or 1005

local JwtKeycloakHandler = {
  VERSION = kong_meta.version,
  PRIORITY = priority,
}

local function custom_helper_table_to_string(tbl)
  local result = ""
  for k, v in pairs(tbl) do
      if type(k) == "string" then result = result.."[\""..k.."\"]".."=" end
      if type(v) == "table" then
          result = result..custom_helper_table_to_string(v)
      elseif type(v) == "boolean" then
          result = result..tostring(v)
      else
          result = result.."\""..v.."\""
      end
      result = result..","
  end
  return result ~= "" and result:sub(1, result:len()-1) or result
end

local function custom_helper_issuer_get_keys(well_known_endpoint)
  kong.log.debug('Getting public keys from token issuer')
  -- Note: Ensure keycloak_keys.lua uses the resty.http patch provided earlier
  local keys, err = keycloak_keys.get_issuer_keys(well_known_endpoint)
  if err then return nil, err end

  local decoded_keys = {}
  for i, key in ipairs(keys) do
      decoded_keys[i] = jwt_decoder:base64_decode(key)
  end

  kong.log.debug('Number of keys retrieved: ' .. #decoded_keys)
  return {
      keys = decoded_keys,
      updated_at = ngx.now(),
  }
end

local function custom_validate_token_signature(conf, jwt, second_call)
  local issuer_cache_key = 'issuer_keys_' .. jwt.claims.iss
  local well_known_endpoint = keycloak_keys.get_wellknown_endpoint(conf.well_known_template, jwt.claims.iss)
  
  local public_keys, err = kong.cache:get(issuer_cache_key, nil, custom_helper_issuer_get_keys, well_known_endpoint)

  if not public_keys or #public_keys.keys == 0 then
      if err then kong.log.err(err) end
      return { status = 403, message = "Unable to get public key for issuer" }
  end

  for _, k in ipairs(public_keys.keys) do
      if jwt:verify_signature(k) then
          kong.log.debug('JWT signature verified')
          return nil
      end
  end

  local since_last_update = ngx.now() - public_keys.updated_at
  if not second_call and since_last_update > conf.iss_key_grace_period then
      kong.log.debug('Refreshing expired keys from issuer')
      kong.cache:invalidate_local(issuer_cache_key)
      return custom_validate_token_signature(conf, jwt, true)
  end

  return { status = 401, message = "Invalid token signature" }
end

local function retrieve_tokens(conf)
  kong.log.debug("[DEBUG-TOKEN-FINDER] Starting token retrieval...")
  local token_set = {}
  
  -- Check Headers
  local request_headers = kong.request.get_headers()
  for _, v in ipairs(conf.header_names or {"authorization"}) do
    local token_header = request_headers[v]
    if token_header then
      kong.log.debug("[DEBUG-TOKEN-FINDER] Found header: ", v)
      local m, err = ngx.re.match(token_header, "\\s*[Bb]earer\\s+(.+)", "jo")
      if m and m[1] then 
        token_set[m[1]] = true 
      end
    end
  end

  local tokens = {}
  for token, _ in pairs(token_set) do table.insert(tokens, token) end

  -- LOG THE FINAL RESULT
  if #tokens == 0 then 
    kong.log.debug("[DEBUG-TOKEN-FINDER] Result: NIL (No tokens found)")
    return nil 
  end
  
  if #tokens == 1 then 
    kong.log.debug("[DEBUG-TOKEN-FINDER] Result: STRING (Single token found)")
    return tokens[1] 
  end
  
  kong.log.debug("[DEBUG-TOKEN-FINDER] Result: TABLE (Multiple tokens found)")
  return tokens
end



local function set_consumer(consumer, credential)
  kong.client.authenticate(consumer, credential)
  local set_header = kong.service.request.set_header
  local clear_header = kong.service.request.clear_header

  if consumer and consumer.id then set_header(constants.HEADERS.CONSUMER_ID, consumer.id)
  else clear_header(constants.HEADERS.CONSUMER_ID) end

  if consumer and consumer.custom_id then set_header(constants.HEADERS.CONSUMER_CUSTOM_ID, consumer.custom_id)
  else clear_header(constants.HEADERS.CONSUMER_CUSTOM_ID) end

  if consumer and consumer.username then set_header(constants.HEADERS.CONSUMER_USERNAME, consumer.username)
  else clear_header(constants.HEADERS.CONSUMER_USERNAME) end

  if credential and credential.id then set_header(constants.HEADERS.CREDENTIAL_ID, credential.id)
  else clear_header(constants.HEADERS.CREDENTIAL_ID) end

  if credential then clear_header(constants.HEADERS.ANONYMOUS)
  else set_header(constants.HEADERS.ANONYMOUS, "yes") end
end

local function do_authentication(conf)
  -- 1. Retrieve the token(s)
  local token, err = retrieve_tokens(conf)
  
  -- Log the type of the 'token' variable for visibility
  kong.log.debug("[DEBUG-AUTH] Token variable type: ", type(token))

  if err then
    kong.log.err("[DEBUG-AUTH] Error during token retrieval: ", tostring(err))
    return false, { status = 500, message = err }
  end

  if not token then
    kong.log.debug("[DEBUG-AUTH] No token found in request")
    return false, { status = 401, message = "No token found" }
  end

  -- 2. Handle cases where multiple tokens might be returned as a table
  if type(token) == "table" then
    kong.log.debug("[DEBUG-AUTH] Multiple tokens found, selecting first element")
    token = token[1]
  end

  -- 3. Decode the JWT
  kong.log.debug("[DEBUG-AUTH] Passing to decoder, length: ", #token)
  
  local jwt, err = jwt_decoder:new(token)
  
  -- CRITICAL FIX: Only enter this block if 'err' actually exists
  if err then
    kong.log.err("[DEBUG-AUTH] Decoder failed: ", tostring(err))
    return false, { status = 401, message = "Bad JWT: " .. tostring(err) }
  end

  -- 4. Proceed to Claims and Signature Validation
  if not jwt.claims or not jwt.claims.iss then
    return false, { status = 401, message = "Invalid token: missing issuer claim" }
  end

  kong.log.debug("[DEBUG-AUTH] JWT Decoded successfully. Claims iss: ", jwt.claims.iss)

  -- Validate the issuer against allowed list
  if not validate_issuer(conf.allowed_iss, jwt.claims) then
    return false, { status = 401, message = "Token issuer not allowed" }
  end

  -- Perform the Keycloak Signature validation (calls keycloak_keys.lua)
  local err_resp = custom_validate_token_signature(conf, jwt)
  if err_resp then 
    kong.log.err("[DEBUG-AUTH] Signature validation failed: ", err_resp.message)
    return false, err_resp 
  end

  -- 5. Final check for registered claims (exp, nbf, etc)
  local ok_claims, errors = jwt:verify_registered_claims(conf.claims_to_verify)
  if not ok_claims then
    return false, { status = 401, message = errors }
  end

  kong.log.debug("[DEBUG-AUTH] Authentication successful")
  return true
end



function JwtKeycloakHandler:access(conf)
  local ok, err = do_authentication(conf)
  if not ok then
    return kong.response.exit(err.status, { message = err.message })
  end
end

return JwtKeycloakHandler
