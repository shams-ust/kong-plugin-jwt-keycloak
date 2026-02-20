local _M = {}

function _M.validate_issuer(allowed_issuers, jwt_claims)
    kong.log.debug("[DEBUG-ISS] Checking token iss: ", jwt_claims and jwt_claims.iss or "nil")
    
    if not allowed_issuers or #allowed_issuers == 0 then 
        return nil, "Allowed issuers config is empty" 
    end

    if not jwt_claims or not jwt_claims.iss then
        return nil, "Missing issuer claim in token"
    end

    for _, curr_iss in ipairs(allowed_issuers) do
        kong.log.debug("[DEBUG-ISS] Comparing against config: ", curr_iss)
        if curr_iss == jwt_claims.iss or (string.match(jwt_claims.iss, curr_iss) ~= nil) then
            kong.log.debug("[DEBUG-ISS] Match found!")
            return true
        end
    end

    return nil, "Issuer mismatch"
end

-- CRITICAL: You must return the table so handler.lua can "index" it
return _M
