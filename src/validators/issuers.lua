local function validate_issuer(allowed_issuers, jwt_claims)
    if not allowed_issuers or #allowed_issuers == 0 then return nil, "Empty config" end
    if not jwt_claims.iss then return nil, "No iss claim" end
    for _, curr_iss in ipairs(allowed_issuers) do
        if curr_iss == jwt_claims.iss or string.match(jwt_claims.iss, curr_iss) then return true end
    end
    return nil, "Issuer mismatch"
end
return { validate_issuer = validate_issuer }
