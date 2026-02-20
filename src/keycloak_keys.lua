local cjson_safe = require "cjson.safe"
local convert = require "kong.plugins.jwt-keycloak.key_conversion"
-- Use Kong's native non-blocking HTTP client
local http = require "resty.http"

local function get_request(url_str)
    local httpc = http.new()
    -- Increase timeout for hosted instances
    httpc:set_timeout(5000)

    local res, err = httpc:request_uri(url_str, {
        method = "GET",
        -- THE FIX: Disable SSL verification for the background fetch
        ssl_verify = false,
        headers = {
            ["Accept"] = "application/json",
        },
    })

    if res then
        kong.log.debug("[DEBUG-HTTP] URL: ", url_str, " Status: ", res.status)
        kong.log.debug("[DEBUG-HTTP] Body Snippet: ", string.sub(res.body or "empty", 1, 100))
    end

    if not res then
        return nil, "Failed calling url " .. url_str .. ": " .. (err or "unknown error")
    end

    if res.status ~= 200 then
        return nil, "Failed calling url " .. url_str .. " response status " .. res.status
    end

    local decoded, err = cjson_safe.decode(res.body)
    if not decoded then
        return nil, "Failed to parse json response from " .. url_str
    end

    return decoded, nil
end

local function get_wellknown_endpoint(well_known_template, issuer)
    -- Safety check for the string format bug
    if not string.find(well_known_template, "%%s") then
        return well_known_template
    end
    return string.format(well_known_template, issuer)
end

local function get_issuer_keys(well_known_endpoint)
    -- 1. Fetch Discovery Document
    local res, err = get_request(well_known_endpoint)
    if err then 
        kong.log.err("[DEBUG-HTTP] Discovery fetch failed: ", err)
        return nil, err 
    end

    -- 2. Fetch JWKS from the uri found in discovery
    local jwks_uri = res['jwks_uri']
    if not jwks_uri then 
        return nil, "jwks_uri not found in discovery document" 
    end

    local res, err = get_request(jwks_uri)
    if err then 
        kong.log.err("[DEBUG-HTTP] JWKS fetch failed: ", err)
        return nil, err 
    end

    -- 3. Extract and Convert Keys
    local keys = {}
    local counter = 0
    
    if not res['keys'] then
        return nil, "No 'keys' array found in JWKS response"
    end

    for _, key in ipairs(res['keys']) do
        -- FIX: Filter for RSA Signature keys only (ignore Encryption 'enc' keys)
        if key.kty == 'RSA' and (key.use == nil or key.use == 'sig') then
            counter = counter + 1
            
            -- Convert the n/e components to PEM format
            local pem = convert.convert_kc_key(key)
            
            -- Strip newlines to store as a single-line base64 string for the decoder
            keys[counter] = string.gsub(pem, "[\r\n]+", "")
            
            kong.log.debug("[DEBUG-HTTP] SUCCESS: Extracted signature key: ", key.kid, " at index: ", counter)
        else
            kong.log.debug("[DEBUG-HTTP] SKIP: non-signature key: ", key.kid, " (use: ", key.use or "nil", ")")
        end
    end

    -- Final verification before returning to handler.lua
    if counter == 0 then
        kong.log.err("[DEBUG-HTTP] Error: No valid RSA signature keys found at ", jwks_uri)
        return nil, "No signature keys found"
    end

    kong.log.debug("[DEBUG-HTTP] Returning table to handler with count: ", #keys)
    return keys, nil
end


return {
    get_request = get_request,
    get_issuer_keys = get_issuer_keys,
    get_wellknown_endpoint = get_wellknown_endpoint,
}
