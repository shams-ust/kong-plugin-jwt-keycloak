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

local function get_issuer_keys(well_known_endpoint, issuer)
    -- 1. Fetch Discovery Document
    local res, err = get_request(well_known_endpoint)
    if err then
        return nil, err
    end

    -- 2. Fetch JWKS from the uri found in discovery
    local jwks_uri = res['jwks_uri']
    if not jwks_uri then
        return nil, "jwks_uri not found in discovery document"
    end

    local res, err = get_request(jwks_uri)
    if err then
        return nil, err
    end

    -- 3. Convert keys
    local keys = {}
    if not res['keys'] then
        return nil, "No keys found in JWKS response"
    end

    for i, key in ipairs(res['keys']) do
        keys[i] = string.gsub(
            convert.convert_kc_key(key), 
            "[\r\n]+", ""
        )
    end
    return keys, nil
end

return {
    get_request = get_request,
    get_issuer_keys = get_issuer_keys,
    get_wellknown_endpoint = get_wellknown_endpoint,
}
