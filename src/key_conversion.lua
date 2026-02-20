-- Standard Lua and OpenResty utilities
local string = string
local math = math
local b64 = ngx.encode_base64
local unb64 = ngx.decode_base64

local function encode_length(length)
    if length < 0x80 then
        return string.char(length)
    elseif length < 0x100 then
        return string.char(0x81, length)
    elseif length < 0x10000 then
        return string.char(0x82, math.floor(length / 0x100), length % 0x100)
    end
    error("Can't encode RSA lengths over 65535")
end

local function encode_bit_string(array)
    local s = "\0" .. array
    return "\3" .. encode_length(#s) .. s
end

local function encode_sequence(array)
    local encoded_array = table.concat(array)
    return string.char(0x30) .. encode_length(#encoded_array) .. encoded_array
end

local function encode_binary_integer(bytes)
    if bytes:byte(1) > 127 then
        bytes = "\0" .. bytes
    end
    return "\2" .. encode_length(#bytes) .. bytes
end

local function base64_url_decode(input)
    local reminder = #input % 4
    if reminder > 0 then
        input = input .. string.rep('=', 4 - reminder)
    end
    input = input:gsub('-', '+'):gsub('_', '/')
    return unb64(input)
end

-- FIX: Ensure PEM headers and footers are explicitly added
local function der2pem(data)
    data = b64(data)
    local pem = "-----BEGIN PUBLIC KEY-----\n"
    -- This loop creates the 64-char lines Kong requires
    for i = 1, #data, 64 do
        pem = pem .. data:sub(i, i + 63) .. "\n"
    end
    pem = pem .. "-----END PUBLIC KEY-----\n"
    return pem
end


local function convert_kc_key(key)
    if not key or not key.n or not key.e then
        return nil, "Invalid key components"
    end

    local der_key = {
        encode_binary_integer(base64_url_decode(key.n)),
        encode_binary_integer(base64_url_decode(key.e))
    }

    local encoded_key = encode_sequence(der_key)
    
    local final_der = encode_sequence({
        encode_sequence({
            "\6\9\42\134\72\134\247\13\1\1\1", -- OID: rsaEncryption
            "\5\0" -- ASN.1 NULL
        }),
        encode_bit_string(encoded_key)
    })

    return der2pem(final_der)
end

return {
    convert_kc_key = convert_kc_key
}
