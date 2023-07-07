local genawssigv4 = require "genawssigv4"

local date_iso8601 = genawssigv4.format_iso8601_date(os.time())
local access_key_id = 'foo'
local secret_access_key = 'bar'
local region = 'jp-north-1'
local method = 'GET'
local url_path = "/日本語/ですね.txt"
-- local url_path = "/%E6%97%A5%E6%9C%AC%E8%AA%9E/%E3%81%A7%E3%81%99%E3%81%AD.txt"
local query = ''
local header_fields = {
    'host:example.com',
    'x-amz-content-sha256:UNSIGNED-PAYLOAD',
    'x-amz-date:' .. date_iso8601,
}
local headers = table.concat(header_fields, '\r\n') .. '\r\n'

local signature = genawssigv4.generate_aws_sigv4(access_key_id, secret_access_key, region, date_iso8601, method, url_path, query, headers)
print(string.format("signature=[%s]", signature))
