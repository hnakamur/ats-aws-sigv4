local genawssigv4 = require "genawssigv4"

local function add_aws_sigv4_authorization(ts, access_key_id, secret_access_key, region)
    local date_iso8601 = genawssigv4.format_iso8601_date(ts.now())
    local date = string.sub(date_iso8601, 1, 8)
    ts.server_request.header["X-Amz-Date"] = date

    local hdr_fields = {}
    for k, v in pairs(ts.server_request.get_headers()) do
        table.insert(hdr_fields, string.format("%s: %s", k, v))
    end
    local headers = table.concat(hdr_fields, "\r\n") .. "\r\n"

    local method = ts.server_request.get_method()
    local url_path = ts.server_request.get_uri()
    local authorization, err = genawssigv4.generate_aws_sigv4(
        access_key_id, secret_access_key, region, date_iso8601, method,
        url_path, headers)
    if err ~= nil then
        print(string.format("error in add_aws_sigv4_authorization: %s", err))
        return
    end
    ts.server_request.header["Authorization"] = authorization
end

return {
    add_aws_sigv4_authorization = add_aws_sigv4_authorization,
}
