local genawssigv4 = require "genawssigv4"

local access_key_id = "AKIAIOSFODNN7EXAMPLE"
local secret_access_key = "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY"
local region = "us-east-1"
local method = "GET"
local url_path = "/"
local date_iso8601 = "20210811"
local date = date_iso8601 .. "T001558Z"
local headers = "Host: iam.amazonaws.com\r\nContent-Type: application/x-www-form-urlencoded; charset=utf-8\r\nX-Amz-Date: "..date.. "\r\n\r\n"

local authorization, signature, err = genawssigv4.generate_aws_sigv4(access_key_id, secret_access_key, region, date_iso8601, method, url_path, headers)
print(string.format("authorization=%s, signature=%s, err=%s", authorization, signature, err))
