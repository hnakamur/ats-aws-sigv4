local genawssigv4 = require "genawssigv4"

local now = os.time()
local date_iso8601 = genawssigv4.format_iso8601_date(now)
-- print(string.format("date_iso8601=%s", date_iso8601))
local date = string.sub(date_iso8601, 1, 8)

local access_key_id = "AKIAIOSFODNN7EXAMPLE"
local secret_access_key = "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY"
local region = "us-east-1"
local method = "GET"
local url_path = "/"
local headers = "Host: iam.amazonaws.com\r\nContent-Type: application/x-www-form-urlencoded; charset=utf-8\r\nX-Amz-Date: "..date.. "\r\n\r\n"

local authorization, err = genawssigv4.generate_aws_sigv4(access_key_id, secret_access_key, region, date_iso8601, method, url_path, headers)
print(string.format("authorization=%s, err=%s", authorization, err))
