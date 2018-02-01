--[[

Inspired by: https://github.com/mozilla-services/lua_sandbox/pull/22

*Haproxy log-format Directive*
  log-format %ci:%cp\ [%t]\ %ft\ %b/%s\ %Tq/%Tw/%Tc/%Tr/%Tt\ %ST\ %B\ %CC\ %CS\ %tsc\ %ac/%fc/%bc/%sc/%rc\ %sq/%bq\ %hr\ %hs\ %{+Q}r

*Example Config*
  [haproxy_udp_input]
  type = "UdpInput"
  address = "127.0.0.1:2514"
  decoder = "haproxy_log_decoder"
  splitter = "NullSplitter"

  [haproxy_log_decoder]
  type = "SandboxDecoder"
  filename = "lua_decoders/haproxy_http_log.lua"

    [haproxy_log_decoder.config]
    type = "haproxy"
    payload_keep = true

*Example Message*
  :Timestamp: 2015-08-27 04:34:43 +0000 UTC
  :Type: haproxy
  :Hostname:
  :Pid: 15435
  :Uuid: 5d0e1f61-0e23-49ae-aca9-707f92e930e2
  :Logger: haproxy_udp_input
  :Payload: 73.157.161.224:60403 [27/Aug/2015:04:34:42.774] http~ treehouse/app02.stage 1009/0/1/155/1165 200 3359 - - ---- 2/2/0/0/0 0/0 "POST /progress HTTP/1.1"
  :EnvVersion:
  :Severity: 6
  :Fields:
      | name:"bytes_read" type:double value:3359 representation:"B"
      | name:"sess_term1_cause" type:string value:"-"
      | name:"timer_Tc" type:double value:1
      | name:"sess_term2_state" type:string value:"-"
      | name:"beconn" type:double value:0
      | name:"backend_name" type:string value:"treehouse"
      | name:"http_version" type:double value:1.1
      | name:"remote_addr" type:string value:"73.157.161.224" representation:"ipv4"
      | name:"time" type:string value:"27/Aug/2015:04:34:42.774"
      | name:"timer_Tq" type:double value:1009
      | name:"timer_Tw" type:double value:0
      | name:"sess_term3_cookie_client" type:string value:"-"
      | name:"hap_req_proto" type:string value:"HTTP"
      | name:"url" type:string value:"/progress"
      | name:"req_method" type:string value:"POST"
      | name:"backend_queue" type:double value:0
      | name:"frontend_name" type:string value:"http~"
      | name:"captured_request_cookie" type:string value:"-"
      | name:"sess_term4_cookie_serv_op" type:string value:"-"
      | name:"retries" type:double value:0
      | name:"srv_conn" type:double value:0
      | name:"remote_port" type:double value:60403
      | name:"timer_Tt" type:double value:1165
      | name:"feconn" type:double value:2
      | name:"status_code" type:double value:200
      | name:"captured_response_cookie" type:string value:"-"
      | name:"actconn" type:double value:2
      | name:"timer_Tr" type:double value:155
      | name:"srv_queue" type:double value:0
      | name:"server_name" type:string value:"app02.stage"
--]]

local syslog = require "syslog"
local dt = require "date_time"
local ip = require "ip_address"
local l = require "lpeg"

l.locale(l)

local msg_type = read_config("type")
local payload_keep = read_config("payload_keep")

local msg = {
    Timestamp   = nil,
    Type        = msg_type,
    Hostname    = nil,
    Payload     = nil,
    Pid         = nil,
    Severity    = nil,
    Fields      = nil
}

local sep = l.P"|"
local elem = l.C((1 - sep)^0)
local m = l.Ct(elem * (sep * elem)^0)

local function capture_split(x)
    local x = m:match(x)
    if x == nil then x = {} end
    return x
end

local sp = l.P" "
local integer = l.digit^1 / tonumber
local double = l.digit^1 * "." * l.digit^1 / tonumber
local slash = l.P"/"
local unreserved = l.alnum + l.S"-._~|"
local pct_encoded = l.P"%" * l.xdigit * l.xdigit
local sub_delims = l.S"!$&'()*+,;="
local req_method = l.P"GET" + "POST" + "HEAD" + "PUT" + "DELETE" + "OPTIONS"
                 + "TRACE" + "CONNECT" + "PURGE" + "LINK" + "UNLINK"
                 + "PROPFIND" + "PROPPATCH" + "MKCOL" + "COPY" + "MOVE"
                 + "LOCK" + "UNLOCK"
local hap_time = l.Cg(dt.date_mday * "/" * dt.date_mabbr * "/"
               * dt.date_fullyear * ":" * dt.rfc3339_partial_time, "time")
local proxyname = (1 - l.space - (l.S"()+!@#$%^&*+=/\{}[],"))^1
local timer_int = (l.P"-"^0 * l.digit^1) / tonumber
local status_code = l.digit^-3 / tonumber
local bytes = l.Ct(l.Cg(integer, "value") * l.Cg(l.Cc"B", "representation"))
local hap_generic_token = (1 - l.space)^1
local hap_term_state_default = l.P"-"
local hap_term_state_one = l.Cg(l.S"-CSPIRDLUKcs", 'sess_term1_cause')
local hap_term_state_two = l.Cg(l.S"-DTHCRLQ", 'sess_term2_state')
local hap_term_state_three = l.Cg(l.S"-NIDVEOU", 'sess_term3_cookie_client')
local hap_term_state_four = l.Cg(l.S"-PDRNUI", 'sess_term4_cookie_serv_op')
local hap_header_capture = l.P"{" * l.C((1  - l.P"}")^1) / capture_split * l.P"}"
local hap_http_req_method =  l.Cg(req_method,  "req_method")
local hap_proxy_connect =  l.Cg(l.P"http://" * (1 - l.P"/")^1, "proxy_connect")
local hap_url = l.Cg(l.P"/" * (1 - l.space)^0, "url")
local hap_req_proto = l.Cg(l.alpha^1, "hap_req_proto") * l.P"/"
local hap_http_version =  l.Cg(double, "http_version")
local host = l.Ct(l.Cg(ip.v4, "value") * l.Cg(l.Cc"ipv4", "representation"))
           + l.Ct(l.Cg(ip.v6, "value") * l.Cg(l.Cc"ipv6", "representation"))
           + l.Ct(l.Cg((unreserved + pct_encoded + sub_delims)^1, "value")
           * l.Cg(l.Cc"hostname", "representation"))

local ci = l.Cg(host, "remote_addr")
local cp = l.Cg(integer, "remote_port")
local t = l.P"[" * hap_time * l.P"]"
local ft = l.Cg(proxyname, "frontend_name") * l.P"~"^0
local b = l.Cg(proxyname, "backend_name")
local s = l.Cg(proxyname, "server_name")
local Tq = l.Cg(timer_int, "timer_Tq")
local Tw = l.Cg(timer_int, "timer_Tw")
local Tc = l.Cg(timer_int, "timer_Tc")
local Tr = l.Cg(timer_int, "timer_Tr")
local Tt = l.Cg(timer_int, "timer_Tt")
local ST = l.Cg(status_code, "status_code")
local B = l.Cg(bytes, "bytes_read")
local CC = l.Cg(hap_generic_token, "captured_request_cookie")
local CS = l.Cg(hap_generic_token, "captured_response_cookie")
local tsc = hap_term_state_one
          * hap_term_state_two
          * hap_term_state_three
          * hap_term_state_four
local ac = l.Cg(integer, "actconn")
local fc = l.Cg(integer, "feconn")
local bc = l.Cg(integer, "beconn")
local sc = l.Cg(integer, "srv_conn")
local rc = l.Cg(integer, "retries")
local sq = l.Cg(integer, "srv_queue")
local bq = l.Cg(integer, "backend_queue")
local hr = l.Cg(hap_header_capture, "captured_request_headers")
local hs = l.Cg(hap_header_capture, "captured_response_headers")
local r = l.P'"' * hap_http_req_method * l.space
        * (hap_proxy_connect^0 * hap_url) * l.space
        * hap_req_proto * hap_http_version * l.P'"'

local rg = syslog.build_rsyslog_grammar("<%PRI%>%TIMESTAMP% %syslogtag% %msg%")
local hg = l.Ct(ci * l.P":" * cp * sp * t * sp * ft * sp * b* slash * s * sp
         * Tq * slash * Tw * slash * Tc * slash * Tr * slash * Tt * sp
         * ST * sp * B * sp * CC * sp * CS * sp * tsc * sp
         * ac * slash * fc * slash * bc * slash * sc * slash * rc * sp
         * sq * slash * bq * sp * r)

function process_message()
    -- do syslog decoding
    local log = read_message("Payload")
    --inject_payload("txt", "error", log)

    local rf = rg:match(log)
    if not rf then return -1 end

    if rf.timestamp then
        msg.Timestamp = rf.timestamp
        rf.timestamp = nil
    end

    if rf.pri then
        msg.Severity = rf.pri.severity
        rf.syslogfacility = rf.pri.facility
        rf.pri = nil
    else
        msg.Severity = rf.syslogseverity or rf["syslogseverity-text"]
        or rf.syslogpriority or rf["syslogpriority-text"]

        rf.syslogseverity = nil
        rf["syslogseverity-text"] = nil
        rf.syslogpriority = nil
        rf["syslogpriority-text"] = nil
    end

    if rf.syslogtag then
        rf.programname = rf.syslogtag.programname
        msg.Pid = rf.syslogtag.pid
        rf.syslogtag = nil
    end

    if not hostname_keep then
        msg.Hostname = rf.hostname or rf.source
        rf.hostname = nil
        rf.source = nil
    end

    if payload_keep then
        msg.Payload = rf.msg
    end

    -- do haproxy message decoding
    local hf = hg:match(rf.msg)
    if not hf then
        -- probably a startup/warning message
        msg.Payload = rf.msg
        msg.Fields = rf
    else
      -- normal http log
        msg.Fields = hf
    end

    -- inject message
    if not pcall(inject_message, msg) then return -1 end
    return 0
end
