local iputils = require "resty.iputils"


local FORBIDDEN = 403


-- cache of parsed CIDR values
local cache = {}


local IpRestrictionHandler = {}

IpRestrictionHandler.PRIORITY = 990
IpRestrictionHandler.VERSION = "2.0.0"

local function cidr_cache(cidr_tab)
  local cidr_tab_len = #cidr_tab

  local parsed_cidrs = kong.table.new(cidr_tab_len, 0) -- table of parsed cidrs to return

  -- build a table of parsed cidr blocks based on configured
  -- cidrs, either from cache or via iputils parse
  -- TODO dont build a new table every time, just cache the final result
  -- best way to do this will require a migration (see PR details)
  for i = 1, cidr_tab_len do
    local cidr        = cidr_tab[i]
    local parsed_cidr = cache[cidr]

    if parsed_cidr then
      parsed_cidrs[i] = parsed_cidr

    else
      -- if we dont have this cidr block cached,
      -- parse it and cache the results
      local lower, upper = iputils.parse_cidr(cidr)

      cache[cidr] = { lower, upper }
      parsed_cidrs[i] = cache[cidr]
    end
  end

  return parsed_cidrs
end

function IpRestrictionHandler:init_worker()
  local ok, err = iputils.enable_lrucache()
  if not ok then
    kong.log.err("could not enable lrucache: ", err)
  end
end


function IpRestrictionHandler:access(conf)
  local block = false
  local match = false
  for _, header in ipairs(conf.client_ip_headers) do
    local header_value = kong.request.get_header(header)
    if not header_value then
      print("no IP")
      goto skip_to_next
      return kong.response.exit(FORBIDDEN, { message = "Cannot identify the client IP address, unix domain sockets are not supported." })
    end

    if conf.blacklist and #conf.blacklist > 0 then
      block = iputils.ip_in_cidrs(header_value, cidr_cache(conf.blacklist))
      print("check blacklist")
    end

    if conf.whitelist and #conf.whitelist > 0 then
      block = not iputils.ip_in_cidrs(header_value, cidr_cache(conf.whitelist))
      print("check whitelist")
    end

    if block then
      print("blocked")
      return kong.response.exit(FORBIDDEN, { message = "Your IP address is not allowed" })
    end
    print("allowed")
    ::skip_to_next::
  end

end

return IpRestrictionHandle
