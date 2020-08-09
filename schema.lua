local typedefs = require "kong.db.schema.typedefs"
return {
  name = "vngcloud-ip-restriction",
  fields = {
    { protocols = typedefs.protocols_http },
    { config = {
        type = "record",
        fields = {
          { whitelist = { type = "array", elements = typedefs.cidr_v4, }, },
          { blacklist = { type = "array", elements = typedefs.cidr_v4, }, },
          { client_ip_headers = { type = "array", elements = { type = "string" }, required = true, }, },
        },
      },
    },
  },
  entity_checks = {
    { only_one_of = { "config.whitelist", "config.blacklist" }, },
    { at_least_one_of = { "config.whitelist", "config.blacklist" }, },
  },
}
