from schema import Schema, And, Or, Optional, Use  # type: ignore


def get_config_file_schema():
    return Schema(
        {
            Optional("common"): {Optional("cache_dir"): And(str)},
            "dns-providers": [
                Or(
                    {
                        "name": And(str, len),
                        "type": And(str, Use(str.lower), "netcup"),
                        "userid": And(str, len),
                        "apikey": And(str, len),
                        "apipass": And(str, len),
                    }
                )
            ],
            "router": {
                "ipv4": {
                    "enabled": bool,
                    "method": And(
                        str, Use(str.lower), lambda x: x in ["wan", "fritzbox"]
                    ),
                    Optional("fritzbox"): {
                        "address": And(str, len),
                        Optional("tls"): bool,
                    },
                    Optional("wan_interface"): And(str, len),
                },
                "ipv6": {
                    "enabled": bool,
                    "method": And(
                        str, Use(str.lower), lambda x: x in ["wan", "fritzbox"]
                    ),
                    Optional("fritzbox"): {
                        "address": And(str, len),
                        Optional("tls"): bool,
                    },
                    Optional("wan_interface"): And(str, len),
                },
            },
            "domains": [
                {
                    "name": And(str, len),
                    "dns-provider": And(str, len),
                    Optional("delay"): And(int, lambda x: x >= 0),
                    "hosts": [
                        {
                            "name": And(str, len),
                            "fqdn": And(str, len),
                            "public_ip_methods": {
                                Optional("ipv4"): Or("router", "local_dns"),
                                Optional("ipv6"): Or("router", "local_dns"),
                            },
                        }
                    ],
                }
            ],
        }
    )
