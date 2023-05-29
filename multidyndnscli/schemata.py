"""Defines the config file schema for multidyndnscli"""
from schema import Schema, And, Or, Optional, Use  # type: ignore

def get_config_file_schema()->Schema:
    """Create the config file schema

    :return: Config file schema
    :rtype: Schema
    """
    return Schema(
        {
            Optional("common"): {Optional("cache_dir"): And(str)},
            "dns_providers": [
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
                        str, Use(str.lower), lambda x: x in ["web", "wan", "fritzbox"]
                    ),
                    Optional("web_url"): And(str, len),
                    Optional("web_timeout"): And(int, lambda x: x>0),
                    Optional("wan_interface"): And(str, len),
                    Optional("fritzbox_address"): And(str, len),
                    Optional("fritzbox_tls"): bool,
                },
                "ipv6": {
                    "enabled": bool,
                    "method": And(
                        str, Use(str.lower), lambda x: x in ["web", "wan", "fritzbox"]
                    ),
                    Optional("web_url"): And(str, len),
                    Optional("web_timeout"): And(int, lambda x: x>0),
                    Optional("wan_interface"): And(str, len),
                    Optional("fritzbox_address"): And(str, len),
                    Optional("fritzbox_tls"): bool,
                },
            },
            "domains": [
                {
                    "name": And(str, len),
                    "dns_provider": And(str, len),
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
