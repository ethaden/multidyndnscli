from schema import Schema, And, Or, Optional, Use

def get_config_file_schema():
    return Schema({
        "dns-providers": [ Or({
            "name": And(Use(str.lower), "netcup"),
            "userid": And(str, len),
            "apikey": And(str, len),
            "apipass": And(str, len)
        })
        ],
        "router": {
            "ipv4": {
                "enabled": bool,
                "method": ["wan", "fritzbox"],
                Optional("fritzbox"):
                    {
                        "address": And(str, Use(str.lower), 
                            lambda x: x.startswith('http://') or x.startswith('https://'))
                    }        
            },
            "ipv6": {
                "enabled": bool,
                "method": ["wan", "fritzbox"],
                Optional("fritzbox"):
                    {
                        "address": And(str, Use(str.lower), lambda x: x.startswith('http://') or x.startswith('https://'))
                    }
            }
        }
    })
