from schema import Schema, And, Or

def get_config_file_schema():
    return Schema({
        "dns-providers": [{
            "name": Or("Netcup")
        }]
    })
