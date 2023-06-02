import yaml
import multidyndnscli

CONFIG_EXAMPLE_FILE="config.example.yaml"

def test_example_config():
    with open(CONFIG_EXAMPLE_FILE, "r") as f:
        config = yaml.safe_load(f)
        schema = multidyndnscli.get_config_file_schema()
        assert schema.validate(config)

def test_config_file_wan():
    with open("./tests/test_files/test-config-wan.yaml", "r") as f:
        config = yaml.safe_load(f)
        schema = multidyndnscli.get_config_file_schema()
        assert schema.validate(config)

def test_config_file_web():
    with open("./tests/test_files/test-config-web.yaml", "r") as f:
        config = yaml.safe_load(f)
        schema = multidyndnscli.get_config_file_schema()
        assert schema.validate(config)

def test_config_file_fritzbox():
    with open("./tests/test_files/test-config-fritzbox.yaml", "r") as f:
        config = yaml.safe_load(f)
        schema = multidyndnscli.get_config_file_schema()
        assert schema.validate(config)
