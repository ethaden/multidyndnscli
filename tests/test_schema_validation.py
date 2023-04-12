import pytest
import yaml
import openwrtdyndnscli

def test_example_config():
    with open('config.yaml.example', 'r') as f:
        config = yaml.safe_load(f)
        schema = openwrtdyndnscli.get_config_file_schema()
        assert schema.validate(config)
