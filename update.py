import sys
import argparse
import yaml
import openwrtdyndnscli

if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument("config_file")
    args = parser.parse_args()
    config_file = args.config_file
    with open(config_file, 'r') as f:
        config = yaml.safe_load(f)
        sys.exit(openwrtdyndnscli.update(config))
