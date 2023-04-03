import sys
import argparse
import yaml
import openwrtdyndnscli
import logging

if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('config_file')
    parser.add_argument('--verbose', '-v', action='count', default=0)
    args = parser.parse_args()
    config_file = args.config_file
    FORMAT = '%(asctime)s - %(levelname)s: %(message)s'
    logging.basicConfig(format=FORMAT)
    if args.verbose>=2:
        logging.getLogger().setLevel(logging.DEBUG)
    elif args.verbose>=1:
        logging.getLogger().setLevel(logging.INFO)
    with open(config_file, 'r') as f:
        config = yaml.safe_load(f)
        sys.exit(openwrtdyndnscli.update(config))
