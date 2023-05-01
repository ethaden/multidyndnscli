import sys
import argparse
import yaml
import multidyndnscli
import logging


def run():
    parser = argparse.ArgumentParser()
    parser.add_argument("config_file")
    parser.add_argument("--verbose", "-v", action="count", default=0)
    parser.add_argument("--dry-run", "-n", action="store_true")
    args = parser.parse_args()
    config_file = args.config_file
    dry_run = args.dry_run
    FORMAT = "%(asctime)s - %(levelname)s: %(message)s"
    logging.basicConfig(format=FORMAT)
    if args.verbose >= 2:
        logging.getLogger().setLevel(logging.DEBUG)
    elif args.verbose >= 1:
        logging.getLogger().setLevel(logging.INFO)
    with open(config_file, "r") as f:
        config = yaml.safe_load(f)
        config_file_schema = multidyndnscli.schemata.get_config_file_schema()
        try:
            config_file_schema.validate(config)
            updater = multidyndnscli.Updater(config)
            sys.exit(updater.update(dry_run))
        except Exception as exc:
            logging.critical(f"An exception occurred: {exc}.\nExiting...")
            sys.exit(1)


if __name__ == "__main__":
    run()
