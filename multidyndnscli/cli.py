import sys
import argparse
from typing import List, Optional
import yaml
import multidyndnscli
import logging


def run(args: Optional[List[str]] = None) -> int:
    parser = argparse.ArgumentParser(exit_on_error=False)
    parser.add_argument("config_file")
    parser.add_argument("--verbose", "-v", action="count", default=0)
    parser.add_argument("--dry-run", "-n", action="store_true")
    try:
        args = parser.parse_args(args=args)
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
                updater = multidyndnscli.Updater.from_config(config)
                return updater.update(dry_run)
            except Exception as exc:
                logging.critical(f"An exception occurred: {exc}.\nExiting...")
    except (argparse.ArgumentError, SystemExit):
        pass
    return 1


if __name__ == "__main__":
    sys.exit(run())  # pragma: no cover
