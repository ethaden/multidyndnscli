"""Command-line interface for multidnscli"""
import logging
import sys
import argparse
from typing import List, Optional
import yaml
import multidyndnscli


def run(args: Optional[List[str]] = None) -> int:
    """Run the tool

    :param args: list of command line arguments (i.e. args), defaults to None
    :type args: Optional[List[str]], optional
    :return: Returns 0 if update was successful, otherwise 1
    :rtype: int
    """
    parser = argparse.ArgumentParser(exit_on_error=False)
    parser.add_argument("config_file")
    parser.add_argument("--verbose", "-v", action="count", default=0)
    parser.add_argument("--dry-run", "-n", action="store_true")
    try:
        args = parser.parse_args(args=args)
        config_file = args.config_file
        dry_run = args.dry_run
        log_format = "%(asctime)s - %(levelname)s: %(message)s"
        logging.basicConfig(format=log_format)
        if args.verbose >= 2:
            logging.getLogger().setLevel(logging.DEBUG)
        elif args.verbose >= 1:
            logging.getLogger().setLevel(logging.INFO)
        with open(config_file, "r", encoding='utf-8') as file:
            config = yaml.safe_load(file)
            config_file_schema = multidyndnscli.schemata.get_config_file_schema()
            try:
                config_file_schema.validate(config)
                updater = multidyndnscli.Updater.from_config(config)
                return updater.update(dry_run)
            except Exception as exc: # pylint: disable=W0718
                logging.critical('An exception occurred: "%s".\nExiting...', str(exc))
    except (argparse.ArgumentError, SystemExit):
        pass
    return 1


if __name__ == "__main__":
    sys.exit(run())  # pragma: no cover
