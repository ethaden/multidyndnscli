# Licensed under the GPL v3: https://www.gnu.org/licenses/gpl-3.0
# For details: https://github.com/ethaden/multidyndnscli/blob/main/LICENSE
# Copyright (c) https://github.com/ethaden/multidyndnscli/blob/main/CONTRIBUTORS.md

from unittest.mock import MagicMock, Mock
import pytest
from multidyndnscli import Updater
from multidyndnscli.cli import run
import logging

CONFIG_EXAMPLE_FILE="config.example.yaml"

def test_run_missing_config_file(mocker):
    args = []
    assert run(args) == 1


def test_run_dry_run(mocker):
    updater_mock = MagicMock(spec=Updater)
    updater_mock.return_value.update = Mock(return_value=0)
    mocker.patch('multidyndnscli.Updater.from_config', updater_mock)
    args = ['--dry-run', CONFIG_EXAMPLE_FILE]
    assert run(args) == 0
    updater_mock.return_value.update.assert_called_once_with(True)


def test_run_non_dry_run(mocker):
    updater_mock = MagicMock(spec=Updater)
    updater_mock.return_value.update = Mock(return_value=0)
    mocker.patch('multidyndnscli.Updater.from_config', updater_mock)
    args = [CONFIG_EXAMPLE_FILE]
    assert run(args) == 0
    updater_mock.return_value.update.assert_called_once_with(False)
    # Check default log level
    assert logging.getLogger().level == logging.WARN


def test_run_logger_info(mocker):
    updater_mock = MagicMock(spec=Updater)
    updater_mock.return_value.update = Mock(return_value=0)
    mocker.patch('multidyndnscli.Updater.from_config', updater_mock)
    args = ['--verbose', CONFIG_EXAMPLE_FILE]
    assert run(args) == 0
    assert logging.getLogger().level == logging.INFO


def test_run_logger_debug(mocker):
    updater_mock = MagicMock(spec=Updater)
    updater_mock.return_value.update = Mock(return_value=0)
    mocker.patch('multidyndnscli.Updater.from_config', updater_mock)
    args = ['--verbose', '--verbose', CONFIG_EXAMPLE_FILE]
    assert run(args) == 0
    assert logging.getLogger().level == logging.DEBUG


def test_run_logger_exception(mocker):
    updater_mock = MagicMock(spec=Updater)
    updater_mock.return_value.update = Mock(side_effect=Exception('Test'))
    mocker.patch('multidyndnscli.Updater.from_config', updater_mock)
    args = [CONFIG_EXAMPLE_FILE]
    assert run(args) == 1
