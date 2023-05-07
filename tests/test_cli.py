from unittest.mock import MagicMock
import pytest
from multidyndnscli.cli import run
import logging

def test_run_missing_config_file(mocker):
    args = []
    assert run(args) == 1

def test_run_dry_run(mocker):
    updater_mock = MagicMock()
    updater_mock.update = MagicMock(return_value=0)
    mocker.patch('multidyndnscli.Updater', return_value=updater_mock)
    args = ['--dry-run', 'config.yaml.example']
    assert run(args) == 0
    assert updater_mock.update.call_count == 1
    updater_mock.update.assert_called_with(True)

def test_run_non_dry_run(mocker):
    updater_mock = MagicMock()
    updater_mock.update = MagicMock(return_value=0)
    mocker.patch('multidyndnscli.Updater', return_value=updater_mock)
    args = ['config.yaml.example']
    assert run(args) == 0
    assert updater_mock.update.call_count == 1
    updater_mock.update.assert_called_with(False)
    # Check default log level
    assert logging.getLogger().level == logging.WARN

def test_run_logger_info(mocker):
    updater_mock = MagicMock()
    updater_mock.update = MagicMock(return_value=0)
    mocker.patch('multidyndnscli.Updater', return_value=updater_mock)
    args = ['--verbose', 'config.yaml.example']
    assert run(args) == 0
    assert logging.getLogger().level == logging.INFO

def test_run_logger_debug(mocker):
    updater_mock = MagicMock()
    updater_mock.update = MagicMock(return_value=0)
    mocker.patch('multidyndnscli.Updater', return_value=updater_mock)
    args = ['--verbose', '--verbose', 'config.yaml.example']
    assert run(args) == 0
    assert logging.getLogger().level == logging.DEBUG

def test_run_logger_exception(mocker):
    updater_mock = MagicMock()
    updater_mock.update = MagicMock(side_effect=Exception('Test'))
    mocker.patch('multidyndnscli.Updater', return_value=updater_mock)
    args = ['config.yaml.example']
    assert run(args) == 1
