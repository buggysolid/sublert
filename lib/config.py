import logging
from pathlib import Path

import tomli

toml_config = None
logger = logging.getLogger(__name__)


def get_config():
    def __read_config():
        cwd = Path.cwd()
        parent_directory = cwd.parent
        path_to_config = Path(parent_directory, cwd, 'config', 'settings.toml')
        with open(path_to_config, 'rb') as config_file_handle:
            logger.debug("Opened config file. %s", config_file_handle)
            toml_config_ = tomli.load(config_file_handle)
        return toml_config_

    global toml_config

    if toml_config is None:
        toml_config = __read_config()

    return toml_config
