import os
import yaml
#import copy, json

def load_config(logger, config_file_path):
    if not os.path.exists(config_file_path):
        logger.error("ERROR: Configuration file not found in " + config_file_path)
        return None
    try:
        with open(config_file_path) as f:
            config = yaml.load(f, Loader=yaml.SafeLoader)
    except:
        logger.error("ERROR: Configuration file cannot be loaded from " + config_file_path)
        return None

    # printable_config = copy.deepcopy(config)
    # printable_config['keycloak']['admin_password'] = "XXXXXXX"
    # logger.info("CONFIG: " + json.dumps(printable_config))

    CONFIG = Config(config)
    required_config_params = ["host_path", "public_domain", "keycloak.admin_password"]
    for param in required_config_params:
        pointer = CONFIG
        for prop in param.split('.'): pointer = getattr(pointer, prop)
        if pointer == "": 
            logger.error("Missing mandatory config parameter: " + param)
            return None

    return CONFIG


class Config:
    def __init__(self, config: dict):
        self.host_path = config["host_path"]
        self.public_domain = config["public_domain"]

        self.keycloak = Config.Keycloak(config["keycloak"])
        
    class Keycloak:
        def __init__(self, keycloak: dict):
            self.admin_password = keycloak["admin_password"]

    