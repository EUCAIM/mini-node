import os
import yaml


class Config:
    def __init__(self, cfg: dict):
        # Top-level required keys
        required_top = ['host_path', 'public_domain', 'postgres', 'keycloak', 'guacamole', 'oidc']
        for key in required_top:
            if key not in cfg:
                raise ValueError(f"Missing required top-level config key: '{key}'")

        self.host_path = cfg['host_path']
        self.public_domain = cfg['public_domain']

        # Subsections
        self.postgres = Config.Postgres(cfg['postgres'])
        self.keycloak = Config.Keycloak(cfg['keycloak'])
        self.guacamole = Config.Guacamole(cfg['guacamole'])
        self.oidc = Config.OIDC(cfg['oidc'])
        
        # Optional: Let's Encrypt configuration for TLS certificates
        if 'letsencrypt' in cfg:
            self.letsencrypt = Config.LetsEncrypt(cfg['letsencrypt'])

    class Postgres:
        def __init__(self, pg: dict):
            required = ['db_password', 'username', 'database']
            for key in required:
                if key not in pg:
                    raise ValueError(f"Missing required postgres config key: '{key}'")
            self.db_password = pg['db_password']
            self.username = pg['username']
            self.database = pg['database']
            # Optional: host and port can default
            self.db_host = pg.get('db_host')
            self.db_port = pg.get('db_port')

    class Keycloak:
        def __init__(self, kc: dict):
            required = ['admin_username', 'admin_password', 'db_password', 'admin_emails']
            for key in required:
                if key not in kc:
                    raise ValueError(f"Missing required keycloak config key: '{key}'")
            self.admin_username = kc['admin_username']
            self.admin_password = kc['admin_password']
            self.db_password = kc['db_password']
            self.admin_emails = kc['admin_emails']
            self.idp_lsri = Config.Keycloak.Idp_lsri(kc['idp_lsri'])

        class Idp_lsri:
            def __init__(self, kc: dict):
                self.enabled = kc['enabled']
                self.client_id = kc['client_id']
                self.client_secret = kc['client_secret']

    class Guacamole:
        def __init__(self, gu: dict):
            required = ['postgresPassword', 'username', 'password', 'database']
            for key in required:
                if key not in gu:
                    raise ValueError(f"Missing required guacamole config key: '{key}'")
            self.postgresPassword = gu['postgresPassword']
            self.username = gu['username']
            self.password = gu['password']
            self.database = gu['database']
            self.hostname = gu['hostname']
            self.port = gu['port']

    class OIDC:
        def __init__(self, od: dict):
            required = [
                'authorization_endpoint', 'jwks_endpoint', 'issuer',
                'clientID', 'redirect_uri', 'username_claim_type', 'groups_claim_type'
            ]
            for key in required:
                if key not in od:
                    raise ValueError(f"Missing required OIDC config key: '{key}'")
            self.authorization_endpoint = od['authorization_endpoint']
            self.jwks_endpoint = od['jwks_endpoint']
            self.issuer = od['issuer']
            self.client_id = od['clientID']
            self.redirect_uri = od['redirect_uri']
            self.username_claim_type = od['username_claim_type']
            self.groups_claim_type = od['groups_claim_type']

    class LetsEncrypt:
        def __init__(self, le: dict):
            required = ['email']
            for key in required:
                if key not in le:
                    raise ValueError(f"Missing required letsencrypt config key: '{key}'")
            self.email = le['email']
            # Optional: use staging environment for testing
            self.use_staging = le.get('use_staging', False)


def load_config(logger, config_file_path) -> Config | None:
    if not os.path.exists(config_file_path):
        logger.error(f"ERROR: Configuration file not found at {config_file_path}")
        return None

    try:
        with open(config_file_path) as f:
            raw = yaml.safe_load(f)
    except Exception as e:
        logger.error(f"ERROR: Cannot load configuration from {config_file_path}: {e}")
        return None

    try:
        CONFIG = Config(raw)
    except ValueError as e:
        logger.error(f"Configuration error: {e}")
        return None

    return CONFIG
