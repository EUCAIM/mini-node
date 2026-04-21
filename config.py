import os
import yaml


class Config:
    def __init__(self, cfg: dict):
        # Top-level required keys
        required_top = ['host_path', 'public_domain', 'postgres', 'keycloak', 'oidc']
        for key in required_top:
            if key not in cfg:
                raise ValueError(f"Missing required top-level config key: '{key}'")

        # Resolve host_path: replace /home/ubuntu with actual home dir if needed
        raw_host_path = cfg['host_path']
        actual_home = os.path.expanduser('~')
        if '/home/ubuntu' in raw_host_path and actual_home != '/home/ubuntu':
            resolved = raw_host_path.replace('/home/ubuntu', actual_home)
            print(f"Warning: host_path in config points to /home/ubuntu but running as {os.environ.get('USER','?')}. "
                  f"Auto-correcting to: {resolved}")
            raw_host_path = resolved
        self.host_path = raw_host_path
        self.public_domain = cfg['public_domain']
        
        # Optional: Use Gateway API instead of traditional Ingress (default: False for backward compatibility)
        self.use_gateway_api = cfg.get('use_gateway_api', False)
        
        # COMMENTED: Optional storage provisioning method selection
        # self.use_storageclass_pvcs = cfg.get('use_storageclass_pvcs', False)
        # When True: uses StorageClass (0-pvcs-storageclass.yaml) for dynamic provisioning
        # When False: uses manual PVs with hostPath (0-pvcs.yaml) with specific directory paths

        # Subsections
        self.postgres = Config.Postgres(cfg['postgres'])
        self.keycloak = Config.Keycloak(cfg['keycloak'])
        self.oidc = Config.OIDC(cfg['oidc'])
        
        # Optional: Platform admin user (simple fields, not a class)
        if 'platform_admin_user' in cfg:
            pa = cfg['platform_admin_user']
            self.platform_admin_username = pa.get('username')
            self.platform_admin_email = pa.get('email')
            self.platform_admin_password = pa.get('password')
        
        # Optional: Let's Encrypt configuration for TLS certificates
        if 'letsencrypt' in cfg:
            self.letsencrypt = Config.LetsEncrypt(cfg['letsencrypt'])
            
        # Optional: Tracer service configuration
        if 'tracer' in cfg:
            self.tracer = Config.Tracer(cfg['tracer'])

        # Optional: Focus + Beam proxy configuration
        if 'focus' in cfg:
            self.focus = Config.Focus(cfg['focus'])

        # Optional: Orthanc configuration
        if 'orthanc' in cfg:
            self.orthanc = Config.Orthanc(cfg['orthanc'])

        # Optional: Guacamole PostgreSQL configuration
        if 'guacamole' in cfg:
            self.guacamole = Config.Guacamole(cfg['guacamole'])

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
            
            # Optional: client_secret for dataset-service authentication
            self.client_secret = kc.get('client_secret', '')
            
            # IDP LSRI configuration (optional)
            if 'idp_lsri' in kc:
                self.idp_lsri = Config.Keycloak.Idp_lsri(kc['idp_lsri'])
            else:
                # Create default idp_lsri with disabled configuration
                self.idp_lsri = Config.Keycloak.Idp_lsri({
                    'enabled': 'false',
                    'client_id': '',
                    'client_secret': ''
                })

        class Idp_lsri:
            def __init__(self, idp: dict):
                # All fields are optional with defaults
                self.enabled = idp.get('enabled', 'false')
                self.client_id = idp.get('client_id', '')
                self.client_secret = idp.get('client_secret', '')

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

    class Tracer:
        def __init__(self, tr: dict):
            self.url = tr.get('url', '')  # URL is optional

    class Orthanc:
        def __init__(self, oc: dict):
            self.patient_id_encryption_key = oc.get('patient_id_encryption_key', '')
            self.admin_username = oc.get('admin_username', 'admin')
            self.admin_password = oc.get('admin_password', 'admon')

    class Focus:
        def __init__(self, fc: dict):
            self.provider = fc['provider']
            self.focus_api_key = fc.get('focus_api_key', '')
            self.dataset_service_auth_header = fc.get('dataset_service_auth_header', '')
            self.beam_broker_url = fc.get('beam_broker_url', 'https://broker.eucaim.cancerimage.eu')
            self.root_crt_pem = fc.get('root_crt_pem', '')

    class Guacamole:
        def __init__(self, gc: dict):
            if 'password' not in gc:
                raise ValueError("Missing required guacamole config key: 'password'")
            self.db_password = gc['password']
            self.username = gc.get('username', 'guacamole')
            self.database = gc.get('database', 'guacamole')
            self.admin_password = gc.get('adminPassword', '')


def load_config(logger, config_file_path):
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
