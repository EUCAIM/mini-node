#! /usr/bin/env python3

import argparse
import enum
import os
import logging
import string
import random
import yaml
import subprocess
import time
from config import *

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
DEFAULT_CONFIG_FILE_PATH = "config.private.yaml"
K8S_DEPLOY_NODE_REPO = "git@github.com:EUCAIM/k8s-deploy-node.git"
CONFIG = None

def cmd(command, exit_on_error=True):
    print(command)
    ret = os.system(command)
    if exit_on_error and ret != 0: exit(1)
    return ret

def cmd_output(command):
    """Execute command and return output as string"""
    try:
        result = subprocess.run(command, shell=True, capture_output=True, text=True)
        return result.stdout
    except Exception as e:
        print(f"Error executing command: {e}")
        return ""

def generate_random_password(length: int = 16) -> str:
    alphabet = string.ascii_letters + string.digits
    return ''.join(random.choice(alphabet) for _ in range(length))

def update_yaml_config(file_path, update_func):
    """Generic function to update YAML configuration files"""
    with open(file_path) as f:
        docs = list(yaml.safe_load_all(f))
    
    updated = update_func(docs)
    
    if updated:
        with open(file_path, 'w') as f:
            yaml.safe_dump_all(docs, f, sort_keys=False)
        return True
    return False

def update_ingress_host(ingress_file, domain):
    """Update host in ingress YAML file"""
    if not os.path.exists(ingress_file):
        print(f"  Ingress file {ingress_file} not found, skipping...")
        return False
    
    def update_hosts(docs):
        updated = False
        for doc in docs:
            if doc.get("kind") == "Ingress":
                for rule in doc["spec"].get("rules", []):
                    rule["host"] = domain
                    updated = True
                if "tls" in doc["spec"]:
                    for tls_entry in doc["spec"]["tls"]:
                        if "hosts" in tls_entry:
                            tls_entry["hosts"] = [domain]
                            updated = True
        return updated
    
    if update_yaml_config(ingress_file, update_hosts):
        print(f" Updated {ingress_file} host to: {domain}")
        return True
    return False

def replace_domain_in_config(config_str, domain):
    """Replace hardcoded domains with configured domain"""
    config_str = config_str.replace("eucaim-node.i3m.upv.es", domain)
    config_str = config_str.replace("mininode.imaging.i3m.upv.es", domain)
    return config_str

def configure_tracer_service(config, tracer_url=None):
    """Configure or disable tracer service in configuration"""
    if "tracer" in config:
        if tracer_url:
            config["tracer"]["url"] = tracer_url
            print(f" Updated tracer URL: {tracer_url}")
        else:
            config["tracer"]["url"] = ""
            print(" Tracer service disabled (URL set to empty)")
    else:
        config["tracer"] = {"url": tracer_url or ""}
        print(" Tracer service disabled (added empty configuration)")
    return config

def update_postgres_password(file_path, password, env_var_name="POSTGRES_PASSWORD"):
    """Update PostgreSQL password in deployment YAML"""
    def update_password(docs):
        updated = False
        for doc in docs:
            if doc.get("kind") == "Deployment":
                for container in doc["spec"]["template"]["spec"]["containers"]:
                    for env in container.get("env", []):
                        if env.get("name") == env_var_name:
                            env["value"] = password
                            updated = True
        return updated
    
    if update_yaml_config(file_path, update_password):
        print(f"Injected password into {env_var_name} in {file_path}")
        return True
    else:
        print(f"Warning: Could not find {env_var_name} to update password.")
        return False

def force_cleanup_pvs():
    """Force cleanup of stuck PVs by removing finalizers"""
    print("Force cleaning up stuck PVs...")
    
    ret = cmd("minikube kubectl -- get pv --no-headers | grep Terminating", exit_on_error=False)
    if ret == 0:
        pv_names = [
            "pv-datalake", "pv-dataset-service-data", "pv-datasets",
            "pv-guacamole-postgresql", "pv-postgres-data",
            "pv-postgres-data-keycloak", "pv-themes-data", "pv-standalone-deployments"
        ]
        for pv in pv_names:
            cmd(f"minikube kubectl -- patch pv {pv} -p '{{\"metadata\":{{\"finalizers\":null}}}}' --type=merge || true")
        cmd("sleep 5")

class Auth_client_secrets():
    def __init__(self):
        private_realm_file = os.path.join(SCRIPT_DIR, "eucaim-node-realm.private.json")
        existing_secrets = {}
        
        if os.path.exists(private_realm_file):
            try:
                import json
                with open(private_realm_file, 'r') as f:
                    realm_data = json.load(f)
                    for client in realm_data.get('clients', []):
                        client_id = client.get('clientId')
                        secret = client.get('secret')
                        if client_id and secret:
                            existing_secrets[client_id] = secret
                print(f" Found existing realm configuration with {len(existing_secrets)} client secrets")
            except Exception as e:
                print(f" Warning: Could not read existing secrets from {private_realm_file}: {e}")
        
        self.CLIENT_DATASET_SERVICE_SECRET = existing_secrets.get('dataset-service', generate_random_password(32))
        self.CLIENT_FEM_CLIENT_SECRET = existing_secrets.get('fem-client', generate_random_password(32))
        self.CLIENT_JOBMAN_SERVICE_SECRET = existing_secrets.get('jobman-service', generate_random_password(32))
        self.CLIENT_KUBERNETES_SECRET = existing_secrets.get('kubernetes', generate_random_password(32))
        self.CLIENT_KUBERNETES_OPERATOR_SECRET = existing_secrets.get('kubernetes-operator', generate_random_password(32))
        
        if existing_secrets:
            print(f" Reusing existing client secrets to maintain consistency")

def install_keycloak(auth_client_secrets: Auth_client_secrets):
    if CONFIG is None: raise Exception()
    keycloak_path = os.path.join(SCRIPT_DIR, "k8s-deploy-node", "keycloak")
    os.chdir(keycloak_path)
    
    # Force cleanup of stuck PVs first
    force_cleanup_pvs()
    
    print("Cleaning up existing Keycloak resources (preserving ingress, certificates, and secrets)...")
    cmd("minikube kubectl -- create namespace keycloak || true")  
    cmd("minikube kubectl -- delete deployment --all -n keycloak --timeout=30s || true")
    cmd("minikube kubectl -- delete statefulset --all -n keycloak --timeout=30s || true")
    cmd("minikube kubectl -- delete service db -n keycloak --timeout=30s || true")  
    cmd("minikube kubectl -- delete service keycloak -n keycloak --timeout=30s || true") 
    cmd("minikube kubectl -- delete pvc --all -n keycloak --timeout=30s || true")
    cmd("minikube kubectl -- delete job --all -n keycloak --timeout=30s || true")
    cmd("minikube kubectl -- delete pod --all -n keycloak --timeout=30s --force --grace-period=0 || true")
    
    print("Waiting for cleanup to complete...")
    cmd("sleep 10")
    
    print("Cleaning Keycloak PVs...")
    cmd("minikube kubectl -- delete pv pv-postgres-data-keycloak pv-themes-data pv-standalone-deployments --timeout=30s --force --grace-period=0 || true")
    cmd("sleep 5")
    
    cmd("minikube kubectl -- label nodes minikube chaimeleon.eu/target=core-services --overwrite")
    cmd("minikube kubectl -- create priorityclass core-services --value=1000 --description='Priority class for core services' || true")
    cmd("minikube kubectl -- create priorityclass core-applications --value=900 --description='Priority class for core applications' || true")

    cmd("minikube ssh -- 'sudo rm -rf /var/hostpath-provisioner/keycloak'")
    cmd("minikube ssh -- 'sudo mkdir -p /var/hostpath-provisioner/keycloak/postgres-data'")
    cmd("minikube ssh -- 'sudo mkdir -p /var/hostpath-provisioner/keycloak/themes-data'")
    cmd("minikube ssh -- 'sudo mkdir -p /var/hostpath-provisioner/keycloak/standalone-deployments'")
    cmd("minikube ssh -- 'sudo chmod -R 777 /var/hostpath-provisioner/keycloak/'")
    cmd("sleep 10")

    update_postgres_password("dep2_database.yaml", CONFIG.keycloak.db_password)

    # Inject Keycloak deployment changes
    realm_config_file_private = "eucaim-node-realm.private.json" 
    keycloak_deploy_file = "dep3_keycloak_v4.yaml"
    with open(keycloak_deploy_file) as f:
        docs = list(yaml.safe_load_all(f))
    updated = False
    for doc in docs:
        if doc.get("kind") == "Deployment":
            for env in doc["spec"]["template"]["spec"]["containers"][0].get("env", []):
                if env.get("name") == "KC_BOOTSTRAP_ADMIN_USERNAME":
                    env["value"] = CONFIG.keycloak.admin_username
                    updated = True
                elif env.get("name") == "KC_BOOTSTRAP_ADMIN_PASSWORD":
                    env["value"] = CONFIG.keycloak.admin_password
                    updated = True
                elif env.get("name") == "KC_DB_PASSWORD":
                    env["value"] = CONFIG.keycloak.db_password
                    updated = True
                elif env.get("name") == "KC_SPI_EVENTS_LISTENER_EMAIL_TO_ADMIN_EMAIL_RECEIVERS":
                    env["value"] = CONFIG.keycloak.admin_emails
                    updated = True
                elif env.get("name") == "KC_HOSTNAME":
                    env["value"] = CONFIG.public_domain
                    updated = True
            
            if not any("--import-realm" in str(param) for param in doc["spec"]["template"]["spec"]["containers"][0].get("args", [])):
                doc["spec"]["template"]["spec"]["containers"][0]["args"].append("--import-realm")
                updated = True
            
            if not any(mount["subPath"] == realm_config_file_private for mount in doc["spec"]["template"]["spec"]["containers"][0]["volumeMounts"]):
                doc["spec"]["template"]["spec"]["containers"][0]["volumeMounts"].append({
                    "name": "vol-standalone-deployments",
                    "subPath": realm_config_file_private,
                    "mountPath": "/opt/keycloak/data/import/" + realm_config_file_private
                })
                updated = True
    if updated:
        with open(keycloak_deploy_file, 'w') as f:
            yaml.safe_dump_all(docs, f, sort_keys=False)
        print(f"Injected config values into {keycloak_deploy_file}")

    # Verify namespace is ready before applying resources
    print("Verifying namespace is ready...")
    cmd("minikube kubectl -- get namespace keycloak")
    
    # Apply storage init manifests
    cmd("minikube kubectl -- apply -f dep0_volumes.yaml -n keycloak")
    cmd("minikube kubectl -- apply -f dep1_init_volumes.yaml -n keycloak")

    jar1_url = "https://github.com/chaimeleon-eu/keycloak-event-listener-email-to-admin/releases/download/v1.0.6/keycloak-event-listener-email-to-admin-1.0.6.jar"
    jar2_url = "https://github.com/chaimeleon-eu/keycloak-required-action-user-validated/releases/download/v1.0.5/keycloak-required-action-user-validated-1.0.5.jar"
    cmd(f"wget -O /tmp/keycloak-event-listener-email-to-admin-1.0.6.jar '{jar1_url}' || true")
    cmd(f"wget -O /tmp/keycloak-required-action-user-validated-1.0.5.jar '{jar2_url}' || true")

    cmd("tar -czf /tmp/themes.tar.gz themes/")
    cmd("minikube cp /tmp/themes.tar.gz minikube:/tmp/")
    cmd("minikube ssh -- 'sudo tar -xzf /tmp/themes.tar.gz -C /var/hostpath-provisioner/keycloak/themes-data/ --strip-components=1'")

    cmd("minikube cp /tmp/keycloak-event-listener-email-to-admin-1.0.6.jar minikube:/var/hostpath-provisioner/keycloak/standalone-deployments/")
    cmd("minikube cp /tmp/keycloak-required-action-user-validated-1.0.5.jar minikube:/var/hostpath-provisioner/keycloak/standalone-deployments/")

    realm_config_file = os.path.join(SCRIPT_DIR, "eucaim-node-realm.json")
    realm_config_file_private_path = os.path.join(os.getcwd(), realm_config_file_private)
    with open(realm_config_file, "rt") as fin:
        with open(realm_config_file_private_path, "wt") as fout:
            for line in fin:
                l = line.replace("{{ PUBLIC_DOMAIN }}", CONFIG.public_domain)
                l = l.replace("{{ IDP_LSRI_ENABLED }}", CONFIG.keycloak.idp_lsri.enabled)
                l = l.replace("{{ IDP_LSRI_CLIENT_ID }}", CONFIG.keycloak.idp_lsri.client_id)
                l = l.replace("{{ IDP_LSRI_CLIENT_SECRET }}", CONFIG.keycloak.idp_lsri.client_secret)
                l = l.replace("{{ CLIENT_DATASET_SERVICE_SECRET }}", auth_client_secrets.CLIENT_DATASET_SERVICE_SECRET)
                l = l.replace("{{ CLIENT_FEM_CLIENT_SECRET }}", auth_client_secrets.CLIENT_FEM_CLIENT_SECRET)
                l = l.replace("{{ CLIENT_JOBMAN_SERVICE_SECRET }}", auth_client_secrets.CLIENT_JOBMAN_SERVICE_SECRET)
                l = l.replace("{{ CLIENT_KUBERNETES_SECRET }}", auth_client_secrets.CLIENT_KUBERNETES_SECRET)
                l = l.replace("{{ CLIENT_KUBERNETES_OPERATOR_SECRET }}", auth_client_secrets.CLIENT_KUBERNETES_OPERATOR_SECRET)
                fout.write(l)
    
    cmd(f"minikube cp {realm_config_file_private_path} minikube:/var/hostpath-provisioner/keycloak/standalone-deployments/")

    cmd("minikube kubectl -- apply -f dep2_database.yaml -n keycloak")
    cmd("minikube kubectl -- wait --for=condition=ready pod -l app=db -n keycloak --timeout=300s")
    cmd("sleep 30")
   
    cmd("minikube kubectl -- apply -f dep3_keycloak_v4.yaml -n keycloak")

    ingress_file = "dep4_ingress.yaml"
    tls_ingress_file = "dep4_ingress_tls.yaml"
    
    use_tls = (hasattr(CONFIG, 'letsencrypt') and 
               hasattr(CONFIG.letsencrypt, 'email') and 
               CONFIG.letsencrypt.email and
               getattr(CONFIG, 'cert_manager_available', False))
    
    if not getattr(CONFIG, 'cert_manager_available', False):
        print("Note: Using HTTP-only ingress (cert-manager not available)")
    
    selected_ingress = tls_ingress_file if use_tls else ingress_file
    update_ingress_host(selected_ingress, CONFIG.public_domain)

    print("Checking if ingress already exists...")
    ingress_exists = cmd(f"minikube kubectl -- get ingress proxy-keycloak -n keycloak 2>/dev/null", exit_on_error=False)
    
    if ingress_exists == 0:
        print(" Ingress already exists - preserving to avoid certificate recreation")
        print("   If you need to update the ingress, delete it manually first")
    else:
        print("Creating new ingress...")
        cmd(f"minikube kubectl -- apply -f {selected_ingress} -n keycloak")
        
        if use_tls:
            print("TLS certificate will be automatically provisioned by cert-manager")

    os.chdir("..")

def ensure_ingress_addon():
    """Ensure minikube ingress addon is enabled"""
    print("Checking minikube ingress addon...")
    ret = cmd("minikube addons list | grep 'ingress' | grep 'enabled'", exit_on_error=False)
    if ret != 0:
        print("Enabling minikube ingress addon...")
        cmd("minikube addons enable ingress")
        print(" Ingress addon enabled")
        # Wait for ingress controller to be ready
        print("Waiting for ingress controller to be ready...")
        cmd("minikube kubectl -- wait --namespace ingress-nginx --for=condition=ready pod --selector=app.kubernetes.io/component=controller --timeout=120s || true")
    else:
        print(" Ingress addon already enabled")

def update_ingress_host(ingress_file: str, domain: str):
    """Update the host in the ingress YAML file"""
    import re
    
    if not os.path.exists(ingress_file):
        print(f"  Ingress file {ingress_file} not found, skipping...")
        return
    
    with open(ingress_file, 'r') as f:
        content = f.read()
    
    # Replace host with the configured domain
    # Match patterns like "host: eucaim-node.i3m.upv.es" or "host: mininode.imaging.i3m.upv.es"
    content = re.sub(r'host:\s+[a-zA-Z0-9.-]+', f'host: {domain}', content)
    
    # Also replace domain in redirect URLs (for root path redirect ingress)
    # Match patterns like "https://eucaim-node.i3m.upv.es/dataset-service"
    content = re.sub(
        r'(https?://)[a-zA-Z0-9.-]+(/[a-zA-Z0-9-]+)', 
        rf'\1{domain}\2', 
        content
    )
    
    with open(ingress_file, 'w') as f:
        f.write(content)
    
    print(f" Updated {ingress_file} host to: {domain}")

def create_dataset_service_pvcs():
    """Create PVCs for dataset-service"""
    print("  Creating dataset-service PVCs...")
    
    dataset_dir = os.path.join(SCRIPT_DIR, "k8s-deploy-node", "dataset-service")
    if not os.path.exists(dataset_dir):
        print(f" Dataset-service directory not found: {dataset_dir}")
        return False
    
    prev_dir = os.getcwd()
    try:
        os.chdir(dataset_dir)
        
        print("Creating directories in minikube...")
        cmd("minikube ssh -- 'sudo mkdir -p /var/hostpath-provisioner/dataset-service/postgres-data'")
        cmd("minikube ssh -- 'sudo mkdir -p /var/hostpath-provisioner/dataset-service/dataset-service-data'")
        cmd("minikube ssh -- 'sudo mkdir -p /var/hostpath-provisioner/dataset-service/datalake'")
        cmd("minikube ssh -- 'sudo mkdir -p /var/hostpath-provisioner/dataset-service/datasets'")
        cmd("minikube ssh -- 'sudo chmod -R 777 /var/hostpath-provisioner/dataset-service/'")
        
        print("Applying PVCs...")
        cmd("minikube kubectl -- apply -f 0-pvcs.yaml -n dataset-service")
        
        print("Verifying PVCs...")
        cmd("minikube kubectl -- get pvc -n dataset-service")
        
        print(" Dataset-service PVCs created successfully")
        return True
        
    except Exception as e:
        print(f" Error creating dataset-service PVCs: {e}")
        return False
    finally:
        os.chdir(prev_dir)

def install_dataset_service(auth_client_secret: str):
    if CONFIG is None: 
        raise Exception("CONFIG is None")
    
    prev_dir = os.getcwd()
    try:
        dataset_dir = os.path.join(SCRIPT_DIR, "k8s-deploy-node", "dataset-service")
        os.chdir(dataset_dir)
        db_service_file = "1-db-service.yaml"
        deployment_file = "2-dataset-service.yaml"

        cmd("minikube kubectl -- create namespace dataset-service || true")
        
        # Create PVCs first (this will auto-create PVs)
        create_dataset_service_pvcs()

        # Try to get the current kid from Keycloak JWKS
        print(f" Attempting to fetch current kid from Keycloak JWKS...")
        kid_rs256 = "UPDATE_ME_WITH_REAL_KID_FROM_JWKS"  # Default placeholder
        
        # Wait for Keycloak to be ready before fetching kid
        print(f" Waiting for Keycloak to be ready...")
        max_wait = 180  # 3 minutes
        waited = 0
        keycloak_ready = False
        
        while waited < max_wait:
            keycloak_check = cmd("minikube kubectl -- get pods -n keycloak -l app=keycloak -o jsonpath='{.items[0].status.conditions[?(@.type==\"Ready\")].status}' 2>/dev/null", exit_on_error=False)
            if keycloak_check == 0:
                # Check if we got "True" in the output
                result = cmd_output("minikube kubectl -- get pods -n keycloak -l app=keycloak -o jsonpath='{.items[0].status.conditions[?(@.type==\"Ready\")].status}' 2>/dev/null")
                if result.strip() == "'True'" or result.strip() == "True":
                    print(f" Keycloak is ready (waited {waited}s)")
                    keycloak_ready = True
                    # Give it a few more seconds to fully start serving requests
                    print(f"   Waiting additional 10s for Keycloak to be fully ready...")
                    time.sleep(10)
                    break
            
            time.sleep(5)
            waited += 5
            if waited % 30 == 0:
                print(f"   Still waiting for Keycloak... ({waited}s)")
        
        if not keycloak_ready:
            print(f" Keycloak not ready after {max_wait}s, will use placeholder kid")
        
        try:
            import requests
            jwks_url = f"https://{CONFIG.public_domain}/auth/realms/EUCAIM-NODE/protocol/openid-connect/certs"
            print(f"   Fetching from: {jwks_url}")
            response = requests.get(jwks_url, verify=False, timeout=10)
            response.raise_for_status()
            jwks_data = response.json()
            
            # Find RS256 key
            for key in jwks_data.get('keys', []):
                if key.get('alg') == 'RS256':
                    kid_rs256 = key.get('kid')
                    print(f" Found RS256 kid from Keycloak: {kid_rs256}")
                    break
            
            if kid_rs256 == "UPDATE_ME_WITH_REAL_KID_FROM_JWKS":
                print(" No RS256 key found in JWKS, using placeholder")
        except Exception as e:
            print(f" Could not fetch kid from Keycloak: {e}")
            print(f"   Will use placeholder and update later")

        # 1. Generate password and inject into POSTGRES_PASSWORD
        update_postgres_password(db_service_file, CONFIG.postgres.db_password)

        with open(deployment_file) as f:
            docs = list(yaml.safe_load_all(f))
        updated = False
        for doc in docs:
            if doc.get("kind") == "Deployment":
                containers = doc["spec"]["template"]["spec"]["containers"]
                for container in containers:
                    for env in container.get("env", []):
                        if env.get("name") == "DATASET_SERVICE_CONFIG":
                            import json
                            config_json = env["value"]
                            config = json.loads(config_json)
                            
                            if "db" in config:
                                config["db"]["password"] = CONFIG.postgres.db_password
                            
                            if "self" in config:
                                for key, value in config["self"].items():
                                    if isinstance(value, str) and value == "XXXXXXXX":
                                        config["self"][key] = generate_random_password(16)
                            
                            if "auth" in config and "client" in config["auth"]:
                                config["auth"]["client"]["client_secret"] = auth_client_secret
                            
                            config_str = json.dumps(config)
                            config_str = replace_domain_in_config(config_str, CONFIG.public_domain)
                            config = json.loads(config_str)
                            
                            tracer_url = CONFIG.tracer.url if hasattr(CONFIG, 'tracer') and hasattr(CONFIG.tracer, 'url') and CONFIG.tracer.url else None
                            config = configure_tracer_service(config, tracer_url)
                            
                            if "auth" in config and "token_validation" in config["auth"]:
                                config["auth"]["token_validation"]["kid"] = kid_rs256
                                if kid_rs256.startswith("UPDATE_ME") or kid_rs256 in ["KEYCLOAK_NOT_READY", "INVALID_JWKS_RESPONSE", "DOWNLOAD_FAILED", "NO_KEYS_FOUND"]:
                                    print(f" Updated kid in config with placeholder: {kid_rs256}")
                                    print("   You will need to update this manually once Keycloak is running")
                                else:
                                    print(f" Updated kid in token validation config: {kid_rs256}")
                            else:
                                print(" Warning: Could not find auth.token_validation section in config")
                            
                            env["value"] = json.dumps(config, indent=2)
                            updated = True
        if updated:
            with open(deployment_file, 'w') as f:
                yaml.safe_dump_all(docs, f, sort_keys=False)
            print(f"Injected password and random tokens into DATASET_SERVICE_CONFIG of {deployment_file}")
        else:
            print("Warning: Could not find DATASET_SERVICE_CONFIG to update password and tokens.")

        # Apply resources
        cmd("minikube kubectl -- apply -f 1-db-service.yaml -n dataset-service")
        cmd("minikube kubectl -- apply -f 0-pvcs.yaml -n dataset-service")
        cmd("minikube kubectl -- apply -f 0-service-account.yaml -n dataset-service")
        
        # Delete existing deployment to force recreation with new kid
        print(f"\n  Deleting existing dataset-service-backend deployment (if exists)...")
        cmd("minikube kubectl -- delete deployment dataset-service-backend -n dataset-service --ignore-not-found=true")
        
        # Wait a moment for the deployment to be fully deleted
        print(f" Waiting for deployment deletion to complete...")
        cmd("sleep 5")
        
        # Apply the new deployment with updated configuration
        print(f" Creating new dataset-service-backend deployment with updated kid...")
        cmd(f"minikube kubectl -- apply -f {deployment_file} -n dataset-service")
        
        print(f"\n Configuring ingress for dataset-service...")
        update_ingress_host("3-ingress.yaml", CONFIG.public_domain)
        cmd("minikube kubectl -- apply -f 3-ingress.yaml -n dataset-service")
        print(f" Ingress applied for dataset-service at https://{CONFIG.public_domain}/dataset-service")
        
        redirect_ingress_file = "4-ingress-for-redirect-from-root-path.yaml"
        if os.path.exists(redirect_ingress_file):
            update_ingress_host(redirect_ingress_file, CONFIG.public_domain)
            
            cmd("minikube kubectl -- apply -f 4-ingress-for-redirect-from-root-path.yaml -n dataset-service")
            print(" Redirect ingress applied")
        
        print(f"\n Waiting for dataset-service-backend deployment to be ready...")
        cmd("minikube kubectl -- wait --for=condition=available --timeout=180s deployment/dataset-service-backend -n dataset-service || true")
    finally:
        os.chdir(prev_dir)

def install_guacamole(CONFIG):
    prev_dir = os.getcwd()
    try:
        guacamole = os.path.join(SCRIPT_DIR, "k8s-deploy-node", "guacamole")
        os.chdir(guacamole)
        # Ensure namespace and PVC exist
        cmd("minikube kubectl -- create namespace guacamole || true")
        cmd("minikube kubectl -- apply -f postgresql-pvc.yaml -n guacamole")

        # 1. Update PostgreSQL values
        values_file = "postgresql-values.yaml"
        with open(values_file, 'r') as f:
            data = yaml.safe_load(f) or {}

        data.setdefault('auth', {})
        data['auth'].update({
            'postgresPassword': CONFIG.guacamole.postgresPassword,
            'username': CONFIG.guacamole.username,
            'password': CONFIG.guacamole.password,
            'database': CONFIG.guacamole.database,
        })
        with open(values_file, 'w') as f:
            yaml.dump(data, f, default_flow_style=False, sort_keys=False, indent=2)

        # 2. Update Guacamole values (Postgres + OIDC)
        guaca_file = "guacamole-values.yaml"
        with open(guaca_file, 'r') as f:
            data_pg = yaml.safe_load(f) or {}


        pg = data_pg.setdefault('postgres', {})
        pg.update({
            'database': CONFIG.guacamole.database,
            'user': CONFIG.guacamole.username,
            'password': CONFIG.guacamole.password,
            'hostname': CONFIG.guacamole.hostname,
            'port': CONFIG.guacamole.port
        })


        dbcreation = data_pg.setdefault('dbcreation', {})
        dbcreation.update({
            'adminLocalPassword': CONFIG.guacamole.postgresPassword
        })

        oidc_cfg = data_pg.setdefault('OIDC', {})
        oidc_cfg.update({
            'authorization_endpoint': CONFIG.oidc.authorization_endpoint,
            'jwks_endpoint': CONFIG.oidc.jwks_endpoint,
            'issuer': CONFIG.oidc.issuer,
            'clientID': CONFIG.oidc.client_id,
            'redirect_uri': CONFIG.oidc.redirect_uri,
            'username_claim_type': CONFIG.oidc.username_claim_type,
            'groups_claim_type': CONFIG.oidc.groups_claim_type,
        })

        # Update ingress host in guacamole-values.yaml BEFORE writing the file
        if 'ingress' in data_pg:
            # hosts is a list of dicts with 'host' and 'paths'
            hosts = data_pg['ingress'].get('hosts')
            if hosts and isinstance(hosts, list) and len(hosts) > 0:
                hosts[0]['host'] = CONFIG.public_domain
                print(f"Updated Guacamole ingress host to: {CONFIG.public_domain}")

            # Update TLS hosts/secretName if present
            if 'tls' in data_pg['ingress']:
                for tls_entry in data_pg['ingress']['tls']:
                    tls_entry['hosts'] = [CONFIG.public_domain]
                    if tls_entry.get('secretName'):
                        tls_entry['secretName'] = CONFIG.public_domain

        with open(guaca_file, 'w') as f:
            yaml.dump(data_pg, f, default_flow_style=False, sort_keys=False, indent=2)

        private_post_values = "postgresql-values.yaml"
        
        print(f"\n Checking if PostgreSQL for Guacamole is already installed...")
        pg_check = cmd("minikube kubectl -- get deployment -n guacamole -l app.kubernetes.io/name=postgresql -o name 2>/dev/null | wc -l", exit_on_error=False)
        
        if pg_check == 0:
            print(f" Installing PostgreSQL for Guacamole...")
            cmd("helm uninstall postgresql --namespace guacamole || true")
            
            # Use helm upgrade --install to be more resilient
            pg_install = cmd(
                f"helm upgrade --install postgresql oci://registry-1.docker.io/bitnamicharts/postgresql \
                 --version 15.5.29 --namespace guacamole -f {private_post_values}",
                exit_on_error=False
            )
            
            if pg_install != 0:
                print(f"  Warning: PostgreSQL installation failed (likely Docker Hub rate limit)")
                print(f"   Checking if PostgreSQL is already running...")
                existing_pg = cmd("minikube kubectl -- get pods -n guacamole -l app.kubernetes.io/name=postgresql 2>/dev/null", exit_on_error=False)
                if existing_pg == 0:
                    print(f" PostgreSQL is already running, continuing...")
                else:
                    print(f"  PostgreSQL not found and installation failed")
                    print(f"   Skipping Guacamole installation")
                    return
        else:
            print(f" PostgreSQL already installed, skipping...")

        chart_dir = "helm-chart-guacamole"
        if not os.path.isdir(chart_dir):
            print(f" Cloning Guacamole Helm chart repository...")
            clone_result = cmd("GIT_TERMINAL_PROMPT=0 git clone --depth 1 https://github.com/chaimeleon-eu/helm-chart-guacamole.git", exit_on_error=False)
            if clone_result != 0:
                print(f"  Warning: Clone failed")
                print(f"   Please check network connectivity to GitHub")
                return

        # Check if Guacamole is already installed
        print(f"\n Checking if Guacamole is already installed...")
        guac_check = cmd("minikube kubectl -- get deployment -n guacamole -l app.kubernetes.io/name=guacamole -o name 2>/dev/null | wc -l", exit_on_error=False)
        
        if guac_check == 0:
            print(f" Installing Guacamole...")
            # Install using the cloned chart with private values
            cmd("helm uninstall guacamole --namespace guacamole || true")
            guac_install = cmd(
                f"helm install guacamole ./{chart_dir} \
                 --namespace guacamole -f guacamole-values.yaml ",
                exit_on_error=False
            )
            
            if guac_install != 0:
                print(f"  Warning: Guacamole installation failed")
                print(f"   Checking if Guacamole is already running...")
                existing_guac = cmd("minikube kubectl -- get pods -n guacamole -l app.kubernetes.io/name=guacamole 2>/dev/null", exit_on_error=False)
                if existing_guac == 0:
                    print(f" Guacamole is already running, continuing...")
                else:
                    print(f"  Guacamole installation failed, but continuing with installation...")
        else:
            print(f" Guacamole already installed, skipping...")

    finally:
        os.chdir(prev_dir)

def install_dsws_operator(CONFIG, auth_client_secrets: Auth_client_secrets):
    """Install DSWS Operator for managing dataset workspaces"""
    prev_dir = os.getcwd()
    try:
        print(f"\n{'='*80}")
        print(" Installing DSWS Operator")
        print(f"{'='*80}\n")
        
        operator_dir = os.path.join(SCRIPT_DIR, "k8s-deploy-node", "dsws-operator")
        os.chdir(operator_dir)
        
        # Create namespace
        cmd("minikube kubectl -- create namespace dsws-operator || true")
        
        # Clone the operator chart repository if not exists
        chart_repo_dir = "k8s-chaimeleon-operator"
        if not os.path.isdir(chart_repo_dir):
            print(f" Cloning DSWS Operator chart repository...")
            # Clone with depth=1 for faster cloning, and disable interactive prompts
            clone_result = cmd("GIT_TERMINAL_PROMPT=0 git clone --depth 1 https://github.com/chaimeleon-eu/k8s-chaimeleon-operator.git", exit_on_error=False)
            if clone_result != 0:
                print(f"  Warning: Clone failed")
                print(f"   Please check network connectivity to GitHub")
                return
        else:
            print(f" DSWS Operator chart repository already exists")
        
        # Update installation-values.yaml with configuration
        values_file = "installation-values.yaml"
        with open(values_file, 'r') as f:
            data = yaml.safe_load(f) or {}
        
        # Update auth configuration
        if 'operatorConfiguration' not in data:
            data['operatorConfiguration'] = {}
        
        if 'auth' not in data['operatorConfiguration']:
            data['operatorConfiguration']['auth'] = {}
        
        data['operatorConfiguration']['auth'].update({
            'url': f"https://{CONFIG.public_domain}/auth/realms/EUCAIM-NODE/protocol/openid-connect/token",
            'client_id': 'kubernetes-operator',
            'client_secret': auth_client_secrets.CLIENT_KUBERNETES_OPERATOR_SECRET,
            'max_retries': 10
        })
        print(f" Updated auth configuration with domain: {CONFIG.public_domain}")
        
        # Update guacamole URL
        if 'guacamole' not in data['operatorConfiguration']:
            data['operatorConfiguration']['guacamole'] = {}
        
        data['operatorConfiguration']['guacamole']['url'] = f"https://{CONFIG.public_domain}/guacamole/"
        print(f" Updated Guacamole URL to: {CONFIG.public_domain}")
        
        # Get service-account-kubernetes-operator password from Keycloak realm
        print(f" Reading Guacamole service account password from Keycloak realm...")
        realm_file = os.path.join(SCRIPT_DIR, "eucaim-node-realm.private.json")
        if os.path.exists(realm_file):
            import json
            with open(realm_file, 'r') as f:
                realm_data = json.load(f)
                # Find service-account-kubernetes-operator user
                for user in realm_data.get('users', []):
                    if user.get('username') == 'service-account-kubernetes-operator':
                        # Get credentials
                        for cred in user.get('credentials', []):
                            if cred.get('type') == 'password':
                                guac_password = cred.get('value')
                                if guac_password:
                                    data['operatorConfiguration']['guacamole']['password'] = guac_password
                                    print(f"  Set Guacamole service account password from realm")
                                    break
                        break
        
        # Save updated values
        with open(values_file, 'w') as f:
            yaml.dump(data, f, default_flow_style=False, sort_keys=False, indent=2)
        
        print(f" Updated {values_file} with configuration")
        
        # Check if operator is already installed
        print(f"\n Checking if DSWS Operator is already installed...")
        op_check = cmd("minikube kubectl -- get deployment -n dsws-operator -o name 2>/dev/null | wc -l", exit_on_error=False)
        
        chart_path = f"./{chart_repo_dir}/chaimeleon-operator-chart"
        
        if op_check == 0:
            print(f" Installing DSWS Operator...")
            
            cmd(f"helm upgrade --install dsws-operator {chart_path} \
                 --namespace dsws-operator -f {values_file}")
            
            print(f" DSWS Operator installed successfully")
        else:
            print(f" DSWS Operator already installed, upgrading...")
            
            cmd(f"helm upgrade --install dsws-operator {chart_path} \
                 --namespace dsws-operator -f {values_file}")
            
            print(f" DSWS Operator upgraded successfully")
        
    finally:
        os.chdir(prev_dir)

def install_kubeapps(CONFIG, client_kubernetes_secret: str):
    """Install Kubeapps dashboard for managing Helm charts"""
    prev_dir = os.getcwd()
    try:
        print(f"\n{'='*80}")
        print(" Installing Kubeapps")
        print(f"{'='*80}\n")
        
        kubeapps_dir = os.path.join(SCRIPT_DIR, "k8s-deploy-node", "kubeapps")
        os.chdir(kubeapps_dir)
        
        # Create namespace
        cmd("minikube kubectl -- create namespace kubeapps || true")
        
        # Label node for core services
        cmd("minikube kubectl -- label nodes minikube chaimeleon.eu/target=core-services --overwrite")
        
        # Create priority classes if not exist
        cmd("minikube kubectl -- create priorityclass core-services --value=1000 --description='Priority class for core services' || true")
        cmd("minikube kubectl -- create priorityclass core-applications --value=900 --description='Priority class for core applications' || true")
        
        # Update values.yaml with configuration
        values_file = "values.yaml"
        with open(values_file, 'r') as f:
            data = yaml.safe_load(f) or {}
        
        # Update PostgreSQL password if it's a placeholder
        if 'postgresql' in data and 'auth' in data['postgresql']:
            if data['postgresql']['auth'].get('password') == 'XXXXXXXXXXXXX':
                pg_password = generate_random_password(16)
                data['postgresql']['auth']['password'] = pg_password
                print(f" Generated PostgreSQL password")
        
        # Update ingress hostname
        if 'ingress' in data:
            data['ingress']['hostname'] = CONFIG.public_domain
            print(f" Updated ingress hostname to: {CONFIG.public_domain}")
        
        # Update authProxy configuration
        if 'authProxy' in data:
            # Update OIDC logout URL with correct domain
            data['authProxy']['oauthLogoutURI'] = (
                f"/apps/oauth2/sign_out?rd=https%3A%2F%2F{CONFIG.public_domain.replace('.', '%2E')}%2Fauth%2Frealms%2FEUCAIM-NODE%2Fprotocol%2Fopenid-connect%2Flogout%3Fclient_id%3Dkubernetes%26post_logout_redirect_uri%3Dhttps%3A%2F%2F{CONFIG.public_domain.replace('.', '%2E')}%2Fapps%2F"
            )
            
            # Use the client_kubernetes_secret from Keycloak auth_client_secrets
            data['authProxy']['clientSecret'] = client_kubernetes_secret
            print(f" Set authProxy client secret (CLIENT_KUBERNETES_SECRET)")
            
            # Generate cookie secret if it's a placeholder
            if data['authProxy'].get('cookieSecret') == 'XXXXXXXXXXXXX':
                import base64
                data['authProxy']['cookieSecret'] = base64.urlsafe_b64encode(os.urandom(16)).decode()
                print(f" Generated authProxy cookie secret")
            
            # Update extra flags with correct domain
            if 'extraFlags' in data['authProxy']:
                updated_flags = []
                for flag in data['authProxy']['extraFlags']:
                    # Replace eucaim-node.i3m.upv.es with actual domain
                    updated_flag = flag.replace('eucaim-node.i3m.upv.es', CONFIG.public_domain)
                    updated_flags.append(updated_flag)
                data['authProxy']['extraFlags'] = updated_flags
                print(f" Updated authProxy flags with domain: {CONFIG.public_domain}")
        
        # Ensure global.security.allowInsecureImages is set (for Harbor images)
        if 'global' not in data:
            data['global'] = {}
        if 'security' not in data['global']:
            data['global']['security'] = {}
        if not data['global']['security'].get('allowInsecureImages'):
            data['global']['security']['allowInsecureImages'] = True
            print(f" Enabled allowInsecureImages for Harbor registry")
        
        # Configure PostgreSQL storageClass based on flavor
        # micro: uses 'standard' (minikube default)
        # standard: uses 'cephfs' (CephFS storage)
        if CONFIG.flavor == 'micro':
            if 'postgresql' not in data:
                data['postgresql'] = {}
            if 'primary' not in data['postgresql']:
                data['postgresql']['primary'] = {}
            if 'persistence' not in data['postgresql']['primary']:
                data['postgresql']['primary']['persistence'] = {}
            data['postgresql']['primary']['persistence']['storageClass'] = 'standard'
            print(f" Configured PostgreSQL to use 'standard' storageClass for micro flavor")
        
        # Configure app repository with dynamic domain
        if 'apprepository' not in data:
            data['apprepository'] = {}
        if 'initialRepos' not in data['apprepository']:
            data['apprepository']['initialRepos'] = []
        
        # Update or add eucaim-node-apps repository with correct domain
        repo_found = False
        for repo in data['apprepository']['initialRepos']:
            if repo.get('name') == 'eucaim-node-apps':
                repo['url'] = f"http://{CONFIG.public_domain}/dataset-service/output-files/charts/"
                repo_found = True
                print(f" Updated eucaim-node-apps repository URL to: {CONFIG.public_domain}")
                break
        
        if not repo_found:
            # Add the repository if it doesn't exist
            data['apprepository']['initialRepos'].append({
                'name': 'eucaim-node-apps',
                'url': f"http://{CONFIG.public_domain}/dataset-service/output-files/charts/"
            })
            print(f" Added eucaim-node-apps repository with URL: {CONFIG.public_domain}")
        
        # Write updated values
        with open(values_file, 'w') as f:
            yaml.dump(data, f, default_flow_style=False, sort_keys=False, indent=2)
        
        print(f"\n Deploying Kubeapps with Helm...")
        print(f"   This will install or upgrade Kubeapps with the latest values.yaml configuration")
        
        # Use helm upgrade --install to install or update Kubeapps
        # --install: Install if not already installed
        # This ensures that any changes in values.yaml are always applied
        cmd(
            f"helm upgrade --install kubeapps oci://registry-1.docker.io/bitnamicharts/kubeapps \
             --version 17.1.1 --namespace kubeapps -f {values_file}"
        )
        
        print(f"\n Forcing Kubeapps frontend pod recreation to apply new secrets...")
        # Delete the main Kubeapps pod to force recreation with new clientSecret
        # This is necessary because helm upgrade doesn't always trigger pod recreation
        # when only Secret/ConfigMap values change
        cmd("minikube kubectl -- delete pod -n kubeapps -l app.kubernetes.io/component=frontend --ignore-not-found=true")
        print(f" Kubeapps frontend pod deleted, waiting for recreation...")
        
        print(f"\n Waiting for Kubeapps pods to be ready...")
        
        # Wait for PostgreSQL to be ready first (other pods depend on it)
        max_wait = 300  # 5 minutes
        waited = 0
        while waited < max_wait:
            result = cmd_output("minikube kubectl -- get pods -n kubeapps -l app.kubernetes.io/component=primary -o jsonpath='{.items[0].status.phase}'")
            if result.strip() == 'Running':
                print(f" PostgreSQL is running")
                break
            time.sleep(5)
            waited += 5
            if waited % 30 == 0:
                print(f"   Still waiting for PostgreSQL... ({waited}s)")
        
        # Wait for all Kubeapps pods to be ready
        cmd("minikube kubectl -- wait --for=condition=ready pod -l app.kubernetes.io/instance=kubeapps -n kubeapps --timeout=300s || true")
        
        # Show final pod status
        print(f"\n Kubeapps pod status:")
        cmd("minikube kubectl -- get pods -n kubeapps")
        
        print(f"\n Kubeapps installed successfully!")
        print(f" Access at: https://{CONFIG.public_domain}/apps/")
        print(f"\n  Note: Kubeapps requires Kubernetes API server to be configured with OIDC.")
        print(f"   See k8s-deploy-node/kubeapps/README.md for details on configuring kube-apiserver.")
        
    finally:
        os.chdir(prev_dir)

def install_cert_manager(CONFIG):
    """Install cert-manager for automatic TLS certificate management"""
    print("Installing cert-manager...")
    
    cert_manager_success = False
    
    # Method 1: Pre-load images using Docker and then install
    print("Pre-loading cert-manager images into minikube...")
    
    # List of cert-manager images for v1.18.2
    images = [
        "quay.io/jetstack/cert-manager-controller:v1.18.2",
        "quay.io/jetstack/cert-manager-cainjector:v1.18.2", 
        "quay.io/jetstack/cert-manager-webhook:v1.18.2"
    ]
    
    # Pull images with Docker and load into minikube
    images_loaded = True
    for image in images:
        print(f"Pulling and loading {image}...")
        # Pull with docker
        pull_result = cmd(f"docker pull {image}", exit_on_error=False)
        if pull_result == 0:
            # Load into minikube
            load_result = cmd(f"minikube image load {image}", exit_on_error=False)
            if load_result != 0:
                print(f"Failed to load {image} into minikube")
                images_loaded = False
                break
        else:
            print(f"Failed to pull {image} with Docker")
            images_loaded = False
            break
    
    if images_loaded:
        print("All images loaded successfully, installing cert-manager...")
        # Now install cert-manager - images should be available locally in minikube
        yaml_install = cmd("minikube kubectl -- apply -f https://github.com/cert-manager/cert-manager/releases/download/v1.18.2/cert-manager.yaml", exit_on_error=False)
        
        if yaml_install == 0:
            print("v1.18.2 installation successful, waiting for pods...")
            # Wait for pods to be ready with 100s timeout
            ret1 = cmd("minikube kubectl -- wait --for=condition=ready pod -l app.kubernetes.io/name=cert-manager -n cert-manager --timeout=100s", exit_on_error=False)
            ret2 = cmd("minikube kubectl -- wait --for=condition=ready pod -l app.kubernetes.io/name=cainjector -n cert-manager --timeout=100s", exit_on_error=False)
            ret3 = cmd("minikube kubectl -- wait --for=condition=ready pod -l app.kubernetes.io/name=webhook -n cert-manager --timeout=100s", exit_on_error=False)
            
            if ret1 == 0 and ret2 == 0 and ret3 == 0:
                cert_manager_success = True
                print("cert-manager v1.18.2 installed successfully!")
    
    # Method 2 (fallback): Try direct installation in case pre-loading wasn't needed
    if not cert_manager_success:
        print("Trying direct installation as fallback...")
        yaml_install = cmd("minikube kubectl -- apply -f https://github.com/cert-manager/cert-manager/releases/download/v1.18.2/cert-manager.yaml", exit_on_error=False)
        
        if yaml_install == 0:
            print("Direct installation successful, waiting for pods...")
            ret1 = cmd("minikube kubectl -- wait --for=condition=ready pod -l app.kubernetes.io/name=cert-manager -n cert-manager --timeout=100s", exit_on_error=False)
            ret2 = cmd("minikube kubectl -- wait --for=condition=ready pod -l app.kubernetes.io/name=cainjector -n cert-manager --timeout=100s", exit_on_error=False)
            ret3 = cmd("minikube kubectl -- wait --for=condition=ready pod -l app.kubernetes.io/name=webhook -n cert-manager --timeout=100s", exit_on_error=False)
            
            if ret1 == 0 and ret2 == 0 and ret3 == 0:
                cert_manager_success = True
                print("cert-manager installed successfully with direct method!")
    
    # Final verification
    if cert_manager_success:
        print("Verifying cert-manager functionality...")
        verify_result = cmd("minikube kubectl -- get pods -n cert-manager", exit_on_error=False)
        if verify_result == 0:
            create_letsencrypt_issuer(CONFIG)
            print("cert-manager installation completed successfully and is functional")
            return True
    
    # If all methods failed
    print("\n" + "="*80)
    print("ERROR: Unable to install functional cert-manager")
    print("Even with pre-loaded images, installation failed.")
    print("="*80)
    
    print("Installation cannot continue without functional cert-manager.")
    exit(1)


def create_letsencrypt_issuer(CONFIG):
    """Create Let's Encrypt ClusterIssuer for automatic certificate generation"""
    if not hasattr(CONFIG, 'letsencrypt') or not hasattr(CONFIG.letsencrypt, 'email'):
        print("Warning: No Let's Encrypt email configured, skipping ClusterIssuer creation")
        return
    
    # Path to the ClusterIssuer template
    template_file = os.path.join(SCRIPT_DIR, "k8s-deploy-node", "cert-manager", "cluster-issuer-template.yaml")
    output_file = "/tmp/cluster-issuer.yaml"
    
    # Check if template exists
    if not os.path.exists(template_file):
        print(f"Warning: ClusterIssuer template not found at {template_file}")
        return
    
    # Read and process the template
    with open(template_file, 'r') as f:
        template_content = f.read()
    
    # Replace placeholders with actual values
    processed_content = template_content.replace('LETSENCRYPT_EMAIL_PLACEHOLDER', CONFIG.letsencrypt.email)
    
    # Optionally switch to staging server if configured
    if hasattr(CONFIG.letsencrypt, 'use_staging') and CONFIG.letsencrypt.use_staging:
        print("Using Let's Encrypt staging environment for testing")
        # Could add logic here to prioritize staging issuer
    
    # Write processed manifest to temporary file
    with open(output_file, 'w') as f:
        f.write(processed_content)
    
    # Apply ClusterIssuer
    cmd(f"minikube kubectl -- apply -f {output_file}")
    print(f"Let's Encrypt ClusterIssuer created successfully using template from {template_file}")


def create_iptables_rules_script():
    """Create and apply iptables rules for external access to minikube ingress"""
    print("Setting up iptables rules for external access...")
    
    # Get ingress-nginx service info to extract nodeports
    try:
        result = subprocess.run(
            ["minikube", "service", "ingress-nginx-controller", "-n", "ingress-nginx", "--url"],
            capture_output=True, text=True, check=True
        )
        service_urls = result.stdout.strip().split('\n')
        
        # Extract nodeports from URLs - first URL is HTTP, second is HTTPS
        http_nodeport = None
        https_nodeport = None
        minikube_ip = "192.168.49.2"  # Default minikube IP
        
        # Parse each URL to extract IP and port
        for i, url in enumerate(service_urls):
            if ':' in url:
                ip_port = url.split('://')[-1]
                if ':' in ip_port:
                    ip, port = ip_port.split(':')
                    minikube_ip = ip
                    # First URL is typically HTTP, second is HTTPS
                    if i == 0:
                        http_nodeport = port
                    elif i == 1:
                        https_nodeport = port
        
        if not http_nodeport or not https_nodeport:
            print("Warning: Could not determine nodeports automatically, using defaults")
            http_nodeport = "30906"
            https_nodeport = "31630"
            
    except subprocess.CalledProcessError:
        print("Warning: Could not get ingress service info, using default nodeports")
        minikube_ip = "192.168.49.2"
        http_nodeport = "30906"
        https_nodeport = "31630"
    
    # Detect the external network interface automatically
    try:
        # Get default route interface
        result = subprocess.run(
            ["ip", "route", "show", "default"],
            capture_output=True, text=True, check=True
        )
        # Extract interface name from output like "default via 10.0.0.1 dev ens4"
        external_interface = None
        for line in result.stdout.strip().split('\n'):
            if 'default' in line and 'dev' in line:
                parts = line.split()
                dev_index = parts.index('dev')
                if dev_index + 1 < len(parts):
                    external_interface = parts[dev_index + 1]
                    break
        
        if not external_interface:
            external_interface = "ens4"  # Default fallback
            print(f"Warning: Could not detect external interface, using default: {external_interface}")
        else:
            print(f"Detected external network interface: {external_interface}")
            
    except subprocess.CalledProcessError:
        external_interface = "ens4"
        print(f"Warning: Could not detect network interface, using default: {external_interface}")
    
    print(f"Detected minikube IP: {minikube_ip}")
    print(f"HTTP nodeport: {http_nodeport}, HTTPS nodeport: {https_nodeport}")
    print(f"External interface: {external_interface}")
    
    # First, apply the iptables rules immediately if running as root
    if os.geteuid() == 0:
        print("Applying interface-specific iptables rules immediately...")
        
        # ONLY use interface-specific NAT rules (with -i flag)
        try:
            # Interface-specific NAT rules for HTTP
            result = subprocess.run(
                ["iptables", "-t", "nat", "-C", "PREROUTING", "-i", external_interface, "-p", "tcp", "--dport", "80", "-j", "DNAT", "--to-destination", f"{minikube_ip}:{http_nodeport}"],
                capture_output=True, check=False
            )
            if result.returncode != 0:
                print(f"Adding interface-specific NAT rule for HTTP on {external_interface}")
                cmd(f"iptables -t nat -A PREROUTING -i {external_interface} -p tcp --dport 80 -j DNAT --to-destination {minikube_ip}:{http_nodeport}")
            else:
                print(f"Interface-specific NAT rule for HTTP on {external_interface} already exists")
                
            # Interface-specific NAT rules for HTTPS
            result = subprocess.run(
                ["iptables", "-t", "nat", "-C", "PREROUTING", "-i", external_interface, "-p", "tcp", "--dport", "443", "-j", "DNAT", "--to-destination", f"{minikube_ip}:{https_nodeport}"],
                capture_output=True, check=False
            )
            if result.returncode != 0:
                print(f"Adding interface-specific NAT rule for HTTPS on {external_interface}")
                cmd(f"iptables -t nat -A PREROUTING -i {external_interface} -p tcp --dport 443 -j DNAT --to-destination {minikube_ip}:{https_nodeport}")
            else:
                print(f"Interface-specific NAT rule for HTTPS on {external_interface} already exists")
                
            # Check and add FORWARD rules
            result = subprocess.run(
                ["iptables", "-C", "FORWARD", "-p", "tcp", "-d", minikube_ip, "--dport", http_nodeport, "-j", "ACCEPT"],
                capture_output=True, check=False
            )
            if result.returncode != 0:
                print("Adding FORWARD rule for HTTP traffic")
                cmd(f"iptables -I FORWARD 1 -p tcp -d {minikube_ip} --dport {http_nodeport} -j ACCEPT")
            else:
                print("FORWARD rule for HTTP traffic already exists")
                
            result = subprocess.run(
                ["iptables", "-C", "FORWARD", "-p", "tcp", "-d", minikube_ip, "--dport", https_nodeport, "-j", "ACCEPT"],
                capture_output=True, check=False
            )
            if result.returncode != 0:
                print("Adding FORWARD rule for HTTPS traffic")
                cmd(f"iptables -I FORWARD 1 -p tcp -d {minikube_ip} --dport {https_nodeport} -j ACCEPT")
            else:
                print("FORWARD rule for HTTPS traffic already exists")
                
            print("Interface-specific iptables rules applied successfully!")
            
        except Exception as e:
            print(f"Warning: Could not apply iptables rules immediately: {e}")
            print("Rules will be applied on next network startup")
    else:
        print("Not running as root - iptables rules will be applied on network startup")
    
    # Create the persistent script content with ONLY interface-specific rules
    script_content = f"""#!/bin/bash
# Mininode iptables rules for external access to minikube ingress
# Auto-generated by install.py
# IMPORTANT: Only using interface-specific rules to preserve minikube connectivity
# External interface: {external_interface}
# Minikube IP: {minikube_ip}

echo "Setting up interface-specific NAT rules for external access..."
echo "External interface: {external_interface}"

# Interface-specific NAT rules ONLY (preserves minikube's own connectivity)
if ! iptables -t nat -C PREROUTING -i {external_interface} -p tcp --dport 80 -j DNAT --to-destination {minikube_ip}:{http_nodeport} 2>/dev/null; then
    echo "Adding interface-specific NAT rule for HTTP on {external_interface}"
    iptables -t nat -A PREROUTING -i {external_interface} -p tcp --dport 80 -j DNAT --to-destination {minikube_ip}:{http_nodeport}
else
    echo "Interface-specific NAT rule for HTTP on {external_interface} already exists, skipping"
fi

if ! iptables -t nat -C PREROUTING -i {external_interface} -p tcp --dport 443 -j DNAT --to-destination {minikube_ip}:{https_nodeport} 2>/dev/null; then
    echo "Adding interface-specific NAT rule for HTTPS on {external_interface}"
    iptables -t nat -A PREROUTING -i {external_interface} -p tcp --dport 443 -j DNAT --to-destination {minikube_ip}:{https_nodeport}
else
    echo "Interface-specific NAT rule for HTTPS on {external_interface} already exists, skipping"
fi

# FORWARD rules to accept forwarded packets
echo "Setting up FORWARD rules..."

if ! iptables -C FORWARD -p tcp -d {minikube_ip} --dport {http_nodeport} -j ACCEPT 2>/dev/null; then
    echo "Adding FORWARD rule for HTTP traffic"
    iptables -I FORWARD 1 -p tcp -d {minikube_ip} --dport {http_nodeport} -j ACCEPT
else
    echo "FORWARD rule for HTTP traffic already exists, skipping"
fi

if ! iptables -C FORWARD -p tcp -d {minikube_ip} --dport {https_nodeport} -j ACCEPT 2>/dev/null; then
    echo "Adding FORWARD rule for HTTPS traffic"
    iptables -I FORWARD 1 -p tcp -d {minikube_ip} --dport {https_nodeport} -j ACCEPT
else
    echo "FORWARD rule for HTTPS traffic already exists, skipping"
fi

echo "Mininode iptables rules configuration completed"
echo "External interface: {external_interface}"
echo "HTTP traffic (port 80) -> {minikube_ip}:{http_nodeport}"
echo "HTTPS traffic (port 443) -> {minikube_ip}:{https_nodeport}"
echo ""
echo "NOTE: These rules only affect traffic coming from {external_interface}"
echo "Minikube's own connectivity to external services is preserved."
echo ""
echo "You can verify the rules with:"
echo "  sudo iptables -t nat -L PREROUTING -n --line-numbers"
echo "  sudo iptables -L FORWARD -n --line-numbers"
"""
    
    # Create persistent script
    if os.geteuid() != 0:
        print("Warning: Not running as root. Creating script in current directory...")
        script_path = "./mininode-iptables-rules"
        print(f"You will need to manually copy this to /etc/network/if-pre-up.d/ as root")
    else:
        script_path = "/etc/network/if-pre-up.d/mininode-iptables-rules"
        # Ensure directory exists
        os.makedirs("/etc/network/if-pre-up.d", exist_ok=True)
    
    # Write the script
    with open(script_path, 'w') as f:
        f.write(script_content)
    
    # Make it executable
    os.chmod(script_path, 0o755)
    
    print(f"Persistent iptables rules script created at: {script_path}")
    if os.geteuid() == 0:
        print("Script will run automatically on network interface startup")
        print("You can also run it manually: sudo /etc/network/if-pre-up.d/mininode-iptables-rules")
        print(f"To verify rules: sudo iptables -t nat -L PREROUTING -n --line-numbers")
    else:
        print("To install system-wide, run as root:")
        print(f"sudo cp {script_path} /etc/network/if-pre-up.d/")
        print("sudo chmod +x /etc/network/if-pre-up.d/mininode-iptables-rules")


def update_dataset_service_kid_from_keycloak(CONFIG):
    """
    Helper function to update the dataset-service kid after Keycloak is running
    Can be called manually or as part of post-installation steps
    """
    print("Updating dataset-service kid from running Keycloak instance...")
    
    try:
        import requests
        import json
        import yaml
        
        # Download current JWKS
        jwks_url = f"https://{CONFIG.public_domain}/auth/realms/EUCAIM-NODE/protocol/openid-connect/certs"
        print(f"Fetching JWKS from: {jwks_url}")
        
        response = requests.get(jwks_url, verify=False, timeout=30)
        response.raise_for_status()
        jwks_data = response.json()
        
        # Find RS256 key
        kid_rs256 = None
        for key in jwks_data.get('keys', []):
            if key.get('alg') == 'RS256':
                kid_rs256 = key.get('kid')
                break
        
        if not kid_rs256:
            print(" No RS256 key found in JWKS")
            return False
        
        print(f" Found RS256 kid: {kid_rs256}")
        
        # Update dataset-service deployment
        dataset_dir = os.path.join(SCRIPT_DIR, "k8s-deploy-node", "dataset-service")
        deployment_file = os.path.join(dataset_dir, "2-dataset-service.yaml")
        
        if not os.path.exists(deployment_file):
            print(f" Dataset service deployment file not found: {deployment_file}")
            return False
        
        with open(deployment_file) as f:
            docs = list(yaml.safe_load_all(f))
        
        updated = False
        for doc in docs:
            if doc.get("kind") == "Deployment":
                containers = doc["spec"]["template"]["spec"]["containers"]
                for container in containers:
                    for env in container.get("env", []):
                        if env.get("name") == "DATASET_SERVICE_CONFIG":
                            config = json.loads(env["value"])
                            
                            # Update kid
                            if "auth" in config and "token_validation" in config["auth"]:
                                old_kid = config["auth"]["token_validation"].get("kid", "unknown")
                                config["auth"]["token_validation"]["kid"] = kid_rs256
                                updated = True
                                print(f" Updated kid: {old_kid} -> {kid_rs256}")
                            
                            # Ensure tracer is properly configured (disabled by default)
                            if "tracer" in config:
                                # Check if we have a specific tracer configuration in CONFIG
                                if hasattr(CONFIG, 'tracer') and hasattr(CONFIG.tracer, 'url') and CONFIG.tracer.url:
                                    config["tracer"]["url"] = CONFIG.tracer.url
                                    print(f" Updated tracer URL: {CONFIG.tracer.url}")
                                else:
                                    # Set tracer URL to empty to disable it
                                    config["tracer"]["url"] = ""
                                    print(" Tracer service disabled (URL set to empty)")
                            else:
                                # Add tracer configuration with empty URL
                                config["tracer"] = {"url": ""}
                                print(" Tracer service disabled (added empty configuration)")
                                updated = True
                            
                            env["value"] = json.dumps(config, indent=2)
        
        if updated:
            with open(deployment_file, 'w') as f:
                yaml.safe_dump_all(docs, f, sort_keys=False)
            
            # Apply the updated deployment
            prev_dir = os.getcwd()
            try:
                os.chdir(dataset_dir)
                cmd("minikube kubectl -- apply -f 2-dataset-service.yaml -n dataset-service")
                print(" Dataset service deployment updated and applied")
                
                # Force restart of pods to pick up new kid value
                print(" Restarting dataset-service pods to apply new kid...")
                cmd("minikube kubectl -- rollout restart deployment/dataset-service-backend -n dataset-service")
                
                # Wait for rollout to complete
                print(" Waiting for rollout to complete...")
                cmd("minikube kubectl -- rollout status deployment/dataset-service-backend -n dataset-service --timeout=120s")
                print(" Dataset service pods restarted successfully with new kid")
                
                return True
            finally:
                os.chdir(prev_dir)
        else:
            print(" Could not find DATASET_SERVICE_CONFIG to update")
            return False
            
    except Exception as e:
        print(f" Error updating kid: {e}")
        return False

def package_workstation_charts(CONFIG):
    """Package and publish workstation Helm charts to dataset-service"""
    prev_dir = os.getcwd()
    try:
        print(f"\n{'='*80}")
        print(" Packaging Workstation Helm Charts")
        print(f"{'='*80}\n")
        
        # Create temporary directory for chart work
        work_dir = os.path.join(SCRIPT_DIR, "workstation-charts-tmp")
        os.makedirs(work_dir, exist_ok=True)
        os.chdir(work_dir)
        
        # Clone the workstation images repository
        repo_dir = "upv-node-workstation-images"
        if not os.path.isdir(repo_dir):
            print(f" Cloning workstation images repository...")
            clone_result = cmd("GIT_TERMINAL_PROMPT=0 git clone --depth 1 https://github.com/EUCAIM/upv-node-workstation-images.git", exit_on_error=False)
            if clone_result != 0:
                print(f"  Warning: Clone failed")
                print(f"   Skipping workstation charts packaging")
                return
        else:
            print(f" Workstation images repository already exists")
        
        # Edit _commonHelpers.tpl to update Guacamole URL
        helpers_file = os.path.join(repo_dir, "helm-charts", "_commonHelpers.tpl")
        if os.path.exists(helpers_file):
            print(f" Updating Guacamole URL in _commonHelpers.tpl...")
            
            with open(helpers_file, 'r') as f:
                content = f.read()
            
            # Replace hardcoded Guacamole URL with configured domain
            # The file contains: https://eucaim-node.i3m.upv.es/guacamole/
            content = content.replace(
                'eucaim-node.i3m.upv.es/guacamole/',
                f'{CONFIG.public_domain}/guacamole/'
            )

            with open(helpers_file, 'w') as f:
                f.write(content)
            
            print(f"  Updated Guacamole URL to: {CONFIG.public_domain}/guacamole/")
        else:
            print(f"  Warning: _commonHelpers.tpl not found at {helpers_file}")
        
        # Run the package-and-upload script
        charts_dir = os.path.join(repo_dir, "helm-charts")
        package_script = os.path.join(charts_dir, "package-and-upload.sh")
        
        if os.path.exists(package_script):
            print(f"\n Packaging Helm charts...")
            
            # Make script executable before changing directory
            cmd(f"chmod +x {package_script}")
            
            # Change to charts directory and run the script
            os.chdir(charts_dir)
            package_result = cmd("./package-and-upload.sh", exit_on_error=False)
            
            if package_result == 0:
                print(f" Charts packaged successfully")
                
                # Copy packaged charts to dataset-service output directory
                # First, find where the charts were packaged
                packaged_charts_dir = os.path.join(charts_dir, "chart-catalogue")
                if not os.path.isdir(packaged_charts_dir):
                    # Try alternate location
                    packaged_charts_dir = charts_dir
                
                # Copy to minikube dataset-service-data volume
                print(f"\n Copying charts to dataset-service...")

                # Ensure output-files/charts directory exists in minikube
                cmd("minikube ssh -- 'sudo mkdir -p /var/hostpath-provisioner/dataset-service/dataset-service-data/output-files/charts'")
                cmd("minikube ssh -- 'sudo chmod -R 777 /var/hostpath-provisioner/dataset-service/dataset-service-data/output-files'")
                
                # Copy entire packaged directory contents to minikube using tar
                print(f"  Copying all files from {packaged_charts_dir}...")
                
                # Create tar.gz with all contents
                cmd(f"tar -czf /tmp/charts-packaged.tar.gz -C {packaged_charts_dir} .")
                
                # Copy tar to minikube
                cmd("minikube cp /tmp/charts-packaged.tar.gz minikube:/tmp/")
                
                # Extract in destination directory
                cmd("minikube ssh -- 'sudo tar -xzf /tmp/charts-packaged.tar.gz -C /var/hostpath-provisioner/dataset-service/dataset-service-data/output-files/charts/'")
                
                # Generate Helm repository index.yaml locally (helm not available inside minikube)
                print(f"\n Generating Helm repository index...")
                host_charts_dir = "/home/ubuntu/minikube-data2/dataset-service/dataset-service-data/output-files/charts"
                cmd(f"helm repo index {host_charts_dir} --url http://{CONFIG.public_domain}/dataset-service/output-files/charts/")
                
                # Clean up temporary files
                cmd("minikube ssh -- 'sudo rm /tmp/charts-packaged.tar.gz'")
                cmd("rm /tmp/charts-packaged.tar.gz")
                
                print(f"\n Workstation charts published successfully!")
                print(f" Charts available at: http://{CONFIG.public_domain}/dataset-service/output-files/charts/")
            else:
                print(f"  Warning: Chart packaging failed")
        else:
            print(f"  Warning: package-and-upload.sh not found at {package_script}")
        
    except Exception as e:
        print(f" Error packaging workstation charts: {e}")
    finally:
        os.chdir(prev_dir)

def install_qpi(CONFIG):

    pass

def install_jobman_service(CONFIG):
    """
    Placeholder for installing the jobman service.
    """
    # TODO: Implement the installation steps for jobman service
    print("Installing jobman service (not yet implemented)")

def apply_pod_priorities():
    """Apply pod priority classes from extra-configurations"""
    print(f"\n{'='*80}")
    print(" Applying Pod Priority Classes")
    print(f"{'='*80}\n")
    
    priorities_dir = os.path.join(SCRIPT_DIR, "k8s-deploy-node", "extra-configurations", "pod-priorities")
    
    if not os.path.exists(priorities_dir):
        print(f" Pod priorities directory not found: {priorities_dir}")
        return
    
    priority_files = [
        "core-services.yml",
        "core-applications.yml",
        "processing-applications.yml"
    ]
    
    for priority_file in priority_files:
        file_path = os.path.join(priorities_dir, priority_file)
        if os.path.exists(file_path):
            print(f" Applying {priority_file}...")
            cmd(f"minikube kubectl -- apply -f {file_path}")
        else:
            print(f"  Warning: {priority_file} not found, skipping")
    
    print(f" Pod priority classes applied successfully")


FLAVORS = ["micro", "mini", "standard"]

def install(flavor):
    global CONFIG
    
    if flavor not in FLAVORS:
        print(f"ERROR: Invalid flavor '{flavor}'. Must be one of: {FLAVORS}")
        exit(1)
    
    # CONFIG is already loaded by load_config() at the bottom of the script
    if CONFIG is None:
        print("ERROR: CONFIG is None. Please ensure load_config() was called successfully.")
        exit(1)
    
    # Add flavor to CONFIG for use in installation functions
    CONFIG.flavor = flavor
    
    print(f" Starting installation with flavor: {flavor}")
    print(f" Configuration loaded from: {DEFAULT_CONFIG_FILE_PATH}")
    print(f" Domain: {CONFIG.public_domain}")
    
    # Ensure ingress addon is enabled before installing services
    ensure_ingress_addon()
    
    # Apply pod priority classes
    apply_pod_priorities()
    
    # Create iptables rules for external access
    create_iptables_rules_script()
    
    # Install cert-manager (needed for TLS certificates)
    cert_manager_available = install_cert_manager(CONFIG)
    
    # Store cert-manager availability for service configurations
    CONFIG.cert_manager_available = cert_manager_available
    if not cert_manager_available:
        print("Note: Services will be configured for HTTP-only access")
    
    # Change to k8s-deploy-node directory
    os.chdir(os.path.join(SCRIPT_DIR, "k8s-deploy-node"))
    
    # Create auth client secrets
    auth_client_secrets = Auth_client_secrets()
    
    # Install components based on flavor
    print(f"\n{'='*80}")
    print(f"Installing components for flavor: {flavor}")
    print(f"{'='*80}\n")
    
    # Keycloak is installed in all flavors
    install_keycloak(auth_client_secrets)
    
    # Dataset service is installed in micro, mini and standard flavors
    if flavor in ["micro", "mini", "standard"]:
        install_dataset_service(auth_client_secrets.CLIENT_DATASET_SERVICE_SECRET)
    
    # Package workstation charts and publish to dataset-service (requires dataset-service to be installed)
    if flavor in ["micro", "standard"]:
        package_workstation_charts(CONFIG)
    
    # Guacamole is installed in micro and standard flavors
    if flavor in ["micro", "standard"]:
        install_guacamole(CONFIG)
    
    # Kubeapps is installed in micro and standard flavors
    if flavor in ["micro", "standard"]:
        install_kubeapps(CONFIG, auth_client_secrets.CLIENT_KUBERNETES_SECRET)
    
    # DSWS Operator is installed in micro and standard flavors (requires dataset-service and guacamole)
    if flavor in ["micro", "standard"]:
        install_dsws_operator(CONFIG, auth_client_secrets)
    
    # QPI service (only in standard)
    if flavor == "standard":
        install_qpi(CONFIG)
    
    # Job manager service (mini and standard)
    if flavor in ["mini", "standard"]:
        install_jobman_service(CONFIG)
    
    # Post-installation tasks
    print(f"\n{'='*80}")
    print(" Post-installation: Attempting to update dataset-service kid from running Keycloak...")
    print(f"{'='*80}\n")
    
    if flavor in ["mini", "standard"]:
        # Wait for Keycloak to be ready
        print("Waiting 30 seconds for Keycloak to be fully operational...")
        cmd("sleep 30")
        
        # Update kid from Keycloak
        print("Updating dataset-service kid from running Keycloak instance...")
        if update_dataset_service_kid_from_keycloak(CONFIG):
            print(" Successfully updated dataset-service kid from Keycloak JWKS")
        else:
            print(" Could not update kid automatically. You may need to do this manually:")
            print(f"   1. Check Keycloak JWKS: curl -k https://{CONFIG.public_domain}/auth/realms/EUCAIM-NODE/protocol/openid-connect/certs")
            print("   2. Find the RS256 key's 'kid' value")
            print("   3. Update the dataset-service deployment with the correct kid")
    
    print(f"\n{'='*80}")
    print(f" Installation completed successfully!")
    print(f"{'='*80}\n")
    print(f" Access your services at: https://{CONFIG.public_domain}")
    print(f" Keycloak: https://{CONFIG.public_domain}/auth")
    
    if flavor in ["mini", "standard"]:
        print(f" Dataset Service: https://{CONFIG.public_domain}/dataset-service")
    
    if flavor in ["micro", "standard"]:
        print(f" Guacamole: https://{CONFIG.public_domain}/guacamole")
        print(f" Kubeapps: https://{CONFIG.public_domain}/apps/")

if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument("FLAVOR", help="Which flavor to install (micro, mini, standard)", nargs="?", default="")
    args = parser.parse_args()

    flavor = str(args.FLAVOR).lower()
    while flavor not in FLAVORS:
        print("Unknown flavor, please select one option:")
        n = 0
        for f in FLAVORS:
            print("%d - %s" % (n, f))
            n += 1
        try:
            flavor = FLAVORS[int(input(""))]
        except (ValueError, IndexError): flavor = ""
    print(flavor)

    CONFIG = load_config(logging.root, DEFAULT_CONFIG_FILE_PATH)
    if CONFIG is None: exit(1)

    install(flavor)

    exit(0)

