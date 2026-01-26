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
import sys

from keycloak_admin_api import KeycloakAdminAPIClient
from auth import AuthClient
from config import *

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
DEFAULT_CONFIG_FILE_PATH = "config.private.yaml"
K8S_DEPLOY_NODE_REPO = "git@github.com:EUCAIM/k8s-deploy-node.git"

CONFIG = None

## Function to execute shell commands 
def cmd(command, exit_on_error=True):
    print(command)
    ret = os.system(command)
    if exit_on_error and ret != 0: exit(1)
    return ret

## To get command output as string
def cmd_output(command):
    '''Execute command and return output as string'''
    try:
        result = subprocess.run(command, shell=True, capture_output=True, text=True)
        return result.stdout
    except Exception as e:
        print(f"Error executing command: {e}")
        return ""


def generate_random_password(length: int = 16) -> str:
    alphabet = string.ascii_letters + string.digits
    return ''.join(random.choice(alphabet) for _ in range(length))

## Generate guacamole admin password globally (after function definition)
guacamole_user_creator_password = generate_random_password(24)


## Update YAML files
def update_yaml_config(file_path, update_func):
    '''Generic function to update YAML configuration files'''
    with open(file_path) as f:
        docs = list(yaml.safe_load_all(f))
    
    updated = update_func(docs)
    
    if updated:
        # If file is in k8s-deploy-node directory, create private copy
        if 'k8s-deploy-node' in file_path:
            # Create new file path with .private.yaml suffix
            base_path = file_path.rsplit('.', 1)[0]  # Remove extension
            private_file_path = base_path + '.private.yaml'
            with open(private_file_path, 'w') as f:
                yaml.safe_dump_all(docs, f, sort_keys=False)
            print(f"Created private copy: {private_file_path}")
            return private_file_path
        else:
            # For non-k8s-deploy-node files, edit in place
            with open(file_path, 'w') as f:
                yaml.safe_dump_all(docs, f, sort_keys=False)
            return True
    return False

## It updates the tracer variable on the 2-dataset-service.yaml with the one indicated by the user
def configure_tracer_service(config, tracer_url=None):
    '''Configure or disable tracer service in configuration'''
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
    '''Update PostgreSQL password in deployment YAML'''
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
    
    result = update_yaml_config(file_path, update_password)
    if result:
        # If result is a string, it's the private file path
        private_path = result if isinstance(result, str) else file_path
        print(f"Injected password into {env_var_name} in {private_path}")
        return private_path
    else:
        print(f"Warning: Could not find {env_var_name} to update password.")
        return False
## Delete stuck PVs by removing finalizers
def force_cleanup_pvs():
    '''Force cleanup of stuck PVs by removing finalizers'''
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

## Class to manage Keycloak client secrets find them if existing to avoid conflicts or generate new ones 
class Auth_client_secrets():
    def __init__(self):
        private_realm_file = os.path.join(SCRIPT_DIR, "eucaim-node-realm.private.json")
        existing_secrets = {}
        
        if os.path.exists(private_realm_file):
            try:
                import json
                with open(private_realm_file, 'r') as f:
                    realm_data = json.load(f)
## Read all existing client secrets
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
    
## Force cleanup of stuck PVs first
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

    realm_config_file_private = "eucaim-node-realm.private.json" 
    keycloak_deploy_file = "dep3_keycloak_v4.yaml"
    
    def update_keycloak_deployment(docs):
        '''Update Keycloak deployment configuration'''
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
        return updated
    
    result = update_yaml_config(keycloak_deploy_file, update_keycloak_deployment)
    if result:
        # If result is a string, it's the edited file path
        keycloak_deploy_file = result if isinstance(result, str) else keycloak_deploy_file
        print(f"Injected config values into {keycloak_deploy_file}")
    
    # OLD CODE (commented for safety):
    # with open(keycloak_deploy_file) as f:
    #     docs = list(yaml.safe_load_all(f))
    # updated = False
    # for doc in docs:
    #     if doc.get("kind") == "Deployment":
    #         for env in doc["spec"]["template"]["spec"]["containers"][0].get("env", []):
    #             if env.get("name") == "KC_BOOTSTRAP_ADMIN_USERNAME":
    #                 env["value"] = CONFIG.keycloak.admin_username
    #                 updated = True
    #             elif env.get("name") == "KC_BOOTSTRAP_ADMIN_PASSWORD":
    #                 env["value"] = CONFIG.keycloak.admin_password
    #                 updated = True
    #             elif env.get("name") == "KC_DB_PASSWORD":
    #                 env["value"] = CONFIG.keycloak.db_password
    #                 updated = True
    #             elif env.get("name") == "KC_SPI_EVENTS_LISTENER_EMAIL_TO_ADMIN_EMAIL_RECEIVERS":
    #                 env["value"] = CONFIG.keycloak.admin_emails
    #                 updated = True
    #             elif env.get("name") == "KC_HOSTNAME":
    #                 env["value"] = CONFIG.public_domain
    #                 updated = True
    #         
    #         if not any("--import-realm" in str(param) for param in doc["spec"]["template"]["spec"]["containers"][0].get("args", [])):
    #             doc["spec"]["template"]["spec"]["containers"][0]["args"].append("--import-realm")
    #             updated = True
    #         
    #         if not any(mount["subPath"] == realm_config_file_private for mount in doc["spec"]["template"]["spec"]["containers"][0]["volumeMounts"]):
    #             doc["spec"]["template"]["spec"]["containers"][0]["volumeMounts"].append({
    #                 "name": "vol-standalone-deployments",
    #                 "subPath": realm_config_file_private,
    #                 "mountPath": "/opt/keycloak/data/import/" + realm_config_file_private
    #             })
    #             updated = True
    # if updated:
    #     with open(keycloak_deploy_file, 'w') as f:
    #         yaml.safe_dump_all(docs, f, sort_keys=False)
    #     print(f"Injected config values into {keycloak_deploy_file}")

    # Verify namespace is ready before applying resources
    print("Verifying namespace is ready...")
    cmd("minikube kubectl -- get namespace keycloak")
    
    # Apply PVC manifests for dataset-service if present (do not replace storageClassName)


    # Always ensure Keycloak volumes (PV + namespaced PVCs) are applied when available
    # This creates the Keycloak PVs and the namespaced PVCs like `postgres-data`.
    if os.path.exists("dep0_volumes.yaml"):
        print(" Applying dep0_volumes.yaml for Keycloak volumes (pv + pvc) — creating a private file with storageClassName='standard' and applying it")
        # Read file and extract only PersistentVolumeClaim documents
        try:
            with open('dep0_volumes.yaml', 'r') as f:
                docs = list(yaml.safe_load_all(f))
        except Exception as e:
            print(f"  Warning: could not read dep0_volumes.yaml: {e}")
            docs = []
        # Update storageClassName to 'standard' for all PVCs
        pvc_docs = [d for d in docs if isinstance(d, dict) and d.get("kind") == "PersistentVolumeClaim"]
        for d in pvc_docs:
            if "spec" not in d:
                d["spec"] = {}
            d["spec"]["storageClassName"] = "standard"
            if "metadata" not in d:
                d["metadata"] = {}
            d["metadata"]["namespace"] = "keycloak"

        # Save the updated PVCs to dep0_volumes.private.yaml
        private_dep0 = "dep0_volumes.private.yaml"
        try:
            with open(private_dep0, "w") as pf:
                yaml.safe_dump_all(pvc_docs, pf, sort_keys=False)
            print(f"  Created private volumes file: {private_dep0}")
        except Exception as e:
            print(f"  Warning: could not write private file {private_dep0}: {e}")

        # Apply the private file
        cmd("minikube kubectl -- create namespace keycloak || true")
        cmd(f"minikube kubectl -- apply -f {private_dep0}")

    # Apply init volumes for keycloak if present
    if os.path.exists("dep1_init_volumes.yaml"):
        cmd("minikube kubectl -- apply -f dep1_init_volumes.yaml -n keycloak")

    jar1_url = "https://github.com/chaimeleon-eu/keycloak-event-listener-email-to-admin/releases/download/v1.0.6/keycloak-event-listener-email-to-admin-1.0.6.jar"
    jar2_url = "https://github.com/chaimeleon-eu/keycloak-required-action-user-validated/releases/download/v1.0.5/keycloak-required-action-user-validated-1.0.5.jar"
    jar1_path = "/tmp/keycloak-event-listener-email-to-admin-1.0.6.jar"
    jar2_path = "/tmp/keycloak-required-action-user-validated-1.0.5.jar"
    
    print("Downloading Keycloak extension JARs...")
    for jar_url, jar_path in [(jar1_url, jar1_path), (jar2_url, jar2_path)]:
        max_retries = 5
        success = False
        
        for attempt in range(max_retries):
            # Remove old file if exists
            cmd(f"rm -f {jar_path}", exit_on_error=False)
            
            # Try wget first (with increased timeout and retries)
            print(f"  Attempt {attempt + 1}/{max_retries}: Downloading {os.path.basename(jar_path)}...")
            download_result = cmd(
                f"wget --timeout=60 --tries=3 --retry-connrefused --waitretry=5 "
                f"--user-agent='Mozilla/5.0' -O {jar_path} '{jar_url}'", 
                exit_on_error=False
            )
            
            # If wget fails, try curl as fallback
            if download_result != 0:
                print(f"    wget failed, trying curl...")
                download_result = cmd(
                    f"curl -L --max-time 60 --retry 3 --retry-delay 5 "
                    f"-A 'Mozilla/5.0' -o {jar_path} '{jar_url}'",
                    exit_on_error=False
                )
            
            if download_result == 0 and os.path.exists(jar_path):
                # Verify file size (JARs should be > 5KB)
                file_size = os.path.getsize(jar_path)
                if file_size < 5000:
                    print(f"    Downloaded file too small ({file_size} bytes), likely error page")
                    continue
                
                # Verify it's a valid ZIP/JAR file
                verify_result = cmd(f"unzip -t {jar_path} >/dev/null 2>&1", exit_on_error=False)
                if verify_result == 0:
                    print(f"  Downloaded and verified: {os.path.basename(jar_path)} ({file_size} bytes)")
                    success = True
                    break
                else:
                    print(f"    File corrupted (invalid ZIP/JAR)")
            else:
                print(f"    Download failed")
            
            # Wait before retry (exponential backoff)
            if attempt < max_retries - 1:
                wait_time = 2 ** attempt
                print(f"    Waiting {wait_time}s before retry...")
                time.sleep(wait_time)
        
        if not success:
            print(f"\n  WARNING: Could not download {os.path.basename(jar_path)} after {max_retries} attempts")
            print(f"   URL: {jar_url}")
            print(f"   Keycloak may not work properly without this extension")
            print(f"   You can manually download it later and copy to /var/hostpath-provisioner/keycloak/standalone-deployments/\n")

    cmd("tar -czf /tmp/themes.tar.gz themes/")
    cmd("minikube cp /tmp/themes.tar.gz minikube:/tmp/")
    cmd("minikube ssh -- 'sudo tar -xzf /tmp/themes.tar.gz -C /var/hostpath-provisioner/keycloak/themes-data/ --strip-components=1'")

    # Only copy JARs if they were successfully downloaded and validated
    if os.path.exists(jar1_path) and os.path.getsize(jar1_path) > 0:
        cmd(f"minikube cp {jar1_path} minikube:/var/hostpath-provisioner/keycloak/standalone-deployments/")
    else:
        print(f"  Warning: Skipping corrupted JAR: {jar1_path}")
    
    if os.path.exists(jar2_path) and os.path.getsize(jar2_path) > 0:
        cmd(f"minikube cp {jar2_path} minikube:/var/hostpath-provisioner/keycloak/standalone-deployments/")
    else:
        print(f"  Warning: Skipping corrupted JAR: {jar2_path}")

    realm_config_file = os.path.join(SCRIPT_DIR, "eucaim-node-realm.json")

# Auto-copy realm template if missing
    if not os.path.exists(realm_config_file):
        source_realm = os.path.join(SCRIPT_DIR, "k8s-deploy-node", "keycloak", "eucaim-node-realm.json")
        if os.path.exists(source_realm):
            print(f"  Copying realm template from k8s-deploy-node...")
            import shutil
            shutil.copy(source_realm, realm_config_file)
        else:
            raise FileNotFoundError(f"Realm template not found: {source_realm}")
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
   
    cmd(f"minikube kubectl -- apply -f {keycloak_deploy_file} -n keycloak")

    # Check if we should use Gateway API or traditional Ingress
    use_gateway_api = getattr(CONFIG, 'use_gateway_api', True)
    
    use_tls = (hasattr(CONFIG, 'letsencrypt') and 
               hasattr(CONFIG.letsencrypt, 'email') and 
               CONFIG.letsencrypt.email and
               getattr(CONFIG, 'cert_manager_available', False))
    
    if use_gateway_api:
        # NEW: Gateway API with HTTPRoute - apply from YAML file
        print(f"\n Configuring HTTPRoute for Keycloak (Gateway API)...")
        
        # Verify Gateway API CRDs are installed
        crd_check = cmd("minikube kubectl -- get crd httproutes.gateway.networking.k8s.io 2>/dev/null", exit_on_error=False)
        if crd_check != 0:
            print("  WARNING: Gateway API CRDs not installed yet")

        else:
            httproute_file = "dep4_httproute.yaml"
            update_ingress_host(httproute_file, CONFIG.public_domain)
            
            cmd(f"minikube kubectl -- apply -f {httproute_file}")
            print(f" HTTPRoute applied for Keycloak at https://{CONFIG.public_domain}/auth")
        
    else:
        ingress_file = "dep4_ingress.yaml"
        
        if not getattr(CONFIG, 'cert_manager_available', False):
            print("Note: Using HTTP-only ingress (cert-manager not available)")
        
        update_ingress_host(ingress_file, CONFIG.public_domain)

        print("Checking if ingress already exists...")
        ingress_exists = cmd(f"minikube kubectl -- get ingress proxy-keycloak -n keycloak 2>/dev/null", exit_on_error=False)
        
        if ingress_exists == 0:
            print(" Ingress already exists - preserving to avoid certificate recreation")

        else:
            print("Creating new ingress...")
            cmd(f"minikube kubectl -- apply -f {ingress_file} -n keycloak")
            
            if use_tls:
                print("TLS certificate will be automatically provisioned by cert-manager")

    os.chdir("..")

def ensure_ingress_addon():
    print("Checking minikube ingress addon...")
    ret = cmd("minikube addons list | grep 'ingress' | grep 'enabled'", exit_on_error=False)
    if ret != 0:
        print("Enabling minikube ingress addon...")
        cmd("minikube addons enable ingress")
        print(" Ingress addon enabled")
        cmd("minikube kubectl -- wait --namespace ingress-nginx --for=condition=ready pod --selector=app.kubernetes.io/component=controller --timeout=120s || true")
    else:
        print(" Ingress addon already enabled")

def install_traefik_gateway_api():
    '''Install Traefik with Gateway API support (uses external traefik-values.yaml file)'''
    prev_dir = os.getcwd()
    try:
        print("\n" + "="*80)
        print(" Installing Traefik with Gateway API support")
        print("="*80 + "\n")
        
        # Check if Traefik is already installed
        ret = cmd("helm list -n traefik 2>/dev/null | grep traefik", exit_on_error=False)
        if ret == 0:
            print(" Traefik already installed")
            return
        
        # Change to traefik directory
        traefik_dir = os.path.join(SCRIPT_DIR, "k8s-deploy-node", "traefik")
        os.chdir(traefik_dir)
        
        # Create namespace
        print("Creating traefik namespace...")
        cmd("minikube kubectl -- create namespace traefik --dry-run=client -o yaml | minikube kubectl -- apply -f -")
        
        # Add Traefik helm repo
        print("Adding Traefik Helm repository...")
        cmd("helm repo add traefik https://traefik.github.io/charts")
        cmd("helm repo update")
        
        # Install Traefik using values file
        print("Installing Traefik via Helm (this may take a minute)...")
        cmd(f"helm install traefik traefik/traefik -n traefik -f traefik-values.yaml --timeout=5m")
        
        # Wait for pods to be ready
        print("Waiting for Traefik pods to be ready...")
        cmd("minikube kubectl -- wait --for=condition=ready pod -l app.kubernetes.io/name=traefik -n traefik --timeout=120s")
        
        print("\n" + " Traefik installed successfully")
        
        # Show GatewayClass
        print("\nAvailable GatewayClasses:")
        cmd("minikube kubectl -- get gatewayclass", exit_on_error=False)
        
        print("\n INFO: Dashboard available at: http://localhost:9000/dashboard/")
        print(" To access: kubectl port-forward -n traefik svc/traefik 9000:9000\n")
        
    finally:
        os.chdir(prev_dir)

def create_main_gateway(domain: str, use_tls: bool = True):
    '''Create the main Gateway resource for Gateway API'''
    print("\n" + "="*80)
    print(f" Creating main Gateway for domain: {domain}")
    print("="*80 + "\n")
    
    # Sanitize domain for secret name (replace dots with dashes)
    secret_name = domain.replace('.', '-') + '-tls'
    
    gateway_yaml = (
        "apiVersion: gateway.networking.k8s.io/v1\n"
        "kind: Gateway\n"
        "metadata:\n"
        "  name: main-gateway\n"
        "  namespace: default\n"
        "  annotations:\n"
        '    description: "Main Gateway for all services in the cluster"\n'
        "spec:\n"
        "  gatewayClassName: traefik\n"
        "  listeners:\n"
        "    - name: http\n"
        "      protocol: HTTP\n"
        "      port: 80\n"
        "      allowedRoutes:\n"
        "        namespaces:\n"
        "          from: All\n"
    )
    
    if use_tls:
        gateway_yaml += (
            "    - name: https\n"
            "      protocol: HTTPS\n"
            "      port: 443\n"
            "      tls:\n"
            "        mode: Terminate\n"
            "        certificateRefs:\n"
            "          - kind: Secret\n"
            f"            name: {secret_name}\n"
            "            namespace: default\n"
            "      allowedRoutes:\n"
            "        namespaces:\n"
            "          from: All\n"
        )
    
    # Write to temp file and apply
    gateway_file = "/tmp/main-gateway.yaml"
    with open(gateway_file, 'w') as f:
        f.write(gateway_yaml)
    
    print(f"Applying Gateway configuration...")
    cmd(f"minikube kubectl -- apply -f {gateway_file}")
    
    # Wait for gateway to be ready
    print("Waiting for Gateway to be ready...")
    time.sleep(5)
    ret = cmd("minikube kubectl -- wait --for=condition=Programmed gateway/main-gateway -n default --timeout=60s", exit_on_error=False)
    
    if ret == 0:
        print(" Gateway is ready and programmed")
    else:
        print(" Gateway created (may take a moment to become ready)")
    
    # Show gateway status
    print("\nGateway status:")
    cmd("minikube kubectl -- get gateway main-gateway -n default", exit_on_error=False)
    
    print("\n Gateway created successfully\n")


def setup_gateway_or_ingress(use_gateway_api: bool = True):
    '''Setup either Gateway API (Traefik) or traditional Ingress (nginx)'''
    if use_gateway_api:
        print("\n" + "="*80)
        print(" Setting up Gateway API with Traefik")
        print("="*80 + "\n")
        install_traefik_gateway_api()
    else:
        print("\n" + "="*80)
        print(" Setting up traditional Ingress (LEGACY)")
        print("="*80 + "\n")
        ensure_ingress_addon()

def update_ingress_host(ingress_file: str, domain: str):
    '''Update the host in the ingress YAML file'''
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
        r'(https?://)[a-zA-Z0-9.-]+(/[a-zA-Z0-9-_/%.]*)', 
        rf'\1{domain}\2', 
        content
    )

    # Replace hostnames entries used by HTTPRoute resources.
    # Handle forms:
    #   hostnames: ["old.host"]
    #   hostnames:
    #     - "old.host"
    #   hostnames:
    #     - old.host
    # Replace them all with the configured domain in quoted form.
    # 1) Inline list form: hostnames: ["..."]
    content = re.sub(
        r'(hostnames:\s*\[\s*")([^"]+)("\s*\])',
        rf'\1{domain}\3',
        content
    )

    # 2) Block form with quoted hostname: hostnames:\n    - "..."
    content = re.sub(
        r'(hostnames:\s*\n\s*-\s*")([^"]+)(")',
        rf'\1{domain}\3',
        content
    )

    # 3) Block form with unquoted hostname: hostnames:\n    - old.host
    content = re.sub(
        r'(hostnames:\s*\n\s*-\s*)([A-Za-z0-9.-]+)',
        rf'\1"{domain}"',
        content
    )
    
    with open(ingress_file, 'w') as f:
        f.write(content)
    
    print(f" Updated {ingress_file} host to: {domain}")

def create_dataset_service_pvcs():
    '''Create PVCs for dataset-service by applying the canonical 0-pvcs.yaml only.'''
    print("  Applying dataset-service PVC manifest (0-pvcs.yaml) only...")

    pvcs_path = os.path.join(SCRIPT_DIR, "k8s-deploy-node", "dataset-service", "0-pvcs.yaml")
    # Ensure namespace exists
    cmd("minikube kubectl -- create namespace dataset-service || true")
    if not os.path.exists(pvcs_path):
        print(f" Warning: PVC manifest not found: {pvcs_path}")
        return False

    # Read original file but do NOT modify it. Create a private copy containing
    # only PersistentVolumeClaim documents and apply that in the dataset-service namespace.
    try:
        with open(pvcs_path, 'r') as f:
            docs = list(yaml.safe_load_all(f))
    except Exception as e:
        print(f" Error reading {pvcs_path}: {e}")
        return False

    pvc_docs = [d for d in docs if isinstance(d, dict) and d.get('kind') == 'PersistentVolumeClaim']
    if not pvc_docs:
        print(f" No PersistentVolumeClaim documents found in {pvcs_path}; nothing to apply")
        return True

    private_path = pvcs_path.rsplit('.', 1)[0] + '.private.yaml'
    try:
        with open(private_path, 'w') as pf:
            yaml.safe_dump_all(pvc_docs, pf, sort_keys=False)
        print(f" Created private PVC manifest: {private_path}")
    except Exception as e:
        print(f" Error writing private PVC manifest {private_path}: {e}")
        return False

    print(f" Applying PVC manifest: {private_path} to namespace dataset-service")
    cmd(f"minikube kubectl -- apply -f {private_path} -n dataset-service")
    cmd("minikube kubectl -- get pvc -n dataset-service")
    return True

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
        result_db = update_postgres_password(db_service_file, CONFIG.postgres.db_password)
        if result_db:
            # If result is a string, it's the edited file path
            db_service_file = result_db if isinstance(result_db, str) else db_service_file

        def update_dataset_service_deployment(docs):
            '''Update dataset-service deployment configuration'''
            import json
            updated = False
            for doc in docs:
                if doc.get("kind") == "Deployment":
                    containers = doc["spec"]["template"]["spec"]["containers"]
                    for container in containers:
                        for env in container.get("env", []):
                            if env.get("name") == "DATASET_SERVICE_CONFIG":
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
                                
                                # Update domain-dependent URLs (direct assignment with correct domain)
                                if "auth" in config:
                                    # Update auth.token_validation fields
                                    if "token_validation" in config["auth"]:
                                        config["auth"]["token_validation"]["token_issuer_public_keys_url"] = \
                                            f"https://{CONFIG.public_domain}/auth/realms/EUCAIM-NODE/protocol/openid-connect/certs"
                                        config["auth"]["token_validation"]["issuer"] = \
                                            f"https://{CONFIG.public_domain}/auth/realms/EUCAIM-NODE"
                                    
                                    # Update auth.client.auth_url
                                    if "client" in config["auth"]:
                                        config["auth"]["client"]["auth_url"] = \
                                            f"https://{CONFIG.public_domain}/auth/realms/EUCAIM-NODE/protocol/openid-connect/token"
                                    
                                    # Update auth.admin_api.url
                                    if "admin_api" in config["auth"]:
                                        config["auth"]["admin_api"]["url"] = \
                                            f"https://{CONFIG.public_domain}/auth/admin/realms/EUCAIM-NODE/"
                                
                                # Update self URLs
                                if "self" in config:
                                    config["self"]["root_url"] = f"https://{CONFIG.public_domain}/dataset-service"
                                    config["self"]["dataset_link_format"] = \
                                        f"https://{CONFIG.public_domain}/dataset-service/datasets/%s/details"
                                
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
            return updated
        
        result = update_yaml_config(deployment_file, update_dataset_service_deployment)
        if result:
            # If result is a string, it's the edited file path
            deployment_file = result if isinstance(result, str) else deployment_file
            print(f"Injected password and random tokens into DATASET_SERVICE_CONFIG of {deployment_file}")
        else:
            print("Warning: Could not find DATASET_SERVICE_CONFIG to update password and tokens.")
        
        # Apply resources
        cmd(f"minikube kubectl -- apply -f {db_service_file} -n dataset-service")
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
        
        # Check if we should use Gateway API or traditional Ingress
        use_gateway_api = getattr(CONFIG, 'use_gateway_api', True)
        
        if use_gateway_api:
            # NEW: Gateway API with HTTPRoute - apply from YAML files
            print(f"\n Configuring HTTPRoute for dataset-service (Gateway API)...")
            
            # Apply HTTPRoute with Middleware (all in one file)
            httproute_file = "3-httproute.yaml"
            update_ingress_host(httproute_file, CONFIG.public_domain)
            cmd(f"minikube kubectl -- apply -f {httproute_file}")
            print(f" HTTPRoute applied for dataset-service at https://{CONFIG.public_domain}/dataset-service")
            
            # Apply redirect HTTPRoute if needed
            redirect_httproute_file = "4-httproute-redirect.yaml"
            if os.path.exists(redirect_httproute_file):
                update_ingress_host(redirect_httproute_file, CONFIG.public_domain)
                cmd(f"minikube kubectl -- apply -f {redirect_httproute_file}")
                print(" Redirect HTTPRoute applied")
            
        else:
            # LEGACY: Traditional Ingress (commented but functional)
            print(f"\n Configuring ingress for dataset-service (LEGACY)...")
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

def install_dataset_explorer(CONFIG):
    '''Build and deploy dataset-explorer UI to be served by dataset-service'''
    print(f"\n{'='*80}")
    print(" Installing Dataset Explorer UI")
    print(f"{'='*80}\n")
    
    dataset_explorer_dir = os.path.join(SCRIPT_DIR, "dataset-explorer")
    
    if not os.path.exists(dataset_explorer_dir):
        print(f"Warning: dataset-explorer directory not found at {dataset_explorer_dir}")
        return
    
    prev_dir = os.getcwd()
    try:
        os.chdir(dataset_explorer_dir)
        
        # Update config.json with correct domain
        print("Configuring dataset-explorer with domain settings...")
        config_file = "config-mini-node.json"
        
        if os.path.exists(config_file):
            import json
            with open(config_file, 'r') as f:
                config_data = json.load(f)
            
            # Update URLs with configured domain
            domain = CONFIG.public_domain
            config_data['datasetServiceURL'] = f"https://{domain}/dataset-service"
            config_data['keycloakURL'] = f"https://{domain}/auth"
            config_data['keycloakRealm'] = "EUCAIM-NODE"
            
            # Write updated config
            with open('public/config.json', 'w') as f:
                json.dump(config_data, f, indent=2)
            print(f" Updated config.json with domain: {domain}")
        
        # Build the React application using Docker
        print("\nBuilding dataset-explorer React application with Docker...")
        print(" This may take a few minutes...")
        
        # Use Docker to build without installing npm locally
        build_result = cmd(
            'docker run --rm -v $(pwd):/home/node/app node:24.9-slim '
            'bash -c "cd /home/node/app && npm install && npm run build"',
            exit_on_error=False
        )
        
        if build_result != 0:
            print("  Error: Build failed")
            print("  Make sure Docker is installed and running")
            return
        
        print(" Build completed successfully")
        
        # Prepare and copy files to minikube
        print("\nCopying files to minikube...")
        
        # Create UI directory in dataset-service if it doesn't exist
        cmd("minikube ssh -- 'sudo mkdir -p /var/hostpath-provisioner/dataset-service/ui'")
        cmd("minikube ssh -- 'sudo chmod 777 /var/hostpath-provisioner/dataset-service/ui'")
        
        # Create tarball and copy
        cmd("sudo tar -czf /tmp/dataset-explorer-build.tar.gz -C build .")
        cmd("minikube cp /tmp/dataset-explorer-build.tar.gz minikube:/tmp/")
        cmd("minikube ssh -- 'sudo rm -rf /var/hostpath-provisioner/dataset-service/ui/*'")
        cmd("minikube ssh -- 'sudo tar -xzf /tmp/dataset-explorer-build.tar.gz -C /var/hostpath-provisioner/dataset-service/ui/'")
        cmd("rm -f /tmp/dataset-explorer-build.tar.gz")
        
        print(" Files copied successfully")
        
        # Restart dataset-service pod to pick up new files
        print("\nRestarting dataset-service to load new UI files...")
        cmd("minikube kubectl -- delete pod -l app=dataset-service-backend -n dataset-service")
        cmd("sleep 10")
        cmd("minikube kubectl -- wait --for=condition=ready pod -l app=dataset-service-backend -n dataset-service --timeout=120s || true")
        
        print(f"\n Dataset Explorer installed successfully!")
        print(f" Access at: https://{CONFIG.public_domain}/")
        
    finally:
        os.chdir(prev_dir)

def install_guacamole(CONFIG, guacamole_user_creator_password: str, auth_client_secrets):
    prev_dir = os.getcwd()
    try:
        guacamole = os.path.join(SCRIPT_DIR, "k8s-deploy-node", "guacamole")
        os.chdir(guacamole)
        # Ensure namespace and PVC exist
        cmd("minikube kubectl -- create namespace guacamole || true")
        # Adaptar el PVC de guacamole-postgresql para usar storageClassName: 'standard' siempre
        pvc_path = os.path.join(os.getcwd(), "postgresql-pvc.yaml")
        with open(pvc_path, 'r') as f:
            pvc_docs = list(yaml.safe_load_all(f))
        updated = False
        # Eliminar cualquier PersistentVolume y adaptar el PVC a storageClassName: 'standard'
        new_docs = []
        for doc in pvc_docs:
            if doc.get('kind') == 'PersistentVolumeClaim':
                doc['spec']['storageClassName'] = 'standard'
                new_docs.append(doc)
                updated = True
            # Ignorar cualquier PersistentVolume
        if updated:
            with open(pvc_path, 'w') as f:
                yaml.safe_dump_all(new_docs, f, sort_keys=False)
            print("Adapted postgresql-pvc.yaml for Guacamole: solo PVC y storageClassName: standard")
        cmd("minikube kubectl -- apply -f postgresql-pvc.yaml -n guacamole")

        # 1. Update PostgreSQL values (write both public and private values)
        values_file = "postgresql-values.yaml"
        private_values_file = "postgresql-values.private.yaml"
        with open(values_file, 'r') as f:
            data = yaml.safe_load(f) or {}

        data.setdefault('auth', {})
        data['auth'].update({
            'adminPassword': CONFIG.guacamole.adminPassword,
            'username': CONFIG.guacamole.username,
            'password': CONFIG.guacamole.password,
            'database': CONFIG.guacamole.database,
        })

        # Note: image tag/repository are managed directly in the values files

        # Do not modify image fields here; image configuration stays in the values files

        # Write both public and private values files so the installer can use the private one
        with open(values_file, 'w') as f:
            yaml.dump(data, f, default_flow_style=False, sort_keys=False, indent=2)
        with open(private_values_file, 'w') as f:
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
            'adminLocalPassword': CONFIG.guacamole.adminPassword
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
        use_gateway_api = getattr(CONFIG, 'use_gateway_api', True)
        
        if 'ingress' in data_pg:
            if use_gateway_api:
                # Disable Helm-managed Ingress when using Gateway API
                data_pg['ingress']['enabled'] = False
                print(" Disabled Helm-managed Ingress (will use HTTPRoute instead)")
            else:
                # LEGACY: Update Ingress configuration
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

        # Write a private guacamole values file without altering image fields
        guaca_private_file = "guacamole-values.private.yaml"
        with open(guaca_private_file, 'w') as f:
            yaml.dump(data_pg, f, default_flow_style=False, sort_keys=False, indent=2)

        private_post_values = "postgresql-values.private.yaml"
        
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

        # Install or upgrade Guacamole using helm upgrade --install
        print(f"\n Installing/upgrading Guacamole...")
        guac_install = cmd(
            f"helm upgrade --install guacamole ./{chart_dir} \
             --namespace guacamole -f guacamole-values.yaml",
            exit_on_error=False
        )
        
        if guac_install != 0:
            print(f"  Warning: Guacamole installation/upgrade failed")
            print(f"   Checking if Guacamole is already running...")
            existing_guac = cmd("minikube kubectl -- get pods -n guacamole -l app.kubernetes.io/name=guacamole 2>/dev/null", exit_on_error=False)
            if existing_guac == 0:
                print(f" Guacamole is already running, continuing...")
            else:
                print(f"  Guacamole not found, skipping user creation...")
                return
        else:
            print(f" Guacamole installed/upgraded successfully")
        
        # Configure routing (HTTPRoute or Ingress)
        if use_gateway_api:
            # NEW: Apply HTTPRoute for Guacamole
            print(f"\n Configuring HTTPRoute for Guacamole...")
            httproute_file = "guacamole-httproute.yaml"
            if os.path.exists(httproute_file):
                update_ingress_host(httproute_file, CONFIG.public_domain)
                cmd(f"minikube kubectl -- apply -f {httproute_file}")
                print(f" HTTPRoute applied for Guacamole at https://{CONFIG.public_domain}/guacamole")
            else:
                print(f"  Warning: {httproute_file} not found")
        
        # Create guacamole-admin user in Keycloak
        try:
            print(f"\n Creating guacamole-admin user in Keycloak...")
            auth_endpoint = f"https://{CONFIG.public_domain}/auth/realms/EUCAIM-NODE/protocol/openid-connect/token"
            auth_client = AuthClient(auth_endpoint, 'dataset-service', login_as_service_account=True, 
                                   client_secret=auth_client_secrets.CLIENT_DATASET_SERVICE_SECRET)
            keycloak_admin_api_endpoint = f"https://{CONFIG.public_domain}/auth/admin/realms/EUCAIM-NODE/"
            admin_client = KeycloakAdminAPIClient(auth_client, keycloak_admin_api_endpoint)
            
            admin_client.createSpecialUser(
                username="guacamole-admin", 
                email="guacamole-admin@test.com", 
                firstName="Guacamole",
                lastName="Admin"
            )
            print(f" guacamole-admin user created successfully in Keycloak")
        except Exception as e:
            print(f"  Warning: Could not create guacamole-admin user: {e}")
            print(f"   This user can be created manually via Keycloak admin UI if needed")
        
        # Install guacli (Guacamole CLI) if not already installed
        print(f"\n Installing guacli (Guacamole CLI tool)...")
        guacli_check = cmd("which guacli", exit_on_error=False)
        if guacli_check != 0:
            print(f"  Installing guacli via pip3...")
            # Use --break-system-packages for modern Python environments (Debian 12+, Ubuntu 23.04+)
            install_result = cmd("pip3 install --break-system-packages guacli", exit_on_error=False)
            
            # If that fails, try without the flag (for older systems)
            if install_result != 0:
                print(f"  Retrying without --break-system-packages flag...")
                install_result = cmd("pip3 install guacli", exit_on_error=False)
            
            # Verify installation
            if cmd("which guacli", exit_on_error=False) == 0:
                print(f" guacli installed successfully")
            else:
                print(f"  Warning: guacli installation failed")
                print(f"   The user management jobs may not work properly")
                return
        else:
            print(f" guacli already installed")
        
        # Determine guacli path (may be in ~/.local/bin for user installations)
        guacli_path = "guacli"
        if cmd("which guacli", exit_on_error=False) != 0:
            # Try common user installation path
            home_dir = os.path.expanduser("~")
            local_bin_path = os.path.join(home_dir, ".local", "bin", "guacli")
            if os.path.exists(local_bin_path):
                guacli_path = local_bin_path
                print(f" Using guacli from: {guacli_path}")
        
        # Wait for Guacamole to be ready
        print(f"\n Waiting for Guacamole to be ready...")
        cmd("sleep 15")
        
        # Create admin group and eucaim-user-creator user using guacli
        print(f" Creating Guacamole admin group and user...")
        cmd(f"{guacli_path} --url \"http://guacamole-guacamole.guacamole.svc.cluster.local/guacamole/\" --user \"guacamole-admin\" --password \"{CONFIG.guacamole.adminPassword}\" \
            create admin-group cloud-services-and-security-management", exit_on_error=False)
        cmd(f"{guacli_path} --url \"http://guacamole-guacamole.guacamole.svc.cluster.local/guacamole/\" --user \"guacamole-admin\" --password \"{CONFIG.guacamole.adminPassword}\" \
            create admin-user eucaim-user-creator --new-user-password \"{guacamole_user_creator_password}\"", exit_on_error=False)

    finally:
        os.chdir(prev_dir)

## 
def configure_user_management_job_template(CONFIG, auth_client_secrets: Auth_client_secrets, guacamole_user_creator_password: str):
    '''Configure the user-management-job-template.yaml with correct domains and passwords'''
    print(f"\n{'='*80}")
    print(" Configuring User Management Job Template")
    print(f"{'='*80}\n")
    
    
    template_file = os.path.join(SCRIPT_DIR, "k8s-deploy-node", "dataset-service", 
                                  "on-event-jobs", "k8s-templates", "user-management-job-template.yaml")
    
    if not os.path.exists(template_file):
        print(f" Warning: Template file not found: {template_file}")
        return
    
    # Generate Guacamole admin password for eucaim-user-creator

    print(f" Generated Guacamole admin password for eucaim-user-creator")
    
    # Get K8S service account token (we'll create a service account for this)
    print(f" Creating service account for user management jobs...")
    cmd("minikube kubectl -- create namespace dataset-service || true")
    cmd("minikube kubectl -- create serviceaccount user-management-sa -n dataset-service || true")
    cmd("minikube kubectl -- create clusterrolebinding user-management-sa-binding --clusterrole=cluster-admin --serviceaccount=dataset-service:user-management-sa || true")
    
    # Get the service account token
    print(f" Retrieving service account token...")
    # Create a secret for the service account token
    secret_yaml = (
        "apiVersion: v1\n"
        "kind: Secret\n"
        "metadata:\n"
        "  name: user-management-sa-token\n"
        "  namespace: dataset-service\n"
        "  annotations:\n"
        "    kubernetes.io/service-account.name: user-management-sa\n"
        "type: kubernetes.io/service-account-token\n"
    )
    with open("/tmp/user-management-sa-secret.yaml", "w") as f:
        f.write(secret_yaml)
    
    cmd("minikube kubectl -- apply -f /tmp/user-management-sa-secret.yaml")
    time.sleep(2)  # Wait for token generation
    
    k8s_token = cmd_output("minikube kubectl -- get secret user-management-sa-token -n dataset-service -o jsonpath='{.data.token}' | base64 -d").strip()
    
    if not k8s_token:
        print(f"  Warning: Could not get service account token, using placeholder")
        k8s_token = "UPDATE_ME_WITH_SERVICE_ACCOUNT_TOKEN"
    else:
        print(f" Service account token retrieved successfully")
    
    # Read the template file
    with open(template_file, 'r') as f:
        content = f.read()
    
    # Replace all placeholders
    replacements = {
        'https://mininode.imaging.i3m.upv.es:6443': f'https://{CONFIG.public_domain}:6443',
        'https://eucaim-node.i3m.upv.es/auth/realms/EUCAIM-NODE/protocol/openid-connect/token': 
            f'https://{CONFIG.public_domain}/auth/realms/EUCAIM-NODE/protocol/openid-connect/token',
        'https://eucaim-node.i3m.upv.es/auth/admin/realms/EUCAIM-NODE/': 
            f'https://{CONFIG.public_domain}/auth/admin/realms/EUCAIM-NODE/',
        'value: "eucaim-node.i3m.upv.es"': f'value: "{CONFIG.public_domain}"',
    }
    
    for old, new in replacements.items():
        content = content.replace(old, new)
    
    # Replace passwords (match exact lines to avoid partial replacements)
    import re
    
# K8S_TOKEN LA SEGUNDA VEZ YA NO LO VA A REEMPLAZAR
    content = re.sub(
        r'(- name: K8S_TOKEN\s+value: )"XXXXXXXXXXXXXXXX"',
        rf'\1"{k8s_token}"',
        content
    )
    
    # KEYCLOAK_CLIENT_SECRET
    content = re.sub(
        r'(- name: KEYCLOAK_CLIENT_SECRET\s+value: )"XXXXXXXXXXXXXXXX"',
        rf'\1"{auth_client_secrets.CLIENT_DATASET_SERVICE_SECRET}"',
        content
    )
    
    # GUACAMOLE_ADMIN_PASSWORD
    content = re.sub(
        r'(- name: GUACAMOLE_ADMIN_PASSWORD\s+value: )"XXXXXXXXXXXXXXXX"',
        rf'\1"{guacamole_user_creator_password}"',
        content
    )
    
    # Write back the updated content
    with open(template_file, 'w') as f:
        f.write(content)
    
    print(f" User management job template updated successfully")
    
    # Create the required directories on the host
    print(f"\n Creating required directories...")
    cmd("sudo mkdir -p /home/ubuntu/minikube-data/data/homes/users")
    cmd("sudo mkdir -p /home/ubuntu/minikube-data/data/homes/shared-folder")
    cmd("sudo chmod -R 777 /home/ubuntu/minikube-data/data/homes")
    print(f" Directories created: /home/ubuntu/minikube-data/data/homes/")
    

    # Save the password to a file for reference
    password_file = os.path.join(SCRIPT_DIR, "guacamole-eucaim-user-creator-password.txt")
    with open(password_file, 'w') as f:
        f.write(f"Username: eucaim-user-creator\n")
        f.write(f"Password: {guacamole_user_creator_password}\n")
    print(f"\n Guacamole user credentials saved to: {password_file}")

def install_dsws_operator(CONFIG, auth_client_secrets: Auth_client_secrets):
    '''Install DSWS Operator for managing dataset workspaces'''
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
    '''Install Kubeapps dashboard for managing Helm charts'''
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

        # Create a private copy of values to avoid editing the original file
        base_path = values_file.rsplit('.', 1)[0]
        private_values_file = base_path + '.private.yaml'
        
        # Update PostgreSQL password if it's a placeholder
        if 'postgresql' in data and 'auth' in data['postgresql']:
            if data['postgresql']['auth'].get('password') == 'XXXXXXXXXXXXX':
                pg_password = generate_random_password(16)
                data['postgresql']['auth']['password'] = pg_password
                print(f" Generated PostgreSQL password")
        
        # Update ingress hostname
        use_gateway_api = getattr(CONFIG, 'use_gateway_api', True)
        
        if 'ingress' in data:
            if use_gateway_api:
                # Disable Helm-managed Ingress when using Gateway API
                data['ingress']['enabled'] = False
                print(" Disabled Helm-managed Ingress (will use HTTPRoute instead)")
            else:
                # LEGACY: Update Ingress configuration
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
        # Write updates to a private values file so the original remains unchanged
        with open(private_values_file, 'w') as f:
            yaml.dump(data, f, default_flow_style=False, sort_keys=False, indent=2)
        
        print(f"\n Deploying Kubeapps with Helm...")
        print(f"   This will install or upgrade Kubeapps with the latest values.yaml configuration")
        
        # Use helm upgrade --install to install or update Kubeapps
        # --install: Install if not already installed
        # This ensures that any changes in values.yaml are always applied
        cmd("helm upgrade --install kubeapps oci://registry-1.docker.io/bitnamicharts/kubeapps "
            "--version 17.1.1 --namespace kubeapps -f {}".format(private_values_file))
        
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
        
        if use_gateway_api:
            # NEW: Apply HTTPRoute for Kubeapps
            print(f"\n Configuring HTTPRoute for Kubeapps...")
            httproute_file = "kubeapps-httproute.yaml"
            if os.path.exists(httproute_file):
                update_ingress_host(httproute_file, CONFIG.public_domain)
                cmd(f"minikube kubectl -- apply -f {httproute_file}")
                print(f" HTTPRoute applied for Kubeapps at https://{CONFIG.public_domain}/apps")
            else:
                print(f"  Warning: {httproute_file} not found")
        
        print(f"\n Kubeapps installed successfully!")
        print(f" Access at: https://{CONFIG.public_domain}/apps/")
        print(f"\n  Note: Kubeapps requires Kubernetes API server to be configured with OIDC.")
        print(f"   See k8s-deploy-node/kubeapps/README.md for details on configuring kube-apiserver.")
        
    finally:
        os.chdir(prev_dir)

def install_cert_manager(CONFIG):
    '''Install cert-manager for automatic TLS certificate management'''
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
        # Pull with docker
        pull_result = cmd(f"docker pull {image}", exit_on_error=False)
        if pull_result == 0:
            # Load into minikube
            load_result = cmd(f"minikube image load {image}", exit_on_error=False)
            if load_result != 0:
                print(f"  Failed to load {image} into minikube")
                images_loaded = False
                break
        else:
            print(f"  Failed to pull {image} with Docker")
            images_loaded = False
            break
    
    if images_loaded:
        print("Images loaded, installing cert-manager v1.18.2...")
        # Now install cert-manager - images should be available locally in minikube
        yaml_install = cmd("minikube kubectl -- apply -f https://github.com/cert-manager/cert-manager/releases/download/v1.18.2/cert-manager.yaml", exit_on_error=False)
        
        if yaml_install == 0:
            # Wait for pods to be ready with 100s timeout
            ret1 = cmd("minikube kubectl -- wait --for=condition=ready pod -l app.kubernetes.io/name=cert-manager -n cert-manager --timeout=100s", exit_on_error=False)
            ret2 = cmd("minikube kubectl -- wait --for=condition=ready pod -l app.kubernetes.io/name=cainjector -n cert-manager --timeout=100s", exit_on_error=False)
            ret3 = cmd("minikube kubectl -- wait --for=condition=ready pod -l app.kubernetes.io/name=webhook -n cert-manager --timeout=100s", exit_on_error=False)
            
            if ret1 == 0 and ret2 == 0 and ret3 == 0:
                cert_manager_success = True
    
    # Method 2 (fallback): Try direct installation in case pre-loading wasn't needed
    if not cert_manager_success:
        print("Trying direct installation as fallback...")
        yaml_install = cmd("minikube kubectl -- apply -f https://github.com/cert-manager/cert-manager/releases/download/v1.18.2/cert-manager.yaml", exit_on_error=False)
        
        if yaml_install == 0:
            ret1 = cmd("minikube kubectl -- wait --for=condition=ready pod -l app.kubernetes.io/name=cert-manager -n cert-manager --timeout=100s", exit_on_error=False)
            ret2 = cmd("minikube kubectl -- wait --for=condition=ready pod -l app.kubernetes.io/name=cainjector -n cert-manager --timeout=100s", exit_on_error=False)
            ret3 = cmd("minikube kubectl -- wait --for=condition=ready pod -l app.kubernetes.io/name=webhook -n cert-manager --timeout=100s", exit_on_error=False)
            
            if ret1 == 0 and ret2 == 0 and ret3 == 0:
                cert_manager_success = True
    
    # Final verification
    if cert_manager_success:
        cmd("minikube kubectl -- get pods -n cert-manager", exit_on_error=False)
        create_letsencrypt_issuer(CONFIG)
        print(" cert-manager installation completed successfully")
        return True
    
    # If all methods failed
    print("\n" + "="*80)
    print("ERROR: Unable to install functional cert-manager")
    print("Even with pre-loaded images, installation failed.")
    print("="*80)
    
    print("Installation cannot continue without functional cert-manager.")
    exit(1)


def create_letsencrypt_issuer(CONFIG):
    '''Create Let's Encrypt ClusterIssuer for automatic certificate generation'''
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
    print(" Let's Encrypt ClusterIssuer created successfully")


def install_api_gateway(CONFIG):
    '''Install the main API Gateway with TLS certificate from YAML file'''
    print("\n" + "="*80)
    print(" Installing API Gateway")
    print("="*80 + "\n")
    
    gateway_file = os.path.join(SCRIPT_DIR, "k8s-deploy-node", "API-Gateway", "main-gateway.yaml")
    
    if not os.path.exists(gateway_file):
        print(f"Warning: Gateway manifest not found at {gateway_file}")
        return False
    
    # Update hostname in the Gateway manifest
    def update_gateway_hostname(docs):
        updated = False
        for doc in docs:
            if doc.get("kind") == "Gateway":
                for listener in doc["spec"].get("listeners", []):
                    if "hostname" in listener:
                        listener["hostname"] = CONFIG.public_domain
                        updated = True
            elif doc.get("kind") == "Certificate":
                if "dnsNames" in doc["spec"]:
                    doc["spec"]["dnsNames"] = [CONFIG.public_domain]
                    updated = True
        return updated
    
    # Update the manifest with the correct domain
    result_gateway = update_yaml_config(gateway_file, update_gateway_hostname)
    if result_gateway:
        # If result is a string, it's the edited file path
        gateway_file = result_gateway if isinstance(result_gateway, str) else gateway_file
    print(f" Updated Gateway hostname to: {CONFIG.public_domain}")
    
    # Apply the Gateway manifest
    result = cmd(f"minikube kubectl -- apply -f {gateway_file}", exit_on_error=False)
    
    if result == 0:
        print(" API Gateway manifest applied successfully")
        
        # Wait a moment for the certificate to be requested
        print("Waiting for certificate to be issued...")
        cmd("sleep 5")
        
        # Check certificate status
        cert_check = cmd("minikube kubectl -- get certificate mininode-tls-cert -n default -o jsonpath='{.status.conditions[?(@.type==\"Ready\")].status}' 2>/dev/null", exit_on_error=False)
        
        if cert_check == 0:
            print(" Certificate issued successfully")
        
        # Show Gateway status
        print("\nGateway status:")
        cmd("minikube kubectl -- get gateway -n default", exit_on_error=False)
        print("\nCertificate status:")
        cmd("minikube kubectl -- get certificate -n default", exit_on_error=False)
        
        print(f"\n API Gateway installed successfully!")
        return True
    else:
        print(f" Failed to apply Gateway manifest")
        return False


def create_iptables_rules_script():
    '''Create and apply iptables rules for external access to minikube ingress'''
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
    script_content = (
        "#!/bin/bash\n"
        "# Mininode iptables rules for external access to minikube ingress\n"
        "# Auto-generated by install.py\n"
        "# IMPORTANT: Only using interface-specific rules to preserve minikube connectivity\n"
        f"# External interface: {external_interface}\n"
        f"# Minikube IP: {minikube_ip}\n"
        "\n"
        'echo "Setting up interface-specific NAT rules for external access..."\n'
        f'echo "External interface: {external_interface}"\n'
        "\n"
        "# Interface-specific NAT rules ONLY (preserves minikube's own connectivity)\n"
        f"if ! iptables -t nat -C PREROUTING -i {external_interface} -p tcp --dport 80 -j DNAT --to-destination {minikube_ip}:{http_nodeport} 2>/dev/null; then\n"
        f'    echo "Adding interface-specific NAT rule for HTTP on {external_interface}"\n'
        f"    iptables -t nat -A PREROUTING -i {external_interface} -p tcp --dport 80 -j DNAT --to-destination {minikube_ip}:{http_nodeport}\n"
        "else\n"
        f'    echo "Interface-specific NAT rule for HTTP on {external_interface} already exists, skipping"\n'
        "fi\n"
        "\n"
        f"if ! iptables -t nat -C PREROUTING -i {external_interface} -p tcp --dport 443 -j DNAT --to-destination {minikube_ip}:{https_nodeport} 2>/dev/null; then\n"
        f'    echo "Adding interface-specific NAT rule for HTTPS on {external_interface}"\n'
        f"    iptables -t nat -A PREROUTING -i {external_interface} -p tcp --dport 443 -j DNAT --to-destination {minikube_ip}:{https_nodeport}\n"
        "else\n"
        f'    echo "Interface-specific NAT rule for HTTPS on {external_interface} already exists, skipping"\n'
        "fi\n"
        "\n"
        "# FORWARD rules to accept forwarded packets\n"
        'echo "Setting up FORWARD rules..."\n'
        "\n"
        f"if ! iptables -C FORWARD -p tcp -d {minikube_ip} --dport {http_nodeport} -j ACCEPT 2>/dev/null; then\n"
        '    echo "Adding FORWARD rule for HTTP traffic"\n'
        f"    iptables -I FORWARD 1 -p tcp -d {minikube_ip} --dport {http_nodeport} -j ACCEPT\n"
        "else\n"
        '    echo "FORWARD rule for HTTP traffic already exists, skipping"\n'
        "fi\n"
        "\n"
        f"if ! iptables -C FORWARD -p tcp -d {minikube_ip} --dport {https_nodeport} -j ACCEPT 2>/dev/null; then\n"
        '    echo "Adding FORWARD rule for HTTPS traffic"\n'
        f"    iptables -I FORWARD 1 -p tcp -d {minikube_ip} --dport {https_nodeport} -j ACCEPT\n"
        "else\n"
        '    echo "FORWARD rule for HTTPS traffic already exists, skipping"\n'
        "fi\n"
        "\n"
        'echo "Mininode iptables rules configuration completed"\n'
        f'echo "External interface: {external_interface}"\n'
        f'echo "HTTP traffic (port 80) -> {minikube_ip}:{http_nodeport}"\n'
        f'echo "HTTPS traffic (port 443) -> {minikube_ip}:{https_nodeport}"\n'
        'echo ""\n'
        f'echo "NOTE: These rules only affect traffic coming from {external_interface}"\n'
        'echo "Minikube\'s own connectivity to external services is preserved."\n'
        'echo ""\n'
        'echo "You can verify the rules with:"\n'
        'echo "  sudo iptables -t nat -L PREROUTING -n --line-numbers"\n'
        'echo "  sudo iptables -L FORWARD -n --line-numbers"\n'
    )
    
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
    
    # If not running as root, execute the script with sudo to apply rules immediately
    if os.geteuid() != 0:
        print("\nApplying iptables rules with sudo...")
        try:
            result = subprocess.run(
                ["sudo", script_path],
                capture_output=True, text=True, check=False
            )
            if result.returncode == 0:
                print("✅ iptables rules applied successfully!")
                print(result.stdout)
            else:
                print("⚠️  Warning: Could not apply iptables rules automatically")
                print(result.stderr)
                print(f"\nPlease run manually: sudo {script_path}")
        except Exception as e:
            print(f"⚠️  Warning: Could not apply iptables rules: {e}")
            print(f"Please run manually: sudo {script_path}")
        
        print("\nTo make rules persistent across reboots:")
        print(f"sudo cp {script_path} /etc/network/if-pre-up.d/")
        print("sudo chmod +x /etc/network/if-pre-up.d/mininode-iptables-rules")
    else:
        print("Script will run automatically on network interface startup")
        print("You can also run it manually: sudo /etc/network/if-pre-up.d/mininode-iptables-rules")
        print(f"To verify rules: sudo iptables -t nat -L PREROUTING -n --line-numbers")

def create_main_gateway(domain: str, use_tls: bool = True):
    '''Create the main Gateway resource'''
    print(f"Creating main Gateway for domain: {domain}...")
    
    gateway_yaml = (
        "\n"
        "apiVersion: gateway.networking.k8s.io/v1\n"
        "kind: Gateway\n"
        "metadata:\n"
        "  name: main-gateway\n"
        "  namespace: default\n"
        "spec:\n"
        "  gatewayClassName: traefik\n"
        "  listeners:\n"
        "    - name: http\n"
        "      protocol: HTTP\n"
        "      port: 80\n"
        "      allowedRoutes:\n"
        "        namespaces:\n"
        "          from: All\n"
    )
    
    if use_tls:
        gateway_yaml += (
            "\n"
            "    - name: https\n"
            "      protocol: HTTPS\n"
            "      port: 443\n"
            "      tls:\n"
            "        mode: Terminate\n"
            "        certificateRefs:\n"
            "          - kind: Secret\n"
            f"            name: {domain.replace('.', '-')}-tls\n"
            "            namespace: default\n"
            "      allowedRoutes:\n"
            "        namespaces:\n"
            "          from: All\n"
        )
    
    # Write to temp file and apply
    gateway_file = "/tmp/main-gateway.yaml"
    with open(gateway_file, 'w') as f:
        f.write(gateway_yaml)
    
    cmd(f"minikube kubectl -- apply -f {gateway_file}")
    
    # Wait for gateway to be ready
    print("Waiting for Gateway to be ready...")
    time.sleep(5)
    cmd("minikube kubectl -- wait --for=condition=Programmed gateway/main-gateway -n default --timeout=60s", exit_on_error=False)
    
    print(" Gateway created successfully")

# def convert_ingress_to_httproute(ingress_file: str, domain: str):
#     '''Convert Ingress YAML to HTTPRoute YAML'''
#     if not os.path.exists(ingress_file):
#         print(f"  Ingress file {ingress_file} not found, skipping conversion...")
#         return None
    
#     # Load the ingress
#     with open(ingress_file, 'r') as f:
#         ingress = yaml.safe_load(f)
    
#     if ingress.get("kind") != "Ingress":
#         print(f"  File {ingress_file} is not an Ingress, skipping...")
#         return None
    
#     # Extract namespace
#     namespace = ingress["metadata"].get("namespace", "default")
#     name = ingress["metadata"]["name"]
#     annotations = ingress["metadata"].get("annotations", {})
    
#     # Start building HTTPRoute
#     httproute = {
#         "apiVersion": "gateway.networking.k8s.io/v1",
#         "kind": "HTTPRoute",
#         "metadata": {
#             "name": f"{name}-route",
#             "namespace": namespace,
#             "annotations": {
#                 "description": f"Migrated from Ingress: {name}"
#             }
#         },
#         "spec": {
#             "parentRefs": [
#                 {
#                     "name": "main-gateway",
#                     "namespace": "default",
#                     "sectionName": "https" if ingress["spec"].get("tls") else "http"
#                 }
#             ],
#             "hostnames": [domain],
#             "rules": []
#         }
#     }
    
    # # Convert each path to HTTPRoute rule
    # for rule in ingress["spec"].get("rules", []):
    #     for path_rule in rule.get("http", {}).get("paths", []):
    #         path = path_rule["path"]
    #         backend = path_rule["backend"]["service"]
            
    #         route_rule = {
    #             "matches": [
    #                 {
    #                     "path": {
    #                         "type": "PathPrefix",
    #                         "value": path
    #                     }
    #                 }
    #             ],
    #             "backendRefs": [
    #                 {
    #                     "name": backend["name"],
    #                     "port": backend["port"]["number"]
    #                 }
    #             ]
    #         }
            
    #         # Handle rewrite-target annotation
    #         rewrite_target = annotations.get("nginx.ingress.kubernetes.io/rewrite-target")
    #         if rewrite_target:
    #             route_rule["filters"].append({
    #                 "type": "URLRewrite",
    #                 "urlRewrite": {
    #                     "path": {
    #                         "type": "ReplacePrefixMatch",
    #                         "replacePrefixMatch": rewrite_target
    #                     }
    #                 }
    #             })
            
    #         # Handle CORS
    #         enable_cors = annotations.get("nginx.ingress.kubernetes.io/enable-cors")
    #         if enable_cors == "true":
    #             route_rule["filters"].append({
    #                 "type": "ResponseHeaderModifier",
    #                 "responseHeaderModifier": {
    #                     "add": [
    #                         {"name": "Access-Control-Allow-Origin", "value": "*"},
    #                         {"name": "Access-Control-Allow-Methods", "value": "GET, POST, PUT, DELETE, OPTIONS"},
    #                         {"name": "Access-Control-Allow-Headers", "value": "Authorization, Content-Type"}
    #                     ]
    #                 }
    #             })
            
    #         httproute["spec"]["rules"].append(route_rule)
    
    # return httproute


## update dataset-service kid after Keycloak is running just in case the kid has changed
def update_dataset_service_kid_from_keycloak(CONFIG):
    '''
    Helper function to update the dataset-service kid after Keycloak is running
    Can be called manually or as part of post-installation steps
    '''
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
            # If file is in k8s-deploy-node directory, create private copy
            if 'k8s-deploy-node' in deployment_file:
                # Create new file path with .private.yaml suffix
                base_path = deployment_file.rsplit('.', 1)[0]  # Remove extension
                private_file_path = base_path + '.private.yaml'
                with open(private_file_path, 'w') as f:
                    yaml.safe_dump_all(docs, f, sort_keys=False)
                print(f"Created private copy: {private_file_path}")
                deployment_file = private_file_path
            else:
                # For non-k8s-deploy-node files, edit in place
                with open(deployment_file, 'w') as f:
                    yaml.safe_dump_all(docs, f, sort_keys=False)
            
            # Apply the updated deployment
            prev_dir = os.getcwd()
            try:
                os.chdir(dataset_dir)
                cmd(f"minikube kubectl -- apply -f {os.path.basename(deployment_file)} -n dataset-service")
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
    '''Package and publish workstation Helm charts to dataset-service'''
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
                # Use absolute path since we changed directory
                packaged_charts_dir = os.path.join(os.getcwd(), "chart-catalogue")
                if not os.path.isdir(packaged_charts_dir):
                    print(f"  Warning: chart-catalogue directory not found at {packaged_charts_dir}")
                    print(f"  Skipping charts deployment to dataset-service")
                    return
                
                # Copy to minikube dataset-service-data volume
                print(f"\n Copying charts to dataset-service...")

                # Ensure output-files/charts directory exists in minikube
                cmd("minikube ssh -- 'sudo mkdir -p /var/hostpath-provisioner/dataset-service/dataset-service-data/output-files/charts'")
                cmd("minikube ssh -- 'sudo chmod -R 777 /var/hostpath-provisioner/dataset-service/dataset-service-data/output-files'")
                
                # Also create the directory on the host for helm repo index command
                host_charts_dir = "/home/ubuntu/minikube-data/dataset-service/dataset-service-data/output-files/charts"
                cmd(f"sudo mkdir -p {host_charts_dir}")
                cmd(f"sudo chmod -R 777 /home/ubuntu/minikube-data/dataset-service/dataset-service-data/output-files")
                
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
    '''
    Placeholder for installing the qpi service.
    '''
    # TODO: Implement the installation steps for qpi service
    pass

def install_jobman_service(CONFIG):
    '''
    Placeholder for installing the jobman service.
    '''
    # TODO: Implement the installation steps for jobman service
    print("Installing jobman service (not yet implemented)")

def apply_pod_priorities():
    '''Apply pod priority classes from extra-configurations'''
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
    
    # Check if Gateway API should be used (default: False for backward compatibility)
    use_gateway_api = getattr(CONFIG, 'use_gateway_api', False)
    
    if use_gateway_api:
        print(f" Using Gateway API with Traefik (NEW)")
    else:
        print(f" Using traditional Ingress (LEGACY)")
    
    # Setup Gateway API (Traefik) or traditional Ingress (nginx)
    setup_gateway_or_ingress(use_gateway_api=use_gateway_api)
    
    # If using Gateway API, create the main gateway after cert-manager is installed
    # (we'll do this after cert-manager installation below)
    
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
    
    # Create main Gateway if using Gateway API (after cert-manager is available)
    if use_gateway_api:
        if cert_manager_available:
            # Try to install from YAML file first (preferred method)
            gateway_installed = install_api_gateway(CONFIG)
            
            # Fallback to programmatic creation if YAML method fails
            if not gateway_installed:
                print("Falling back to programmatic Gateway creation...")
                use_tls = hasattr(CONFIG, 'letsencrypt') and CONFIG.letsencrypt.email
                create_main_gateway(domain=CONFIG.public_domain, use_tls=use_tls)
        else:
            print("Warning: Gateway API requested but cert-manager not available")
            print("  Gateway API requires cert-manager for TLS certificates")
        
        # Apply any pending HTTPRoutes now that CRDs are available
        print("\n" + "="*80)
        print(" Applying pending HTTPRoutes")
        print("="*80 + "\n")
        
        # Keycloak HTTPRoute
        keycloak_httproute = os.path.join(SCRIPT_DIR, "k8s-deploy-node", "keycloak", "dep4_httproute.yaml")
        if os.path.exists(keycloak_httproute):
            print("Applying Keycloak HTTPRoute...")
            cmd(f"minikube kubectl -- apply -f {keycloak_httproute}", exit_on_error=False)
    
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
        install_dataset_explorer(CONFIG)
    
    # Package workstation charts and publish to dataset-service (requires dataset-service to be installed)
    if flavor in ["micro", "standard"]:
        package_workstation_charts(CONFIG)
    
    # Guacamole is installed in micro and standard flavors
    if flavor in ["micro", "standard"]:
        install_guacamole(CONFIG, guacamole_user_creator_password, auth_client_secrets)
    
    # Configure user management job template (requires guacamole to be installed)
    if flavor in ["micro", "standard"]:
        configure_user_management_job_template(CONFIG, auth_client_secrets, guacamole_user_creator_password)
    
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

