#! /usr/bin/env python3

import argparse
import enum
import os
import logging
import shlex
import string
import random
import re
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
##WHY None?  Because CONFIG is set later after parsing args in main
CONFIG = None

# Deployment target: minikube (default) or real K8s cluster (set via --k8s flag)
KUBECTL = "minikube kubectl --"
USE_MINIKUBE = True

def _localize_minikube(command):
    '''Convert a minikube ssh/cp command to a local equivalent using CONFIG.host_path.
    Returns (localized_command, None) if convertible, or (None, manual_instruction) if complex.'''
    if CONFIG is None:
        return None, None
    host_path = getattr(CONFIG, 'host_path', '')
    if not host_path:
        return None, None

    strip = "minikube ssh -- '"
    if command.startswith(strip) and command.endswith("'"):
        inner = command[len(strip):-1]
        # Pattern: sudo mkdir -p <dirs>
        if inner.startswith("sudo mkdir -p "):
            dirs = inner[len("sudo mkdir -p "):]
            local = dirs.replace("/var/hostpath-provisioner", host_path)
            return f"sudo mkdir -p {local}", None
        # Pattern: sudo chmod -R 777 <dir>
        if inner.startswith("sudo chmod -R 777 "):
            path = inner[len("sudo chmod -R 777 "):]
            return f"sudo chmod -R 777 {path.replace('/var/hostpath-provisioner', host_path)}", None
        # Pattern: sudo tar -xzf <file> -C <dest>
        if inner.startswith("sudo tar"):
            return None, "Extract files manually to " + host_path + "/..."
        # Pattern: sudo rm <files>
        if inner.startswith("sudo rm "):
            files = inner[len("sudo rm "):]
            return f"sudo rm {files.replace('/var/hostpath-provisioner', host_path)}", None
        # Pattern: sudo bash <script>
        if inner.startswith("sudo bash ") or inner.startswith("sudo grep") or inner.startswith("grep"):
            return None, "Run this script manually on the cluster node"
        # Pattern: test -f <file>
        if inner.startswith("test -f "):
            filep = inner[len("test -f "):]
            return f"test -f {filep.replace('/var/hostpath-provisioner', host_path)}", None
        # Pattern: sudo apt-get
        if inner.startswith("sudo apt-get"):
            return None, "Install required packages on the cluster node manually"
        # Pattern: sudo systemctl
        if inner.startswith("sudo systemctl") or "systemctl" in inner:
            return None, "Run systemctl commands manually on the cluster node"
        # Pattern: bindfs / mount / umount
        if any(kw in inner for kw in ("bindfs", "mount.", "umount ", "/mnt/datalake", "/mnt/datasets", "/var/lib/orthanc")):
            return None, "Set up bind mounts manually on the cluster node"
        # Multi-command chains (&& / ;)
        if "&&" in inner or ";" in inner:
            return None, "Run these commands manually on the cluster node"

    # Pattern: minikube cp <src> minikube:<dest>
    cp_match = __import__('re').match(r"^minikube cp (\S+) minikube:(.+)$", command.strip())
    if cp_match:
        src = cp_match.group(1)
        dest = cp_match.group(2)
        local_dest = dest.replace("/var/hostpath-provisioner", host_path)
        return f"sudo cp {src} {local_dest}", None

    # Pattern: minikube image load
    if "minikube image load" in command:
        return None, "Load container images manually on each cluster node"

    return None, None


def _prepare_command(command):
    '''Substitute kubectl and localize/skip minikube-only commands based on deployment target.'''
    command = command.replace("minikube kubectl --", KUBECTL)
    if not USE_MINIKUBE and ("minikube ssh" in command or "minikube cp " in command
                             or "minikube addons" in command or "minikube image load" in command):
        localized, manual = _localize_minikube(command)
        if localized is not None:
            print(f"[LOCAL] {localized}")
            return localized
        print(f"[SKIP - K8s mode]: {command}")
        if manual:
            print(f"  >> ADMIN: {manual}")
        return None
    return command

def get_node_ip():
    '''Get the cluster node IP (minikube IP or first K8s node IP).'''
    if USE_MINIKUBE:
        try:
            result = subprocess.run(["minikube", "ip"], capture_output=True, text=True, check=True)
            return result.stdout.strip()
        except subprocess.CalledProcessError:
            return "192.168.49.2"
    else:
        try:
            result = subprocess.run(
                ["kubectl", "get", "nodes", "-o",
                 "jsonpath={.items[0].status.addresses[?(@.type=='InternalIP')].address}"],
                capture_output=True, text=True, check=True
            )
            return result.stdout.strip()
        except subprocess.CalledProcessError:
            return ""

def _normalize_storage_class_name(value: str) -> str:
    """Normalize jsonpath output to a single storage class name."""
    value = (value or "").strip().strip("'\"")
    if not value:
        return ""
    return value.split()[0]


def _storage_class_exists(sc_name: str) -> bool:
    """Return True when the given storage class exists in the cluster."""
    if not sc_name:
        return False
    # Use KUBECTL (not bare 'kubectl') so this works in minikube mode.
    # _prepare_command() only substitutes 'minikube kubectl --', not plain 'kubectl'.
    out = cmd_output(f"{KUBECTL} get storageclass {shlex.quote(sc_name)} -o name 2>/dev/null")
    return bool((out or "").strip())


def _detect_storage_class():
    """Detect a usable storage class from the cluster.

    Automation rule:
    - Minikube mode: use 'standard'.
    - --k8s mode: use 'managed-nfs-storage'.
    """
    preferred = "standard" if USE_MINIKUBE else "managed-nfs-storage"

    # Use KUBECTL (not bare 'kubectl') so this works in minikube mode.
    default_sc = _normalize_storage_class_name(cmd_output(
        f"{KUBECTL} get storageclass"
        " -o jsonpath='{.items[?(@.metadata.annotations.storageclass\\.kubernetes\\.io/is-default-class==\"true\")].metadata.name}'"
        " 2>/dev/null"
    ))
    first_sc = _normalize_storage_class_name(cmd_output(
        f"{KUBECTL} get storageclass -o jsonpath='{{.items[0].metadata.name}}' 2>/dev/null"
    ))

    if _storage_class_exists(preferred):
        return preferred
    if default_sc:
        print(f" Warning: preferred StorageClass '{preferred}' not found, using default '{default_sc}'")
        return default_sc
    if first_sc:
        print(f" Warning: preferred StorageClass '{preferred}' not found, using first available '{first_sc}'")
        return first_sc

    if preferred:
        print(f" Warning: no StorageClass detected, falling back to '{preferred}'")
        return preferred

    print(" Warning: no StorageClass detected; PVCs will rely on cluster defaults/static provisioning")
    return ""

## Function to execute shell commands
def cmd(command, exit_on_error=True):
    command = _prepare_command(command)
    if command is None:
        return 0
    print(command)
    ret = os.system(command)
    if exit_on_error and ret != 0: exit(1)
    return ret

## To get command output as string
def cmd_output(command):
    '''Execute command and return output as string'''
    command = _prepare_command(command)
    if command is None:
        return ""
    try:
        result = subprocess.run(command, shell=True, capture_output=True, text=True)
        return result.stdout
    except Exception as e:
        print(f"Error executing command: {e}")
        return ""


def generate_random_password(length: int = 16) -> str:
    alphabet = string.ascii_letters + string.digits
    return ''.join(random.choice(alphabet) for _ in range(length))

## Load or generate guacamole admin password (persisted across runs so reinstalls don't break the DB)
_guac_pw_file = os.path.join(SCRIPT_DIR, "guacamole-eucaim-user-creator-password.txt")
_guac_pw_loaded = None
if os.path.exists(_guac_pw_file):
    with open(_guac_pw_file) as _f:
        for _line in _f:
            if _line.startswith("Password:"):
                _guac_pw_loaded = _line.split(":", 1)[1].strip()
                break
if _guac_pw_loaded:
    guacamole_user_creator_password = _guac_pw_loaded
    print(f"Reusing existing guacamole-eucaim-user-creator password from {_guac_pw_file}")
else:
    guacamole_user_creator_password = generate_random_password(24)

## TLS secret backup path (persisted across minikube delete)
_TLS_BACKUP_FILE = os.path.join(SCRIPT_DIR, "mininode-tls-backup.yaml")

def get_tls_secret_name():
    return getattr(CONFIG, 'public_domain', 'mininode-tls')

_TLS_SECRET_NAME = "mininode-tls"
_TLS_CERT_BACKUP_FILE = os.path.join(SCRIPT_DIR, "mininode-tls-cert-backup.yaml")


def _tls_backup_exists() -> bool:
    return os.path.exists(_TLS_BACKUP_FILE) and os.path.getsize(_TLS_BACKUP_FILE) > 0

def save_tls_secret():
    secret_name = get_tls_secret_name()
    # Wait for the secret to be created by cert-manager (up to 120s)
    for attempt in range(12):
        for ns in ("keycloak", "default", "cert-manager"):
            exists = os.system(f"{KUBECTL} get secret {secret_name} -n {ns} -o name > /dev/null 2>&1") >> 8
            if exists == 0:
                break
        else:
            if attempt < 11:
                time.sleep(10)
                continue
            print(f" TLS secret '{secret_name}' not found after 120s, skipping backup")
            return
        break
    print(f" Found '{secret_name}' in namespace {ns}, saving...")
    saved = os.system(f"{KUBECTL} get secret {secret_name} -n {ns} -o yaml > {_TLS_BACKUP_FILE}") >> 8
    if saved == 0 and os.path.getsize(_TLS_BACKUP_FILE) > 0:
        print(f" TLS secret saved to {_TLS_BACKUP_FILE}")
    else:
        print(f" Failed to save TLS secret")
    # Also backup the Certificate resource (so cert-manager doesn't re-issue)
    cert_ns = ns
    cert_exists = os.system(f"{KUBECTL} get certificate {secret_name} -n {cert_ns} -o name > /dev/null 2>&1") >> 8
    if cert_exists == 0:
        os.system(f"{KUBECTL} get certificate {secret_name} -n {cert_ns} -o yaml > {_TLS_CERT_BACKUP_FILE}")
        print(f" TLS Certificate backed up to {_TLS_CERT_BACKUP_FILE}")
    else:
        print(f" Certificate '{secret_name}' not found, skipping backup")

def restore_tls_secret():
    if not os.path.exists(_TLS_BACKUP_FILE) or os.path.getsize(_TLS_BACKUP_FILE) == 0:
        return False
    print(f" Found existing TLS backup, restoring secret...")
    try:
        with open(_TLS_BACKUP_FILE) as f:
            content = f.read()
            if not content.strip():
                return False
        doc = yaml.safe_load(content)
    except Exception as e:
        print(f"  Could not parse TLS backup: {e}")
        return False

    # Strip server-managed metadata fields that cause kubectl apply/replace conflicts.
    # kubectl get -o yaml embeds resourceVersion, uid, etc. which must be removed before re-applying.
    meta = doc.get('metadata', {}) or {}
    for field in ('resourceVersion', 'uid', 'creationTimestamp', 'generation',
                  'managedFields', 'selfLink'):
        meta.pop(field, None)
    ann = meta.get('annotations') or {}
    ann.pop('kubectl.kubernetes.io/last-applied-configuration', None)
    doc.pop('status', None)

    # Ensure the target namespace exists (it may not have been created yet at this stage).
    #ns = meta.get('namespace', 'default')
 #   cmd(f"{KUBECTL} create namespace {ns}", exit_on_error=False)
    cmd(f"{KUBECTL} create namespace keycloak", exit_on_error=False)
    # Write the cleaned secret to a temp file and apply it.
    tmp_path = "/tmp/mininode-tls-restore.yaml"
    with open(tmp_path, 'w') as f:
        yaml.safe_dump(doc, f, sort_keys=False)

    ret = cmd(f"{KUBECTL} apply -f {tmp_path}", exit_on_error=False)
    if ret != 0:
        # Fallback: replace works when the resource already exists with conflicting metadata.
        ret = cmd(f"{KUBECTL} replace -f {tmp_path}", exit_on_error=False)
    if ret == 0:
        print(f" TLS secret restored from backup ")
        return True
    print(f"  Failed to restore TLS secret (will fall back to cert-manager)")
    return False

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

    if USE_MINIKUBE:
        cmd("minikube kubectl -- label nodes minikube chaimeleon.eu/target=core-services --overwrite")
    else:
        _first_node = cmd_output("kubectl get nodes -o jsonpath='{.items[0].metadata.name}' 2>/dev/null").strip()
        if _first_node:
            cmd(f"kubectl label nodes {_first_node} chaimeleon.eu/target=core-services --overwrite || true")
    cmd("minikube kubectl -- create priorityclass core-services --value=1000 --description='Priority class for core services' || true")
    cmd("minikube kubectl -- create priorityclass core-applications --value=900 --description='Priority class for core applications' || true")

    if USE_MINIKUBE:
        cmd("minikube ssh -- 'sudo rm -rf /var/hostpath-provisioner 2>/dev/null; sudo mkdir -p /var/hostpath-provisioner && sudo rm -rf /var/hostpath-provisioner/keycloak && sudo mkdir -p /var/hostpath-provisioner/keycloak/postgres-data /var/hostpath-provisioner/keycloak/themes-data /var/hostpath-provisioner/keycloak/standalone-deployments && sudo chmod -R 777 /var/hostpath-provisioner/keycloak'")
    else:
        hp = CONFIG.host_path
        cmd(f"sudo mkdir -p {hp}/keycloak/postgres-data {hp}/keycloak/themes-data {hp}/keycloak/standalone-deployments")
        cmd(f"sudo chmod -R 777 {hp}/keycloak")

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

    # Ensure namespace exists before applying resources
    cmd(f"{KUBECTL} create namespace keycloak --dry-run=client -o yaml | {KUBECTL} apply -f -")
    print("Verifying namespace is ready...")
    cmd(f"{KUBECTL} get namespace keycloak")

    # Apply PVC manifests for dataset-service if present (do not replace storageClassName)


    # Always ensure Keycloak volumes (PV + namespaced PVCs) are applied when available
    # This creates the Keycloak PVs and the namespaced PVCs like `postgres-data`.
    if os.path.exists("dep0_volumes.yaml"):
        print(" Applying dep0_volumes.yaml for Keycloak volumes (pv + pvc) with a cluster-detected storageClassName")
        # Read file and extract only PersistentVolumeClaim documents
        try:
            with open('dep0_volumes.yaml', 'r') as f:
                docs = list(yaml.safe_load_all(f))
        except Exception as e:
            print(f"  Warning: could not read dep0_volumes.yaml: {e}")
            docs = []
        _sc = _detect_storage_class()
        if _sc:
            print(f" Using storage class: {_sc}")
        else:
            print(" No storage class detected; using static PV binding (storageClassName: '')")

        # Keep BOTH PersistentVolume and PersistentVolumeClaim documents.
        # Stripping PVs caused PVCs to remain unbound when storageClassName was ''
        # because there was no PV (static or dynamic) to satisfy the claim.
        pv_docs  = [d for d in docs if isinstance(d, dict) and d.get("kind") == "PersistentVolume"]
        pvc_docs = [d for d in docs if isinstance(d, dict) and d.get("kind") == "PersistentVolumeClaim"]

        for d in pv_docs:
            # Strip server-managed fields that block re-apply after delete+recreate.
            meta = d.get('metadata') or {}
            for field in ('resourceVersion', 'uid', 'creationTimestamp',
                          'managedFields', 'selfLink', 'generation'):
                meta.pop(field, None)
            d.pop('status', None)
            # Clear claimRef.uid so the PV can rebind to the freshly created PVC.
            claim_ref = (d.get('spec') or {}).get('claimRef') or {}
            claim_ref.pop('uid', None)
            claim_ref.pop('resourceVersion', None)
            if _sc and 'spec' in d:
                d['spec']['storageClassName'] = _sc

        for d in pvc_docs:
            d.setdefault('spec', {})
            d['spec']['storageClassName'] = _sc if _sc else ""
            d.setdefault('metadata', {})
            d['metadata']['namespace'] = 'keycloak'

        # Save PVs first (cluster-scoped), then PVCs (namespace-scoped)
        private_dep0 = "dep0_volumes.private.yaml"
        try:
            with open(private_dep0, "w") as pf:
                yaml.safe_dump_all(pv_docs + pvc_docs, pf, sort_keys=False)
            print(f"  Created private volumes file: {private_dep0} "
                  f"({len(pv_docs)} PVs, {len(pvc_docs)} PVCs)")
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
    if USE_MINIKUBE:
        cmd("minikube cp /tmp/themes.tar.gz minikube:/tmp/")
        cmd("minikube ssh -- 'sudo tar -xzf /tmp/themes.tar.gz -C /var/hostpath-provisioner/keycloak/themes-data/ --strip-components=1'")
    else:
        kc_dest = os.path.join(CONFIG.host_path, "keycloak", "themes-data")
        cmd(f"sudo mkdir -p {kc_dest}")
        cmd(f"sudo tar -xzf /tmp/themes.tar.gz -C {kc_dest} --strip-components=1")

    # Only copy JARs if they were successfully downloaded and validated
    if os.path.exists(jar1_path) and os.path.getsize(jar1_path) > 0:
        if USE_MINIKUBE:
            cmd(f"minikube cp {jar1_path} minikube:/var/hostpath-provisioner/keycloak/standalone-deployments/")
        else:
            cmd(f"sudo cp {jar1_path} {CONFIG.host_path}/keycloak/standalone-deployments/")
    else:
        print(f"  Warning: Skipping corrupted JAR: {jar1_path}")

    if os.path.exists(jar2_path) and os.path.getsize(jar2_path) > 0:
        if USE_MINIKUBE:
            cmd(f"minikube cp {jar2_path} minikube:/var/hostpath-provisioner/keycloak/standalone-deployments/")
        else:
            cmd(f"sudo cp {jar2_path} {CONFIG.host_path}/keycloak/standalone-deployments/")
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

    if USE_MINIKUBE:
        cmd(f"minikube cp {realm_config_file_private_path} minikube:/var/hostpath-provisioner/keycloak/standalone-deployments/")
    else:
        cmd(f"sudo cp {realm_config_file_private_path} {CONFIG.host_path}/keycloak/standalone-deployments/")

    cmd("minikube kubectl -- apply -f dep2_database.yaml -n keycloak")

    # Wait for the db pod to become Ready with a long timeout and clear diagnostics.
    # 'kubectl wait' alone with exit_on_error=True would abort the whole install on timeout.
    print("Waiting for Keycloak db pod to become Ready (up to 600s)...")
    _db_ready = False
    for _i in range(60):          # 60 × 10s = 600s
        _status = cmd_output(
            f"{KUBECTL} get pods -n keycloak -l app=db --no-headers 2>/dev/null"
        ).strip()
        if _status:
            _cols = _status.split()
            # READY column is index 1 (e.g. "1/1")
            _ready_col = _cols[1] if len(_cols) > 1 else ""
            _phase     = _cols[2] if len(_cols) > 2 else ""
            if _ready_col and _ready_col.split("/")[0] == _ready_col.split("/")[-1] and _ready_col != "0/0":
                print(f" db pod is Ready ({_ready_col})")
                _db_ready = True
                break
            print(f"  db pod status: {_phase} ready={_ready_col} (attempt {_i+1}/60)")
            if _phase in ("CrashLoopBackOff", "Error", "OOMKilled", "ImagePullBackOff", "ErrImagePull"):
                print(f"  db pod entered terminal state '{_phase}', printing logs for diagnosis:")
                cmd(f"{KUBECTL} logs -n keycloak -l app=db --tail=40", exit_on_error=False)
                cmd(f"{KUBECTL} describe pod -n keycloak -l app=db", exit_on_error=False)
                break
        time.sleep(10)

    if not _db_ready:
        print("  WARNING: Keycloak db pod did not become Ready within 600s.")
        print("  Printing pod events and last logs for diagnosis:")
        cmd(f"{KUBECTL} describe pod -n keycloak -l app=db", exit_on_error=False)
        cmd(f"{KUBECTL} logs -n keycloak -l app=db --tail=60", exit_on_error=False)
        print("  Continuing installation — Keycloak may fail to start if db is not ready.")

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

        # Always use the same ingress file (no separate TLS ingress file)
        update_ingress_host(ingress_file, CONFIG.public_domain)

        print(f" Applying/updating Keycloak ingress with domain: {CONFIG.public_domain}")
        cmd(f"minikube kubectl -- apply -f {ingress_file} -n keycloak")

        if use_tls:
            print("TLS certificate will be automatically provisioned by cert-manager")

    os.chdir("..")

def ensure_ingress_addon():
    if not USE_MINIKUBE:
        print("SKIP - ingress addon management (K8s mode). Ensure nginx-ingress is installed manually.")
        return
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
            f"            name: {_TLS_SECRET_NAME}\n"
            "            namespace: default\n"
            "      allowedRoutes:\n"
            "        namespaces:\n"
            "          from: All\n"
        )
        gateway_yaml += (
            "---\n"
            "apiVersion: cert-manager.io/v1\n"
            "kind: Certificate\n"
            "metadata:\n"
            f"  name: {_TLS_SECRET_NAME}-cert\n"
            "  namespace: default\n"
            "spec:\n"
            f"  secretName: {_TLS_SECRET_NAME}\n"
            "  commonName: " + domain + "\n"
            "  dnsNames:\n"
            f"    - {domain}\n"
            "  issuerRef:\n"
            "    name: letsencrypt-prod\n"
            "    kind: ClusterIssuer\n"
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
    content = re.sub(r'host:\s+[a-zA-Z0-9.-]+', f'host: {domain}', content)

    # Replace domain in redirect URLs (for root path redirect ingress)
    content = re.sub(
        r'(https?://)[a-zA-Z0-9.-]+(/[a-zA-Z0-9-_/%.]*)',
        rf'\1{domain}\2',
        content
    )

    # Replace hostnames entries used by HTTPRoute resources.
    content = re.sub(
        r'(hostnames:\s*\[\s*")([^\"]+)("\s*\])',
        rf'\1{domain}\3',
        content
    )
    content = re.sub(
        r'(hostnames:\s*\n\s*-\s*")([^\"]+)(")',
        rf'\1{domain}\3',
        content
    )
    content = re.sub(
        r'(hostnames:\s*\n\s*-\s*)([A-Za-z0-9.-]+)',
        rf'\1"{domain}"',
        content
    )

    # Replace TLS hosts in several common YAML forms (inline list, block quoted, block unquoted)
    content = re.sub(
        r'(tls:\s*\n\s*-\s*hosts:\s*\[\s*")([^\"]+)("\s*\])',
        rf'\1{domain}\3',
        content
    )
    content = re.sub(
        r'(tls:\s*\n\s*-\s*hosts:\s*\n\s*-\s*")([^\"]+)(")',
        rf'\1{domain}\3',
        content
    )
    content = re.sub(
        r'(tls:\s*\n\s*-\s*hosts:\s*\n\s*-\s*)([A-Za-z0-9.-]+)',
        rf'\1"{domain}"',
        content
    )

    # Replace secretName in TLS section with the domain
    content = re.sub(
        r'(secretName:\s*)[a-zA-Z0-9._-]+',
        rf'\1{domain}',
        content
    )

    with open(ingress_file, 'w') as f:
        f.write(content)

    print(f" Updated {ingress_file} host to: {domain}")

def create_dataset_service_pvcs():
    '''Create PVCs for dataset-service by applying the canonical 0-pvcs.yaml only.'''
    print("  Applying dataset-service PVC manifest (0-pvcs-hostpath.yaml) ...")

    pvcs_path = os.path.join(SCRIPT_DIR, "k8s-deploy-node", "dataset-service", "0-pvcs.yaml")
    # Ensure namespace exists
    cmd("minikube kubectl -- create namespace dataset-service || true")

    # Ensure all required host directories exist on the minikube VM before applying PVCs.
    # The hostpath provisioner requires the directories to already exist or the pod will
    # fail with "no such file or directory" (CreateContainerConfigError).
    print("  Creating required host directories on minikube VM...")
    dirs = [
        "/var/hostpath-provisioner/dataset-service/postgres-data",
        "/var/hostpath-provisioner/dataset-service/dataset-service-data",
        "/var/hostpath-provisioner/dataset-service/datalake",
        "/var/hostpath-provisioner/dataset-service/datasets",
    ]
    for d in dirs:
        cmd(f"minikube ssh -- 'sudo mkdir -p {d}'")
    cmd("minikube ssh -- 'sudo chmod -R 777 /var/hostpath-provisioner/dataset-service/'")
    print("  Host directories created.")

    if not os.path.exists(pvcs_path):
        print(f" Warning: PV manifest not found: {pvcs_path}")
        return False

    print(f" Applying PV/PVC manifest: {pvcs_path} to namespace dataset-service")
    cmd(f"minikube kubectl -- apply -f {pvcs_path} -n dataset-service")
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
            result = cmd_output(
                "minikube kubectl -- get pods -n keycloak -l app=keycloak "
                "-o jsonpath='{.items[0].status.conditions[?(@.type==\"Ready\")].status}' 2>/dev/null"
            ).strip()
            if result in ("True", "'True'"):
                print(f" Keycloak is ready (waited {waited}s)")
                keycloak_ready = True
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
        # Ensure kube-apiserver is responsive before applying (it may have restarted for OIDC config)
        print(f" Waiting for kube-apiserver to be ready before applying manifests...")
        api_waited = 0
        while api_waited < 120:
            api_ok = cmd_output("minikube kubectl -- get --raw=/healthz 2>/dev/null").strip()
            if api_ok == "ok":
                print(f" API server ready")
                break
            time.sleep(5)
            api_waited += 5
            if api_waited % 20 == 0:
                print(f"   Still waiting for API server... ({api_waited}s)")
        else:
            print(f"  Warning: API server may not be ready, proceeding anyway")

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
            _ret = cmd("minikube kubectl -- apply -f 3-ingress.yaml -n dataset-service", exit_on_error=False)
            if _ret != 0:
                print("  Webhook not ready, retrying with --validate=false...")
                cmd("minikube kubectl -- apply -f 3-ingress.yaml -n dataset-service --validate=false", exit_on_error=False)
            print(f" Ingress applied for dataset-service at https://{CONFIG.public_domain}/dataset-service")

            redirect_ingress_file = "4-ingress-for-redirect-from-root-path.yaml"
            if os.path.exists(redirect_ingress_file):
                update_ingress_host(redirect_ingress_file, CONFIG.public_domain)

                _ret2 = cmd("minikube kubectl -- apply -f 4-ingress-for-redirect-from-root-path.yaml -n dataset-service", exit_on_error=False)
                if _ret2 != 0:
                    print("  Webhook not ready, retrying with --validate=false...")
                    cmd("minikube kubectl -- apply -f 4-ingress-for-redirect-from-root-path.yaml -n dataset-service --validate=false", exit_on_error=False)
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

    dataset_explorer_dir = os.path.join(SCRIPT_DIR, "k8s-deploy-node", "dataset-explorer")

    if not os.path.exists(dataset_explorer_dir):
        print(f"Warning: dataset-explorer directory not found at {dataset_explorer_dir}")
        return

    prev_dir = os.getcwd()
    try:
        os.chdir(dataset_explorer_dir)

        # Update config-mini-node.json with correct domain
        print("Configuring dataset-explorer with domain settings...")
        config_file = "config-mini-node.json"

        if os.path.exists(config_file):
            import json
            import re

            # Backup original file
            backup_file = "config-mini-node.json.backup"
            if not os.path.exists(backup_file):
                cmd(f"cp {config_file} {backup_file}")

            with open(config_file, 'r') as f:
                raw = f.read()

            domain = CONFIG.public_domain

            # Detect ALL old node domains from the file (any https:// URL that is NOT
            # a well-known external host and NOT the target domain).
            external_hosts = {'github.com', 'zenodo.org', 'www.zenodo.org'}
            old_domains = []
            for m in re.finditer(r'https?://([a-zA-Z0-9._-]+)', raw):
                host = m.group(1)
                if host not in external_hosts and host != domain and host not in old_domains:
                    old_domains.append(host)

            if old_domains:
                for old_domain in old_domains:
                    print(f" Replacing old domain '{old_domain}' → '{domain}' in {config_file}")
                    raw = raw.replace(old_domain, domain)
            else:
                print(f" No old domain detected in {config_file}, skipping domain replacement")

            # Replace any localhost references with the configured domain
            if 'localhost' in raw:
                print(f" Replacing 'localhost' → '{domain}' in {config_file}")
                raw = re.sub(r'localhost(?::\d+)?', domain, raw)

            config_data = json.loads(raw)

            # Always enforce correct realm and project name
            if "keycloak" in config_data and "config" in config_data["keycloak"]:
                old_realm = config_data["keycloak"]["config"].get("realm", "")
                config_data["keycloak"]["config"]["realm"] = "EUCAIM-NODE"
                if old_realm != "EUCAIM-NODE":
                    print(f" Fixed keycloak realm: '{old_realm}' → 'EUCAIM-NODE'")

            if "project" in config_data:
                old_name = config_data["project"].get("name", "")
                config_data["project"]["name"] = "EUCAIM-NODE"
                if old_name != "EUCAIM-NODE":
                    print(f" Fixed project name: '{old_name}' → 'EUCAIM-NODE'")

                # Ensure termsConditions and privacyPolicy use the configured domain
                for key in ("termsConditions", "privacyPolicy"):
                    old_url = config_data["project"].get(key, "")
                    if old_url:
                        new_url = re.sub(r'https?://[^/]+', f'https://{domain}', old_url)
                        if new_url != old_url:
                            config_data["project"][key] = new_url
                            print(f" Fixed project.{key}: '{old_url}' → '{new_url}'")

            # Replace any qpinsights link/icon with orthanc in externalServices and caseExplorer
            for service in list(config_data.get("externalServices", [])) + [config_data.get("caseExplorer")]:
                if not service:
                    continue
                if "qpinsights" in service.get("link", "").lower():
                    old_link = service["link"]
                    service["link"] = re.sub(r'(https?://[^/]+)/qpinsights[^\s"]*', rf'\1/orthanc/ui/app/index.html#/', old_link)
                    print(f" Fixed {service.get('link', old_link)}: '{old_link}' → '{service['link']}'")
                if "quibim" in service.get("icon", "").lower():
                    old_icon = service["icon"]
                    service["icon"] = "/icons/orthanc.png"
                    print(f" Fixed {service.get('name', 'entry')} icon: '{old_icon}' → '/icons/orthanc.png'")

            # Write updated config back to config-mini-node.json
            with open(config_file, 'w') as f:
                json.dump(config_data, f, indent=2)

            # Also copy to public/config.json for the build
            with open('public/config.json', 'w') as f:
                json.dump(config_data, f, indent=2)

            print(f" Updated {config_file} with domain: {domain}")
            print("\n=== Final config-mini-node.json configuration ===")
            print(json.dumps(config_data, indent=2))
            print("=" * 50 + "\n")

        # Build the React application using Docker
        print("\nBuilding dataset-explorer React application with Docker...")
        print(" This may take a few minutes...")

        # Use Docker to build without installing npm locally
        build_result = cmd(
            'docker run --rm -v $(pwd):/home/node/app node:24.9-slim '
            'bash -c "cd /home/node/app && npm install && npm run build-mini-node"',
            exit_on_error=False
        )

        if build_result != 0:
            print("  Error: Build failed")
            print("  Make sure Docker is installed and running")
            return

        print(" Build completed successfully")

        # Prepare and copy files to host-mounted path (avoid minikube cp/ssh)
        print(f"\nCopying files to host path {CONFIG.host_path} (host-mounted to /var/hostpath-provisioner)...")

        # Define both UI directories
        host_ui_dir_legacy = os.path.join(CONFIG.host_path, "dataset-service/ui")
        host_ui_dir = os.path.join(CONFIG.host_path, "dataset-service/dataset-service-data/ui")

        # Create tarball of build
        cmd("sudo tar -czf /tmp/dataset-explorer-build.tar.gz -C build .")

        # Copy to both locations
        for ui_dir in [host_ui_dir_legacy, host_ui_dir]:
            print(f"  Copying to {ui_dir}...")
            # Ensure destination exists and is writable
            cmd(f"sudo mkdir -p {ui_dir}")
            cmd(f"sudo chmod 0777 {ui_dir}")

            # Extract tarball
            cmd(f"sudo rm -rf {ui_dir}/*")
            cmd(f"sudo tar -xzf /tmp/dataset-explorer-build.tar.gz -C {ui_dir}")

            # Ensure permissions so the container can read the files
            cmd(f"sudo chmod -R 0777 {ui_dir}")

        # Clean up tarball
        cmd("sudo rm -f /tmp/dataset-explorer-build.tar.gz")

        print(" Files copied to host path successfully")

        # Restart dataset-service pod to pick up new files
        print("\nRestarting dataset-service to load new UI files...")
        cmd("minikube kubectl -- delete pod -l app=dataset-service-backend -n dataset-service")
        cmd("sleep 10")
        cmd("minikube kubectl -- wait --for=condition=ready pod -l app=dataset-service-backend -n dataset-service --timeout=120s || true")

        print(f"\n Dataset Explorer installed successfully!")
        print(f" Access at: https://{CONFIG.public_domain}/")

    finally:
        os.chdir(prev_dir)

def install_fem_client(CONFIG: Config, auth_client_secrets: Auth_client_secrets):
    """Deploy the FEM (Federated Execution Module) client into the eucaim-fed-computation namespace."""

    print(f"\n{'='*80}")
    print(" Installing FEM Client")
    print(f"{'='*80}\n")

    fem_dir = os.path.join(SCRIPT_DIR, "k8s-deploy-node", "fem-client")

    fem_cfg = getattr(CONFIG, 'fem', None)
    fem_node_name = getattr(fem_cfg, 'node_name', 'EUCAIM')
    fem_cert_prefix = getattr(fem_cfg, 'cert_prefix', fem_node_name)
    fem_node_user = getattr(fem_cfg, 'node_user', 'EUCAIMrmq')
    fem_node_password = getattr(fem_cfg, 'node_password', 'xxxx')
    fem_central_server_ip = getattr(fem_cfg, 'central_server_ip', 'fedcomp.eucaim.cancerimage.eu')
    fem_central_server_port = getattr(fem_cfg, 'central_server_port', 5671)
    fem_central_rabbitmq_vhost = getattr(fem_cfg, 'central_rabbitmq_vhost', 'rabbit_server')
    fem_api_base_url = getattr(fem_cfg, 'api_base_url', 'https://fedcomp.eucaim.cancerimage.eu/orchestrator/eucaim-fem/API/v1')
    fem_client_id = getattr(fem_cfg, 'client_id', 'fem-client')
    fem_audience = getattr(fem_cfg, 'audience', 'jobman-service')
    fem_subject_issuer = getattr(fem_cfg, 'subject_issuer', 'lifescience-ri-oidc')
    fem_dataset_id = getattr(fem_cfg, 'dataset_id', 'c2677037-3e1a-4cc2-90f0-e76cb677de17')

    def register_fem_host_metadata():
        mongo_uri = getattr(fem_cfg, 'mongodb_uri', '') if fem_cfg else ''
        mongo_db = getattr(fem_cfg, 'mongodb_database', '') if fem_cfg else ''
        mongo_collection = getattr(fem_cfg, 'mongodb_collection', 'hosts') if fem_cfg else 'hosts'

        if not mongo_uri or not mongo_db:
            print(" Skipping FEM hosts registration: set fem.mongodb_uri and fem.mongodb_database in config.private.yaml")
            return

        if not re.fullmatch(r'[A-Z0-9_]+', fem_node_name or ''):
            print(f" WARNING: FEM node_name '{fem_node_name}' does not match required pattern [A-Z0-9_]+")
            print("   Skipping MongoDB hosts registration")
            return

        host_name = getattr(fem_cfg, 'host_display_name', fem_node_name)
        accessible_via = getattr(fem_cfg, 'accessible_via', 'ampq')
        launchers = getattr(fem_cfg, 'launchers', ["Docker", "Singularity", "Jobman"])
        whitelist_ip = getattr(fem_cfg, 'whitelist_ip', [])
        status = getattr(fem_cfg, 'status', 'active')

        if not isinstance(launchers, list):
            launchers = ["Docker", "Singularity", "Jobman"]
        if not isinstance(whitelist_ip, list):
            whitelist_ip = []
        if not whitelist_ip:
            node_ip = get_node_ip()
            if node_ip:
                whitelist_ip = [node_ip]

        host_doc = {
            "_id": fem_node_name,
            "name": host_name,
            "accessible_via": accessible_via,
            "launchers": launchers,
            "whitelist_ip": whitelist_ip,
            "status": status,
        }

        try:
            from pymongo import MongoClient
        except Exception as e:
            print(f" WARNING: pymongo is required for FEM hosts registration but is not available: {e}")
            print("   Install with: pip3 install pymongo")
            return

        try:
            client = MongoClient(mongo_uri, serverSelectionTimeoutMS=5000)
            client.admin.command("ping")
            result = client[mongo_db][mongo_collection].update_one(
                {"_id": fem_node_name},
                {"$set": host_doc},
                upsert=True,
            )
            if result.upserted_id is not None:
                print(f" Registered FEM host '{fem_node_name}' in MongoDB ({mongo_db}.{mongo_collection})")
            else:
                print(f" Updated FEM host '{fem_node_name}' in MongoDB ({mongo_db}.{mongo_collection})")
            client.close()
        except Exception as e:
            print(f" WARNING: Could not register FEM host metadata in MongoDB: {e}")

    # Register this node in FEM orchestrator metadata DB (hosts collection)
    register_fem_host_metadata()

    # --- Substitute domain and client secret in cm-fem.yaml → cm-fem.private.yaml ---
    cm_src  = os.path.join(fem_dir, "cm-fem.yaml")
    cm_priv = os.path.join(fem_dir, "cm-fem.private.yaml")

    with open(cm_src, "r") as f:
        cm_content = f.read()

    cm_content = cm_content.replace(
        "eucaim-node.i3m.upv.es",
        CONFIG.public_domain
    )
    cm_content = cm_content.replace(
        '"client_secret": "xxxxx"',
        f'"client_secret": "{auth_client_secrets.CLIENT_FEM_CLIENT_SECRET}"'
    )
    cm_content = cm_content.replace("node_name = 'EUCAIM'", f"node_name = '{fem_node_name}'")
    cm_content = cm_content.replace("node_user = 'EUCAIMrmq'", f"node_user = '{fem_node_user}'")
    cm_content = cm_content.replace("node_password = 'xxxx'", f"node_password = '{fem_node_password}'")
    cm_content = cm_content.replace("central_server_ip = 'fedcomp.eucaim.cancerimage.eu'", f"central_server_ip = '{fem_central_server_ip}'")
    cm_content = cm_content.replace("central_server_port = 5671", f"central_server_port = {fem_central_server_port}")
    cm_content = cm_content.replace("central_rabbitmq_vhost = 'rabbit_server'", f"central_rabbitmq_vhost = '{fem_central_rabbitmq_vhost}'")
    cm_content = cm_content.replace(
        "api_base_url =\n    'https://fedcomp.eucaim.cancerimage.eu/orchestrator/eucaim-fem/API/v1'",
        f"api_base_url =\n    '{fem_api_base_url}'"
    )
    cm_content = cm_content.replace('"client_id": "fem-client"', f'"client_id": "{fem_client_id}"')
    cm_content = cm_content.replace('"audience": "jobman-service"', f'"audience": "{fem_audience}"')
    cm_content = cm_content.replace('"subject_issuer": "lifescience-ri-oidc"', f'"subject_issuer": "{fem_subject_issuer}"')
    cm_content = cm_content.replace('"DATASET_ID": "c2677037-3e1a-4cc2-90f0-e76cb677de17"', f'"DATASET_ID": "{fem_dataset_id}"')

    with open(cm_priv, "w") as f:
        f.write(cm_content)

    print(f" Generated {cm_priv} (domain → {CONFIG.public_domain})")

    # --- Warn if secret-fem.yaml still contains placeholder values, generate valid private copy ---
    secret_file = os.path.join(fem_dir, "secret-fem.yaml")
    secret_priv = os.path.join(fem_dir, "secret-fem.private.yaml")
    with open(secret_file, "r") as f:
        secret_content = f.read()

    # Replace any placeholder values with empty-string base64 ("") so kubectl doesn't reject it
    import re as _re
    has_placeholders = bool(_re.search(r'<[^>]+>', secret_content))
    if has_placeholders:
        print("\n WARNING: secret-fem.yaml contains placeholder values.")
        print("   Applying with empty certificates — FEM will start but RabbitMQ connection will fail")
        print("   until you populate the real certs and re-run: kubectl apply -f secret-fem.yaml -n eucaim-fed-computation")
        print(f"   File: {secret_file}\n")
        # Replace anything between < > with valid empty base64 ("")
        secret_content = _re.sub(r'<[^>]+>', '""', secret_content)
    with open(secret_priv, "w") as f:
        f.write(secret_content)

    # Keep certificate filenames aligned with node identity used by FEM config.
    secret_content = secret_content.replace("EUCAIM_client_", f"{fem_cert_prefix}_client_")
    with open(secret_priv, "w") as f:
        f.write(secret_content)

    deploy_src = os.path.join(fem_dir, "deploy-fem.yaml")
    deploy_priv = os.path.join(fem_dir, "deploy-fem.private.yaml")
    with open(deploy_src, "r") as f:
        deploy_content = f.read()
    deploy_content = deploy_content.replace("EUCAIM_client_", f"{fem_cert_prefix}_client_")
    with open(deploy_priv, "w") as f:
        f.write(deploy_content)

    # --- Ensure the namespace exists ---
    cmd("minikube kubectl -- create namespace eucaim-fed-computation --dry-run=client -o yaml | minikube kubectl -- apply -f -")

    # --- Ensure the homes directory exists on the host ---
    homes_path = os.path.join(CONFIG.host_path, "data", "homes", "users")
    cmd(f"sudo mkdir -p {homes_path}")
    cmd(f"sudo chmod 0755 {homes_path}")
    print(f" Ensured homes directory: {homes_path}")

    # --- Apply manifests in order ---
    manifests = [
        os.path.join(fem_dir, "pvs-fem.yaml"),
        secret_priv,
        cm_priv,
        os.path.join(fem_dir, "service-fem.yaml"),
        deploy_priv,
    ]

    for manifest in manifests:
        print(f" Applying {os.path.basename(manifest)} ...")
        cmd(f"minikube kubectl -- apply -f {manifest}", exit_on_error=False)

    # --- Wait for the deployment to roll out ---
    print("\n Waiting for fem-client deployment to be ready (timeout 180s)...")
    cmd("minikube kubectl -- rollout status deployment/fem-client -n eucaim-fed-computation --timeout=180s || true")

    print("\n FEM Client installation complete!")


def install_guacamole(CONFIG: Config, guacamole_user_creator_password: str, auth_client_secrets):
    prev_dir = os.getcwd()
    try:
        guacamole = os.path.join(SCRIPT_DIR, "k8s-deploy-node", "guacamole")
        os.chdir(guacamole)
        # Ensure namespace and PVC exist
        cmd("minikube kubectl -- create namespace guacamole || true")
        # Adapt the guacamole-postgresql PVC to a storage class available in the cluster.
        pvc_path = os.path.join(os.getcwd(), "postgresql-pvc.yaml")
        with open(pvc_path, 'r') as f:
            pvc_docs = list(yaml.safe_load_all(f))
        updated = False
        # Keep only PVCs and set/remove storageClassName depending on cluster capabilities.
        new_docs = []
        _sc = _detect_storage_class()
        for doc in pvc_docs:
            if doc.get('kind') == 'PersistentVolumeClaim':
                if 'spec' not in doc:
                    doc['spec'] = {}
                if _sc:
                    doc['spec']['storageClassName'] = _sc
                else:
                    doc['spec']['storageClassName'] = ""
                new_docs.append(doc)
                updated = True
            # Ignore PersistentVolume documents.
        if updated:
            with open(pvc_path, 'w') as f:
                yaml.safe_dump_all(new_docs, f, sort_keys=False)
            if _sc:
                print(f"Adapted postgresql-pvc.yaml for Guacamole: PVC only and storageClassName={_sc}")
            else:
                print("Adapted postgresql-pvc.yaml for Guacamole: PVC only and no forced storageClassName")
        cmd("minikube kubectl -- apply -f postgresql-pvc.yaml -n guacamole")

        # 1. Update PostgreSQL values in a private file
        postgresql_values_file = "postgresql-values.yaml"
        postgresql_private_values_file = "postgresql-values.private.yaml"
        username = "guacamole"
        # Use password from config.private.yaml (guacamole.password)
        if hasattr(CONFIG, 'guacamole') and CONFIG.guacamole.db_password:
            password = CONFIG.guacamole.db_password
            password_is_reused = True
            print(" Using Guacamole PostgreSQL password from config.private.yaml")
        else:
            raise ValueError("Missing 'guacamole.password' in config.private.yaml — please set it before running the installer")
        database = "guacamole"
        adminUsername = username
        if hasattr(CONFIG, 'guacamole') and CONFIG.guacamole.admin_password:
            adminLocalPassword = CONFIG.guacamole.admin_password
        else:
            raise ValueError("Missing 'guacamole.adminPassword' in config.private.yaml — please set it before running the installer")

        with open(postgresql_values_file, 'r') as f:
            data = yaml.safe_load(f) or {}

        data.setdefault('auth', {})
        data['auth'].update({
            'postgresPassword': password,
            'username': username,
            'password': password,
            'database': database,
        })

        # Note: image tag/repository are managed directly in the values files

        # Do not modify image fields here; image configuration stays in the values files

        # Write private values file so the installer can use it
        with open(postgresql_private_values_file, 'w') as f:
            yaml.dump(data, f, default_flow_style=False, sort_keys=False, indent=2)

        # 2. Update Guacamole values (Postgres + OIDC)
        guacamole_values_file = "guacamole-values.yaml"
        guacamole_values_private_file = "guacamole-values.private.yaml"

        with open(guacamole_values_file, 'r') as f:
            data_pg = yaml.safe_load(f) or {}

        pg = data_pg.setdefault('postgres', {})
        pg.update({
            'database': database,
            'user': username,
            'password': password
        })

        dbcreation = data_pg.setdefault('dbcreation', {})
        dbcreation.update({
            'adminUsername': adminUsername,
            'adminLocalPassword': adminLocalPassword
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

                # Update TLS hosts if present; secretName is always fixed
                if 'tls' in data_pg['ingress']:
                    for tls_entry in data_pg['ingress']['tls']:
                        tls_entry['hosts'] = [CONFIG.public_domain]
                        tls_entry['secretName'] = get_tls_secret_name()

        # Write a private guacamole values file without altering image fields
        with open(guacamole_values_private_file, 'w') as f:
            yaml.dump(data_pg, f, default_flow_style=False, sort_keys=False, indent=2)

        print(f"\n Checking if PostgreSQL for Guacamole is already installed...")
        pg_check = cmd("minikube kubectl -- get deployment -n guacamole -l app.kubernetes.io/name=postgresql -o name 2>/dev/null | wc -l", exit_on_error=False)

        if pg_check == 0:
            print(f" Installing PostgreSQL for Guacamole...")
            cmd("helm uninstall postgresql --namespace guacamole || true")

            # Use helm upgrade --install to be more resilient
            pg_install = cmd(f"helm upgrade --install postgresql oci://registry-1.docker.io/bitnamicharts/postgresql"
                             f"             --version 15.5.29 --namespace guacamole -f {postgresql_private_values_file}",
                             exit_on_error=False)

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

        print(" Waiting for PostgreSQL pod to be ready (timeout: 300s)...")
        cmd("minikube kubectl -- wait --for=condition=ready pod -l app.kubernetes.io/name=postgresql -n guacamole --timeout=300s || true")

        # Persist the PostgreSQL password in a plain-text file for easy reference after install
        pg_password_file = "guacamole-postgresql-password.txt"
        with open(pg_password_file, 'w') as _pf:
            _pf.write(password + "\n")
        print(f" PostgreSQL password saved to {pg_password_file}")

        # Check if the current password can connect to PostgreSQL and report status.
        # Note: the actual password stored in the PVC is hashed — we cannot read it in plaintext.
        print(" Verifying PostgreSQL credentials...")
        print(f"   Password in use ({'reused from private file' if password_is_reused else 'newly generated'}): {password}")
        pv_path = cmd_output(
            "minikube kubectl -- get pv -o json | python3 -c \""
            "import json,sys; pvs=json.load(sys.stdin);"
            " [print(p['spec'].get('hostPath',{}).get('path','')) for p in pvs['items']"
            " if p['spec'].get('claimRef',{}).get('namespace')=='guacamole']\""
        ).strip().split('\n')[0].strip()
        print(f"   PVC data directory: {pv_path or '(not found)'}")
        pg_auth_check = cmd_output(
            f"minikube kubectl -- exec -n guacamole postgresql-0 --"
            f" env PGPASSWORD={password} psql -U guacamole -d guacamole -c '\\q' 2>&1"
        )
        if "password authentication failed" in pg_auth_check or "FATAL" in pg_auth_check:
            print("  WARNING: PostgreSQL connection failed with current password.")
            print(f"   The PVC at '{pv_path}' likely contains data from a previous install with a different password.")
            print("   To fix, wipe the PVC data manually and restart PostgreSQL:")
            print(f"     minikube kubectl -- scale statefulset/postgresql -n guacamole --replicas=0")
            print(f"     minikube ssh -- 'sudo rm -rf {pv_path}'")
            print(f"     minikube kubectl -- scale statefulset/postgresql -n guacamole --replicas=1")
        else:
            print(" PostgreSQL credentials verified OK")

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
        guac_install = cmd(f"helm upgrade --install guacamole ./{chart_dir} --namespace guacamole -f {guacamole_values_private_file}", exit_on_error=False)

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

        # # Create guacamole-admin user in Keycloak
        # try:
        #     print(f"\n Creating guacamole-admin user in Keycloak...")
        #     auth_endpoint = f"https://{CONFIG.public_domain}/auth/realms/EUCAIM-NODE/protocol/openid-connect/token"
        #     auth_client = AuthClient(auth_endpoint, 'dataset-service', login_as_service_account=True,
        #                            client_secret=auth_client_secrets.CLIENT_DATASET_SERVICE_SECRET)
        #     keycloak_admin_api_endpoint = f"https://{CONFIG.public_domain}/auth/admin/realms/EUCAIM-NODE/"
        #     admin_client = KeycloakAdminAPIClient(auth_client, keycloak_admin_api_endpoint)

        #     admin_client.createSpecialUser(
        #         username="guacamole-admin",
        #         email="guacamole-admin@test.com",
        #         firstName="Guacamole",
        #         lastName="Admin"
        #     )
        #     print(f" guacamole-admin user created successfully in Keycloak")
        # except Exception as e:
        #     print(f"  Warning: Could not create guacamole-admin user: {e}")
        #     print(f"   This user can be created manually via Keycloak admin UI if needed")

        # Install guacli (Guacamole CLI) if not already installed
        print(f"\n Installing guacli (Guacamole CLI tool)...")
        guacli_check = cmd("which guacli", exit_on_error=False)
        if guacli_check != 0:
            print(f"  Installing guacli via pip3...")
            # Use --break-system-packages for modern Python environments (Debian 12+, Ubuntu 23.04+)
            install_result = cmd("sudo pip3 install --break-system-packages guacli", exit_on_error=False)

            # If that fails, try without the flag (for older systems)
            if install_result != 0:
                print(f"  Retrying without --break-system-packages flag...")
                install_result = cmd("sudo pip3 install guacli", exit_on_error=False)

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


        print(f"\n Waiting for Guacamole pod to be ready...")
        # Poll until at least one guacamole pod exists, then wait for ready
        guac_ready = False
        for _attempt in range(30):
            _pod = cmd_output(
                "minikube kubectl -- get pods -n guacamole --no-headers 2>/dev/null"
                " | grep guacamole-guacamole | grep Running | head -1"
            ).strip()
            if _pod:
                guac_ready = True
                break
            time.sleep(10)
        if not guac_ready:
            print("  Warning: Guacamole pod did not reach Running state in time")
        cmd("sleep 30")

        # Create admin group and eucaim-user-creator user using guacli.
        # Use kubectl port-forward so guacli connects to Guacamole via the internal cluster service
        # (HTTP, no TLS needed) instead of the public HTTPS URL which may not be available yet.
        print(f" Creating Guacamole admin group and user-creator...")
        _guac_user = shlex.quote(adminUsername)
        _guac_pass = shlex.quote(adminLocalPassword)
        _creator_pass = shlex.quote(guacamole_user_creator_password)
        _pf_port = 58088
        _pf_cmd = f"{KUBECTL} port-forward -n guacamole svc/guacamole-guacamole {_pf_port}:80"
        print(f" Starting port-forward to Guacamole on localhost:{_pf_port}...")
        _pf_proc = subprocess.Popen(_pf_cmd, shell=True,
                                    stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        time.sleep(3)
        _guac_url = shlex.quote(f"http://localhost:{_pf_port}/guacamole/")
        try:
            cmd(f"{guacli_path} --url {_guac_url} --user {_guac_user} --password {_guac_pass}"
                f" create admin-group cloud-services-and-security-management", exit_on_error=False)
            cmd(f"{guacli_path} --url {_guac_url} --user {_guac_user} --password {_guac_pass}"
                f" create admin-user eucaim-user-creator --new-user-password {_creator_pass}", exit_on_error=False)
            cmd(f"{guacli_path} --url {_guac_url} --user {_guac_user} --password {_guac_pass}"
                f" create admin-user service-account-kubernetes-operator --new-user-password {_creator_pass}", exit_on_error=False)
        finally:
            _pf_proc.terminate()
            _pf_proc.wait()

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

    # Write private file next to the template (not overwriting the original)
    private_file = template_file.replace('.yaml', '.private.yaml')

    if not os.path.exists(template_file):
        print(f" Warning: Template file not found: {template_file}")
        return

    # Get the Guacamole admin password from the running container's ADMIN_PASSWORD env variable
    print(f" Retrieving Guacamole admin password from container...")
    guacamole_admin_password = cmd_output(
        "minikube kubectl -- exec -n guacamole deploy/guacamole-guacamole -c guacamole "
        "-- bash -c 'echo $ADMIN_PASSWORD' 2>/dev/null"
    ).strip()
    if not guacamole_admin_password:
        print(f"  Warning: Could not retrieve ADMIN_PASSWORD from guacamole container, falling back to provided password")
        guacamole_admin_password = guacamole_user_creator_password
    else:
        print(" Guacamole admin password retrieved successfully")

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

    # Replace all placeholders with actual values
    replacements = {
        '__KEYCLOAK_TOKEN_ENDPOINT__': f'https://{CONFIG.public_domain}/auth/realms/EUCAIM-NODE/protocol/openid-connect/token',
        '__KEYCLOAK_ADMIN_ENDPOINT__': f'https://{CONFIG.public_domain}/auth/admin/realms/EUCAIM-NODE/',
        '__KEYCLOAK_CLIENT__': 'dataset-service',
        '__KEYCLOAK_CLIENT_SECRET__': auth_client_secrets.CLIENT_DATASET_SERVICE_SECRET,
        '__GUACAMOLE_ENDPOINT__': 'http://guacamole-guacamole.guacamole.svc.cluster.local/guacamole/',
        '__GUACAMOLE_ADMIN_USER__': 'eucaim-user-creator',
        #grabar la contraseña random en el values del operatos
        '__GUACAMOLE_ADMIN_PASSWORD__': guacamole_user_creator_password,
        '__EXTERNAL_SHARING_SERVICE_ENDPOINT__': 'http://external-sharing-service.external-sharing-service.svc.cluster.local:80',
        '__MAIN_DOMAIN_NAME__': CONFIG.public_domain,
        '__HARBOR_DOMAIN_NAME__': f'harbor.eucaim-node.i3m.upv.es',
        '__K8S_ENDPOINT__': f'https://{get_node_ip()}:8443',
        '__K8S_TOKEN__': k8s_token,
    }

    for placeholder, value in replacements.items():
        content = content.replace(placeholder, value)

    # Write to the .private.yaml file
    with open(private_file, 'w') as f:
        f.write(content)

    print(f" Created private configuration: {private_file}")
    print(f" User management job template configured successfully")

    # Copy the generated private template and scripts to the minikube-data volume path
    print(f"\n Copying on-event-jobs files to host data path...")
    on_event_jobs_data_dir = os.path.join(CONFIG.host_path, "dataset-service", "dataset-service-data", "on-event-jobs")
    scripts_data_dir = os.path.join(on_event_jobs_data_dir, "scripts")
    cmd(f"sudo mkdir -p {on_event_jobs_data_dir}")
    cmd(f"sudo mkdir -p {scripts_data_dir}")
    cmd(f"sudo cp {private_file} {on_event_jobs_data_dir}/user-management-job-template.private.yaml")
    # Copy k8s-templates dir (contains user-management-job-template.yaml)
    k8s_templates_src = os.path.join(SCRIPT_DIR, "k8s-deploy-node", "dataset-service", "on-event-jobs", "k8s-templates")
    cmd(f"sudo cp -r {k8s_templates_src} {on_event_jobs_data_dir}/k8s-templates")
    # Copy all scripts: .sh files, Python files, and the templates/ subdirectory
    scripts_src_dir = os.path.join(SCRIPT_DIR, "k8s-deploy-node", "dataset-service", "on-event-jobs", "scripts")
    cmd(f"sudo cp {scripts_src_dir}/*.sh {scripts_data_dir}/")
    cmd(f"sudo cp {scripts_src_dir}/*.py {scripts_data_dir}/")
    cmd(f"sudo cp -r {scripts_src_dir}/templates {scripts_data_dir}/templates")
    cmd(f"sudo chmod -R 755 {on_event_jobs_data_dir}")
    print(f" on-event-jobs files copied to: {on_event_jobs_data_dir}")

    # Create the required directories on the host
    print(f"\n Creating required directories...")
    homes_base_dir = os.path.join(CONFIG.host_path, "data/homes")
    cmd(f"sudo mkdir -p {homes_base_dir}/users")
    cmd(f"sudo mkdir -p {homes_base_dir}/shared-folder")
    cmd(f"sudo chmod -R 777 {homes_base_dir}")
    print(f" Directories created: {homes_base_dir}/")


    # Save the password to a file for reference
    password_file = os.path.join(SCRIPT_DIR, "guacamole-eucaim-user-creator-password.txt")
    with open(password_file, 'w') as f:
        f.write(f"Username: eucaim-user-creator\n")
        f.write(f"Password: {guacamole_user_creator_password}\n")
    print(f"\n Guacamole user credentials saved to: {password_file}")

def apply_roles_and_bindings():
    '''Apply all RBAC roles and bindings from extra-configurations directory'''
    print(f"\n{'='*80}")
    print(" Applying RBAC Roles and Bindings")
    print(f"{'='*80}\n")

    roles_dir = os.path.join(SCRIPT_DIR, "k8s-deploy-node", "extra-configurations", "roles-and-bindings")

    if not os.path.exists(roles_dir):
        print(f"  Warning: Roles directory not found: {roles_dir}")
        return

    # Get all YAML files in the directory
    yaml_files = sorted([f for f in os.listdir(roles_dir) if f.endswith('.yaml') or f.endswith('.yml')])

    if not yaml_files:
        print(f"  No YAML files found in {roles_dir}")
        return

    print(f" Found {len(yaml_files)} RBAC configuration files:")
    for yaml_file in yaml_files:
        print(f"   - {yaml_file}")

    # Apply each YAML file
    for yaml_file in yaml_files:
        file_path = os.path.join(roles_dir, yaml_file)
        print(f"\n Applying {yaml_file}...")
        result = cmd(f"minikube kubectl -- apply -f {file_path}", exit_on_error=False)
        if result == 0:
            print(f"   Successfully applied {yaml_file}")
        else:
            print(f"   Warning: Failed to apply {yaml_file}")

    print(f"\n RBAC roles and bindings applied successfully\n")

def install_dsws_operator(CONFIG, auth_client_secrets: Auth_client_secrets, guacamole_user_creator_password: str):
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

        # Apply PVC for user homes
        print(f" Applying user-homes PVC...")
        cmd("minikube kubectl -- apply -f pvcs-for-operator.yaml")

        # Use only the current dsws-operator folder and installation-values.yaml
        print(f" Using current dsws-operator directory and installation-values.yaml (no chart repo check)")

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

        # Use the eucaim-user-creator password (generated by install_guacamole) for the operator
        data['operatorConfiguration']['guacamole']['password'] = guacamole_user_creator_password
        print(f" Set Guacamole eucaim-user-creator password in operator configuration")

        # Disable node selection (minikube has a single node, no scheduling constraints needed)
        if 'k8s' not in data['operatorConfiguration']:
            data['operatorConfiguration']['k8s'] = {}
        data['operatorConfiguration']['k8s']['node_selection'] = False
        print(f" Disabled node_selection in k8s configuration")

        # Save updated values
        with open(values_file, 'w') as f:
            yaml.dump(data, f, default_flow_style=False, sort_keys=False, indent=2)

        print(f" Updated {values_file} with configuration")

        # Add Helm repo for chaimeleon-operator chart
        print(f"\n Adding chaimeleon-services Helm repository...")
        cmd("helm repo add chaimeleon-services https://harbor.chaimeleon-eu.i3m.upv.es/chartrepo/chaimeleon-services", exit_on_error=False)
        cmd("helm repo update chaimeleon-services", exit_on_error=False)

        # Install or upgrade DSWS Operator
        print(f"\n Checking if DSWS Operator is already installed...")
        cmd(f"helm upgrade --install dsws-operator chaimeleon-services/chaimeleon-operator "
            f"--version 1.3.2 --namespace dsws-operator -f {values_file}")
        print(f" DSWS Operator installed/upgraded successfully")

    finally:
        os.chdir(prev_dir)

def configure_kube_apiserver_oidc(CONFIG):
    '''Configure kube-apiserver with OIDC authentication for Kubeapps'''
    if not USE_MINIKUBE:
        print(f"\n{'='*80}")
        print(" KUBE-APISERVER OIDC CONFIGURATION (SKIPPED)")
        print(f"{'='*80}")
        print("  >> ADMIN: Configure OIDC manually on your cluster:")
        print(f"      1. Add --oidc-issuer-url=https://{CONFIG.public_domain}/auth/realms/EUCAIM-NODE")
        print(f"      2. Add --oidc-client-id=kubernetes")
        print(f"      3. Add --oidc-username-claim=preferred_username")
        print(f"      4. Add --oidc-username-prefix=oidc:")
        print(f"      5. Add --oidc-groups-claim=groups")
        print(f"      6. Add --oidc-groups-prefix=oidc:")
        print(f"    For kubeadm: edit /etc/kubernetes/manifests/kube-apiserver.yaml")
        print(f"    For managed K8s: use cloud provider's OIDC configuration API")
        return

    print(f"\n{'='*80}")
    print(" Configuring kube-apiserver with OIDC")
    print(f"{'='*80}\n")

    # --- Token auth file setup ---
    # Generate token.csv from the user-management-sa-token k8s secret.
    # The file is injected into the minikube VM via ~/.minikube/files so it is
    # available at /etc/ca-certificates/token.csv inside the VM, which is the
    # path passed to --token-auth-file in the apiserver.
    print(" Setting up token-auth-file for kube-apiserver...")
    token_csv_src = os.path.join(SCRIPT_DIR, "token.csv")
    minikube_files_dir = os.path.expanduser("~/.minikube/files/etc/ca-certificates")
    token_csv_dst = os.path.join(minikube_files_dir, "token.csv")

    # Extract token from the service account secret (created in configure_user_management_job_template)
    print(" Extracting token from user-management-sa-token secret...")
    sa_token = cmd_output(
        "minikube kubectl -- get secret user-management-sa-token -n dataset-service "
        "-o jsonpath='{.data.token}' 2>/dev/null | base64 -d"
    ).strip()

    if not sa_token:
        print("  Warning: Could not extract token from user-management-sa-token secret, skipping token-auth-file setup")
    else:
        # Write token.csv: format is  token,username,uid,"group1,group2"
        with open(token_csv_src, 'w') as f:
            f.write(f"{sa_token},user-management-sa,user-management-sa,\"system:masters\"\n")
        print(f" token.csv generated at {token_csv_src}")

        cmd(f"mkdir -p {minikube_files_dir}")
        cmd(f"cp {token_csv_src} {token_csv_dst}")
        print(f" token.csv copied to {token_csv_dst}")

        # Patch kube-apiserver manifest to add --token-auth-file if not already present
        print(" Patching kube-apiserver manifest with --token-auth-file...")
        token_patch_script = r"""#!/bin/bash
set -e
APISERVER_YAML=/etc/kubernetes/manifests/kube-apiserver.yaml
if grep -q 'token-auth-file' "$APISERVER_YAML"; then
    echo "--token-auth-file already present, skipping"
else
    sed -i '/--tls-private-key-file/a\    - --token-auth-file=/etc/ca-certificates/token.csv' "$APISERVER_YAML"
    echo "--token-auth-file added"
fi
"""
        with open('/tmp/patch_token_auth.sh', 'w') as f:
            f.write(token_patch_script)
        cmd("minikube cp /tmp/patch_token_auth.sh minikube:/tmp/patch_token_auth.sh")
        cmd("minikube ssh -- 'sudo bash /tmp/patch_token_auth.sh'")
        print(" kube-apiserver patched with --token-auth-file")

    # OIDC configuration flags
    oidc_flags = [
        f'--oidc-issuer-url=https://{CONFIG.public_domain}/auth/realms/EUCAIM-NODE',
        '--oidc-client-id=kubernetes',
        '--oidc-username-claim=preferred_username',
        "'--oidc-username-prefix=oidc:'",
        '--oidc-groups-claim=groups',
        "'--oidc-groups-prefix=oidc:'"
    ]

    # Check if OIDC is already configured
    print(" Checking current kube-apiserver configuration...")
    check_oidc = cmd("minikube ssh -- 'sudo grep -q oidc-issuer-url /etc/kubernetes/manifests/kube-apiserver.yaml && echo FOUND || echo NOT_FOUND'", exit_on_error=False)

    if check_oidc == 0:
        # Check output to see if OIDC is configured
        output = cmd_output("minikube ssh -- 'sudo grep -q oidc-issuer-url /etc/kubernetes/manifests/kube-apiserver.yaml && echo FOUND || echo NOT_FOUND'").strip()

        if 'FOUND' in output:
            # Check if it's the correct domain
            current_domain = cmd_output(f"minikube ssh -- 'sudo grep oidc-issuer-url /etc/kubernetes/manifests/kube-apiserver.yaml'").strip()

            if CONFIG.public_domain in current_domain:
                print(f" kube-apiserver already configured with OIDC for {CONFIG.public_domain}")
                return
            else:
                print(f" Updating kube-apiserver OIDC configuration to use {CONFIG.public_domain}")

    print(f" Configuring kube-apiserver with OIDC for domain: {CONFIG.public_domain}")

    # Create a bash script to modify the YAML in-place (avoids needing Python YAML library)
    modify_script = f'''set -e

APISERVER_YAML="/etc/kubernetes/manifests/kube-apiserver.yaml"
TEMP_YAML="/tmp/kube-apiserver-temp.yaml"

# Remove any existing OIDC flags first and save to temp file
grep -v -- '--oidc-issuer-url' "$APISERVER_YAML" | \\
grep -v -- '--oidc-client-id' | \\
grep -v -- '--oidc-username-claim' | \\
grep -v -- '--oidc-username-prefix' | \\
grep -v -- '--oidc-groups-claim' | \\
grep -v -- '--oidc-groups-prefix' > "$TEMP_YAML"

# Find the line with --tls-private-key-file and insert OIDC flags after it
awk '{{
    print $0
    if ($0 ~ /--tls-private-key-file/) {{
        print "    - --oidc-issuer-url=https://{CONFIG.public_domain}/auth/realms/EUCAIM-NODE"
        print "    - --oidc-client-id=kubernetes"
        print "    - --oidc-username-claim=preferred_username"
        print "    - \\"--oidc-username-prefix=oidc:\\""
        print "    - --oidc-groups-claim=groups"
        print "    - \\"--oidc-groups-prefix=oidc:\\""
    }}
}}' "$TEMP_YAML" > "$APISERVER_YAML"

# Clean up
rm -f "$TEMP_YAML"

echo "OIDC configuration applied successfully"
'''

    # Write script to temp file
    with open('/tmp/modify_apiserver.sh', 'w') as f:
        f.write(modify_script)

    # Copy script to minikube
    cmd("minikube cp /tmp/modify_apiserver.sh minikube:/tmp/modify_apiserver.sh")

    # Run the script by piping it to bash (avoids permission issues with /tmp)
    print(" Modifying kube-apiserver.yaml...")
    cmd("minikube ssh -- 'sudo bash /tmp/modify_apiserver.sh'")

    # Wait for apiserver to restart (it monitors the manifest file)
    print(" Waiting for kube-apiserver to restart with new configuration...")
    print("  (This may take 30-60 seconds)")
    time.sleep(10)

    # Wait for apiserver to be ready
    max_wait = 180
    waited = 0
    while waited < max_wait:
        result = cmd("minikube kubectl -- get --raw=/healthz 2>/dev/null", exit_on_error=False)
        if result == 0:
            print(f" kube-apiserver is ready with OIDC configuration")
            break
        time.sleep(5)
        waited += 5
        if waited % 15 == 0:
            print(f"   Still waiting for apiserver... ({waited}s)")

    if waited >= max_wait:
        print(f"  Warning: apiserver took longer than expected to restart")
        print(f"   You may need to check manually with: kubectl get pods -n kube-system")

    # Verify OIDC configuration
    print("\n Verifying OIDC configuration...")
    cmd("minikube ssh -- 'sudo grep oidc-issuer-url /etc/kubernetes/manifests/kube-apiserver.yaml'")

    print(f"\n kube-apiserver configured successfully with OIDC!")

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
        if USE_MINIKUBE:
            cmd("minikube kubectl -- label nodes minikube chaimeleon.eu/target=core-services --overwrite")
        else:
            _first_node = cmd_output("kubectl get nodes -o jsonpath='{.items[0].metadata.name}' 2>/dev/null").strip()
            if _first_node:
                cmd(f"kubectl label nodes {_first_node} chaimeleon.eu/target=core-services --overwrite || true")

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
                print(f" Disabled Helm-managed Ingress (will use HTTPRoute instead)")
            else:
                # LEGACY: Enable and configure Helm-managed Ingress
                data['ingress']['enabled'] = True
                data['ingress']['hostname'] = CONFIG.public_domain

                # Configure TLS if available
                use_tls = (hasattr(CONFIG, 'letsencrypt') and
                           hasattr(CONFIG.letsencrypt, 'email') and
                           CONFIG.letsencrypt.email and
                           getattr(CONFIG, 'cert_manager_available', False))

                if use_tls:
                    if 'tls' not in data['ingress']:
                        data['ingress']['tls'] = True
                    data['ingress']['extraTls'] = [{
                        'hosts': [CONFIG.public_domain],
                        'secretName': get_tls_secret_name()
                    }]
                    print(f" Configured Helm-managed Ingress with TLS: {CONFIG.public_domain}")
                else:
                    print(f" Configured Helm-managed Ingress: {CONFIG.public_domain}")

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

            # Update extra flags with correct domain using regex
            if 'extraFlags' in data['authProxy']:
                updated_flags = []
                for flag in data['authProxy']['extraFlags']:
                    # Replace any domain in --oidc-issuer-url (keep /auth/realms/EUCAIM-NODE)
                    updated_flag = re.sub(
                        r'(--oidc-issuer-url=https://)[a-zA-Z0-9.-]+(/auth/realms/EUCAIM-NODE)',
                        rf'\1{CONFIG.public_domain}\2',
                        flag
                    )
                    # Replace any domain in --whitelist-domain
                    updated_flag = re.sub(
                        r'(--whitelist-domain=)[a-zA-Z0-9.-]+',
                        rf'\1{CONFIG.public_domain}',
                        updated_flag
                    )

                    updated_flags.append(updated_flag)

                data['authProxy']['extraFlags'] = updated_flags
                print(f" Updated authProxy flags with domain: {CONFIG.public_domain}")

        # Configure frontend to work properly with /apps/ prefix
        if 'frontend' not in data:
            data['frontend'] = {}

        # Set the path prefix so frontend knows it's served from /apps
        data['frontend']['pathPrefix'] = '/apps'
        print(f" Configured frontend pathPrefix: /apps")

        # Enable proxypass access URLs for proper path handling
        data['frontend']['proxypassAccessURLs'] = f"https://{CONFIG.public_domain}/apps"
        print(f" Configured frontend proxypassAccessURLs: https://{CONFIG.public_domain}/apps")

        # Increase nginx header buffer size for OIDC tokens
        if 'largeClientHeaderBuffers' not in data['frontend']:
            data['frontend']['largeClientHeaderBuffers'] = "4 32k"
            print(f" Configured frontend largeClientHeaderBuffers for OIDC")

        # Ensure global.security.allowInsecureImages is set (for Harbor images)
        if 'global' not in data:
            data['global'] = {}
        if 'security' not in data['global']:
            data['global']['security'] = {}
        if not data['global']['security'].get('allowInsecureImages'):
            data['global']['security']['allowInsecureImages'] = True
            print(f" Enabled allowInsecureImages for Harbor registry")

        # Configure PostgreSQL storageClass dynamically
        _sc = _detect_storage_class()
        if CONFIG.flavor == 'micro':
            if 'postgresql' not in data:
                data['postgresql'] = {}
            if 'primary' not in data['postgresql']:
                data['postgresql']['primary'] = {}
            if 'persistence' not in data['postgresql']['primary']:
                data['postgresql']['primary']['persistence'] = {}
            if _sc:
                data['postgresql']['primary']['persistence']['storageClass'] = _sc
                print(f" Configured PostgreSQL to use '{_sc}' storageClass")
            else:
                data['postgresql']['primary']['persistence'].pop('storageClass', None)
                print(" No storage class detected; PostgreSQL will use chart/cluster defaults")

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

        # Delete existing ingress to avoid conflicts during upgrade
        print(f" Removing existing Kubeapps ingress to avoid conflicts...")
        cmd("minikube kubectl -- delete ingress kubeapps-ingress -n kubeapps --ignore-not-found=true", exit_on_error=False)

        # Delete PostgreSQL StatefulSet to avoid immutable field errors during upgrade
        print(f" Removing existing PostgreSQL StatefulSet to allow upgrades...")
        cmd("minikube kubectl -- delete statefulset kubeapps-postgresql -n kubeapps --ignore-not-found=true", exit_on_error=False)

        # Wait a moment for the StatefulSet to be fully deleted
        cmd("sleep 5")

        # AppRepository can conflict with apprepository-controller field ownership
        # on upgrade; deleting it allows Helm to recreate it cleanly.
        print(f" Removing potentially conflicting AppRepository before Helm upgrade...")
        cmd(
            "minikube kubectl -- delete apprepository eucaim-node-apps "
            "-n kubeapps --ignore-not-found=true",
            exit_on_error=False,
        )

        # Use helm upgrade --install to install or update Kubeapps
        # --install: Install if not already installed
        # Note: --force is intentionally omitted; it conflicts with server-side apply in newer Helm versions.
        # Pod recreation is handled explicitly below instead.
        helm_cmd = (
            "helm upgrade --install kubeapps oci://registry-1.docker.io/bitnamicharts/kubeapps "
            "--version 17.1.1 --namespace kubeapps -f {}".format(private_values_file)
        )
        helm_ret = cmd(helm_cmd, exit_on_error=False)
        if helm_ret != 0:
            print("  First Helm upgrade failed; retrying after AppRepository cleanup...")
            cmd(
                "minikube kubectl -- delete apprepository eucaim-node-apps "
                "-n kubeapps --ignore-not-found=true",
                exit_on_error=False,
            )
            cmd("sleep 3")
            helm_ret = cmd(helm_cmd, exit_on_error=False)
            if helm_ret != 0:
                print("  ERROR: Kubeapps Helm upgrade failed after retry")
                print("   Check details with: helm -n kubeapps status kubeapps")
                print("   And: minikube kubectl -- get apprepository -n kubeapps -o yaml")
                exit(1)

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
        else:
            # LEGACY: Ingress is now managed by Helm via values.yaml
            print(f"\n Ingress configured via Helm values.yaml")
            print(f" Kubeapps will be available at https://{CONFIG.public_domain}/apps")

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

    images_loaded = False
    if USE_MINIKUBE:
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
            pull_result = cmd(f"docker pull {image}", exit_on_error=False)
            if pull_result == 0:
                load_result = cmd(f"minikube image load {image}", exit_on_error=False)
                if load_result != 0:
                    print(f"  Failed to load {image} into minikube")
                    images_loaded = False
                    break
            else:
                print(f"  Failed to pull {image} with Docker")
                images_loaded = False
                break

    if images_loaded or not USE_MINIKUBE:
        print("Images loaded, installing cert-manager v1.18.2...")
        # Now install cert-manager - images should be available locally in minikube
        yaml_install = cmd("minikube kubectl -- apply -f https://github.com/cert-manager/cert-manager/releases/download/v1.18.2/cert-manager.yaml", exit_on_error=False)

        if yaml_install == 0:
            print("Waiting for cert-manager pods to be created...")
            time.sleep(10)
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
            print("Waiting for cert-manager pods to be created...")
            time.sleep(10)
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

    preserve_existing_tls = _tls_backup_exists()

    # Update the manifest with the correct domain.
    # If a TLS backup already exists, skip the Certificate resource entirely so
    # cert-manager cannot reconcile it and re-issue a different secret.
    with open(gateway_file, 'r') as f:
        docs = list(yaml.safe_load_all(f))

    updated_docs = []
    for doc in docs:
        if not isinstance(doc, dict):
            continue
        if doc.get("kind") == "Gateway":
            for listener in doc.get("spec", {}).get("listeners", []):
                if "hostname" in listener:
                    listener["hostname"] = CONFIG.public_domain
        elif doc.get("kind") == "Certificate":
            if preserve_existing_tls:
                print(" Preserving existing TLS secret: skipping Certificate resource")
                continue
            if "dnsNames" in doc.get("spec", {}):
                doc["spec"]["dnsNames"] = [CONFIG.public_domain]
        updated_docs.append(doc)

    gateway_file = "/tmp/main-gateway.yaml"
    with open(gateway_file, 'w') as f:
        yaml.safe_dump_all(updated_docs, f, sort_keys=False)
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

    # Get ingress-nginx service info to extract nodeports using kubectl
    http_nodeport = None
    https_nodeport = None

    max_retries = 15
    retry_count = 0

    while retry_count < max_retries:
        try:
            result = subprocess.run(
                ["minikube", "kubectl", "--", "get", "svc", "ingress-nginx-controller", "-n", "ingress-nginx",
                 "-o", "jsonpath={.spec.ports[?(@.name==\"http\")].nodePort},{.spec.ports[?(@.name==\"https\")].nodePort}"],
                capture_output=True, text=True, check=True
            )
            ports = result.stdout.strip().split(',')

            if len(ports) == 2 and ports[0] and ports[1]:
                http_nodeport = ports[0]
                https_nodeport = ports[1]
                print(f"Detected NodePorts from ingress-nginx service: HTTP={http_nodeport}, HTTPS={https_nodeport}")
                break
            else:
                print(f"Warning: Could not parse nodeports (attempt {retry_count + 1}/{max_retries}), retrying...")
                retry_count += 1
                if retry_count < max_retries:
                    time.sleep(10)

        except subprocess.CalledProcessError as e:
            print(f"Warning: Could not get ingress service info (attempt {retry_count + 1}/{max_retries}): {e}")
            retry_count += 1
            if retry_count < max_retries:
                time.sleep(10)

    if not http_nodeport or not https_nodeport:
        print("Warning: Could not detect NodePorts from ingress-nginx service after multiple attempts.")
        print("Skipping iptables rules setup. You can apply them manually later:")
        print("  minikube kubectl -- get svc -n ingress-nginx")
        return

    # Get node IP (minikube or first K8s node)
    minikube_ip = get_node_ip()
    if minikube_ip:
        print(f"Detected node IP: {minikube_ip}")
    else:
        minikube_ip = "192.168.49.2"
        print(f"Warning: Could not get node IP, using default: {minikube_ip}")

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

    # First, clean up ALL old rules targeting minikube HTTP/HTTPS (we'll re-add the correct ones)
    if os.geteuid() == 0:
        print("\nCleaning up ALL existing iptables rules for minikube HTTP/HTTPS...")
        try:
            # Remove ALL DNAT rules to minikube for ports 80 and 443
            # We need to do this in a loop because line numbers change after each deletion
            while True:
                result = subprocess.run(
                    ["iptables", "-t", "nat", "-L", "PREROUTING", "-n", "--line-numbers"],
                    capture_output=True, text=True, check=True
                )

                # Find first DNAT rule to minikube on port 80 or 443
                line_to_delete = None
                proto = None
                for line in result.stdout.split('\n'):
                    # Check for any DNAT rules to minikube on port 80 or 443
                    if 'DNAT' in line and minikube_ip in line:
                        parts = line.split()
                        if parts and parts[0].isdigit():
                            # Remove any HTTP rule (dpt:80)
                            if 'dpt:80' in line:
                                line_to_delete = int(parts[0])
                                proto = 'HTTP'
                                break
                            # Remove any HTTPS rule (dpt:443)
                            elif 'dpt:443' in line:
                                line_to_delete = int(parts[0])
                                proto = 'HTTPS'
                                break

                # If we found a rule to delete, delete it and loop again
                if line_to_delete:
                    print(f"Removing {proto} PREROUTING rule at line {line_to_delete}")
                    subprocess.run(["iptables", "-t", "nat", "-D", "PREROUTING", str(line_to_delete)], check=False)
                else:
                    # No more rules to delete
                    break

            # Clean up ALL FORWARD rules to minikube on specific ports
            while True:
                result = subprocess.run(
                    ["iptables", "-L", "FORWARD", "-n", "--line-numbers"],
                    capture_output=True, text=True, check=True
                )

                line_to_delete = None
                for line in result.stdout.split('\n'):
                    # Check for ACCEPT rules to minikube with wrong ports
                    if minikube_ip in line and 'ACCEPT' in line and 'tcp' in line and 'dpt:' in line:
                        # Check if it has a port that's not our current ports
                        if f'dpt:{http_nodeport}' not in line and f'dpt:{https_nodeport}' not in line:
                            parts = line.split()
                            if parts and parts[0].isdigit():
                                line_to_delete = int(parts[0])
                                break

                if line_to_delete:
                    print(f"Removing old FORWARD rule at line {line_to_delete}")
                    subprocess.run(["iptables", "-D", "FORWARD", str(line_to_delete)], check=False)
                else:
                    break

        except Exception as e:
            print(f"Warning: Could not clean old rules: {e}")

    # Now, apply the iptables rules immediately if running as root
    if os.geteuid() == 0:
        print("\nApplying interface-specific iptables rules...")

        # ONLY use interface-specific NAT rules (with -i flag)
        # Insert them at position 2 (right after DOCKER rule which is at position 1)
        try:
            # Interface-specific NAT rules for HTTP - insert at position 2
            result = subprocess.run(
                ["iptables", "-t", "nat", "-C", "PREROUTING", "-i", external_interface, "-p", "tcp", "--dport", "80", "-j", "DNAT", "--to-destination", f"{minikube_ip}:{http_nodeport}"],
                capture_output=True, check=False
            )
            if result.returncode != 0:
                print(f"Adding interface-specific NAT rule for HTTP on {external_interface} at position 2")
                cmd(f"iptables -t nat -I PREROUTING 2 -i {external_interface} -p tcp --dport 80 -j DNAT --to-destination {minikube_ip}:{http_nodeport}")
            else:
                print(f"Interface-specific NAT rule for HTTP on {external_interface} already exists")

            # Interface-specific NAT rules for HTTPS - insert at position 3 (after HTTP rule)
            result = subprocess.run(
                ["iptables", "-t", "nat", "-C", "PREROUTING", "-i", external_interface, "-p", "tcp", "--dport", "443", "-j", "DNAT", "--to-destination", f"{minikube_ip}:{https_nodeport}"],
                capture_output=True, check=False
            )
            if result.returncode != 0:
                print(f"Adding interface-specific NAT rule for HTTPS on {external_interface} at position 3")
                cmd(f"iptables -t nat -I PREROUTING 3 -i {external_interface} -p tcp --dport 443 -j DNAT --to-destination {minikube_ip}:{https_nodeport}")
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

            # Add FORWARD rules for minikube outbound traffic (so pods can access internet)
            print("\nConfiguring outbound internet access for minikube...")

            # Allow forwarding from minikube network to external interface
            result = subprocess.run(
                ["iptables", "-C", "FORWARD", "-s", "192.168.49.0/24", "-o", external_interface, "-j", "ACCEPT"],
                capture_output=True, check=False
            )
            if result.returncode != 0:
                print(f"Adding FORWARD rule for minikube outbound traffic to {external_interface}")
                cmd(f"iptables -I FORWARD 1 -s 192.168.49.0/24 -o {external_interface} -j ACCEPT")
            else:
                print(f"FORWARD rule for minikube outbound traffic already exists")

            # Allow return traffic from external interface to minikube
            result = subprocess.run(
                ["iptables", "-C", "FORWARD", "-i", external_interface, "-d", "192.168.49.0/24", "-m", "state", "--state", "RELATED,ESTABLISHED", "-j", "ACCEPT"],
                capture_output=True, check=False
            )
            if result.returncode != 0:
                print(f"Adding FORWARD rule for return traffic from {external_interface} to minikube")
                cmd(f"iptables -I FORWARD 1 -i {external_interface} -d 192.168.49.0/24 -m state --state RELATED,ESTABLISHED -j ACCEPT")
            else:
                print(f"FORWARD rule for return traffic already exists")

            # Add POSTROUTING MASQUERADE rule for minikube outbound traffic
            result = subprocess.run(
                ["iptables", "-t", "nat", "-C", "POSTROUTING", "-s", "192.168.49.0/24", "-o", external_interface, "-j", "MASQUERADE"],
                capture_output=True, check=False
            )
            if result.returncode != 0:
                print(f"Adding POSTROUTING MASQUERADE rule for minikube on {external_interface}")
                cmd(f"iptables -t nat -A POSTROUTING -s 192.168.49.0/24 -o {external_interface} -j MASQUERADE")
            else:
                print(f"POSTROUTING MASQUERADE rule already exists")

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
        "# First, clean up any old rules for minikube HTTP/HTTPS\n"
        'echo "Cleaning up old iptables rules for minikube HTTP/HTTPS..."\n'
        "\n"
        "# Remove all DNAT rules to minikube on ports 80 and 443\n"
        "while true; do\n"
        f'    LINE=$(iptables -t nat -L PREROUTING -n --line-numbers | grep "DNAT" | grep "{minikube_ip}" | grep -E "dpt:(80|443)" | head -1 | awk \'{{print $1}}\')\n'
        '    if [ -z "$LINE" ]; then\n'
        "        break\n"
        "    fi\n"
        '    echo "Removing old PREROUTING rule at line $LINE"\n'
        '    iptables -t nat -D PREROUTING "$LINE"\n'
        "done\n"
        "\n"
        "# Remove FORWARD rules to minikube with old ports (keep only current ones)\n"
        "while true; do\n"
        f'    LINE=$(iptables -L FORWARD -n --line-numbers | grep "{minikube_ip}" | grep "ACCEPT" | grep "tcp" | grep "dpt:" | grep -v "dpt:{http_nodeport}" | grep -v "dpt:{https_nodeport}" | head -1 | awk \'{{print $1}}\')\n'
        '    if [ -z "$LINE" ]; then\n'
        "        break\n"
        "    fi\n"
        '    echo "Removing old FORWARD rule at line $LINE"\n'
        '    iptables -D FORWARD "$LINE"\n'
        "done\n"
        "\n"
        'echo "Setting up interface-specific NAT rules for external access..."\n'
        f'echo "External interface: {external_interface}"\n'
        "\n"
        "# Interface-specific NAT rules ONLY (preserves minikube's own connectivity)\n"
        "# Insert at specific positions: 2 for HTTP, 3 for HTTPS (after DOCKER rule at position 1)\n"
        f"if ! iptables -t nat -C PREROUTING -i {external_interface} -p tcp --dport 80 -j DNAT --to-destination {minikube_ip}:{http_nodeport} 2>/dev/null; then\n"
        f'    echo "Adding interface-specific NAT rule for HTTP on {external_interface} at position 2"\n'
        f"    iptables -t nat -I PREROUTING 2 -i {external_interface} -p tcp --dport 80 -j DNAT --to-destination {minikube_ip}:{http_nodeport}\n"
        "else\n"
        f'    echo "Interface-specific NAT rule for HTTP on {external_interface} already exists, skipping"\n'
        "fi\n"
        "\n"
        f"if ! iptables -t nat -C PREROUTING -i {external_interface} -p tcp --dport 443 -j DNAT --to-destination {minikube_ip}:{https_nodeport} 2>/dev/null; then\n"
        f'    echo "Adding interface-specific NAT rule for HTTPS on {external_interface} at position 3"\n'
        f"    iptables -t nat -I PREROUTING 3 -i {external_interface} -p tcp --dport 443 -j DNAT --to-destination {minikube_ip}:{https_nodeport}\n"
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
        "# FORWARD rules for minikube outbound traffic (internet access)\n"
        'echo "Configuring minikube outbound internet access..."\n'
        "\n"
        f"if ! iptables -C FORWARD -s 192.168.49.0/24 -o {external_interface} -j ACCEPT 2>/dev/null; then\n"
        f'    echo "Adding FORWARD rule for minikube outbound traffic to {external_interface}"\n'
        f"    iptables -I FORWARD 1 -s 192.168.49.0/24 -o {external_interface} -j ACCEPT\n"
        "else\n"
        '    echo "FORWARD rule for minikube outbound traffic already exists, skipping"\n'
        "fi\n"
        "\n"
        f"if ! iptables -C FORWARD -i {external_interface} -d 192.168.49.0/24 -m state --state RELATED,ESTABLISHED -j ACCEPT 2>/dev/null; then\n"
        f'    echo "Adding FORWARD rule for return traffic from {external_interface} to minikube"\n'
        f"    iptables -I FORWARD 1 -i {external_interface} -d 192.168.49.0/24 -m state --state RELATED,ESTABLISHED -j ACCEPT\n"
        "else\n"
        '    echo "FORWARD rule for return traffic already exists, skipping"\n'
        "fi\n"
        "\n"
        "# POSTROUTING MASQUERADE for minikube outbound traffic\n"
        f"if ! iptables -t nat -C POSTROUTING -s 192.168.49.0/24 -o {external_interface} -j MASQUERADE 2>/dev/null; then\n"
        f'    echo "Adding POSTROUTING MASQUERADE rule for minikube on {external_interface}"\n'
        f"    iptables -t nat -A POSTROUTING -s 192.168.49.0/24 -o {external_interface} -j MASQUERADE\n"
        "else\n"
        '    echo "POSTROUTING MASQUERADE rule already exists, skipping"\n'
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
                print("iptables rules applied successfully!")
                print(result.stdout)
            else:
                print("Warning: Could not apply iptables rules automatically")
                print(result.stderr)
                print(f"\nPlease run manually: sudo {script_path}")
        except Exception as e:
            print(f"Warning: Could not apply iptables rules: {e}")
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

    preserve_existing_tls = _tls_backup_exists()

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
            f"            name: {_TLS_SECRET_NAME}\n"
            "            namespace: default\n"
            "      allowedRoutes:\n"
            "        namespaces:\n"
            "          from: All\n"
        )
        if not preserve_existing_tls:
            gateway_yaml += (
                "---\n"
                "apiVersion: cert-manager.io/v1\n"
                "kind: Certificate\n"
                "metadata:\n"
                f"  name: {_TLS_SECRET_NAME}-cert\n"
                "  namespace: default\n"
                "spec:\n"
                f"  secretName: {_TLS_SECRET_NAME}\n"
                "  commonName: " + domain + "\n"
                "  dnsNames:\n"
                f"    - {domain}\n"
                "  issuerRef:\n"
                "    name: letsencrypt-prod\n"
                "    kind: ClusterIssuer\n"
            )
        else:
            print(" Preserving existing TLS secret: not generating a Certificate resource")

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

                # Ensure output-files/charts directory exists
                host_charts_dir = os.path.join(CONFIG.host_path, "dataset-service/dataset-service-data/output-files/charts")
                host_output_files_dir = os.path.join(CONFIG.host_path, "dataset-service/dataset-service-data/output-files")
                cmd(f"sudo mkdir -p {host_charts_dir}")
                cmd(f"sudo chmod -R 777 {host_output_files_dir}")

                if USE_MINIKUBE:
                    cmd("minikube ssh -- 'sudo mkdir -p /var/hostpath-provisioner/dataset-service/dataset-service-data/output-files/charts'")
                    cmd("minikube ssh -- 'sudo chmod -R 777 /var/hostpath-provisioner/dataset-service/dataset-service-data/output-files'")

                # Copy entire packaged directory contents using tar
                print(f"  Copying all files from {packaged_charts_dir}...")

                # Create tar.gz with all contents
                cmd(f"tar -czf /tmp/charts-packaged.tar.gz -C {packaged_charts_dir} .")

                if USE_MINIKUBE:
                    # Copy tar to minikube and extract there
                    cmd("minikube cp /tmp/charts-packaged.tar.gz minikube:/tmp/")
                    cmd("minikube ssh -- 'sudo tar -xzf /tmp/charts-packaged.tar.gz -C /var/hostpath-provisioner/dataset-service/dataset-service-data/output-files/charts/'")
                else:
                    # Extract locally (already at host_charts_dir)
                    cmd(f"sudo tar -xzf /tmp/charts-packaged.tar.gz -C {host_charts_dir}")

                # Re-apply permissions after extraction (tar inside minikube creates root-owned files
                # on the host-mounted path, which would otherwise block helm repo index)
                cmd(f"sudo chmod -R 777 {host_charts_dir}")

                # Generate Helm repository index.yaml locally (helm not available inside minikube).
                # Must run with sudo because the charts dir is root-owned from the VM-side tar extraction;
                # helm writes a temp file (index.yaml<random>) into the same directory before renaming it,
                # so the process needs root write access regardless of the directory mode.
                print(f"\n Generating Helm repository index...")
                cmd(f"sudo $(which helm) repo index {host_charts_dir} --url http://{CONFIG.public_domain}/dataset-service/output-files/charts/")
                # Make index.yaml world-readable so the dataset-service container can read it
                cmd(f"sudo chmod 644 {host_charts_dir}/index.yaml")

                # Clean up temporary files
                cmd("minikube ssh -- 'sudo rm -f /tmp/charts-packaged.tar.gz'")
                cmd("rm -f /tmp/charts-packaged.tar.gz")

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

def install_fed_search(CONFIG):
    '''Install Focus and Beam-proxy for EUCAIM federated query support'''
    if not hasattr(CONFIG, 'focus'):
        print("\n Focus/Beam configuration not found in config.yaml, skipping installation.")
        return

    prev_dir = os.getcwd()
    try:
        print(f"\n{'='*80}")
        print(" Installing Focus + Beam-proxy")
        print(f"{'='*80}\n")

        focus_dir = os.path.join(SCRIPT_DIR, "k8s-deploy-node", "federated-search")
        os.chdir(focus_dir)

        provider     = CONFIG.focus.provider
        broker_url   = CONFIG.focus.beam_broker_url

        # Create namespace
        cmd("minikube kubectl -- create namespace federated-search --dry-run=client -o yaml | minikube kubectl -- apply -f -")

        # --- Secret: api-keys (used by focus deployment) ---
        cmd(
            f"minikube kubectl -- create secret generic api-keys"
            f" --namespace federated-search"
            f" --from-literal=FOCUS_API_KEY={CONFIG.focus.focus_api_key}"
            f" --from-literal=DATASET_SERVICE_AUTH_HEADER='{CONFIG.focus.dataset_service_auth_header}'"
            f" --dry-run=client -o yaml | minikube kubectl -- apply -f -"
        )
        print(" Secret 'api-keys' applied")

        # --- Secret: spot-beam-secret (used by beam-proxy: APP_focus_KEY/BEAM_SECRET) ---
        cmd(
            f"minikube kubectl -- create secret generic spot-beam-secret"
            f" --namespace federated-search"
            f" --from-literal=BEAM_SECRET={CONFIG.focus.focus_api_key}"
            f" --dry-run=client -o yaml | minikube kubectl -- apply -f -"
        )
        print(" Secret 'spot-beam-secret' applied")

        # --- Secret: root-crt-pem (projected volume in beam-proxy pod) ---
        root_cert_file = "/tmp/root-crt-pem.pem"
        with open(root_cert_file, "w") as f:
            f.write(CONFIG.focus.root_crt_pem)
        cmd(
            f"minikube kubectl -- create secret generic root-crt-pem"
            f" --namespace federated-search"
            f" --from-file=root.crt.pem={root_cert_file}"
            f" --dry-run=client -o yaml | minikube kubectl -- apply -f -"
        )
        import os as _os
        _os.remove(root_cert_file)
        print(" Secret 'root-crt-pem' applied")

        # --- Secret: private key (skip if secret already exists - user manages it manually) ---
        proxy_private_key_pem = getattr(CONFIG.focus, 'proxy_private_key_pem', '')
        if proxy_private_key_pem:
            _priv_secret_name = "certs"
            try:
                with open("beam.yaml") as _f:
                    import re as _re
                    _m = _re.search(r'secret:\s*\n\s+name:\s+(\S+)', _f.read())
                    if _m:
                        _priv_secret_name = _m.group(1)
            except Exception:
                pass
            _exists = cmd(
                f"minikube kubectl -- get secret {_priv_secret_name} -n federated-search 2>/dev/null",
                exit_on_error=False,
            )
            if _exists == 0:
                print(f" Secret '{_priv_secret_name}' already exists, skipping.")
            else:
                privkey_file = "/tmp/beam-privkey.pem"
                with open(privkey_file, "w") as f:
                    f.write(proxy_private_key_pem)
                cmd(
                    f"minikube kubectl -- create secret generic {_priv_secret_name}"
                    f" --namespace federated-search"
                    f" --from-file=proxy.pem={privkey_file}"
                    f" --dry-run=client -o yaml | minikube kubectl -- apply -f -"
                )
                import os as _os2; _os2.remove(privkey_file)
                print(f" Secret '{_priv_secret_name}' created")
        else:
            print("  WARNING: 'focus.proxy_private_key_pem' not set in config.")
            print("  Beam-proxy pod will fail until this secret is created manually.")

        # --- Focus deployment ---
        # Parse focus.yaml to: strip Secret docs, strip nodeSelector/priorityClassName
        # (nodeSelector: chaimeleon.eu/target: core-services prevents scheduling on minikube)
        with open("focus.yaml", "r") as f:
            focus_raw = f.read()
        focus_docs = [doc for doc in yaml.safe_load_all(focus_raw) if doc and doc.get('kind') != 'Secret']
        for doc in focus_docs:
            if doc.get('kind') == 'Deployment':
                pod_spec = doc['spec']['template']['spec']
                pod_spec.pop('nodeSelector', None)
                pod_spec.pop('priorityClassName', None)
        focus_private = "focus.private.yaml"
        with open(focus_private, "w") as f:
            yaml.dump_all(focus_docs, f, default_flow_style=False)
        cmd(f"minikube kubectl -- apply -n federated-search -f {focus_private}")
        print(f" Focus deployment applied")

        # --- Beam-proxy deployment ---
        # Strip Secret documents (created separately above) before applying
        with open("beam.yaml", "r") as f:
            beam_raw = f.read()
        beam_docs = [doc for doc in beam_raw.split('\n---\n') if 'kind: Secret' not in doc]
        beam_yaml = '\n---\n'.join(beam_docs)
        beam_private = "beam.private.yaml"
        with open(beam_private, "w") as f:
            f.write(beam_yaml)
        cmd(f"minikube kubectl -- apply -n federated-search -f {beam_private}")
        print(f" Beam-proxy deployment + service applied")

        # Wait for pods
        cmd("minikube kubectl -- wait --for=condition=available --timeout=120s"
            " deployment/beam-proxy-deployment -n federated-search || true")
        cmd("minikube kubectl -- wait --for=condition=available --timeout=120s"
            " deployment/focus-deployment -n federated-search || true")

        print(f"\n Federated search installed successfully!")
        print(f"   Beam app ID: focus.{provider}.broker.eucaim.cancerimage.eu")
        print(f"   Broker: {broker_url}")

    finally:
        os.chdir(prev_dir)


def install_qpi(CONFIG):
    '''
    Placeholder for installing the qpi service.
    '''
    # TODO: Implement the installation steps for qpi service
    pass

def install_jobman_service(CONFIG, auth_client_secrets: Auth_client_secrets):
    '''Install Jobman service for managing batch jobs'''
    prev_dir = os.getcwd()
    try:
        print(f"\n{'='*80}")
        print(" Installing Jobman Service")
        print(f"{'='*80}\n")

        jobman_dir = os.path.join(SCRIPT_DIR, "k8s-deploy-node", "jobman", "k8s")
        os.chdir(jobman_dir)

        # Read and update webservice.yml
        webservice_file = "webservice.yml"
        with open(webservice_file, 'r') as f:
            webservice_content = f.read()

        # Replace <jobman_host> placeholder with actual domain
        webservice_content = webservice_content.replace('<jobman_host>', CONFIG.public_domain)

        # Fix the Service spec: target -> targetPort (source yaml uses 'target' which is not valid K8s)
        webservice_content = webservice_content.replace('target: 8080', 'targetPort: 8080')

        # Read and process settings.json template
        settings_template_file = os.path.join(os.path.expanduser("~"), "mini-node", "jobman-settings.json")
        if os.path.exists(settings_template_file):
            with open(settings_template_file, 'r') as f:
                settings_content = f.read()

            # Replace placeholders in settings.json
            settings_content = settings_content.replace('PUBLIC_DOMAIN', CONFIG.public_domain)
            settings_content = settings_content.replace('CLIENT_JOBMAN_SECRET', auth_client_secrets.CLIENT_JOBMAN_SERVICE_SECRET)

            print(f" Configured settings.json with:")
            print(f"   - Domain: {CONFIG.public_domain}")
            print(f"   - OIDC client secret configured")

            # Replace the placeholder in the ConfigMap with indented JSON
            webservice_content = webservice_content.replace(
                'settings.json: paste_here_the_adapted_settings_json_for_the_web_service_found_in_src',
                f'settings.json: |\n' + '\n'.join('    ' + line for line in settings_content.split('\n'))
            )
        else:
            print(f"  Warning: settings-template.json not found at {settings_template_file}")
            print(f"  You will need to manually configure the webservice-config ConfigMap")

        # Write updated webservice to temporary file
        # Strip Namespace docs - already pre-created above, re-applying them
        # causes patch errors due to stale last-applied-configuration
        yaml_docs = webservice_content.split('\n---\n')
        yaml_docs = [d for d in yaml_docs if 'kind: Namespace' not in d]
        webservice_content = '\n---\n'.join(yaml_docs)

        temp_webservice = "/tmp/jobman-webservice.yaml"
        with open(temp_webservice, 'w') as f:
            f.write(webservice_content)

        # Apply webservice manifests
        # First create namespaces separately to avoid timing issues
        print(f"\n Creating Jobman namespaces...")
        cmd("minikube kubectl -- create namespace jobman-service --dry-run=client -o yaml | minikube kubectl -- apply -f -")
        cmd("minikube kubectl -- create namespace jobman-service-exec --dry-run=client -o yaml | minikube kubectl -- apply -f -")

        # Wait a moment for namespaces to be ready
        print(f" Waiting for namespaces to be ready...")
        time.sleep(2)

        print(f"\n Applying Jobman webservice manifests...")
        cmd(f"minikube kubectl -- apply -f {temp_webservice}")

        # Apply cron-job manifests
        print(f" Applying Jobman cron-job manifests...")
        cron_job_file = "cron-job.yml"
        if os.path.exists(cron_job_file):
            cmd(f"minikube kubectl -- apply -f {cron_job_file}")
        else:
            print(f"  Warning: {cron_job_file} not found")

        # Build and deploy jobman client (works in both minikube and K8s modes)
        jobman_root = os.path.join(SCRIPT_DIR, "k8s-deploy-node", "jobman")
        if os.path.isdir(jobman_root):
            print(f"\n Building Jobman client...")
            _build_cwd = os.getcwd()
            os.chdir(jobman_root)
            if not os.path.isdir("node_modules"):
                print(" Running npm install...")
                os.system("npm install")
            if os.path.exists("release.sh"):
                print(" Running ./release.sh client...")
                os.system("bash release.sh client")
            os.chdir(_build_cwd)
            client_dest = "/var/hostpath-provisioner/data/homes/shared-folder/apps/jobman"
            client_tar = os.path.join(jobman_root, "build", "jobman.tar.gz")
            if os.path.exists(client_tar):
                print(f" Copying jobman client payload to {CONFIG.host_path}/data/homes/shared-folder/apps/jobman/...")
                cmd(f"minikube ssh -- 'sudo mkdir -p {client_dest}'")
                cmd(f"minikube cp {shlex.quote(client_tar)} minikube:{shlex.quote(client_dest + '/')}")
            else:
                print(f"  Warning: {client_tar} not found, client build may have failed")
            client_settings = os.path.join(SCRIPT_DIR, "settings.json")
            if os.path.exists(client_settings):
                cmd(f"minikube cp {shlex.quote(client_settings)} minikube:{shlex.quote(client_dest + '/')}")
                print(f" settings.json copied")
            else:
                print(f"  Warning: settings.json not found at {client_settings}")
                print(f"  Place it at {CONFIG.host_path}/data/homes/shared-folder/apps/jobman/settings.json")
        else:
            print(f"  Warning: jobman repo not found at {jobman_root}")

        # Wait for deployment to be ready
        print(f"\n Waiting for Jobman deployment to be ready...")
        cmd("minikube kubectl -- wait --for=condition=available deployment/jobman-service-deployment -n jobman-service --timeout=180s || true")

        # Show pod status
        print(f"\n Jobman pod status:")
        cmd("minikube kubectl -- get pods -n jobman-service")

        print(f"\n Jobman service installed successfully!")
        print(f" Access at: https://{CONFIG.public_domain}/jobman-service/")

    except Exception as e:
        print(f" Error installing Jobman service: {e}")
    finally:
        os.chdir(prev_dir)

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

    # Wait for API server to be reachable before applying (it may be restarting after OIDC config)
    print(" Waiting for kube-apiserver to be ready...")
    api_waited = 0
    while api_waited < 120:
        api_ok = cmd_output("minikube kubectl -- get --raw=/healthz 2>/dev/null").strip()
        if api_ok == "ok":
            print(f" API server ready")
            break
        time.sleep(5)
        api_waited += 5
        if api_waited % 20 == 0:
            print(f"   Still waiting for API server... ({api_waited}s)")
    else:
        print(f"  Warning: API server may not be ready, proceeding anyway")

    for priority_file in priority_files:
        file_path = os.path.join(priorities_dir, priority_file)
        if os.path.exists(file_path):
            print(f" Applying {priority_file}...")
            # --validate=false avoids a remote openapi fetch that fails when the API
            # server has just restarted (e.g. after OIDC reconfiguration).
            cmd(f"minikube kubectl -- apply --validate=false -f {file_path}", exit_on_error=False)
        else:
            print(f"  Warning: {priority_file} not found, skipping")

    print(f" Pod priority classes applied successfully")

def install_orthanc(CONFIG):
    '''Install Orthanc PACS server - uses dataset-service namespace and shares datalake-data PVC'''
    print(f"\n{'='*80}")
    print(" Installing Orthanc PACS Server")
    print(f"{'='*80}\n")

    prev_dir = os.getcwd()
    try:
        orthanc_dir = os.path.join(SCRIPT_DIR, "k8s-deploy-node", "orthanc")
        os.chdir(orthanc_dir)

        # Create orthanc namespace
        print(" Creating orthanc namespace...")
        cmd("minikube kubectl -- create namespace orthanc --dry-run=client -o yaml | minikube kubectl -- apply -f -")

        # Create all host directories for PVs
        print(" Creating host directories for PVs...")
        for subdir in ["orthanc-storage", "orthanc-db", "keycloak-db", "orthanc-wrapper"]:
            cmd(f"minikube ssh -- 'sudo mkdir -p /var/hostpath-provisioner/orthanc/{subdir}'")
        cmd("minikube ssh -- 'sudo chmod -R 777 /var/hostpath-provisioner/orthanc'")
        # Populate orthanc-wrapper payload from fixed tar file in repo.
        # Expected input: k8s-deploy-node/orthanc/orthanc-wrapper.tar.gz
        wrapper_repo_tar = os.path.join(orthanc_dir, "wrapper", "orthanc-wrapper.tar.gz")
        if not os.path.isfile(wrapper_repo_tar):
            wrapper_repo_tar = os.path.join(orthanc_dir, "orthanc-wrapper.tar.gz")

        wrapper_payload_available = False

        if USE_MINIKUBE:
            wrapper_tar = "/tmp/orthanc-wrapper-seed.tar.gz"
            if os.path.isfile(wrapper_repo_tar):
                print(f" Found orthanc-wrapper payload tar: {wrapper_repo_tar}")
                cmd(f"minikube cp {shlex.quote(wrapper_repo_tar)} minikube:{wrapper_tar}")
                cmd(
                    "minikube ssh -- '"
                    "set -e; "
                    "TARGET=/var/hostpath-provisioner/orthanc/orthanc-wrapper; "
                    "TMP=/tmp/orthanc-wrapper-seed-unpack; "
                    "sudo mkdir -p $TARGET; "
                    "sudo rm -rf $TMP; "
                    "sudo mkdir -p $TMP; "
                    "sudo tar -xzf /tmp/orthanc-wrapper-seed.tar.gz -C $TMP; "
                    "if [ -f $TMP/init_node.sh ]; then "
                    "  SRC=$TMP; "
                    "elif [ -f $TMP/wrapper/init_node.sh ]; then "
                    "  SRC=$TMP/wrapper; "
                    "else "
                    "  FOUND=$(sudo find $TMP -maxdepth 4 -type f -name init_node.sh | head -n1); "
                    "  if [ -n \"$FOUND\" ]; then SRC=$(dirname \"$FOUND\"); else SRC=$TMP; fi; "
                    "fi; "
                    "sudo rm -rf $TARGET/*; "
                    "sudo cp -a $SRC/. $TARGET/; "
                    "sudo chmod +x $TARGET/init_node.sh 2>/dev/null || true; "
                    "sudo chmod +x $TARGET/restart_node_server.sh 2>/dev/null || true; "
                    "sudo chmod +x $TARGET/update_app.sh 2>/dev/null || true; "
                    "sudo chmod -R 755 $TARGET'"
                )
                cmd("rm -f /tmp/orthanc-wrapper-seed.tar.gz", exit_on_error=False)
                cmd("minikube ssh -- 'sudo rm -f /tmp/orthanc-wrapper-seed.tar.gz; sudo rm -rf /tmp/orthanc-wrapper-seed-unpack'", exit_on_error=False)
            else:
                print(
                    "  Warning: orthanc-wrapper payload not found. "
                    "Expected k8s-deploy-node/orthanc/orthanc-wrapper.tar.gz"
                )

            wrapper_payload_available = (
                cmd(
                    "minikube ssh -- 'test -f /var/hostpath-provisioner/orthanc/orthanc-wrapper/init_node.sh'",
                    exit_on_error=False,
                ) == 0
            )
            if not wrapper_payload_available:
                print(
                    "  Warning: /var/hostpath-provisioner/orthanc/orthanc-wrapper/init_node.sh is missing; "
                    "orthanc-wrapper deployment will be skipped"
                )
            else:
                print(" Ensuring Orthanc wrapper Node/Meteor runtime dependencies are installed...")
                wrapper_dep_ret = cmd(
                    "minikube ssh -- '"
                    "WRAPPER_DIR=/var/hostpath-provisioner/orthanc/orthanc-wrapper; "
                    "SERVER_DIR=$WRAPPER_DIR/bundle/programs/server; "
                    "if [ -f \"$SERVER_DIR/package.json\" ]; then "
                    "if ! command -v npm >/dev/null 2>&1; then "
                    "echo \"npm not found on minikube node, installing nodejs/npm...\"; "
                    "sudo apt-get update -qq && sudo apt-get install -y -qq nodejs npm; "
                    "fi; "
                    "cd \"$SERVER_DIR\" && "
                    "if [ -f package-lock.json ]; then "
                    "npm ci --omit=dev --no-audit --no-fund || npm install --omit=dev --no-audit --no-fund; "
                    "else "
                    "npm install --omit=dev --no-audit --no-fund; "
                    "fi && "
                    "npm install --no-save --no-audit --no-fund @meteorjs/reify && "
                    "node -e 'require(\"@meteorjs/reify/lib/runtime\"); console.log(\"reify-ok\")'; "
                    "else "
                    "echo \"WARN: $SERVER_DIR/package.json not found, skipping wrapper dependency bootstrap\"; "
                    "fi'",
                    exit_on_error=False,
                )
                if wrapper_dep_ret != 0:
                    print(
                        "  Warning: could not auto-install orthanc-wrapper dependencies in minikube; "
                        "wrapper pod may fail until dependencies are installed manually"
                    )
                runtime_check_ret = cmd(
                    "minikube ssh -- 'test -f /var/hostpath-provisioner/orthanc/orthanc-wrapper/bundle/programs/server/node_modules/@meteorjs/reify/lib/runtime.js'",
                    exit_on_error=False,
                )
                if runtime_check_ret != 0:
                    print(
                        "  Warning: @meteorjs/reify runtime not found after bootstrap; "
                        "orthanc-wrapper may still fail with missing module errors"
                    )
        elif os.path.isfile(wrapper_repo_tar):
            print(" Orthanc wrapper deployment (SKIP - K8s mode)")
            print("  >> ADMIN: Manually deploy orthanc-wrapper from:")
            print(f"       {wrapper_repo_tar}")
            print(f"       Extract to {CONFIG.host_path}/orthanc/orthanc-wrapper/")
            print(f"       Then install npm dependencies in bundle/programs/server")

        # Copy Lua script from repo into the host-path for Orthanc
        script_source = os.path.join(orthanc_dir, "scripts", "script.lua")
        script_dest = os.path.join(CONFIG.host_path, "orthanc", "orthanc-storage", "scripts", "script.lua")
        if os.path.exists(script_source):
            print(f" Copying script.lua to {script_dest}...")
            cmd(f"sudo mkdir -p {shlex.quote(os.path.dirname(script_dest))}")
            cmd(f"sudo cp {shlex.quote(script_source)} {shlex.quote(script_dest)}")
            cmd(f"sudo chmod 644 {shlex.quote(script_dest)}")
            print(f" script.lua copied successfully")
        else:
            print(f"  Warning: script.lua not found at {script_source}, Orthanc may fail at startup")

        # Apply PVs and PVCs
        if os.path.exists("orthanc-pvc.yaml"):
            print(" Applying Orthanc PVs and PVCs...")
            cmd("minikube kubectl -- apply -f orthanc-pvc.yaml")

        # Create orthanc-secrets from config (idempotent)
        import json as _json
        oc = getattr(CONFIG, 'orthanc', None)
        encryption_key = getattr(oc, 'patient_id_encryption_key', '')
        if oc and oc.db_orthanc_password:
            svc_user = oc.svc_internal_user or 'svc-internal'
            svc_pw   = oc.svc_internal_password or ''
            users_json = _json.dumps({svc_user: svc_pw})
            auth_secret_key_q = shlex.quote(oc.auth_secret_key or '')
            db_orthanc_password_q = shlex.quote(oc.db_orthanc_password or '')
            db_keycloak_password_q = shlex.quote(oc.db_keycloak_password or '')
            kc_admin_user_q = shlex.quote(oc.kc_admin_user or '')
            kc_admin_password_q = shlex.quote(oc.kc_admin_password or '')
            kc_client_secret_q = shlex.quote(oc.kc_client_secret or '')
            svc_user_q = shlex.quote(svc_user)
            svc_pw_q = shlex.quote(svc_pw)
            users_json_q = shlex.quote(users_json)
            encryption_key_q = shlex.quote(encryption_key or '')
            print(" Creating orthanc-secrets...")
            cmd("minikube kubectl -- delete secret orthanc-secrets -n orthanc --ignore-not-found=true")
            cmd(
                f"minikube kubectl -- create secret generic orthanc-secrets"
                f" --namespace=orthanc"
                f" --from-literal=AUTH_SECRET_KEY={auth_secret_key_q}"
                f" --from-literal=DB_ORTHANC_PASSWORD={db_orthanc_password_q}"
                f" --from-literal=DB_KEYCLOAK_PASSWORD={db_keycloak_password_q}"
                f" --from-literal=KC_ADMIN_USER={kc_admin_user_q}"
                f" --from-literal=KC_ADMIN_PASSWORD={kc_admin_password_q}"
                f" --from-literal=KC_CLIENT_SECRET={kc_client_secret_q}"
                f" --from-literal=SVC_INTERNAL_USER={svc_user_q}"
                f" --from-literal=SVC_INTERNAL_PASSWORD={svc_pw_q}"
                f" --from-literal=SVC_INTERNAL_USERS_JSON={users_json_q}"
                f" --from-literal=patient-id-encryption-key={encryption_key_q}"
            )
        else:
            print("  Warning: orthanc secrets not set in config, skipping orthanc-secrets creation")

        # Apply ConfigMap with domain substitution
        if os.path.exists("orthanc-cm.yaml"):
            print(" Applying Orthanc ConfigMap...")
            with open("orthanc-cm.yaml", 'r') as _f:
                _cm_content = _f.read()
            _cm_content = _cm_content.replace("YOURDOMAIN", CONFIG.public_domain)
            _cm_content = _cm_content.replace("ORTHANC_NODE_NAME", CONFIG.orthanc.node_name)

            _orthanc_client_id = 'orthanc'
            if oc and getattr(oc, 'kc_client_id', None):
                _orthanc_client_id = oc.kc_client_id
            _cm_content = _cm_content.replace("ORTHANC_KEYCLOAK_CLIENT_ID", _orthanc_client_id)
            with open("orthanc-cm.private.yaml", 'w') as _f:
                _f.write(_cm_content)
            cmd("minikube kubectl -- apply -f orthanc-cm.private.yaml")

        # Apply deploy YAML with domain substitution for auth-service URLs
        if os.path.exists("orthanc-deploy.yaml"):
            print(" Applying Orthanc Deployments...")
            with open("orthanc-deploy.yaml", 'r') as _f:
                _deploy_content = _f.read()
            _deploy_content = _deploy_content.replace("YOURDOMAIN", CONFIG.public_domain)
            _deploy_docs = [doc for doc in yaml.safe_load_all(_deploy_content) if doc]
            _forced_keycloak_uri = "http://keycloak.keycloak.svc.cluster.local:8080/auth/realms/EUCAIM-NODE/"
            for _doc in _deploy_docs:
                if _doc.get('kind') == 'Deployment' and _doc.get('metadata', {}).get('name') == 'orthanc-auth-service':
                    for _container in _doc.get('spec', {}).get('template', {}).get('spec', {}).get('containers', []):
                        if _container.get('name') != 'auth-service':
                            continue
                        for _env in _container.get('env', []):
                            if _env.get('name') == 'KEYCLOAK_URI':
                                _env['value'] = _forced_keycloak_uri
                                break
            if not wrapper_payload_available:
                _deploy_docs = [
                    doc for doc in _deploy_docs
                    if doc.get('metadata', {}).get('name') not in ('orthanc-wrapper', 'orthanc-wrapper-service')
                ]
            with open("orthanc-deploy.private.yaml", 'w') as _f:
                yaml.safe_dump_all(_deploy_docs, _f, sort_keys=False)
            cmd("minikube kubectl -- apply -f orthanc-deploy.private.yaml")
            cmd(
                "minikube kubectl -- -n orthanc set env deployment/orthanc-auth-service "
                f"KEYCLOAK_URI={_forced_keycloak_uri}",
                exit_on_error=False,
            )

            # Reconcile postgres password on existing persistent DBs so Orthanc can always reconnect
            # after password changes in config.private.yaml.
            if oc and oc.db_orthanc_password:
                print(" Reconciling Orthanc DB password with configured secret...")
                cmd("minikube kubectl -- wait --for=condition=available --timeout=180s deployment/orthanc-db -n orthanc || true")
                sql_pw = (oc.db_orthanc_password or '').replace("'", "''")
                sql_stmt = f"ALTER USER postgres WITH PASSWORD '{sql_pw}';"
                cmd(
                    f"minikube kubectl -- exec -n orthanc deploy/orthanc-db -- "
                    f"psql -U postgres -d postgres -c {shlex.quote(sql_stmt)} || true"
                )

            # Ensure both services reload the current secret/config values.
            # This avoids transient 401 errors between Orthanc and auth-service after updates.
            print(" Restarting Orthanc auth-service and Orthanc to pick up updated secrets/config...")
            cmd("minikube kubectl -- rollout restart deployment/orthanc-auth-service -n orthanc || true")
            cmd("minikube kubectl -- wait --for=condition=available --timeout=180s deployment/orthanc-auth-service -n orthanc || true")
            cmd("minikube kubectl -- rollout restart deployment/orthanc -n orthanc || true")
            cmd("minikube kubectl -- wait --for=condition=available --timeout=180s deployment/orthanc -n orthanc || true")

        # Apply Ingress with domain substitution
        # Delete first to avoid nginx admission webhook rejecting updates on existing host/path combos
        ingress_file = "orthanc-ingress.yaml"
        if os.path.exists(ingress_file):
            update_ingress_host(ingress_file, CONFIG.public_domain)
            cmd("minikube kubectl -- delete ingress -n orthanc --all --ignore-not-found=true")
            cmd(f"minikube kubectl -- apply -f {ingress_file}")
            print(f" Applied Ingress for Orthanc with domain: {CONFIG.public_domain}")
        else:
            print(f"  Warning: {ingress_file} not found")

        # Setup bindfs mounts on the minikube node so that desktops and jobman
        # can access datalake files with symlinks resolved to the real DICOM files.
        if USE_MINIKUBE:
            print(" Setting up bindfs mounts on minikube node...")
            cmd("minikube ssh -- 'sudo apt-get update -qq && sudo apt-get install -y -qq bindfs'")

            # 1. /var/lib/orthanc → actual orthanc storage (needed to resolve symlinks)
            cmd("minikube ssh -- 'sudo mkdir -p /var/lib/orthanc'")
            cmd("minikube ssh -- '"
                "sudo sed -i \"/var\\/lib\\/orthanc/d\" /etc/fstab && "
                "printf \"/var/hostpath-provisioner/orthanc/orthanc-storage"
                "     /var/lib/orthanc  fuse.bindfs  nouser,ro,resolve-symlinks,perms=o+rD  0  2\\n\""
                " | sudo tee -a /etc/fstab > /dev/null'")

            # 2. /mnt/datalake → datalake storage_link with symlinks resolved (for desktops/jobman)
            cmd("minikube ssh -- 'sudo mkdir -p /mnt/datalake /var/hostpath-provisioner/dataset-service/datalake/storage_link'")
            cmd("minikube ssh -- '"
                "sudo sed -i \"/mnt\\/datalake/d\" /etc/fstab && "
                "printf \"/var/hostpath-provisioner/dataset-service/datalake/storage_link"
                "     /mnt/datalake  fuse.bindfs  nouser,ro,resolve-symlinks,perms=o+rD  0  2\\n\""
                " | sudo tee -a /etc/fstab > /dev/null'")

            # 3. /mnt/datasets → datasets (for desktops/jobman)
            cmd("minikube ssh -- 'sudo mkdir -p /mnt/datasets'")
            cmd("minikube ssh -- '"
                "sudo sed -i \"/mnt\\/datasets/d\" /etc/fstab && "
                "printf \"/var/hostpath-provisioner/dataset-service/datasets"
                "  /mnt/datasets  fuse.bindfs  nouser,ro,resolve-symlinks,perms=o+rD  0  2\\n\""
                " | sudo tee -a /etc/fstab > /dev/null'")

            # Reload systemd so it sees the new fstab, then (re)mount all three
            cmd("minikube ssh -- 'sudo systemctl daemon-reload'")
            cmd("minikube ssh -- 'sudo umount /var/lib/orthanc 2>/dev/null || true && sudo mount /var/lib/orthanc'")
            cmd("minikube ssh -- 'sudo umount /mnt/datalake 2>/dev/null || true && sudo mount /mnt/datalake'")
            cmd("minikube ssh -- 'sudo umount /mnt/datasets 2>/dev/null || true && sudo mount /mnt/datasets'")
        else:
            hp = CONFIG.host_path
            print(" SKIP bindfs mounts (K8s mode)")
            print("  >> ADMIN: Set up bindfs mounts manually on your cluster nodes if needed:")
            print(f"      bindfs {hp}/orthanc/orthanc-storage /var/lib/orthanc -o nouser,ro,resolve-symlinks,perms=o+rD")
            print(f"      bindfs {hp}/dataset-service/datalake/storage_link /mnt/datalake -o nouser,ro,resolve-symlinks,perms=o+rD")
            print(f"      bindfs {hp}/dataset-service/datasets /mnt/datasets -o nouser,ro,resolve-symlinks,perms=o+rD")

        print(f" Orthanc installation completed")
        print(f" Access Orthanc at: https://{CONFIG.public_domain}/orthanc (or configured subdomain)")

    finally:
        os.chdir(prev_dir)




def install_clinical_data_sql_db():
    '''Install Clinical Data SQL DB - deploys PostgreSQL database for clinical data'''
    if CONFIG is None:
        raise Exception("CONFIG is None")

    print(f"\n{'='*80}")
    print(" Installing Clinical Data SQL DB")
    print(f"{'='*80}\n")

    prev_dir = os.getcwd()
    try:
        clinical_db_dir = os.path.join(SCRIPT_DIR, "k8s-deploy-node", "clinical-data-sql-db")

        if not os.path.exists(clinical_db_dir):
            print(f"  Warning: clinical-data-sql-db directory not found at {clinical_db_dir}")
            print(f"  Skipping clinical-data-sql-db installation")
            return

        os.chdir(clinical_db_dir)

        # Create namespace
        print(" Creating clinical-data-sql-db namespace...")
        cmd("minikube kubectl -- create namespace clinical-data-sql-db || true")

        # Create host directories on minikube VM if needed
        print(" Creating host directories on minikube VM...")
        cmd("minikube ssh -- 'sudo mkdir -p /var/hostpath-provisioner/clinical-data-sql-db'")
        cmd("minikube ssh -- 'sudo chmod -R 777 /var/hostpath-provisioner/clinical-data-sql-db'")

        # Apply PVC
        if os.path.exists("0-pvc.yaml"):
            print(" Applying persistent volume claims (0-pvc.yaml)...")
            cmd("minikube kubectl -- apply -n clinical-data-sql-db -f 0-pvc.yaml")
        else:
            print("  Warning: 0-pvc.yaml not found, skipping PVC creation")

        # Inject PostgreSQL password from config into deployment file
        db_service_file = "1-db-service.yaml"
        if os.path.exists(db_service_file):
            print(f" Injecting PostgreSQL password from config into {db_service_file}...")
            result_db = update_postgres_password(db_service_file, CONFIG.postgres.db_password)

            # Use the private file if it was created
            if result_db and isinstance(result_db, str):
                db_service_file = result_db

            # Apply database deployment and service
            print(f" Applying database deployment and service ({db_service_file})...")
            cmd(f"minikube kubectl -- apply -n clinical-data-sql-db -f {db_service_file}")
        else:
            print(f"  Warning: {db_service_file} not found, skipping database deployment")

        print(f"\n Clinical Data SQL DB installation completed")
        print(f" Namespace: clinical-data-sql-db")
        print(f" To check status: minikube kubectl -- get all -n clinical-data-sql-db")

    except Exception as e:
        print(f"  Error during clinical-data-sql-db installation: {e}")
    finally:
        os.chdir(prev_dir)


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

    # Apply RBAC roles and bindings
    apply_roles_and_bindings()

    # Create iptables rules for external access (only relevant for minikube)
    if USE_MINIKUBE:
        create_iptables_rules_script()
    else:
        print("Skipping iptables rules (K8s mode)")

    # Try to restore TLS secret from backup (survives minikube delete)
    tls_restored = restore_tls_secret()

    # Always install cert-manager so its CRDs exist (required for Certificate resources)
    cert_manager_available = install_cert_manager(CONFIG)
    CONFIG.cert_manager_available = cert_manager_available
    if not cert_manager_available:
        print("Note: Services will be configured for HTTP-only access")

    # Restore Certificate resource from backup if available (so cert-manager doesn't re-issue)
    if tls_restored and os.path.exists(_TLS_CERT_BACKUP_FILE) and os.path.getsize(_TLS_CERT_BACKUP_FILE) > 0:
        cmd(f"{KUBECTL} apply -f {_TLS_CERT_BACKUP_FILE}", exit_on_error=False)
        print(" TLS Certificate restored from backup")

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

            # Save TLS secret for future reinstalls (only if backup doesn't exist yet)
            if not tls_restored and (not os.path.exists(_TLS_BACKUP_FILE) or not os.path.exists(_TLS_CERT_BACKUP_FILE)):
                save_tls_secret()
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

    # Configure kube-apiserver with OIDC - done AFTER Keycloak so the OIDC issuer URL is reachable
    configure_kube_apiserver_oidc(CONFIG)

    # Clinical Data SQL DB is installed in all flavors
    install_clinical_data_sql_db()

    # Dataset service is installed in micro, mini and standard flavors
    if flavor in ["micro", "mini", "standard"]:
        install_dataset_service(auth_client_secrets.CLIENT_DATASET_SERVICE_SECRET)
        install_dataset_explorer(CONFIG)

    # Package workstation charts and publish to dataset-service (requires dataset-service to be installed)
    if flavor in ["micro", "mini", "standard"]:
        package_workstation_charts(CONFIG)

    # Guacamole is installed in micro, mini and standard flavors
    if flavor in ["micro", "mini", "standard"]:
        install_guacamole(CONFIG, guacamole_user_creator_password, auth_client_secrets)

    # Orthanc PACS server is installed in micro, mini and standard flavors
    if flavor in ["micro", "mini", "standard"]:
        install_orthanc(CONFIG)

    # Configure user management job template (requires guacamole to be installed)
    if flavor in ["micro", "mini", "standard"]:
        configure_user_management_job_template(CONFIG, auth_client_secrets, guacamole_user_creator_password)

    # Kubeapps is installed in micro, mini and standard flavors
    if flavor in ["micro", "mini", "standard"]:
        install_kubeapps(CONFIG, auth_client_secrets.CLIENT_KUBERNETES_SECRET)

    # Focus + Beam-proxy (optional, requires 'focus' section in config)
    if flavor in ["mini", "standard"]:
        install_fed_search(CONFIG)

    # DSWS Operator is installed in micro, mini and standard flavors (requires dataset-service and guacamole)
    if flavor in ["micro", "mini", "standard"]:
        install_dsws_operator(CONFIG, auth_client_secrets, guacamole_user_creator_password)

    # Apply RBAC roles and bindings for OIDC groups
    apply_roles_and_bindings()

    # QPI service (only in standard)
    if flavor == "standard":
        install_qpi(CONFIG)

    # Job manager service (micro, mini and standard)
    if flavor in ["micro", "mini", "standard"]:
        install_jobman_service(CONFIG, auth_client_secrets)

    # FEM Client (mini and standard)
    if flavor in ["mini", "standard"]:
        install_fem_client(CONFIG, auth_client_secrets)

    # Post-installation tasks
    print(f"\n{'='*80}")
    print(" Post-installation: Attempting to update dataset-service kid from running Keycloak...")
    print(f"{'='*80}\n")

    if flavor in ["micro", "mini", "standard"]:
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

    # Save TLS secret for future reinstalls (only if backup doesn't exist yet)
    if getattr(CONFIG, 'cert_manager_available', False):
        if not os.path.exists(_TLS_BACKUP_FILE) or not os.path.exists(_TLS_CERT_BACKUP_FILE):
            save_tls_secret()

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
    parser.add_argument("--k8s", action="store_true",
                        help="Deploy to a real Kubernetes cluster using 'kubectl' instead of 'minikube kubectl --'")
    args = parser.parse_args()

    if args.k8s:
        KUBECTL = "kubectl"
        USE_MINIKUBE = False
        print("K8s mode enabled: using 'kubectl' instead of 'minikube kubectl --'")
        print("Note: minikube-specific operations (ssh, cp, addons) will be skipped.")

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