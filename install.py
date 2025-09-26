#! /usr/bin/env python3

import argparse
import enum
import os
import logging
import string
import random
import yaml
import subprocess
from config import *

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
#Specify that the user should be previously logged in GitHub and have the SSH key configured
DEFAULT_CONFIG_FILE_PATH = "config.private.yaml"
K8S_DEPLOY_NODE_REPO = "git@github.com:EUCAIM/k8s-deploy-node.git"
CONFIG = None

def cmd(command, exit_on_error=True):
    print(command)
    ret = os.system(command)
    if exit_on_error and ret != 0: exit(1)
    return ret

def generate_random_password(length: int = 16) -> str:

    alphabet = string.ascii_letters + string.digits
    return ''.join(random.choice(alphabet) for _ in range(length))

# def clone_deployment_repo():
#     cmd("git clone "+ K8S_DEPLOY_NODE_REPO)

def force_cleanup_pvs():
    """Force cleanup of stuck PVs by removing finalizers"""
    print("Force cleaning up stuck PVs...")
    
    # Get all PVs in terminating state
    ret = cmd("minikube kubectl -- get pv --no-headers | grep Terminating", exit_on_error=False)
    if ret == 0:
        # Remove finalizers from stuck PVs
        cmd("minikube kubectl -- patch pv pv-datalake -p '{\"metadata\":{\"finalizers\":null}}' --type=merge || true")
        cmd("minikube kubectl -- patch pv pv-dataset-service-data -p '{\"metadata\":{\"finalizers\":null}}' --type=merge || true")
        cmd("minikube kubectl -- patch pv pv-datasets -p '{\"metadata\":{\"finalizers\":null}}' --type=merge || true")
        cmd("minikube kubectl -- patch pv pv-guacamole-postgresql -p '{\"metadata\":{\"finalizers\":null}}' --type=merge || true")
        cmd("minikube kubectl -- patch pv pv-postgres-data -p '{\"metadata\":{\"finalizers\":null}}' --type=merge || true")
        
        cmd("sleep 5")

def install_keycloak():
    if CONFIG is None: raise Exception()
    keycloak_path = os.path.join(SCRIPT_DIR, "k8s-deploy-node", "keycloak")
    os.chdir(keycloak_path)
    # TODO ADD KUBERNETES PORTFORWARDING TO ACESS KEYCLOAK INGRESS
    # Force cleanup of stuck PVs first
    force_cleanup_pvs()
    
    # Force delete ALL resources in keycloak namespace in correct order
    print("Cleaning up existing Keycloak resources...")
    cmd("minikube kubectl -- delete namespace keycloak --timeout=30s || true")
    
    # Wait for namespace to be completely deleted
    print("Waiting for namespace deletion to complete...")
    cmd("minikube kubectl -- wait --for=delete namespace/keycloak --timeout=60s || true")
    cmd("sleep 10")
    
    # Create namespace and wait for it to be ready
    print("Creating keycloak namespace...")
    cmd("minikube kubectl -- create namespace keycloak")
    cmd("minikube kubectl -- wait --for=condition=ready namespace/keycloak --timeout=30s || true")
    cmd("sleep 5")
    
    # Clean persistent volumes globally with force
    cmd("minikube kubectl -- delete pv --all --timeout=30s --force --grace-period=0 || true")
    
    cmd("minikube kubectl -- label nodes minikube chaimeleon.eu/target=core-services --overwrite")
    cmd("minikube kubectl -- create priorityclass core-services --value=1000 --description='Priority class for core services' || true")
    cmd("minikube kubectl -- create priorityclass core-applications --value=900 --description='Priority class for core applications' || true")

    # Create directories inside minikube and clean them COMPLETELY
    cmd("minikube ssh -- 'sudo rm -rf /var/hostpath-provisioner/keycloak'")
    cmd("minikube ssh -- 'sudo mkdir -p /var/hostpath-provisioner/keycloak/postgres-data'")
    cmd("minikube ssh -- 'sudo mkdir -p /var/hostpath-provisioner/keycloak/themes-data'")
    cmd("minikube ssh -- 'sudo mkdir -p /var/hostpath-provisioner/keycloak/standalone-deployments'")
    cmd("minikube ssh -- 'sudo chmod -R 777 /var/hostpath-provisioner/keycloak/'")

    # Wait a bit to ensure cleanup is complete
    cmd("sleep 10")

    # Inject DB password into dep2_database.yaml
    keycloak_db_file = "dep2_database.yaml"
    with open(keycloak_db_file) as f:
        docs = list(yaml.safe_load_all(f))
    updated = False
    for doc in docs:
        if doc.get("kind") == "Deployment":
            for env in doc["spec"]["template"]["spec"]["containers"][0].get("env", []):
                if env.get("name") == "POSTGRES_PASSWORD":
                    env["value"] = CONFIG.keycloak.db_password
                    updated = True
    if updated:
        with open(keycloak_db_file, 'w') as f:
            yaml.safe_dump_all(docs, f, sort_keys=False)
        print(f"Injected password into POSTGRES_PASSWORD in {keycloak_db_file}")

    # Inject Keycloak deployment env vars
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

    # Download JARs locally first
    jar1_url = "https://github.com/chaimeleon-eu/keycloak-event-listener-email-to-admin/releases/download/v1.0.6/keycloak-event-listener-email-to-admin-1.0.6.jar"
    jar2_url = "https://github.com/chaimeleon-eu/keycloak-required-action-user-validated/releases/download/v1.0.5/keycloak-required-action-user-validated-1.0.5.jar"
    cmd(f"wget -O /tmp/keycloak-event-listener-email-to-admin-1.0.6.jar '{jar1_url}' || true")
    cmd(f"wget -O /tmp/keycloak-required-action-user-validated-1.0.5.jar '{jar2_url}' || true")

    # Copy themes using tar to avoid directory conflicts
    cmd("tar -czf /tmp/themes.tar.gz themes/")
    cmd("minikube cp /tmp/themes.tar.gz minikube:/tmp/")
    cmd("minikube ssh -- 'sudo tar -xzf /tmp/themes.tar.gz -C /var/hostpath-provisioner/keycloak/themes-data/ --strip-components=1'")

    # Copy JARs individually with specific filenames
    cmd("minikube cp /tmp/keycloak-event-listener-email-to-admin-1.0.6.jar minikube:/var/hostpath-provisioner/keycloak/standalone-deployments/")
    cmd("minikube cp /tmp/keycloak-required-action-user-validated-1.0.5.jar minikube:/var/hostpath-provisioner/keycloak/standalone-deployments/")
    # Apply Keycloak deployment manifests - DATABASE FIRST
    cmd("minikube kubectl -- apply -f dep2_database.yaml -n keycloak")
    
    # Wait for database to be ready before deploying Keycloak
    cmd("minikube kubectl -- wait --for=condition=ready pod -l app=db -n keycloak --timeout=300s")
    cmd("sleep 30")  # Additional wait for DB initialization
    
    cmd("minikube kubectl -- apply -f dep3_keycloak_v4.yaml -n keycloak")

    # Update Ingress host
    ingress_file = "dep4_ingress.yaml"
    tls_ingress_file = "dep4_ingress_tls.yaml"
    
    # Choose TLS ingress if Let's Encrypt is configured AND cert-manager is available
    use_tls = (hasattr(CONFIG, 'letsencrypt') and 
               hasattr(CONFIG.letsencrypt, 'email') and 
               CONFIG.letsencrypt.email and
               getattr(CONFIG, 'cert_manager_available', False))
    
    if not getattr(CONFIG, 'cert_manager_available', False):
        print("Note: Using HTTP-only ingress (cert-manager not available)")
    
    selected_ingress = tls_ingress_file if use_tls else ingress_file
    
    with open(selected_ingress) as f:
        ingress_docs = list(yaml.safe_load_all(f))
    updated = False
    for doc in ingress_docs:
        if doc.get("kind") == "Ingress":
            for rule in doc["spec"]["rules"]:
                rule["host"] = CONFIG.public_domain
                updated = True
            # Update TLS section if present
            if "tls" in doc["spec"]:
                for tls_entry in doc["spec"]["tls"]:
                    if "hosts" in tls_entry:
                        tls_entry["hosts"] = [CONFIG.public_domain]
                        updated = True
    if updated:
        with open(selected_ingress, "w") as f:
            yaml.safe_dump_all(ingress_docs, f, sort_keys=False)
        print(f"Injected host into {selected_ingress}")

    cmd(f"minikube kubectl -- apply -f {selected_ingress} -n keycloak")
    
    if use_tls:
        print("TLS certificate will be automatically provisioned by cert-manager")

    os.chdir("..")

def install_dataset_service():
    if CONFIG is None: raise Exception()
    prev_dir = os.getcwd()
    try:
        dataset_dir = os.path.join(SCRIPT_DIR, "k8s-deploy-node", "dataset-service")
        os.chdir(dataset_dir)
        db_service_file = "1-db-service.yaml"
        deployment_file = "2-dataset-service.yaml"

        cmd("minikube kubectl -- create namespace dataset-service || true")
        
        # Create directories inside minikube
        cmd("minikube ssh -- 'sudo mkdir -p /var/hostpath-provisioner/dataset-service/postgres-data'")
        cmd("minikube ssh -- 'sudo mkdir -p /var/hostpath-provisioner/dataset-service/dataset-service-data'")
        cmd("minikube ssh -- 'sudo mkdir -p /var/hostpath-provisioner/dataset-service/datalake'")
        cmd("minikube ssh -- 'sudo mkdir -p /var/hostpath-provisioner/dataset-service/datasets'")
        cmd("minikube ssh -- 'sudo chmod -R 777 /var/hostpath-provisioner/dataset-service/'")

        # 1. Generar contraseña e inyectar en POSTGRES_PASSWORD
        with open(db_service_file) as f:
            docs = list(yaml.safe_load_all(f))
        updated_db = False
        for doc in docs:
            if doc.get("kind") == "Deployment":
                containers = doc["spec"]["template"]["spec"]["containers"]
                for container in containers:
                    for env in container.get("env", []):
                        if env.get("name") == "POSTGRES_PASSWORD":
                            env["value"] = CONFIG.postgres.db_password
                            updated_db = True
        if updated_db:
            with open(db_service_file, 'w') as f:
                yaml.safe_dump_all(docs, f, sort_keys=False)
            print(f"Injected password into POSTGRES_PASSWORD in {db_service_file}")
        else:
            print("Warning: Could not find POSTGRES_PASSWORD to update password.")
        ### IMPORTANTE, EN 2-dataset-service.private.yaml --> env DATASET_SERVICE_CONFIG --> auth --> client --> client_secret hay que añadir el secret de keycloak no aleatorio
        # 2. Inyectar contraseña y tokens en DATASET_SERVICE_CONFIG del deployment
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
                            # 1. Poner la misma password en db.password
                            if "db" in config:
                                config["db"]["password"] = CONFIG.postgres.db_password
                            # 2. Reemplazar XXXXXXXX en self por tokens aleatorios
                            if "self" in config:
                                for key, value in config["self"].items():
                                    if isinstance(value, str) and value == "XXXXXXXX":
                                        config["self"][key] = generate_random_password(16)
                            # 3. Inject Keycloak client secret in auth.client.client_secret
                            if "auth" in config and "client" in config["auth"]:
                                config["auth"]["client"]["client_secret"] = CONFIG.keycloak.client_secret
                            
                            # 4. Replace hardcoded domain with configured public domain
                            config_str = json.dumps(config)
                            config_str = config_str.replace("eucaim-node.i3m.upv.es", CONFIG.public_domain)
                            config = json.loads(config_str)
                            
                            env["value"] = json.dumps(config, indent=2)
                            updated = True
        if updated:
            with open(deployment_file, 'w') as f:
                yaml.safe_dump_all(docs, f, sort_keys=False)
            print(f"Injected password and random tokens into DATASET_SERVICE_CONFIG of {deployment_file}")
        else:
            print("Warning: Could not find DATASET_SERVICE_CONFIG to update password and tokens.")

        # Aplicar recursos
        cmd("minikube kubectl -- apply -f 1-db-service.yaml -n dataset-service")
        cmd("minikube kubectl -- apply -f 0-pvcs.yaml -n dataset-service")
        cmd("minikube kubectl -- apply -f 0-service-account.yaml -n dataset-service")
        cmd(f"minikube kubectl -- apply -f {deployment_file} -n dataset-service")
    finally:
        os.chdir(prev_dir)


def install_guacamole():
    if CONFIG is None: raise Exception()
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
            'postgresPassword': CONFIG.postgres.db_password,
            'username': CONFIG.postgres.username,
            'password': CONFIG.postgres.db_password,
            'database': CONFIG.postgres.database,
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

        with open(guaca_file, 'w') as f:
            yaml.dump(data_pg, f, default_flow_style=False, sort_keys=False, indent=2)

        # 3. Clone custom Helm chart and install Guacamole
        private_post_values = "postgresql-values.yaml"
        cmd("helm uninstall postgresql --namespace guacamole || true")

        cmd(
            f"helm install postgresql oci://registry-1.docker.io/bitnamicharts/postgresql \
             --version 15.5.29 --namespace guacamole -f {private_post_values}"
        )


        chart_dir = "helm-chart-guacamole"
        if not os.path.isdir(chart_dir):
            cmd("git clone https://github.com/chaimeleon-eu/helm-chart-guacamole.git")

        # Install using the cloned chart with private values
        cmd("helm uninstall guacamole --namespace guacamole || true")
        cmd(
            f"helm install guacamole ./{chart_dir} \
             --namespace guacamole -f guacamole-values.yaml "
        )

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

def install_cert_manager_helm(CONFIG):
    """Install cert-manager using Helm (more reliable for image pulling)"""
    print("Installing cert-manager via Helm...")
    
    # Add Jetstack repository
    cmd("helm repo add jetstack https://charts.jetstack.io")
    cmd("helm repo update")
    
    # Install cert-manager
    cmd("helm install cert-manager jetstack/cert-manager --namespace cert-manager --create-namespace --version v1.13.2 --set installCRDs=true")
    
    # Wait for readiness
    cmd("minikube kubectl -- wait --for=condition=ready pod -l app.kubernetes.io/name=cert-manager -n cert-manager --timeout=300s")
    
    # Create Let's Encrypt ClusterIssuer
    create_letsencrypt_issuer(CONFIG)

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

def install_qpi():
    pass

def install_jobman_service():
    if CONFIG is None: raise Exception()
    """
    Placeholder for installing the jobman service.
    """
    # TODO: Implement the installation steps for jobman service
    print("Installing jobman service (not yet implemented)")

def remove_tmp_files():
    if input("Do you want to remove temporary files ? [y/N] ").lower() == "y":
        os.unlink("tmpDir")


FLAVORS = ["micro", "mini", "standard"]

def install(flavor):

    cmd("minikube addons enable ingress")
    
    # Create iptables rules for external access
    create_iptables_rules_script()
    
    # Install cert-manager (needed for TLS certificates)
    cert_manager_available = install_cert_manager(CONFIG)
    
    # Store cert-manager availability for service configurations
    CONFIG.cert_manager_available = cert_manager_available
    if not cert_manager_available:
        print("Note: Services will be configured for HTTP-only access")
    
    # clone_deployment_repo()
    os.chdir("k8s-deploy-node")


    if flavor == "micro":
        install_keycloak()
        install_dataset_service()
        install_guacamole()
        # TO COMPLETE

    if flavor == "mini":
        install_keycloak()
        install_dataset_service()
        install_jobman_service()

        # TO COMPLETE

    if flavor == "standard":
        install_keycloak()
        install_dataset_service()
        install_qpi()
        install_jobman_service()

        # TO COMPLETE


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

