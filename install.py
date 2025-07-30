#! /usr/bin/env python3

import argparse
import enum
import os
import logging
import string
import random
import yaml
from config import *

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
DEFAULT_CONFIG_FILE_PATH = "config.yaml"
K8S_DEPLOY_NODE_REPO = "git@github.com:EUCAIM/k8s-deploy-node.git"

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

def install_keycloak(CONFIG):
    keycloak_path = os.path.join(SCRIPT_DIR, "k8s-deploy-node", "keycloak")
    os.chdir(keycloak_path)
    cmd("minikube kubectl -- create namespace keycloak || true")

    keycloak_db_file = "dep2_database.yaml"
    with open(keycloak_db_file) as f:
        docs = list(yaml.safe_load_all(f))
    updated = False
    for doc in docs:
        if doc.get("kind") == "Deployment":
            containers = doc["spec"]["template"]["spec"]["containers"]
            for container in containers:
                for env in container.get("env", []):
                    if env.get("name") == "POSTGRES_PASSWORD":
                        env["value"] = CONFIG.keycloak.db_password
                        updated = True
    if updated:
        with open(keycloak_db_file, 'w') as f:
            yaml.safe_dump_all(docs, f, sort_keys=False)
        print(f"Injected password into POSTGRES_PASSWORD in {keycloak_db_file}")

    keycloak_deploy_file = "dep3_keycloak_v4.yaml"
    with open(keycloak_deploy_file) as f:
        docs = list(yaml.safe_load_all(f))
    updated = False
    for doc in docs:
        if doc.get("kind") == "Deployment":
            containers = doc["spec"]["template"]["spec"]["containers"]
            for container in containers:
                for env in container.get("env", []):
                    if env.get("name") == "KC_BOOTSTRAP_ADMIN_USERNAME":
                        env["value"] = CONFIG.keycloak.admin_username
                        updated = True
                    if env.get("name") == "KC_BOOTSTRAP_ADMIN_PASSWORD":
                        env["value"] = CONFIG.keycloak.admin_password
                        updated = True
                    if env.get("name") == "KC_DB_PASSWORD":
                        env["value"] = CONFIG.keycloak.db_password
                        updated = True
                    if env.get("name") == "KC_SPI_EVENTS_LISTENER_EMAIL_TO_ADMIN_EMAIL_RECEIVERS":
                        env["value"] = CONFIG.keycloak.admin_emails
                        updated = True
                    if env.get("name") == "KC_HOSTNAME":
                        env["value"] = CONFIG.public_domain
                        updated = True

    if updated:
        with open(keycloak_deploy_file, 'w') as f:
            yaml.safe_dump_all(docs, f, sort_keys=False)
        print(f"Injected config values into {keycloak_deploy_file}")

    cmd("sudo mkdir -p /mnt/data/keycloak/themes-data")
    cmd("minikube kubectl -- apply -f dep0_volumes.yaml -n keycloak")
    cmd("minikube kubectl -- apply -f dep1_init_volumes.yaml -n keycloak")
    cmd("sudo cp -r themes/* /mnt/data/keycloak/themes-data")
    cmd("wget 'https://github.com/chaimeleon-eu/keycloak-event-listener-email-to-admin/releases/download/v1.0.6/keycloak-event-listener-email-to-admin-1.0.6.jar'")
    cmd("wget 'https://github.com/chaimeleon-eu/keycloak-required-action-user-validated/releases/download/v1.0.5/keycloak-required-action-user-validated-1.0.5.jar'")
    cmd("sudo cp *.jar /mnt/data/keycloak/themes-data")
    cmd("minikube kubectl -- apply -f dep2_database.yaml -n keycloak")
    cmd("minikube kubectl -- apply -f dep3_keycloak_v4.yaml -n keycloak")

    ingress_file = "dep4_ingress.yaml"
    with open(ingress_file) as f:
        ingress_docs = list(yaml.safe_load_all(f))
    updated = False
    for doc in ingress_docs:
        if doc.get("kind") == "Ingress":
            for rule in doc["spec"]["rules"]:
                rule["host"] = CONFIG.public_domain
                updated = True
    if updated:
        with open(ingress_file, "w") as f:
            yaml.safe_dump_all(ingress_docs, f, sort_keys=False)
        print(f"Injected host into {ingress_file}")

    cmd("minikube kubectl -- apply -f dep4_ingress.yaml -n keycloak")

    os.chdir("..")
    

def install_dataset_service(CONFIG):
    """
    Installs the dataset service by injecting a randomly generated password into the
    'POSTGRES_PASSWORD' field of the '1-db-service.private.yaml' file and into the
    db.password field of the DATASET_SERVICE_CONFIG environment variable in the deployment.

    Args:
        CONFIG: Configuration object containing installation parameters.
    """
    prev_dir = os.getcwd()
    try:
        dataset_dir = os.path.join(SCRIPT_DIR, "k8s-deploy-node", "dataset-service")
        os.chdir(dataset_dir)
        db_service_file = "1-db-service.yaml"
        deployment_file = "2-dataset-service.yaml"

        cmd("minikube kubectl -- create namespace dataset-service || true")

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
                            env["value"] = json.dumps(config, indent=2)
                            updated = True
        if updated:
            with open(deployment_file, 'w') as f:
                yaml.safe_dump_all(docs, f, sort_keys=False)
            print(f"Injected password and random tokens into DATASET_SERVICE_CONFIG of {deployment_file}")
        else:
            print("Warning: Could not find DATASET_SERVICE_CONFIG to update password and tokens.")

        cmd("minikube kubectl -- apply -f 1-db-service.yaml -n dataset-service")
        cmd("minikube kubectl -- apply -f 0-pvcs.yaml -n dataset-service")
        cmd("minikube kubectl -- apply -f 0-service-account.yaml -n dataset-service")
        cmd(f"minikube kubectl -- apply -f {deployment_file} -n dataset-service")
    finally:
        os.chdir(prev_dir)
        

def install_guacamole(CONFIG):
    prev_dir = os.getcwd()
    try:
        guacamole = os.path.join(SCRIPT_DIR, "k8s-deploy-node", "guacamole")
        os.chdir(guacamole)
        cmd("minikube kubectl -- create namespace guacamole || true")
        cmd("minikube kubectl -- apply -f postgresql-pvc.yaml -n guacamole")

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

        private_post_values = "postgresql-values.yaml"
        cmd("helm uninstall postgresql --namespace guacamole || true")

        cmd(
            f"helm install postgresql oci://registry-1.docker.io/bitnamicharts/postgresql \
             --version 15.5.29 --namespace guacamole -f {private_post_values}"
        )


        chart_dir = "helm-chart-guacamole"
        if not os.path.isdir(chart_dir):
            cmd("git clone https://github.com/chaimeleon-eu/helm-chart-guacamole.git")

        cmd("helm uninstall guacamole --namespace guacamole || true")
        cmd(
            f"helm install guacamole ./{chart_dir} \
             --namespace guacamole -f guacamole-values.yaml "
        )

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

def remove_tmp_files():
    if input("Do you want to remove temporary files ? [y/N] ").lower() == "y":
        os.unlink("tmpDir")


FLAVORS = ["micro", "mini", "standard"]

def install(flavor):
    # clone_deployment_repo()
    os.chdir("k8s-deploy-node")

    if flavor == "micro":
        install_keycloak(CONFIG)
        install_dataset_service(CONFIG)
        install_guacamole(CONFIG)
        # TO COMPLETE

    if flavor == "mini":
        install_keycloak(CONFIG)
        install_dataset_service(CONFIG)
        install_jobman_service(CONFIG)

        # TO COMPLETE

    if flavor == "standard":
        install_keycloak(CONFIG)
        install_dataset_service(CONFIG)
        install_qpi(CONFIG)
        install_jobman_service(CONFIG)

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
