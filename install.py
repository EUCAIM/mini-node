#! /usr/bin/env python3

import argparse
import enum
import os
import logging
from config import *

DEFAULT_CONFIG_FILE_PATH = "config.yaml"
K8S_DEPLOY_NODE_REPO = "git@github.com:EUCAIM/k8s-deploy-node.git"

def cmd(command, exit_on_error=True):
    print(command)
    ret = os.system(command)
    if exit_on_error and ret != 0: exit(1)
    return ret


def clone_deployment_repo():
    cmd("git clone "+ K8S_DEPLOY_NODE_REPO)

def install_keycloak(CONFIG):
    os.chdir("keycloak")
    cmd("kubectl apply -f dep0_volumes.yaml")
    cmd("cp -r themes/* "+CONFIG.host_path+"/themes-data/")   # TO DO: confirm path in host where the volume is created by minikube in the previous line
                                                              #        maybe it is required to get some guid generated on creation.
    cmd("wget 'https://github.com/chaimeleon-eu/keycloak-event-listener-email-to-admin/releases/download/v1.0.6/keycloak-event-listener-email-to-admin-1.0.6.jar'")
    cmd("wget 'https://github.com/chaimeleon-eu/keycloak-required-action-user-validated/releases/download/v1.0.5/keycloak-required-action-user-validated-1.0.5.jar'")
    cmd("cp *.jar "+CONFIG.host_path+"/standalone-deployments/")   # TO DO: confirm path in host where the volume is created
                                                                   #        maybe it is required to get some guid generated on creation.
    # TO COMPLETE

    os.chdir("..")

def install_dataset_service(CONFIG):
    # TO DO
    pass

def install_jobman_service(CONFIG):
    # TO DO
    pass

def install_qpi(CONFIG):
    # TO DO
    pass

def remove_tmp_files():
    if input("Do you want to remove temporary files ? [y/N] ").lower() == "y": 
        os.unlink("tmpDir")


FLAVORS = ["micro", "mini", "standard"]

def install(flavor):
    clone_deployment_repo()
    os.chdir("k8s-deploy-node")

    if flavor == "micro":
        install_keycloak(CONFIG)
        install_dataset_service(CONFIG)
        # TO COMPLETE

    if flavor == "mini":
        install_jobman_service(CONFIG)
        # TO COMPLETE

    if flavor == "standard":
        install_qpi(CONFIG)
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
