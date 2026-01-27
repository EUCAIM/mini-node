
# EUCAIM Node Installation

This repository contains the installation and configuration scripts for deploying a complete EUCAIM node infrastructure on Kubernetes.

## Overview

The installation script (`install.py`) automates the deployment of:
- Keycloak (authentication/authorization)
- Dataset Service 
- Dataset Explorer 
- Guacamole 
- Jobman
- Harbor (container registry)
- Kubeapps (application management)
- Kubernetes Dashboard
- DSWS Operator (workspace management)
- Traefik 
- cert-manager 

## Prerequisites

### System Requirements

- **Operating System**: Linux (Ubuntu/Debian recommended)
- **Kubernetes**: Minikube or production Kubernetes cluster

### Required Software

The following tools must be installed before running the installation:

1. **Minikube** (for development/single-node setup)
   ```bash
   curl -LO https://storage.googleapis.com/minikube/releases/latest/minikube-linux-amd64
   sudo install minikube-linux-amd64 /usr/local/bin/minikube
   ```

2. **Helm** (Kubernetes package manager)

   #### Ubuntu:
   ```bash
   curl https://raw.githubusercontent.com/helm/helm/main/scripts/get-helm-3 | bash
   ```

   #### Windows:
   1. Download the Helm binary from the [Helm Releases Page](https://github.com/helm/helm/releases).
   2. Extract the binary and add it to your system's PATH.
   3. Verify the installation by running:
      ```bash
      helm version
      ```


3. **Docker** (container runtime)
   ```bash
   curl -fsSL https://get.docker.com -o get-docker.sh
   sudo sh get-docker.sh
   ```

4. **Git** (version control)
   ```bash
   sudo apt-get install git
   ```

5. **Python 3** with dependencies
   ```bash
   sudo apt-get install python3 python3-pip python3-yaml
   ```





### Required Source Code

The following must exist in the installation directory:


1. **config.private.yaml** - Main configuration file
   - Template: `config.yaml`
   - Contains: domain, passwords, database settings, OIDC configuration, etc.

2. **eucaim-node-realm.private.json** - Keycloak realm configuration
   - Template: `eucaim-node-realm.json`
   - Contains: client secrets, realm settings, identity providers



## Installation Steps

1. **Prepare the environment**
   ```bash
   # Clone this repository
   git clone <this-repo-url>
   cd mini-node
   # Clone k8s-deploy-node (mininode branch) and jobman inside mini-node
   git clone --branch mininode git@github.com:EUCAIM/k8s-deploy-node.git
   git clone git@github.com:EUCAIM/jobman.git
   # Ensure dataset-explorer source code is present
   # (should be included in this repository)
   ```

The folder structure should look like this:

```
<working-directory>/
└── mini-node/
   ├── k8s-deploy-node/
   └── jobman/
```

2. **Create configuration files**
   ```bash
   # Copy and edit the configuration template
   cp config.yaml config.private.yaml
   nano config.private.yaml
   
   # Copy and edit the Keycloak realm template
   cp eucaim-node-realm.json eucaim-node-realm.private.json
   nano eucaim-node-realm.private.json
   ```

3. **Run the installation**
   ```bash
   python3 install.py <flavour>
   ```
