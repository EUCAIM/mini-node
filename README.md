# EUCAIM Node Installation

This repository contains the installation and configuration scripts for deploying a complete EUCAIM node infrastructure on Kubernetes.

## Overview

The installation script (`install.py`) automates the deployment of:
- Keycloak (authentication/authorization)
- Dataset Service (core data management)
- Dataset Explorer (web frontend)
- Guacamole (remote desktop gateway)
- Harbor (container registry)
- Kubeapps (application management)
- Kubernetes Dashboard
- DSWS Operator (workspace management)
- Traefik (ingress controller)
- cert-manager (SSL certificate management)

## Prerequisites

### System Requirements

- **Operating System**: Linux (Ubuntu/Debian recommended)
- **Kubernetes**: Minikube or production Kubernetes cluster

### Required Software

The following tools must be installed before running the installation:

1. **Minikube** *(only for development/single-node setup — skip if using a production Kubernetes cluster)*
   ```bash
   curl -LO https://storage.googleapis.com/minikube/releases/latest/minikube-linux-amd64
   sudo install minikube-linux-amd64 /usr/local/bin/minikube
   ```

   For production Kubernetes, ensure **`kubectl`** is installed and your kubeconfig is configured to point to the target cluster:
   ```bash
   # Example: install kubectl
   curl -LO "https://dl.k8s.io/release/$(curl -sL https://dl.k8s.io/release/stable.txt)/bin/linux/amd64/kubectl"
   sudo install kubectl /usr/local/bin/kubectl
   # Verify cluster access
   kubectl cluster-info
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


## External Dependencies

### Required Repositories (Manual Setup)

These must be cloned manually before running the installation:

- **k8s-deploy-node** — all Helm charts and Kubernetes manifests
  ```bash
  git clone --branch mininode https://github.com/EUCAIM/k8s-deploy-node.git
  ```

- **jobman** — job manager service *(cloned inside k8s-deploy-node)*
  ```bash
  cd k8s-deploy-node
  git clone --depth 1 --branch v2.2.5 https://github.com/EUCAIM/jobman.git
  ```

- **dataset-explorer** — web frontend *(cloned inside k8s-deploy-node)*
  ```bash
  git clone https://github.com/EUCAIM/dataset-explorer.git
  cd ..
  ```


## Configuration Files

### Required Files

1. **config.private.yaml** - Main configuration file
   - Template: `config.yaml`
   - Contains: domain, passwords, database settings, OIDC configuration, etc.

2. **eucaim-node-realm.private.json** - Keycloak realm configuration
   - Template: `eucaim-node-realm.json`
   - Contains: client secrets, realm settings, identity providers


## Installation Steps

The script supports two deployment targets, selected via the `--release` flag:

| Flag | Target | kubectl command used |
|---|---|---|
| `--release minikube` *(default)* | Minikube single-node VM | `minikube kubectl --` |
| `--release kubernetes` | Production Kubernetes cluster | `kubectl` |

In `--release kubernetes` mode the following minikube-specific steps are **skipped automatically**:
- Minikube ingress addon management
- kube-apiserver OIDC patching (done via SSH into the minikube VM)
- iptables rules for NodePort exposure
- kube-apiserver crash detection and repair

---

### Option A — Minikube (development / single-node)

1. **Prepare the environment**
   ```bash
   # Clone this repository
   git clone <this-repo-url>
   cd <repo-directory>

   # Clone k8s-deploy-node (mininode branch)
   git clone --branch mininode https://github.com/EUCAIM/k8s-deploy-node.git
   cd k8s-deploy-node
   git clone --depth 1 --branch v2.2.5 https://github.com/EUCAIM/jobman.git
   git clone https://github.com/EUCAIM/dataset-explorer.git
   cd ..
   ```

2. **Create configuration files** *(see [Configuration Templates](#configuration-templates) above for the full structure)*
   ```bash
   cp config.yaml config.private.yaml
   nano config.private.yaml

   cp eucaim-node-realm.json eucaim-node-realm.private.json
   nano eucaim-node-realm.private.json
   ```

3. **Start Minikube** with the host data folder mounted
   ```bash
   minikube start --mount --mount-string="/home/ubuntu/<host-data-path>:/var/hostpath-provisioner"
   ```

4. **Run the installation**
   ```bash
   python3 install.py <flavor>              # flavor: micro | mini | standard
   # or explicitly:
   python3 install.py <flavor> --release minikube
   ```

---

### Option B — Production Kubernetes cluster

1. **Prepare the environment** *(same as Minikube — clone repos and config files)*
   ```bash
   git clone <this-repo-url>
   cd <repo-directory>

   git clone --branch mininode https://github.com/EUCAIM/k8s-deploy-node.git
   cd k8s-deploy-node
   git clone --depth 1 --branch v2.2.5 https://github.com/EUCAIM/jobman.git
   git clone https://github.com/EUCAIM/dataset-explorer.git
   cd ..
   ```

2. **Create configuration files** *(see [Configuration Templates](#configuration-templates) above for the full structure)*
   ```bash
   cp config.yaml config.private.yaml
   nano config.private.yaml

   cp eucaim-node-realm.json eucaim-node-realm.private.json
   nano eucaim-node-realm.private.json
   ```

3. **Ensure `kubectl` is configured** for the target cluster
   ```bash
   kubectl cluster-info   # must respond before running install
   ```

4. **Run the installation**
   ```bash
   python3 install.py <flavor> --release kubernetes
   ```

   > **Note:** OIDC configuration for the Kubernetes API server and firewall rules
   > must be set up manually when using a production cluster, as they depend on
   > direct SSH access to the control-plane node (handled automatically only in
   > Minikube mode).



## Security Notes

 **Never commit these files to public repositories:**
- `config.private.yaml`
- `eucaim-node-realm.private.json`
- Any files ending in `.private.*`
- Password files like `guacamole-eucaim-user-creator-password.txt`
