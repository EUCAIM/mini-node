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

1. **Python 3** with dependencies
   ```bash
   sudo apt-get install python3 python3-pip python3-yaml
   ```

2. **Git** (version control)
   ```bash
   sudo apt-get install git
   ```

3. **Docker** (container runtime)
   ```bash
   curl -fsSL https://get.docker.com -o get-docker.sh
   sudo sh get-docker.sh
   ```

4. **Minikube** *(only for development/single-node setup — skip if using a production Kubernetes cluster)*
   ```bash
   curl -LO https://storage.googleapis.com/minikube/releases/latest/minikube-linux-amd64
   sudo install minikube-linux-amd64 /usr/local/bin/minikube
   ```

5. For production Kubernetes, ensure **`kubectl`** is installed and your kubeconfig is configured to point to the target cluster:
   ```bash
   # Example: install kubectl
   curl -LO "https://dl.k8s.io/release/$(curl -sL https://dl.k8s.io/release/stable.txt)/bin/linux/amd64/kubectl"
   sudo install kubectl /usr/local/bin/kubectl
   # Verify cluster access
   kubectl cluster-info
   ```

6. **Helm** (Kubernetes package manager)
   ```bash
   curl https://raw.githubusercontent.com/helm/helm/main/scripts/get-helm-3 | bash
   ```

### Required Repositories

Some repositories must be cloned manually before running the installation:

- **This one**
   ```bash
   git clone https://github.com/EUCAIM/mini-node.git
   cd mini-node
   ```

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


### Required Configuration Files

1. **config.private.yaml** - Main configuration file
   - Template: `config.yaml`
   - Contains: domain, passwords, database settings, OIDC configuration, etc.
   
   The first time you must create your own private copy from the template  
   and adjust the values in your copy according to your deployment case using your favorite editor:
   ```
   cp config.yaml config.private.yaml
   nano config.private.yaml
   ```

2. **eucaim-node-realm.private.json** - Keycloak realm configuration
   - Template: `eucaim-node-realm.json`
   - Contains: client secrets, realm settings, identity providers
   
   You don't need to create this one, it is automatically created by the script the first time with random client secrets
   and later, when upgrading, it will be read to keep the same secrets.


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
   - Ensure all required software has been installed *(see [Required Software](#required-software) above)*.
   - Ensure all required repositories has been downloaded *(see [Required Repositories](#required-repositories) above)*.
   - Prepare your private copy of the configuration file *(see [Required Configuration Files](#required-configuration-files) above)*.

2. **Start Minikube** with the host data folder mounted
   ```bash
   minikube start --mount --mount-string="/home/ubuntu/<host-data-path>:/var/hostpath-provisioner"
   ```

3. **Run the installation**
   ```bash
   python3 install.py <flavor>              # flavor: micro | mini | standard
   # or explicitly:
   python3 install.py <flavor> --release minikube
   ```

---

### Option B — Production Kubernetes cluster

1. **Prepare the environment**
   - Ensure all required software has been installed *(see [Required Software](#required-software) above)*.
     Ensure `kubectl` is configured for the target cluster: `kubectl cluster-info`
   - Ensure all required repositories has been downloaded *(see [Required Repositories](#required-repositories) above)*.
   - Prepare your private copy of the configuration file *(see [Required Configuration Files](#required-configuration-files) above)*.
   
2. **Run the installation**
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
