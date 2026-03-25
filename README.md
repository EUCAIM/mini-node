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

### Git Repositories (Auto-cloned during installation)

The installation script automatically clones these repositories when needed:

1. **helm-chart-guacamole**
   - URL: `https://github.com/chaimeleon-eu/helm-chart-guacamole.git`
   - Purpose: Helm chart for Guacamole deployment

2. **upv-node-workstation-images**
   - URL: `https://github.com/EUCAIM/upv-node-workstation-images.git`
   - Purpose: Workstation Docker images and Helm charts

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

### Configuration Templates

The `config.yaml` file is the template — copy it to get started:

```bash
cp config.yaml config.private.yaml
```

Full structure of `config.yaml`:

```yaml
host_path: "/home/ubuntu/minikube-data2/"
  # The path in the host that it is shared to the node services

public_domain: "mininode.imaging.i3m.upv.es"
  # The public domain where the node will be accessible

postgres:
  db_password: "yourdbpassword"
  username: "yourusername"
  database: "yourdatabase"

use_gateway_api: true

tracer:
  url: ""

keycloak:
  admin_username: "admin"
    # The name of the admin user
  admin_password: "supersecret_admin"
    # The password to access the admin console of users management
  db_password: "supersecret_db"
    # The password for the keycloak database user
  admin_emails: "admin@example.com,admin2@example.com"
    # Comma-separated list of admin emails to notify new user registrations
  idp_lsri:
    enabled: "false"
    client_id: "xxxxxxxxx"
    client_secret: "xxxxxxxxx"

# Optional: Platform administrator user (cluster admin)
platform_admin_user:
  username: "platform-admin"
  email: "platform-admin@example.com"
  password: "supersecret_platform_admin"
    # This user will have administrative access to the entire platform

guacamole:
  hostname: "postgresql"
  port: "5432"
  username: "guacamole"
  password: "password"
  database: "guacamole"
  adminPassword: "xxxxxxxxx"

oidc:
  authorization_endpoint: "https://[]/auth/realms/EUCAIM-NODE/protocol/openid-connect/auth"
  jwks_endpoint: "https://[]/auth/realms/EUCAIM-NODE/protocol/openid-connect/certs"
  issuer: "https://[]/auth/realms/EUCAIM-NODE"
  clientID: "guacamole"
  redirect_uri: "https://[]/guacamole/"
  username_claim_type: "preferred_username"
  groups_claim_type: "groups"

letsencrypt:
  email: "admin@i3m.upv.es"
  use_staging: false

focus:
  provider: "YOUR_PROV"
    # Short provider identifier, e.g. 'upv' — used in beam app IDs
  focus_api_key: "changeme"
    # API key for the focus application (from beam broker registration)
  dataset_service_auth_header: "Basic changeme"
    # Authorization header value for dataset-service API calls (Base64 encoded credentials)
  beam_broker_url: "https://broker.eucaim.cancerimage.eu"
    # URL of the EUCAIM beam broker
  root_crt_pem: |
    -----BEGIN CERTIFICATE-----
    REPLACE_WITH_BROKER_ROOT_CA_PEM
    -----END CERTIFICATE-----
    # PEM-encoded root CA certificate of the beam broker (for TLS verification)
  proxy_private_key_pem: |
    -----BEGIN PRIVATE KEY-----
    REPLACE_WITH_PROXY_PRIVATE_KEY_PEM
    -----END PRIVATE KEY-----
    # PEM-encoded private key of this node's beam proxy certificate (not base64, raw PEM)
```

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

## Utility Scripts

### create_guacamole_admin.py
Creates the `guacamole-admin` user in Keycloak if it doesn't exist.

```bash
python3 create_guacamole_admin.py
```

### set_guacamole_admin_password.py
Updates the password for the `guacamole-admin` user in Keycloak.

```bash
python3 set_guacamole_admin_password.py
```

### configure_user_management.py
Reconfigures the user management job template without reinstalling everything.

```bash
python3 configure_user_management.py
```

## Support Modules

- **auth.py** - Authentication client for Keycloak
- **config.py** - Configuration parser and validator
- **keycloak_admin_api.py** - Keycloak Admin API client

## Network Requirements

The installation requires internet access to:
- GitHub (for cloning repositories)
- Docker Hub (for pulling container images)
- Helm chart repositories
- Let's Encrypt (for SSL certificates)

## Troubleshooting

### Common Issues

1. **Missing k8s-deploy-node**: Ensure you've cloned the repository manually
2. **Build failures**: Check that Node.js and Docker are properly installed
3. **SSL certificate issues**: Verify Let's Encrypt email and domain configuration
4. **Resource constraints**: Ensure sufficient CPU/RAM for Minikube

### Logs

Installation logs are written to:
- `install.log` - Main installation log
- Individual component logs in namespace-specific locations

## Security Notes

 **Never commit these files to public repositories:**
- `config.private.yaml`
- `eucaim-node-realm.private.json`
- Any files ending in `.private.*`
- Password files like `guacamole-eucaim-user-creator-password.txt`

## License

[Add your license information here]

## Support

[Add support contact information here]
