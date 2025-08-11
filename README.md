# all-in-one-node
This repository contains scripts and configuration files to automate the deployment of a mini EUCAIM node using Kubernetes and Minikube.
It includes automated installation for Keycloak, Guacamole, and the Dataset Service, with all secrets and configuration injected from a single YAML file.

## Contents
install.py – Main Python script to deploy all services and inject configuration.
config.py – Configuration loader and validation logic.
config.yaml – Example configuration file for secrets, domains, and service parameters.

## Prerequisites
Linux distribution
Python 3.8+
kubectl and minikube installed and configured
Helm installed (helm must be available in your PATH)
GitHub SSH key configured

### Persistent Storage Setup (Recommended)
By default, Minikube’s default hostPath provisioner stores PersistentVolume data inside the Minikube VM/container. When using the Docker driver, this means that the data lives inside the ephemeral Minikube container and will be lost if the cluster is deleted or recreated.

To ensure data is stored on the host machine and survives Minikube restarts, configure a host directory mount at startup so that /var/hostpath-provisioner in Minikube points to a persistent directory on your host.

Example (Linux host):

`minikube start --driver=docker \` <br/>
`--mount \` <br/>
`--mount-string="/home/ubuntu/minikube-data:/var/hostpath-provisioner"`

Example (Windows host):

**Important:** For the mount to work on Windows, the host path must be inside a directory that Docker Desktop has shared with the internal Linux VM. This is configured in Docker Desktop → Settings → Resources → File Sharing.

<pre> ```powershell minikube start --driver=docker ` --mount ` --mount-string="C:/Users/<username>/minikube-data:/var/hostpath-provisioner" ``` </pre>


## Usage
1. Clone this repository:

  `git clone https://github.com/EUCAIM/mini-node.git`<br/>
  `cd mini-node`

2. Edit config.yaml
Fill in your domain, passwords, and other required values.

3. Run the installer:

- micro: Installs Keycloak, Dataset Service, and Guacamole.
- mini: TODO//
- standard: TODO//
