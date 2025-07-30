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

## Usage
1. Clone this repository:

`git clone https://github.com/EUCAIM/mini-node.git`<br/>
`cd mini-node`

