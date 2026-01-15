# Traefik Gateway API Installation

This directory contains the configuration files for installing Traefik as a Gateway API provider in the EUCAIM mininode.

## Overview

Traefik is used as an alternative to nginx-ingress when Gateway API mode is enabled. It provides:
- **Gateway API support**: Native implementation of Kubernetes Gateway API
- **Automatic service discovery**: Kubernetes provider for dynamic routing
- **TLS termination**: Handles HTTPS traffic with certificate management
- **Observability**: Prometheus metrics and access logs

## Files

### traefik-values.yaml
Helm chart values for Traefik installation. Key configurations:
- **Gateway API provider**: Enables Kubernetes Gateway API support
- **LoadBalancer service**: Exposes Traefik on ports 80 (HTTP) and 443 (HTTPS)
- **Dashboard**: IngressRoute for Traefik web UI (for debugging)
- **Metrics**: Prometheus metrics endpoint enabled

### traefik-namespace.yaml
Namespace definition for Traefik deployment (optional, can be created via kubectl).

## Installation

The Traefik installation is handled automatically by the `install_traefik_gateway_api()` function in `install.py` when Gateway API mode is enabled.


### Customization
To customize Traefik behavior, edit `traefik-values.yaml`:
- **Replicas**: Change `deployment.replicas` for high availability
- **Log level**: Adjust `logs.general.level` (DEBUG, INFO, WARN, ERROR)
- **Resources**: Add resource limits/requests under `resources`

## Troubleshooting

### Check Traefik pods
```bash
kubectl get pods -n traefik
kubectl logs -n traefik -l app.kubernetes.io/name=traefik
```

### Verify GatewayClass
```bash
kubectl get gatewayclass
kubectl describe gatewayclass traefik
```

### Check service exposure
```bash
kubectl get svc -n traefik
minikube service list
```

## References
- [Traefik Documentation](https://doc.traefik.io/traefik/)
- [Kubernetes Gateway API](https://gateway-api.sigs.k8s.io/)
- [Traefik Helm Chart](https://github.com/traefik/traefik-helm-chart)
