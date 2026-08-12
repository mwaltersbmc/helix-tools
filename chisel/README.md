# Chisel server

Kubernetes manifests for a [chisel](https://github.com/jpillora/chisel) reverse-tunnel server. Clients authenticate using a `users.json` file mounted from the `chisel-auth` Secret.

## Overview

Use this when you need access to the BMC Helix IS AR API port without exposing a Kubernetes worker node IP. A chisel server runs in the cluster behind an Ingress. Clients open a WebSocket tunnel to that server and forward a local port to a `service.namespace:port` inside the cluster; applications then connect via the local port.

Replace all placeholders in the manifests before applying.

## Placeholders

| Placeholder | Description |
| ----------- | ----------- |
| `<NAMESPACE>` | Kubernetes namespace (typically the IS namespace) |
| `<CHISEL-ALIAS>` | Ingress hostname that clients connect to |
| `<USER>:<PASS>` | Chisel credentials — used in `users.json` and client `--auth` |
| `<LOCAL-PORT>` | Port bound on the client machine |
| `<TARGET-SERVICE>` | In-cluster service to tunnel to |
| `<TARGET-PORT>` | Port on `<TARGET-SERVICE>` |

## Deploy

Edit the manifests, then apply:

```bash
kubectl apply -f chisel-server.yaml -n <NAMESPACE>
kubectl apply -f chisel-ingress -n <NAMESPACE>
```

Before applying:

- Set `<USER>:<PASS>` in `stringData.users.json` in the Secret.
- Set `<CHISEL-ALIAS>` in `chisel-ingress` — DNS must resolve to your ingress controller or load balancer.

## Ingress

`chisel-ingress` exposes the server through nginx with extended proxy timeouts so long-lived WebSocket tunnels are not dropped. TLS is optional: enable it on the Ingress, or terminate HTTPS on an external load balancer (see commented block in the manifest).

## Auth file

The server reads `/etc/chisel/users.json` from the Secret. Each key is a `user:password` pair; the value is a list of allowed address regexes. An empty string `""` matches all tunnels (full access):

```json
{
  "<USER>:<PASS>": [""]
}
```

## Client

Connect through the ingress hostname (use `http://` if TLS is not enabled):

```bash
chisel client --auth <USER>:<PASS> https://<CHISEL-ALIAS> \
  <LOCAL-PORT>:<TARGET-SERVICE>.<NAMESPACE>.svc.cluster.local:<TARGET-PORT>
```

**Example** — tunnel to the IS `platform-admin-ext` service so Developer Studio, connecting via localhost:10000, can reach the AR TCP port:

```bash
chisel client --auth devstudio:devstudio https://chisel.example.com \
  10000:platform-admin-ext.is-namespace.svc.cluster.local:46262
```

Install the client from [chisel releases](https://github.com/jpillora/chisel/releases) or `go install github.com/jpillora/chisel@latest`.
