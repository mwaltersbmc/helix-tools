# Chisel server

Kubernetes manifest for a [chisel](https://github.com/jpillora/chisel) reverse-tunnel server. Clients authenticate with credentials from a `users.json` file mounted from the `chisel-auth` Secret.

Replace placeholders in the manifests before applying.

## Placeholders

| Placeholder | Description |
| ----------- | ----------- |
| `<NAMESPACE>` | Kubernetes namespace (IS namespace) |
| `<CHISEL-ALIAS>` | Ingress hostname clients connect to |
| `<USER>:<PASS>` | Chisel auth credentials in `users.json` and `--auth` |
| `<LOCAL-PORT>` | Local port on the client machine |
| `<TARGET-SERVICE>` | Cluster service name to tunnel to |
| `<TARGET-PORT>` | Port on `<TARGET-SERVICE>` |

## Deploy

```bash
kubectl apply -f chisel-server.yaml -n <NAMESPACE>
kubectl apply -f chisel-ingress -n <NAMESPACE>
```

Update `stringData.users.json` in the Secret (replace `<USER>:<PASS>`). Set `<CHISEL-ALIAS>` in `chisel-ingress` (DNS must resolve to your ingress controller / load balancer).

## Ingress

`chisel-ingress` exposes the server on nginx with long proxy timeouts so WebSocket tunnels stay up. Optional TLS is commented in the manifest — enable it on the Ingress, or terminate HTTPS on an external load balancer.

## Auth file

The server reads `/etc/chisel/users.json` from the Secret. Each entry maps `user:password` to a list of allowed address regexes. An empty string `""` matches all tunnels (full access):

```json
{
  "<USER>:<PASS>": [""]
}
```

## Client

Connect via the ingress hostname (use `http://` if TLS is not enabled):

```bash
chisel client --auth <USER>:<PASS> https://<CHISEL-ALIAS> <LOCAL-PORT>:<TARGET-SERVICE>.<NAMESPACE>.svc.cluster.local:<TARGET-PORT>
```

Example (after substitution):

Connect to IS platform-admin-ext service to allow Developer Studio access to IS server AR TCP port.

```bash
chisel client --auth devstudio:devstudio https://chisel.example.com 10000:platform-admin-ext.is-namespace.svc.cluster.local:46262
```

Install the client from [chisel releases](https://github.com/jpillora/chisel/releases) or `go install github.com/jpillora/chisel@latest`.
