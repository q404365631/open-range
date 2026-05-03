# OpenRange Cyber Webapp Offense Kind Pack

This directory is a pack-owned Kind lab bundle. It keeps the Kubernetes
deployment artifacts close to the cyber pack instead of importing the old
`open_range` runtime/compiler stack.

Render a local lab bundle:

```bash
python src/openrange/packs/cyber_webapp_offense/kind/render_kind.py \
  --out .openrange-kind/cyber-webapp-offense \
  --flag 'ORANGE{local_kind_flag}'
```

Boot and apply:

```bash
kind create cluster --config .openrange-kind/cyber-webapp-offense/kind-config.yaml
kubectl apply -k .openrange-kind/cyber-webapp-offense
kubectl -n openrange-external exec deploy/sandbox-red -- \
  curl -s http://svc-web.openrange-dmz.svc.cluster.local:8080/openapi.json
```

The lab is intentionally local. The web target models SSRF and command injection
inside the service process; it does not execute host commands or perform
external network fetches.
