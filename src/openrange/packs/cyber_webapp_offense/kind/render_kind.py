from __future__ import annotations

import argparse
import hashlib
import json
import shutil
import textwrap
from pathlib import Path

PACK_ROOT = Path(__file__).resolve().parents[1]
KIND_ROOT = Path(__file__).resolve().parent


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument("--flag", default="ORANGE{kind_cyber_webapp_admin_flag}")
    args = parser.parse_args()

    render(args.out, args.flag)


def render(outdir: Path, flag: str) -> None:
    if outdir.exists():
        shutil.rmtree(outdir)
    outdir.mkdir(parents=True)

    topology = json.loads((KIND_ROOT / "topology.json").read_text(encoding="utf-8"))
    app_source = (PACK_ROOT / "app.py").read_text(encoding="utf-8")
    briefing = (KIND_ROOT / "README.md").read_text(encoding="utf-8")
    red_plan = (KIND_ROOT / "red-reference-plan.json").read_text(encoding="utf-8")

    copy("kind-config.yaml", outdir / "kind-config.yaml")
    write(outdir / "kustomization.yaml", kustomization_yaml())
    write(outdir / "namespaces.yaml", namespaces_yaml())
    write(outdir / "configmaps.yaml", configmaps_yaml(app_source, briefing, red_plan))
    write(outdir / "secrets.yaml", secrets_yaml(flag))
    write(outdir / "deployments.yaml", deployments_yaml())
    write(outdir / "services.yaml", services_yaml())
    write(outdir / "networkpolicies.yaml", networkpolicies_yaml())
    write(outdir / "cilium-policies.yaml", cilium_policies_yaml())
    write(
        outdir / "manifest-summary.json",
        json.dumps(summary(topology, flag), indent=2, sort_keys=True) + "\n",
    )


def copy(name: str, target: Path) -> None:
    target.write_text((KIND_ROOT / name).read_text(encoding="utf-8"), encoding="utf-8")


def write(path: Path, content: str) -> None:
    path.write_text(content.rstrip() + "\n", encoding="utf-8")


def block(value: str, spaces: int) -> str:
    return textwrap.indent(value.rstrip() + "\n", " " * spaces)


def kustomization_yaml() -> str:
    return """\
apiVersion: kustomize.config.k8s.io/v1beta1
kind: Kustomization
resources:
  - namespaces.yaml
  - configmaps.yaml
  - secrets.yaml
  - deployments.yaml
  - services.yaml
  - networkpolicies.yaml
  - cilium-policies.yaml
"""


def namespaces_yaml() -> str:
    return """\
apiVersion: v1
kind: Namespace
metadata:
  name: openrange-external
  labels:
    openrange/zone: external
---
apiVersion: v1
kind: Namespace
metadata:
  name: openrange-dmz
  labels:
    openrange/zone: dmz
---
apiVersion: v1
kind: Namespace
metadata:
  name: openrange-corp
  labels:
    openrange/zone: corp
---
apiVersion: v1
kind: Namespace
metadata:
  name: openrange-data
  labels:
    openrange/zone: data
---
apiVersion: v1
kind: Namespace
metadata:
  name: openrange-management
  labels:
    openrange/zone: management
"""


def configmaps_yaml(app_source: str, briefing: str, red_plan: str) -> str:
    topology = (KIND_ROOT / "topology.json").read_text(encoding="utf-8")
    return f"""\
apiVersion: v1
kind: ConfigMap
metadata:
  name: svc-web-app
  namespace: openrange-dmz
  labels:
    app: svc-web
data:
  app.py: |
{block(app_source, 4)}
---
apiVersion: v1
kind: ConfigMap
metadata:
  name: openrange-cyber-briefing
  namespace: openrange-external
data:
  README.md: |
{block(briefing, 4)}
  topology.json: |
{block(topology, 4)}
  red-reference-plan.json: |
{block(red_plan, 4)}
---
apiVersion: v1
kind: ConfigMap
metadata:
  name: svc-email-mailbox
  namespace: openrange-corp
data:
  support.txt: |
    Subject: Password reset verification

    username=admin
    password=admin
    reset_token=support-reset-2026
---
apiVersion: v1
kind: ConfigMap
metadata:
  name: svc-fileshare-data
  namespace: openrange-data
data:
  finance_docs.txt: |
    public finance index
  exposed-idp-admin-cred.txt: |
    username=admin
    password=admin
"""


def secrets_yaml(flag: str) -> str:
    return f"""\
apiVersion: v1
kind: Secret
metadata:
  name: openrange-range-secrets
  namespace: openrange-dmz
type: Opaque
stringData:
  flag: {json.dumps(flag)}
  idp-admin-password: "admin"
"""


def deployments_yaml() -> str:
    return """\
apiVersion: apps/v1
kind: Deployment
metadata:
  name: svc-web
  namespace: openrange-dmz
  labels:
    app: svc-web
spec:
  replicas: 1
  selector:
    matchLabels:
      app: svc-web
  template:
    metadata:
      labels:
        app: svc-web
        openrange/zone: dmz
        openrange/service-kind: web_app
    spec:
      containers:
        - name: webapp
          image: python:3.14-alpine
          imagePullPolicy: IfNotPresent
          command:
            - python
            - /opt/openrange/app.py
            - --host
            - 0.0.0.0
            - --port
            - "8080"
            - --flag
            - $(OPENRANGE_FLAG)
            - --log
            - /var/log/openrange/requests.jsonl
          env:
            - name: OPENRANGE_FLAG
              valueFrom:
                secretKeyRef:
                  name: openrange-range-secrets
                  key: flag
          ports:
            - containerPort: 8080
              name: http
          volumeMounts:
            - name: app
              mountPath: /opt/openrange
            - name: logs
              mountPath: /var/log/openrange
      volumes:
        - name: app
          configMap:
            name: svc-web-app
        - name: logs
          emptyDir: {}
---
apiVersion: apps/v1
kind: Deployment
metadata:
  name: svc-email
  namespace: openrange-corp
  labels:
    app: svc-email
spec:
  replicas: 1
  selector:
    matchLabels:
      app: svc-email
  template:
    metadata:
      labels:
        app: svc-email
        openrange/zone: corp
        openrange/service-kind: email
    spec:
      containers:
        - name: email
          image: busybox:1.36
          command: ["/bin/sh", "-lc", "httpd -f -p 8025 -h /srv/mail"]
          ports:
            - containerPort: 8025
              name: http
          volumeMounts:
            - name: mailbox
              mountPath: /srv/mail
      volumes:
        - name: mailbox
          configMap:
            name: svc-email-mailbox
---
apiVersion: apps/v1
kind: Deployment
metadata:
  name: svc-fileshare
  namespace: openrange-data
  labels:
    app: svc-fileshare
spec:
  replicas: 1
  selector:
    matchLabels:
      app: svc-fileshare
  template:
    metadata:
      labels:
        app: svc-fileshare
        openrange/zone: data
        openrange/service-kind: fileshare
    spec:
      containers:
        - name: fileshare
          image: busybox:1.36
          command: ["/bin/sh", "-lc", "httpd -f -p 8080 -h /srv/shared"]
          ports:
            - containerPort: 8080
              name: http
          volumeMounts:
            - name: data
              mountPath: /srv/shared
      volumes:
        - name: data
          configMap:
            name: svc-fileshare-data
---
apiVersion: apps/v1
kind: Deployment
metadata:
  name: svc-idp
  namespace: openrange-corp
  labels:
    app: svc-idp
spec:
  replicas: 1
  selector:
    matchLabels:
      app: svc-idp
  template:
    metadata:
      labels:
        app: svc-idp
        openrange/zone: corp
        openrange/service-kind: idp
    spec:
      containers:
        - name: idp
          image: busybox:1.36
          command:
            - /bin/sh
            - -lc
            - >
              mkdir -p /www &&
              echo admin:admin > /www/default-creds.txt &&
              httpd -f -p 8080 -h /www
          ports:
            - containerPort: 8080
              name: http
---
apiVersion: apps/v1
kind: Deployment
metadata:
  name: svc-db
  namespace: openrange-data
  labels:
    app: svc-db
spec:
  replicas: 1
  selector:
    matchLabels:
      app: svc-db
  template:
    metadata:
      labels:
        app: svc-db
        openrange/zone: data
        openrange/service-kind: db
    spec:
      containers:
        - name: db
          image: mysql:8.0
          env:
            - name: MYSQL_ROOT_PASSWORD
              value: rootpass
            - name: MYSQL_DATABASE
              value: app
          ports:
            - containerPort: 3306
              name: mysql
---
apiVersion: apps/v1
kind: Deployment
metadata:
  name: svc-siem
  namespace: openrange-management
  labels:
    app: svc-siem
spec:
  replicas: 1
  selector:
    matchLabels:
      app: svc-siem
  template:
    metadata:
      labels:
        app: svc-siem
        openrange/zone: management
        openrange/service-kind: siem
    spec:
      containers:
        - name: siem
          image: busybox:1.36
          command:
            - /bin/sh
            - -lc
            - >
              mkdir -p /srv/http/siem &&
              touch /srv/http/siem/all.log &&
              httpd -f -p 9200 -h /srv/http/siem
          ports:
            - containerPort: 9200
              name: http
---
apiVersion: apps/v1
kind: Deployment
metadata:
  name: sandbox-red
  namespace: openrange-external
  labels:
    app: sandbox-red
spec:
  replicas: 1
  selector:
    matchLabels:
      app: sandbox-red
  template:
    metadata:
      labels:
        app: sandbox-red
        openrange/zone: external
        openrange/role: red
    spec:
      containers:
        - name: tools
          image: wbitt/network-multitool:alpine-extra
          command: ["/bin/sh", "-lc", "sleep infinity"]
          volumeMounts:
            - name: briefing
              mountPath: /opt/openrange
      volumes:
        - name: briefing
          configMap:
            name: openrange-cyber-briefing
---
apiVersion: apps/v1
kind: Deployment
metadata:
  name: sandbox-blue
  namespace: openrange-management
  labels:
    app: sandbox-blue
spec:
  replicas: 1
  selector:
    matchLabels:
      app: sandbox-blue
  template:
    metadata:
      labels:
        app: sandbox-blue
        openrange/zone: management
        openrange/role: blue
    spec:
      containers:
        - name: tools
          image: wbitt/network-multitool:alpine-extra
          command: ["/bin/sh", "-lc", "sleep infinity"]
"""


def services_yaml() -> str:
    return """\
apiVersion: v1
kind: Service
metadata:
  name: svc-web
  namespace: openrange-dmz
spec:
  selector:
    app: svc-web
  ports:
    - name: http
      port: 8080
      targetPort: 8080
---
apiVersion: v1
kind: Service
metadata:
  name: svc-email
  namespace: openrange-corp
spec:
  selector:
    app: svc-email
  ports:
    - name: http
      port: 8025
      targetPort: 8025
---
apiVersion: v1
kind: Service
metadata:
  name: svc-idp
  namespace: openrange-corp
spec:
  selector:
    app: svc-idp
  ports:
    - name: http
      port: 8080
      targetPort: 8080
---
apiVersion: v1
kind: Service
metadata:
  name: svc-fileshare
  namespace: openrange-data
spec:
  selector:
    app: svc-fileshare
  ports:
    - name: http
      port: 8080
      targetPort: 8080
---
apiVersion: v1
kind: Service
metadata:
  name: svc-db
  namespace: openrange-data
spec:
  selector:
    app: svc-db
  ports:
    - name: mysql
      port: 3306
      targetPort: 3306
---
apiVersion: v1
kind: Service
metadata:
  name: svc-siem
  namespace: openrange-management
spec:
  selector:
    app: svc-siem
  ports:
    - name: http
      port: 9200
      targetPort: 9200
"""


def networkpolicies_yaml() -> str:
    return """\
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: default-deny
  namespace: openrange-dmz
spec:
  podSelector: {}
  policyTypes: ["Ingress", "Egress"]
---
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: allow-red-to-web
  namespace: openrange-dmz
spec:
  podSelector:
    matchLabels:
      app: svc-web
  ingress:
    - from:
        - namespaceSelector:
            matchLabels:
              openrange/zone: external
      ports:
        - protocol: TCP
          port: 8080
  egress:
    - to:
        - namespaceSelector:
            matchLabels:
              openrange/zone: corp
        - namespaceSelector:
            matchLabels:
              openrange/zone: data
        - namespaceSelector:
            matchLabels:
              openrange/zone: management
  policyTypes: ["Ingress", "Egress"]
---
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: allow-blue-management
  namespace: openrange-management
spec:
  podSelector: {}
  ingress:
    - from:
        - namespaceSelector:
            matchLabels:
              openrange/zone: management
  egress:
    - {}
  policyTypes: ["Ingress", "Egress"]
"""


def cilium_policies_yaml() -> str:
    return """\
apiVersion: cilium.io/v2
kind: CiliumNetworkPolicy
metadata:
  name: l7-web-offense-surface
  namespace: openrange-dmz
spec:
  endpointSelector:
    matchLabels:
      app: svc-web
  ingress:
    - fromEndpoints:
        - matchLabels:
            k8s:io.kubernetes.pod.namespace: openrange-external
      toPorts:
        - ports:
            - port: "8080"
              protocol: TCP
          rules:
            http:
              - method: GET
                path: "/"
              - method: GET
                path: "/robots.txt"
              - method: GET
                path: "/openapi.json"
              - method: GET
                path: "/search.*"
              - method: GET
                path: "/records.*"
              - method: GET
                path: "/api/admin.*"
              - method: GET
                path: "/download.*"
              - method: GET
                path: "/fetch.*"
              - method: GET
                path: "/ops.*"
              - method: GET
                path: "/idp/token.*"
              - method: GET
                path: "/vault.*"
              - method: GET
                path: "/siem/events"
---
apiVersion: cilium.io/v2
kind: CiliumNetworkPolicy
metadata:
  name: allow-dns-egress
  namespace: openrange-external
spec:
  endpointSelector: {}
  egress:
    - toEndpoints:
        - matchLabels:
            k8s:io.kubernetes.pod.namespace: kube-system
            k8s:k8s-app: kube-dns
      toPorts:
        - ports:
            - port: "53"
              protocol: UDP
            - port: "53"
              protocol: TCP
"""


def summary(topology: object, flag: str) -> dict[str, object]:
    if not isinstance(topology, dict):
        topology = {}
    services = topology.get("services", [])
    weaknesses = topology.get("weaknesses", [])
    zones = topology.get("zones", [])
    return {
        "pack": "cyber.webapp.offense",
        "runtime": "kind",
        "service_count": len(services) if isinstance(services, list) else 0,
        "weakness_count": len(weaknesses) if isinstance(weaknesses, list) else 0,
        "zone_count": len(zones) if isinstance(zones, list) else 0,
        "flag_hash": hashlib.sha256(flag.encode()).hexdigest(),
        "entrypoint": "http://svc-web.openrange-dmz.svc.cluster.local:8080",
    }


if __name__ == "__main__":
    main()
