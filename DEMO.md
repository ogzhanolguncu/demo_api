# Egress demo

Set `H` to the app's host first, for example:

```bash
H=https://local-api-my-app-local.unkey.local
```

## 1. The code (1 min)

Open `main.go`. One handler, six outbound calls. `call` forwards
`X-Unkey-Request-Id`; the analytics call does not.

## 2. One request, every call (3 min)

```bash
curl -s $H/checkout
```

Open the request in Requests. The panel shows a waterfall:

- github, then the slow `delay/1`
- the `503` in red, then the retry
- the receipt
- "x% of this request waited on linked calls"
- no analytics call: it has no id, and we never guess

## 3. Outbound page (1 min)

Every host the app calls, with p50/p95/p99. The analytics call is here.

## 4. A client that pins (2 min)

```bash
curl -s $H/pinned   # failed: certificate signed by unknown authority
curl -s $H/pinned   # ok: the proxy now relays this host untouched
```

The first row is `closed`, then `passthrough`: host and bytes, no path.

## 5. Kill switch (2 min)

```bash
kubectl -n unkey patch configmap egress-override --type merge -p '{"data":{"mode":"off"}}'
curl -s $H/checkout   # still works, nothing under the request
kubectl -n unkey patch configmap egress-override --type merge -p '{"data":{"mode":"observe"}}'
```

## 6. Questions

Open the flow diagram and click the boxes.
