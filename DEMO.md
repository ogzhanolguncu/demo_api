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

## 5. A request that never answers (frontline slot test)

`/hang` accepts the request, writes nothing, and waits for the caller to give
up. Each held request occupies one gateway connection and one upstream wait.

```bash
oha -z 60s -c 500 $H/hang &
sleep 5
time curl -s -o /dev/null -w '%{http_code}\n' $H/
```

While the flood runs, check the healthy route:

- fast `200`: frontline absorbs the hold, no finding
- slow or hung: one app is taking gateway slots from the rest

Watch connections, not CPU. CPU stays flat because a hold costs a goroutine and
a socket, not cycles:

```bash
kubectl -n frontline exec deploy/frontline -- sh -c 'ls /proc/1/fd | wc -l'
```

Read the number before, during, and after. If it climbs with `-c` and does not
come back down, the hold is not bounded.

Do not wait out the timeout. The default request timeout is 15 minutes. Growth
with flat CPU is the finding; the deadline only says how long a slot stays
taken.
