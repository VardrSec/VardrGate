# Strict assurance and real-app interface parity

`vampi-parity.json` records 14 successful checks against the existing pinned
VAmPI vulnerable/protected fixtures. It records the product revision, executable
hash and lab revision. No credentials, response values, login bodies or private
book contents are retained.

The integration driver uses the separate lab's reset and database-inspection
helpers. It independently verifies whether a peer changes the victim password,
then resets the fixture before each Gate execution.

- Read assertions and principal preflight agree across the synchronous HTTP API,
  JSON case CLI and offline job envelope in both modes.
- A malformed credential and a valid credential for the wrong principal each
  fail the API preflight with no resource executions or findings, in both modes.
- A YAML policy's `verify:` block and API write verification agree in both
  modes, with an owner control and strict preflight for owner and peer. The
  vulnerable mode finds the peer write; protected mode verifies its denial.

With the lab's two containers running on their documented loopback ports:

```sh
go build -o /tmp/vardrgate ./cmd/vardrgate
python scripts/integration/strict_vampi.py --lab /path/to/vardrgate-lab --gate /tmp/vardrgate --out /tmp/strict-vampi.json
```

Container lifecycle stays explicit: the script starts and stops its Gate process,
but does not start or stop externally managed target services. Resetting the
fixtures is destructive to those disposable lab databases; never point the lab
helpers at a real engagement. This integration exercise is source-informed,
not a blind configuration study or a production-accuracy estimate.
