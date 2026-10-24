# ADR 0009 — Policy discovery, and the line it must not cross

- Status: Accepted
- Date: 2026-08-04

## Context

VardrGate's strength and its ceiling are the same property. Because expectations
are declared rather than inferred, findings are trustworthy — but the tool is
silent about every endpoint nobody wrote a policy for. Authoring is the
expensive part, and the teams with the least authorization discipline, who need
this most, are the least likely to pay it.

The obvious fix is to infer more. That is also the fastest way to destroy the
thing being sold. A scanner earns its keep by guessing well and accepts false
positives as the cost; VardrGate earns its keep by never claiming more than it
was told. Merging the two produces a mediocre scanner with a conservative
reputation it no longer deserves.

There is a real distinction available. Discovery can observe *structure* — which
path parameter addresses an object, which response field carries a tenant, which
properties are sensitive. Those are facts about an artifact. What it cannot
observe is *intent*: whether a given caller **should** reach an endpoint is a
business decision recorded nowhere a machine can read.

## Decision

`vardrgate discover --spec openapi.json [--sample response.json] [--out dir]`
proposes one draft policy per operation that addresses an object, inferring the
object identifier, resource type, and — given a captured response body — the
tenant field and sensitive properties. Every inference is explained in a note
printed to stderr, so a reviewer checks reasoning rather than trusting output.

**Every expectation is emitted as the marker `TODO`, and the policy parser
rejects `TODO`.**

That second clause is the whole decision. A default guess — even a plausible one
like `owner: allow, anonymous: deny` — would let someone run a draft unread and
put a heuristic behind a VardrGate finding. Making the placeholder unparseable
means a draft *physically cannot execute* until a person has typed a decision.
The invariant is enforced by the compiler, not promised by documentation, and
`discover_test.go` asserts that every generated draft fails to parse.

The rule generalizes: **inference may inform authoring, never assertion.** Any
future heuristic must land on the side of proposing a policy a human signs, and
never on the side of emitting a finding.

Two consequences for what was borrowed from prior work on heuristic scanning:

- Identifier recognition matches whole normalized names, never substrings.
  Substring matching classifies `username` as an identifier because it contains
  `user`. That noise is free in a prober generating probes and unacceptable in
  a document someone will sign off on.
- Confidence heuristics that judge whether a response "contains real data" by
  size or shape were rejected outright. They are guesses of exactly the kind
  this tool refuses to make.

## Consequences

- The blank-page cost of covering an API drops substantially, without any
  heuristic reaching a finding.
- Draft policies are inert artifacts. A repository full of them tests nothing,
  which is honest: they are proposals, and the coverage report will keep
  reporting those operations as untested until they are completed.
- `discover` is spec-driven and offline. It does not crawl, replay traffic, or
  send a request; `--sample` takes a response body the user captured. Adding
  live discovery later would not change the invariant.
- Drafts for unsafe methods carry `mutating: false`, so they refuse to run even
  after the expectations are filled in, until that is reviewed too (ADR 0008).
- `openapi.Spec.Operations()` is exported so discovery can walk a document
  without duplicating the traversal.
