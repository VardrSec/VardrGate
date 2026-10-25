# ADR 0022: Review-only generation and offline traffic hypotheses

Accepted 2026-10-25.

`gen` previously preselected authenticated allow and anonymous deny. An OpenAPI
operation and a captured success cannot justify those permissions. Generated
JSON now uses the existing invalid-decision validation boundary (`TODO`) for
every caller and adds peer/cross-tenant identity templates. This intentionally
changes the CLI scaffolding default; existing cases, policies and importer
library behavior stay compatible.

Optional HAR correlation supplies a separate hypothesis report, scoped to a
declared origin and operation. Values remain in memory and only structural
field names and capture indices leave it. Different credential material is
evidence to investigate identity relationships, never proof of principals.
Ownership, tenancy and permissions require operator confirmation. No live
crawling, automatic credential extraction, or detection engine is introduced.
