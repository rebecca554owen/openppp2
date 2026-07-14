# Documentation Style

> Status: Active
> Type: Governance
> Last verified: a9cfec7

Stable references belong in `docs/README.md` and normally have an English/Chinese pair. Narrow designs, audits,
migration plans, and governance decisions belong in their specialized sections.

Governed documents start with:

```markdown
> Status: Draft
> Type: Design
> Last verified: <commit>
```

`tools/check_docs.py` validates metadata, relative links, and bilingual pairs in the document map. Existing
metadata debt is listed by exact path in `METADATA_GRANDFATHERED.txt`; new documents cannot use directory-wide
exceptions.
