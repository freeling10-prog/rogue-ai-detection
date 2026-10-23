# Ethics and compliance framework

This prototype uses synthetic data only. This document describes the rules a real deployment should adopt before collecting any real data. It is a project policy template, not legal advice. Get legal review for your jurisdiction.

## Principles
- Respect for persons: collect the minimum, protect people who are not the subject of the research, and never publish personal data.
- Beneficence: weigh benefits and harms for every affected party, including operators who may be wrongly flagged.
- Justice: do not target groups or communities because they are easy to observe.
- Respect for law and public interest: follow the law and platform rules, be transparent about methods, and be accountable. These four principles follow the Menlo Report.

## Collector compliance checklist
Complete every item, in writing, before enabling any collector for real data.
- Source is allowed: an official API or data-access program is used where one exists. For EU platforms, check the Digital Services Act Article 40 vetted researcher route.
- Terms of service reviewed for that source. Do not log in or use accounts in ways the terms forbid.
- robots.txt, CAPTCHAs and rate limits are respected. Do not bypass technical access controls.
- Legal review covers computer misuse law (for the United States, the CFAA as interpreted in Van Buren v. United States and hiQ Labs v. LinkedIn), contract claims, and data protection law (for example GDPR).
- Data minimization: collect only the fields in the event schema. Prefer synthetic data, then pseudonymized data, then raw data.
- Pseudonymize identifiers at ingest (see `JSONLFileCollector(pseudonymize_ids=True)`) and redact free text.
- Documented lawful basis and a data protection impact assessment where required.
- Retention limit is set and enforced. Delete data when it is no longer needed.
- Ethics or institutional review where applicable.
- A contact route exists for people to ask questions or object.

## What the code enforces today
- The network collector is a disabled stub that raises an error.
- The importer rejects events with unknown fields, redacts emails, phone numbers and credential-like strings, and can pseudonymize agent ids.
- Events and alerts carry a `synthetic` flag, and exports are labeled synthetic.
- The community report form rejects credentials and email addresses.
- Unsupervised-only evidence is capped at low severity.

## What the code does not enforce
Legal review, lawful-basis analysis, retention, access control, and ethics review are organizational processes. The checklist above is only a record of them.

## Fairness and error handling
- A flag means a behavioral lead for human review. It is not an attribution of intent or identity.
- Track false positives by agent type. Benign automation (scheduled jobs, crawlers, orchestrators) is deliberately included in the synthetic data as a test case.
- Give any operator named in a finding a route to dispute it before any public naming.

## Primary sources
- The Menlo Report (DHS, 2012).
- Van Buren v. United States (2021); hiQ Labs v. LinkedIn (9th Cir. 2022); Meta Platforms v. Bright Data (N.D. Cal. 2024).
- EDPB Guidelines 03/2026 on web scraping in the context of generative AI (draft for consultation). The scope is generative AI training by private entities, so apply by analogy.
- Regulation (EU) 2022/2065 (DSA) Article 40 and Delegated Regulation (EU) 2025/2050.
