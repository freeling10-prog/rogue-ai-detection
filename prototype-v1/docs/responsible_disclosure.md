# Responsible disclosure guidelines

These guidelines are for findings about suspicious or misused AI agents. They adapt coordinated vulnerability disclosure practice (ISO/IEC 29147, the CERT/CC Guide to Coordinated Vulnerability Disclosure, and CISA's coordination program) to behavioral findings. They are a template for a real program, not a statement that this prototype runs one.

## Before you report
- Check the evidence by hand. Confirm the behavior is not explained by a benign cause such as a shared scheduler, an orchestrator, or a known crawler.
- Remove personal data and credentials. Describe observable behavior only.
- Record your confidence honestly (low, medium, high) and what would change it.

## Steps
1. Find a contact. Use the operator's or platform's published security contact. If there is none, use a coordinator such as CISA or CERT/CC.
2. Send a private report with: what was seen, when, how to reproduce the observation, the confidence level, and your contact details.
3. Allow a reasonable response window, agreed in the program policy and extended when the operator is actively working on the issue.
4. Support triage. Answer questions and share a minimal evidence package.
5. Share indicators with trusted partners in a structured form (the STIX 2.1 export in this prototype), after personal data is removed and the operator has had a chance to respond.
6. Publish only aggregate methods and lessons once the issue is addressed or the window ends. Do not publish exploit detail that enables copycats.

## Fairness rules
- Do not name an operator publicly before they have had a route to dispute the finding.
- Do not describe a behavioral flag as proof of malicious intent.
- Correct or withdraw a finding quickly if it is wrong, and tell everyone who received it.

## Report template
- Summary (one sentence)
- Observed behavior and timeline
- Evidence available on request
- Confidence and alternative explanations considered
- Suggested mitigations (least privilege, approval for high-impact actions, logging)
- Reporter contact
