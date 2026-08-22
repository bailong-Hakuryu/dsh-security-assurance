---
status: accepted
---

# v0.1 Service operations are fixed and explicit

The v0.1 Security Service Operation Catalog is exactly `getHealth`, `getCatalog`, `registerRepository`, `updateRepository`, `disableRepository`, `getRepository`, `listRepositories`, `startAssessment`, `getAssessment`, `listAssessments`, `waitForAssessmentRevision`, `resumeAssessment`, `cancelAssessment`, `listFindings`, `getFinding`, `getEvidenceView`, `recordRiskDecision`, `getBundleManifest`, `getAssuranceSubmission`, `requestExport`, `getExport`, and the composition-only `registerAnalyzer`. New behavior requires a named typed operation and contract review; no generic execute, query, CRUD, SQL, or arbitrary tool operation supplements this list.
