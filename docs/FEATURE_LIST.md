# Dapptility — Product Feature List and Scope

**Domain:** `dapptility.com`  
**Document version:** 0.2  
**Product type:** Web3 RPC Security Scanner and Productized Security Assessment  
**Initial market:** Blockchain networks and Web3 projects with public EVM RPC endpoints

---

## 1. Product Definition

Dapptility is a web-based platform for assessing the external security posture of blockchain RPC infrastructure. The product supports two customer acquisition paths:

1. **Outbound Assessment:** The Dapptility team performs a limited, non-intrusive review of a publicly documented RPC endpoint, creates a private preliminary report, and responsibly contacts the project's security or infrastructure team.
2. **Self-service Assessment:** A user signs in, submits an RPC endpoint, runs a free preliminary scan, verifies ownership of the domain, pays online, and receives a more comprehensive automated report.

The product should deliver fast, technical, and actionable results without requiring an agent, SSH access, internal credentials, or access to customer infrastructure.

---

## 2. Value Proposition

- Identify exposed RPC methods and infrastructure misconfigurations before they cause an incident.
- Assess HTTP RPC endpoints from an external attacker's perspective (WebSocket in V1).
- Detect sensitive, administrative, or resource-intensive RPC namespaces.
- Distinguish expected public RPC surface from real security findings.
- Provide actionable remediation for Nginx, HAProxy, Envoy, Cloudflare, and Kubernetes Ingress.
- Generate reports suitable for engineering teams and management.
- Require no installed agent, SSH access, or shared secret.

### Primary Landing Page Message

> Secure your blockchain RPC infrastructure before exposure becomes an incident.

### Primary Calls to Action

- `Run a Free RPC Scan`
- `View Sample Report`
- `Request an Expert Review`

---

## 3. Target Users

### Primary Personas

- CTOs and technical co-founders of Web3 projects
- Heads of Infrastructure or Platform Engineering
- DevOps engineers and SREs
- Security engineers
- L1, L2, rollup, appchain, and bridge teams
- Small and medium-sized RPC providers

### Recommended Initial Segment

- EVM JSON-RPC only
- Recently launched networks or projects with small technical teams
- Projects operating an RPC endpoint on their own domain
- Projects with an active mainnet or testnet and a visible operating budget

---

## 4. Outbound Assessment Workflow

### 4.1 Lead Discovery

- Manually create a project record.
- Store project name, website, and network type.
- Store HTTP RPC endpoints (WebSocket endpoints deferred to V1).
- Record the source through which the project was discovered.
- Record funding, launch stage, and approximate team size.
- Calculate and manually adjust a lead score.
- Store technical contacts and responsible disclosure channels.
- Record security policy and bug bounty restrictions.

### 4.2 Pre-scan Safety Review

- Confirm endpoint ownership through official documentation and domain records.
- Detect endpoints operated by third-party providers such as Alchemy, Ankr, Infura, or QuickNode.
- Block or skip outbound scans against third-party provider infrastructure; do not treat provider-hosted URLs as if the project owns the RPC stack.
- Check for `security.txt` and published disclosure instructions.
- Record applicable bug bounty restrictions.
- Select the permitted scan profile for the target.
- Prevent high-risk checks from running automatically.

### 4.3 Limited External Scan

- Run only the `Outbound` scan profile: low-risk, non-intrusive checks.
- Enforce strict request count and request-rate limits.
- Record the scan time and scanner source.
- Store sanitized technical evidence.
- Automatically stop on instability, unexpected errors, or abnormal responses.
- Require manual review before publishing any outbound finding.

### 4.4 Free Private Report

- Generate a private link with a high-entropy token.
- Display the project and affected endpoint.
- Display a clear **What we did / What we did not do** block (scope, limits, no exploitation).
- Display the date, scan profile, and limitations of the review.
- Display an overall security score.
- Display finding counts by severity.
- Reveal at least one confirmed observation.
- Explain which intrusive tests were not performed.
- Support optional report expiration.
- Allow immediate report revocation by an administrator.
- Include a clear CTA for purchasing an extended assessment.

### 4.5 Outreach Management

MVP:

- Generate a personalized email draft from a template.
- Require human approval before sending.
- Use plain text or minimal HTML.
- Do not use tracking pixels in security outreach.
- Record recipient, subject, sending date, and reply status.
- Maintain a do-not-contact list.

Deferred to V1:

- Scheduled follow-ups.
- Full pipeline states (`Draft`, `Sent`, `Replied`, `Interested`, `Paid`, `Closed`) as a productized CRM.

---

## 5. Self-service Assessment Workflow

### 5.1 User Accounts

- Sign up with email.
- Verify email address.
- Sign in and sign out.
- Support a magic link or password recovery flow.
- Require acceptance of Terms of Service and Acceptable Use Policy.
- Display previous scans and reports.
- Support account deletion and data deletion requests via manual administrator fulfillment during MVP (self-serve deletion in V1).

### 5.2 Endpoint Submission

- Submit an HTTP RPC URL.
- Automatically detect Chain ID.
- Detect the network name when possible.
- Fail clearly when Chain ID is unknown or outside the supported network set; do not produce a half-scored report for unsupported chains.
- Validate URL and protocol scheme.
- Block private, internal, reserved, and local targets.
- Protect against SSRF, redirect abuse, and DNS rebinding.
- Block localhost, cloud metadata endpoints, and private IP ranges.
- Limit the number of endpoints per account.
- Remove or mask credentials and tokens found in URLs.

WebSocket URL submission is deferred to V1.

### 5.3 Free Scan

- Run the `Free` scan profile: a limited set of non-intrusive checks.
- Display an overall score.
- Display the number of Critical, High, Medium, Low, and Informational findings.
- Reveal a limited subset of findings.
- Hide full evidence and detailed remediation.
- Display the scan completion time.
- Allow private report sharing of the limited free result.
- Enforce a defined free-scan abuse budget (see Scan Profiles).

### 5.4 Domain Ownership Verification

MVP method:

- DNS TXT record

V1 and later methods:

- Verification file hosted under the target domain
- Email verification on the same organizational domain
- Manual administrator approval
- Well-known URI verification

Required capabilities:

- Generate a random verification token.
- Display step-by-step instructions.
- Automatically verify the DNS TXT record.
- Expire unused verification tokens.
- Record verification time and method.
- Require reverification after important endpoint changes.
- Prevent verification reuse across unrelated domains.

### 5.5 Full Automated Report Purchase

- Select an assessment package.
- Display the exact scope and scan profile before payment.
- Require explicit authorization for the defined test profile.
- Accept USDC payments (MVP).
- Card payments deferred to V1.
- Generate a unique order ID.
- Confirm payments automatically.
- Use secure and idempotent payment webhooks.
- Generate a receipt or simple invoice.
- Handle failed and expired payments.
- Prevent duplicate fulfillment.
- Use a manual refund workflow during MVP.

### 5.6 Full Scan

- Run only after domain verification, authorization, and payment.
- Use the `Authorized-Full` scan profile.
- Display the approved scope and safety limitations.
- Execute scans in isolated worker jobs.
- Provide queueing, timeout, and cancellation.
- Apply a target-specific rate limit.
- Provide an emergency stop for every scan.
- Record a complete audit trail.
- Apply limited retries for temporary failures.
- Prevent concurrent scans against the same endpoint.
- Auto-publish paid self-service findings with confidence labels (`Confirmed`, `Likely`, `Needs Review`).
- Require human confirmation before publishing Critical findings on outbound assessments only.

### 5.7 Full Report Delivery

- Private HTML report.
- Downloadable PDF report.
- Combined executive and technical summary in one report (separate report types in V1).
- Overall security score.
- Findings grouped by severity.
- Clear labeling of expected public RPC surface versus security findings.
- Sanitized technical evidence.
- Impact analysis.
- Actionable remediation guidance.
- Relevant technical references.
- Scan date, scanner version, and scan profile.
- **What we did / What we did not do** scope block on every report.
- Optional report expiration.
- PDF regeneration.

### 5.8 Expert Review Upsell

MVP:

- CTA and request form on the site and in reports.
- Manual sales and fulfillment offline (email, calendar, invoice).

Productized later (after demand is validated):

- Standard service packages with fixed scope.
- Online payment for expert review.
- Optional technical meeting.
- One remediation retest.
- Retest report or confirmation certificate.

---

## 6. Scan Profiles

Every scan must run under exactly one named profile. Profiles define allowed rules, request budgets, and forbidden actions. This matrix is a safety and legal control, not an optional feature.

### 6.1 Profile Matrix

| Capability | Free | Outbound | Authorized-Full |
|---|---|---|---|
| Ownership verification required | No | Manual pre-check | DNS TXT (MVP) |
| Payment required | No | No | Yes |
| Sensitive namespace probes (`debug_*`, `admin_*`, etc.) | Presence only, no expensive calls | Presence only, no expensive calls | Allowed within safe ceilings |
| Rate-limit / batch stress checks | No | No | Limited, authorized only |
| WebSocket checks | No (MVP) | No (MVP) | No (MVP); V1 |
| Human review before publish | No | Yes (all findings) | No (auto-publish with confidence) |
| Max requests per scan | ≤ 40 | ≤ 40 | ≤ 200 |
| Max request rate | ≤ 2 rps | ≤ 1 rps | ≤ 5 rps |
| Max scan duration | 60 seconds | 60 seconds | 5 minutes |

### 6.2 Free-Scan Abuse Budget

- Per account: 10 free scans per rolling 24 hours.
- Per IP: 20 free scans per rolling 24 hours.
- Per domain / endpoint: 3 free scans per rolling 24 hours.
- CAPTCHA after repeated failures or burst behavior.
- Global emergency kill switch stops all new and in-flight scans.

### 6.3 Forbidden Across All Profiles

- Exploitation or proof-of-compromise actions.
- Broad port scanning.
- Public load testing or unbounded concurrency.
- Expensive debug/trace payloads on Free or Outbound.
- Scanning private, reserved, or metadata IP ranges.

---

## 7. EVM Scan Engine

### 7.1 Network Identity and Consistency

- Call `eth_chainId`.
- Call `net_version`.
- Resolve Chain ID against a maintained supported-network list.
- Fail closed for unknown or unsupported chains with a clear user-facing message.
- Call `eth_blockNumber`.
- Detect block lag against a trusted reference endpoint when a reference is available.
- Detect responses from the wrong network.

WebSocket consistency checks are deferred to V1.

### 7.2 Client Exposure

- Call `web3_clientVersion`.
- Detect client name and exact version exposure.
- Flag known outdated versions through a maintained rule database.
- Detect backend and proxy header disclosure.
- Detect debug information in error responses.

### 7.3 RPC Method Exposure and Expected Surface

Expected public surface (informational / not scored as vulnerabilities by default):

- Common read methods such as `eth_blockNumber`, `eth_chainId`, `eth_getBalance`, `eth_call`, `eth_getLogs` (within normal limits).
- `eth_sendRawTransaction` on a public RPC, when intentionally exposed.

Security findings (scored):

- Exposed `debug_*` namespaces.
- Exposed `trace_*` namespaces.
- Exposed `admin_*` namespaces.
- Exposed `personal_*` namespaces.
- Exposed `txpool_*` namespaces when disclosure risk is material.
- Exposed `engine_*` namespaces.
- Client-specific and chain-specific privileged methods.
- Dangerous CORS with credentials combined with sensitive method exposure.

Rules must:

- Distinguish namespace availability from execution of an expensive operation.
- Never send expensive payloads during the Free or Outbound profile.
- Label expected public surface separately from findings in reports.

### 7.4 HTTP and TLS Security

High-signal checks:

- Validate the TLS certificate.
- Confirm hostname matching.
- Detect approaching certificate expiration.
- Check HTTP-to-HTTPS behavior.
- Detect server header disclosure when it reveals backend versions.
- Validate response Content-Type for JSON-RPC.
- Detect dangerous credentialed CORS combinations.

Info-only or lower priority for public RPC APIs (do not over-weight the score):

- HSTS.
- Generic HTTP security headers unrelated to RPC abuse.
- Broad CORS policy review without credentials risk.
- Generic HTTP method handling noise.

### 7.5 Rate Limiting and Abuse Protection

- Detect basic rate limiting with a very small controlled burst (Authorized-Full only for broader checks).
- Review rate-limit response headers.
- Review HTTP `429` behavior.
- Review `Retry-After` behavior.
- Assess request body size and batch-count controls only under Authorized-Full and within a hard safety ceiling.
- Enforce a hard safety ceiling in the scanner regardless of profile.

### 7.6 WebSocket Security

Deferred to V1. When implemented:

- Test basic connection availability.
- Review Origin validation.
- Detect authentication requirements.
- Assess subscription controls within a safe scope.
- Review idle timeout and connection timeout.
- Review message size handling.
- Detect information disclosure in errors.
- Test connection or subscription limits only under an authorized scan profile.

### 7.7 Availability and Resilience

- Measure baseline latency.
- Collect a small sample for approximate p50 and p95 latency.
- Detect inconsistent block height.
- Detect stale endpoints.
- Review DNS records.
- Flag a single DNS or infrastructure endpoint as an informational risk.
- Add status-page correlation later.

### 7.8 Rule Engine

Each rule should include:

- Unique Rule ID
- Title and description
- Category
- Severity
- Confidence level
- Whether the check is `expected_surface`, `finding`, or `info`
- Check implementation version
- Evidence template
- Impact template
- Remediation template
- Technical references
- Enabled/disabled state
- Allowed scan profiles
- Last modification date

---

## 8. Findings and Scoring

- Severity levels: `Critical`, `High`, `Medium`, `Low`, and `Info`.
- Confidence levels: `Confirmed`, `Likely`, and `Needs Review`.
- Overall score from 0 to 100.
- Do not score expected public RPC surface as vulnerabilities.
- Reduce the impact of duplicate or closely related findings.
- Do not publish outbound findings without human confirmation.
- Do not publish outbound Critical findings without human confirmation.

MVP finding states:

- `Open`
- `Confirmed`
- `False Positive`

V1 finding states and workflows:

- `Accepted Risk`
- `Fixed`
- Preserve finding identity between scans.
- Compare an original scan with its remediation retest.

Internal notes for reviewers are available in MVP.

---

## 9. Administration Panel

### Dashboard (MVP)

- Total leads
- Total scans and completed scans
- Reports created
- Purchases (count)

Revenue charts, conversion funnels, and detailed outreach analytics are deferred to V1. Early metrics may live in a spreadsheet.

### Project Management

- Create, read, update, and archive projects.
- Manage HTTP endpoints.
- Add network, project type, and launch-stage tags.
- Manually edit lead score.
- Store responsible disclosure contacts.
- Store basic communication notes.
- Maintain do-not-contact status.
- Flag third-party-provider endpoints and block unsafe outbound scans.

### Scan Management

- Start and stop scans.
- Select an approved scan profile.
- View structured logs.
- View raw results with restricted access and retention limits.
- Confirm or reject findings (outbound).
- Mark false positives.
- Rerun an individual rule.
- Provide a global scan kill switch.

### Report Management

- Create a free preliminary report.
- Create a full paid report.
- Preview before publication.
- Publish and revoke reports.
- Configure expiration.
- Generate PDF.
- Record payment and unlock state.

### User and Order Management

- View users and accounts.
- Review domain verifications.
- Review orders and payments.
- Manually unlock a report.
- Manage refund status.
- Fulfill account and data deletion requests.
- Suspend abusive accounts.
- Record administrator actions in an audit log.

---

## 10. Public Website Pages

MVP:

- Home / Landing Page (include short How It Works and What We Check sections)
- Free RPC Scan
- Pricing
- Sample Report
- Responsible Disclosure Policy
- Terms of Service
- Privacy Policy
- Acceptable Use Policy
- Scan Safety Policy
- Login / Sign Up
- Private Report Viewer
- Payment Result

V1 or later as separate pages if needed:

- Expert Review (productized)
- About
- Contact
- Standalone How It Works / What We Check pages

---

## 11. Email System

### Transactional Emails

MVP:

- Email verification / passwordless login
- Scan completed
- Domain verification instructions
- Domain verified or failed
- Payment confirmed or failed
- Full report ready

V1:

- Scan queued
- Retest completed
- Complete transactional set

### Outbound Emails

- Initial responsible notification
- One manual follow-up
- Request for the correct security contact
- Private report delivery

### Deliverability Requirements

- SPF, DKIM, and DMARC
- Separate human outreach and transactional mail subdomains
- No URL shorteners
- No tracking pixels in security outreach
- Plain text or minimal HTML
- Low-volume, personalized sending
- No bulk outreach without a real confirmed observation
- Do-not-contact handling for commercial communication

---

## 12. Payments and Suggested Pricing

### Free Quick Scan — Free

- One HTTP endpoint
- `Free` profile checks
- Overall score
- Finding counts
- Limited result visibility

### Full Automated Report — Approximately USD 79

- Domain verification
- `Authorized-Full` checks within a clearly defined scope
- Full findings and evidence
- Remediation guidance
- PDF report
- One limited rescan within a defined period, added in V1

### Expert Review — Approximately USD 399–750

- Sold and fulfilled manually during MVP
- Human validation
- Multiple endpoints
- Technical meeting
- Custom remediation guidance
- One retest

### Payment Capabilities

- MVP: USDC on one low-fee network
- V1: Card payments
- Automatic confirmation
- Receipt or simple invoice
- Clear pricing and tax policy

---

## 13. Platform Security

- SSRF protection
- DNS rebinding protection
- Controlled scanner egress
- Blocking of private and reserved IP ranges
- Restricted redirects
- Account, IP, domain, and endpoint rate limits with documented abuse budgets
- CAPTCHA after suspicious behavior
- CSRF protection
- Secure session cookies
- MFA for administrators
- Encryption of sensitive stored data
- Secret management
- Administrative audit logs
- Masking of credentials and API keys in URLs
- Protection of private RPC URLs in reports
- Signed or high-entropy private report URLs
- Backup and restore
- Vulnerability disclosure policy for the product
- Emergency global scan kill switch

### Evidence Retention and Raw-Log Access

- Retain sanitized findings and report content for the life of the customer account or a documented default period.
- Retain raw scanner responses for a short window only (recommended MVP default: 30 days), then delete or further redact.
- Restrict raw-log access to administrators with an audit trail.
- Never expose raw logs in customer-facing free reports.
- Document retention periods in Privacy Policy and Scan Safety Policy.

---

## 14. Non-functional Requirements

- Responsive desktop and mobile interface
- English as the initial product language
- Typical free scan completion in under 60 seconds
- Explicit job timeouts
- Idempotent scan and payment jobs
- Structured logging
- Error tracking
- Health checks
- Basic operational metrics
- Daily database backup
- Minimal operational dependencies
- Initial deployment on one VPS or simple container platform
- No Kubernetes requirement for MVP

---

## 15. High-level Data Model

- `users`
- `projects`
- `endpoints`
- `domain_verifications`
- `scan_profiles`
- `scans`
- `scan_runs`
- `rules`
- `findings`
- `evidence`
- `reports`
- `report_views`
- `orders`
- `payments`
- `contacts`
- `outreach_messages`
- `audit_logs`

`retests` is added in V1 with automated retesting.

---

## 16. Roles and Permissions

### Visitor

- View public pages.
- View the sample report.
- Create an account.

### Registered User

- Add an HTTP endpoint.
- Run a free scan.
- View owned reports.
- Start domain verification.
- Purchase a full report.
- Request expert review via form (manual fulfillment).

### Verified Domain Owner

- Run a purchased full scan.
- View complete evidence and remediation.
- Download PDF reports.

### Administrator

- Manage projects, users, scans, findings, reports, and orders.
- Operate the outbound workflow.
- Confirm outbound findings.
- Fulfill deletion and refund requests.
- Stop individual or all scans.

---

## 17. MVP Feature Set

### P0 — Required for the First Sale

- Landing page with embedded How It Works / What We Check
- Pricing page and sample report
- Email magic-link authentication
- HTTP RPC endpoint submission
- Supported-chain detection with clear failure for unknown chains
- Limited EVM free scan (`Free` profile)
- Simple rule engine with expected-surface vs finding labels
- Security score and finding summary
- Documented scan profile matrix and abuse budgets
- Third-party RPC provider detection for outbound safety
- DNS TXT domain verification
- USDC payment
- Authorized full-scan profile
- Private HTML report with What we did / did not do
- PDF report
- Simple administration panel (no full analytics dashboard)
- Manual creation of outbound projects
- Administrator-operated limited scan
- Private free-report link generation
- Personalized outreach email draft generation
- Manual outbound finding confirmation
- Evidence retention policy and raw-log access controls
- SSRF and scan safety controls including global kill switch
- Terms, Privacy, Acceptable Use, and Scan Safety policies

### MVP Definition of Done

The MVP is complete when:

1. A user can create an account.
2. The user can submit an HTTP RPC endpoint and run a free scan under the `Free` profile.
3. Unsupported or unknown chains fail with a clear message.
4. The user can verify domain ownership using DNS TXT.
5. The user can pay with USDC.
6. A full scan can run under `Authorized-Full` and produce a complete private report with scope disclosure.
7. An administrator can assess an outbound project, skip third-party provider endpoints, and generate a private preliminary report.
8. No high-risk test can run without ownership verification and explicit authorization.
9. Free-scan abuse budgets and the global kill switch are enforced.

---

## 18. V1 — After Initial Customers

- WebSocket endpoint submission and assessment
- File-based domain verification
- Card payments
- Automatic invoices
- Automated retesting and finding identity across scans
- Scan-to-scan comparison
- Multiple endpoints per project
- Advanced rule versioning
- Complete transactional email set
- Outreach CRM states and scheduled follow-ups
- Automated lead scoring
- ChainList data import
- Expanded third-party provider catalog
- Additional remediation templates
- Revenue and conversion dashboard
- Separate executive and technical reports
- Self-serve account and data deletion
- Productized Expert Review checkout and retest workflow

**V1 entry condition:** At least five paying customers or strong evidence of a repeated customer need.

---

## 19. Later Features

- Cosmos/CometBFT support
- Solana support
- Continuous monitoring
- Scheduled scans
- Alerting
- Team accounts and enterprise RBAC
- Public API
- Slack or Discord integration
- CI/CD integration
- Compliance mapping
- White-label reports
- Partner and reseller program
- Bug bounty workflow
- AI-generated explanations with human review
- Standalone marketing pages as traffic justifies them

---

## 20. Explicitly Out of Scope for Now

- Kubernetes for the product's own infrastructure
- Agents installed on customer nodes
- 24/7 monitoring
- Mobile application
- Internal chat
- Marketplace
- Multiple blockchain families in MVP
- Complex organization and team management
- Public API
- Automatic exploitation
- Public load testing
- Broad port scanning
- Bulk email campaigns
- Subscription billing before demand is validated
- WebSocket assessment in MVP
- File-based domain verification in MVP
- Productized Expert Review workflow before demand is validated
- Scoring expected public RPC methods as vulnerabilities

---

## 21. Suggested Milestones

### Milestone 1 — Scanner CLI

- 10–15 low-risk rules including expected-surface labeling
- `Free` and `Outbound` profiles with hard budgets
- Supported-chain list and unknown-chain failure path
- Third-party provider detection stubs
- JSON output
- Tests against controlled RPC endpoints
- Hard safety limits and kill switch

### Milestone 2 — Reports and Admin

- Projects and HTTP endpoints
- Scan execution from the admin panel
- Finding review and confirmation for outbound
- HTML and PDF reports with What we did / did not do
- Private report links
- Evidence retention defaults

### Milestone 3 — Public Self-service

- Landing page
- User accounts
- Free scan with abuse budgets
- Rate limiting
- Abuse prevention

### Milestone 4 — Verification and Payment

- DNS TXT verification
- USDC checkout
- Automatic payment confirmation
- `Authorized-Full` unlock and report delivery

### Milestone 5 — First Sales

- Publish a sample report.
- Identify 20 qualified leads.
- Produce five valid outbound reports (skipping third-party provider endpoints).
- Begin targeted outreach.
- Close the first paying customer.
- Handle Expert Review requests manually if they appear.

---

## 22. Success Metrics

- Number of valid free scans
- Percentage of free scans rejected as unsupported chain or blocked target
- Percentage of users starting domain verification
- Domain verification success rate
- Free-to-paid conversion rate
- Average order value
- Number of outbound reports delivered
- Outreach reply rate
- Outbound-to-paid conversion rate
- False-positive rate (especially expected-surface mislabels)
- Human review time per outbound report
- Refund and dispute rate
- Percentage of customers requesting a retest or expert review

### Initial Targets

- Less than 30 minutes of human work per outbound lead
- Less than 10 minutes of human review for a normal automated report (spot-check, not publish gate)
- At least 5% positive response rate from highly targeted outreach
- At least 2% free-to-paid conversion during early validation
- First sale before starting V1 development

---

## 23. Scope-Control Rule

A new feature may enter active development only when at least one of these conditions is met:

1. A customer has paid for it.
2. At least three independent customers have requested the same capability.
3. It is required for the safety or correct operation of the platform.

Otherwise, the feature remains in the `Later` backlog.
