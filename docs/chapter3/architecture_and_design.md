# Chapter 3: System Architecture & Design

This document details the architectural design, security model, entity relationships, and data workflows of the SecureSDLC Framework, aligning directly with Sections 3, 4, and 5 of `CLAUDE.md`.

---

## 1. High-Level Framework Architecture

The SecureSDLC framework enforces shift-left security and continuous penetration testing throughout all six software development lifecycle phases.

```mermaid
flowchart TD
    subgraph Users ["Actors & Client Tier"]
        Admin["System Admin"]
        PM["Project Manager"]
        Dev["Developer"]
        Pen["Pentester"]
    end

    subgraph AppTier ["Django Application Layer (Web & Core Services)"]
        Auth["Authentication & RBAC<br/>(accounts.permissions)"]
        Projects["Project Management<br/>(projects)"]
        Phases["Phase Gate Engine<br/>(phases.services)"]
        Vulns["Vulnerability Workflow<br/>(vulns.services)"]
        Scans["Scanner Manager<br/>(scans.views)"]
        Dash["Risk Dashboard<br/>(dashboard.services)"]
        Reports["Report Generator<br/>(reports.services)"]
    end

    subgraph AsyncTier ["Asynchronous Worker Layer"]
        Worker["Django-Q2 Cluster<br/>(run_zap_scan task)"]
        ZAPClient["ZAP API Wrapper<br/>(scans.zap_client)"]
    end

    subgraph ExternalTier ["External Security Tools & Targets"]
        ZAP["OWASP ZAP Daemon<br/>(Docker port 8080)"]
        Target["Juice Shop Testbed<br/>(Docker port 3000)"]
    end

    subgraph DataTier ["Persistence & Artifacts"]
        DB[("Relational Database<br/>(SQLite / PostgreSQL)")]
        Media["Media Storage<br/>(media/reports/*.pdf)"]
    end

    Users -->|HTTPS / Session Auth| Auth
    Auth --> Projects
    Auth --> Phases
    Auth --> Vulns
    Auth --> Scans
    Auth --> Dash
    Auth --> Reports

    Projects --> DB
    Phases --> DB
    Vulns --> DB
    Dash --> DB

    Scans -->|Enqueue Scan Job| DB
    Worker -->|Poll Scheduled Jobs| DB
    Worker --> ZAPClient
    ZAPClient -->|REST API Calls| ZAP
    ZAP -->|Active Scan / Spider| Target
    Worker -->|Import Findings & Alerts| DB

    Reports -->|Generate PDF via xhtml2pdf| Media
```

---

## 2. Role-Based Access Control (RBAC) & Use Case Diagram

The system specifies four roles with strictly partitioned capabilities (CLAUDE.md §3).

```mermaid
flowchart LR
    subgraph Actors ["Roles"]
        AdminActor["Admin"]
        PMActor["Project Manager"]
        DevActor["Developer"]
        PenActor["Pentester"]
    end

    subgraph UseCases ["SecureSDLC Capabilities"]
        UC1["Manage Users & System Roles"]
        UC2["Create Projects & SDLC Model"]
        UC3["Manage Project Team Members"]
        UC4["Complete Checklists with Evidence"]
        UC5["Advance Phase (Phase Gate)"]
        UC6["Reopen Phase (Agile Model)"]
        UC7["Register Authorized Scan Targets"]
        UC8["Log Vulnerability Finding"]
        UC9["Transition Finding to Fixed"]
        UC10["Verify / Close / Re-open Finding"]
        UC11["Trigger OWASP ZAP Scan"]
        UC12["Generate & Download PDF Report"]
        UC13["View Project & Global Dashboard"]
    end

    AdminActor --> UC1
    AdminActor --> UC2
    AdminActor --> UC3
    AdminActor --> UC4
    AdminActor --> UC5
    AdminActor --> UC6
    AdminActor --> UC7
    AdminActor --> UC8
    AdminActor --> UC9
    AdminActor --> UC10
    AdminActor --> UC11
    AdminActor --> UC12
    AdminActor --> UC13

    PMActor --> UC2
    PMActor --> UC3
    PMActor --> UC4
    PMActor --> UC5
    PMActor --> UC6
    PMActor --> UC7
    PMActor --> UC12
    PMActor --> UC13

    DevActor --> UC4
    DevActor --> UC9
    DevActor --> UC13

    PenActor --> UC4
    PenActor --> UC7
    PenActor --> UC8
    PenActor --> UC10
    PenActor --> UC11
    PenActor --> UC12
    PenActor --> UC13
```

---

## 3. Data Flow Diagram (DFD)

### Level 0 Context Diagram

```mermaid
flowchart TD
    User["Project Stakeholder<br/>(Admin, PM, Dev, Pentester)"]
    System["SecureSDLC Framework"]
    ZAPDaemon["OWASP ZAP Scanner"]
    JuiceShop["Authorized Scan Target"]

    User -->|"Credentials, Checklists, Findings, Status Transitions"| System
    System -->|"Dashboards, Phase Status, Reports, Findings"| User

    System -->|"Scan Target URL, Spider & Scan Directives"| ZAPDaemon
    ZAPDaemon -->|"HTTP Attacks, Payloads, Probes"| JuiceShop
    JuiceShop -->|"HTTP Responses, Vulnerability Manifestations"| ZAPDaemon
    ZAPDaemon -->|"Raw Scan Alerts, CWEs, Risk Levels"| System
```

### Level 1 Data Flow Diagram (Core Workflows)

```mermaid
flowchart TD
    User["Project Member"]
    
    subgraph D1 ["Data Stores"]
        DS_Projects[("Projects & Phases")]
        DS_Checklists[("Checklist Responses")]
        DS_Vulns[("Vulnerabilities & Events")]
        DS_Scans[("Scan Targets & Runs")]
        DS_Reports[("Audit Records & Reports")]
    end

    P1["1.0 Project Setup & Team Assignment"]
    P2["2.0 Phase Checklist Execution"]
    P3["3.0 Phase Gate Decision Engine"]
    P4["4.0 Target Registration & Validation"]
    P5["5.0 Asynchronous DAST Scan Execution"]
    P6["6.0 Vulnerability Remediation Workflow"]
    P7["7.0 Metrics Aggregation & Reporting"]

    User -->|Define Project & Model| P1
    P1 -->|Store Project & Provision 6 Phases| DS_Projects

    User -->|Submit Evidence & Mark Done| P2
    P2 -->|Save Responses| DS_Checklists

    User -->|Request Phase Gate Advancement| P3
    DS_Checklists -->|Fetch Required Responses| P3
    DS_Vulns -->|Query Open Critical & High Vulns| P3
    P3 -->|Evaluate can_advance & Log Decision| DS_Projects
    P3 -->|Write Audit Log| DS_Reports

    User -->|Register URL with Authorization| P4
    P4 -->|Verify SCAN_ALLOWED_HOSTS| DS_Scans

    User -->|Trigger Scan| P5
    DS_Scans -->|Fetch Target & Re-verify Allowlist| P5
    P5 -->|Execute Background Scan Task| DS_Scans
    P5 -->|Import Alerts as Vulnerabilities| DS_Vulns

    User -->|Transition Status: Open -> Fixed -> Verified -> Closed| P6
    P6 -->|Enforce Role Permission & Transition Rules| DS_Vulns
    P6 -->|Append VulnerabilityEvent Audit Trail| DS_Vulns

    P7 -->|Aggregate Counts & Calculate Risk Score| DS_Vulns
    P7 -->|Generate PDF Report via xhtml2pdf| DS_Reports
    DS_Reports -->|Download Report| User
```

---

## 4. Entity-Relationship Diagram (ERD)

The data model follows CLAUDE.md §4, providing full referential integrity and timestamp tracking.

```mermaid
erDiagram
    USER ||--o{ PROJECT : "creates"
    USER ||--o{ PROJECT_MEMBER : "participates as"
    PROJECT ||--o{ PROJECT_MEMBER : "has team"
    PROJECT ||--|{ PHASE : "contains 6 phases"
    PROJECT ||--o| PHASE : "current_phase pointer"

    PHASE ||--o{ VULNERABILITY : "linked to"
    CHECKLIST_ITEM ||--o{ CHECKLIST_RESPONSE : "answered in"
    PROJECT ||--o{ CHECKLIST_RESPONSE : "records"
    USER ||--o{ CHECKLIST_RESPONSE : "completed by"

    PROJECT ||--o{ GATE_DECISION : "evaluates"
    PHASE ||--o{ GATE_DECISION : "gate target"
    USER ||--o{ GATE_DECISION : "evaluated by"

    PROJECT ||--o{ VULNERABILITY : "belongs to"
    USER ||--o{ VULNERABILITY : "reported by"
    USER ||--o{ VULNERABILITY : "assigned to"
    VULNERABILITY ||--o{ VULNERABILITY_EVENT : "audit history"
    USER ||--o{ VULNERABILITY_EVENT : "transition actor"

    PROJECT ||--o{ SCAN_TARGET : "registers"
    PROJECT ||--o{ SCAN : "runs"
    SCAN_TARGET ||--o{ SCAN : "target for"
    SCAN ||--o{ VULNERABILITY : "imports alerts to"
    USER ||--o{ SCAN : "requested by"

    PROJECT ||--o{ REPORT : "produces"
    USER ||--o{ REPORT : "generated by"

    USER {
        int id PK
        string username
        string role "ADMIN, PM, DEVELOPER, PENTESTER"
        boolean is_staff
    }

    PROJECT {
        int id PK
        string name
        text description
        string sdlc_model "WATERFALL, AGILE"
        int created_by_id FK
        int current_phase_id FK
    }

    PROJECT_MEMBER {
        int id PK
        int project_id FK
        int user_id FK
        string project_role "PM, DEVELOPER, PENTESTER"
    }

    PHASE {
        int id PK
        int project_id FK
        string kind "REQ, DESIGN, CODING, TESTING, DEPLOY, MAINT"
        int order "1 to 6"
        string status "NOT_STARTED, IN_PROGRESS, COMPLETED"
    }

    CHECKLIST_ITEM {
        int id PK
        string phase_kind
        string code "e.g. REQ-01"
        string text
        text guidance
        boolean required
        string owasp_ref
    }

    CHECKLIST_RESPONSE {
        int id PK
        int project_id FK
        int item_id FK
        boolean done
        text evidence
        int completed_by_id FK
        datetime completed_at
    }

    GATE_DECISION {
        int id PK
        int project_id FK
        int phase_id FK
        string action "ADVANCE, REOPEN"
        boolean allowed
        json reasons
        int actor_id FK
        datetime timestamp
    }

    VULNERABILITY {
        int id PK
        int project_id FK
        int phase_id FK
        string title
        text description
        string affected_component
        string cvss_vector
        decimal cvss_score
        string severity "CRITICAL, HIGH, MEDIUM, LOW, INFO"
        string owasp_category "A01 to A10"
        string status "OPEN, FIXED, VERIFIED, CLOSED"
        string source "MANUAL, ZAP"
        int reporter_id FK
        int assignee_id FK
        int scan_id FK
        string zap_alert_id
        date due_date
    }

    VULNERABILITY_EVENT {
        int id PK
        int vulnerability_id FK
        string from_status
        string to_status
        int actor_id FK
        text note
        datetime created_at
    }

    SCAN_TARGET {
        int id PK
        int project_id FK
        string url
        string environment "STAGING, LOCAL_TEST"
        boolean authorization_confirmed
        string authorized_by
        datetime authorized_at
    }

    SCAN {
        int id PK
        int project_id FK
        int target_id FK
        string tool "ZAP"
        string status "QUEUED, RUNNING, DONE, FAILED"
        int requested_by_id FK
        json raw_result
        text error_message
    }

    REPORT {
        int id PK
        int project_id FK
        int generated_by_id FK
        file file "media/reports/*.pdf"
        datetime generated_at
    }
```

---

## 5. Vulnerability Remediation Lifecycle State Machine

Implemented strictly in `vulns/services.py::transition()` (CLAUDE.md §5.3):

```mermaid
stateDiagram-v2
    [*] --> OPEN : Reported by Pentester / Admin (or ZAP Import)

    OPEN --> FIXED : Developer / Admin marks Fixed (remediation code submitted)
    
    FIXED --> VERIFIED : Pentester / Admin confirms fix via re-testing
    FIXED --> OPEN : Pentester / Admin rejects fix (defect reproduced)

    VERIFIED --> CLOSED : Pentester / Admin closes out defect
    VERIFIED --> OPEN : Pentester / Admin reopens (regression detected)

    CLOSED --> [*]
```

---

## 6. Phase Gate Decision Logic

Implemented strictly in `phases/services.py::can_advance()` (CLAUDE.md §5.1):

```mermaid
flowchart TD
    Start["User triggers Phase Gate Advancement"] --> CheckStatus{"Is phase already<br/>COMPLETED?"}
    CheckStatus -- Yes --> BlockCompleted["Blocked: Phase is already completed"]
    CheckStatus -- No --> CheckItems{"Are all required<br/>ChecklistItems done=True<br/>with non-empty evidence?"}
    
    CheckItems -- No --> BlockItems["Blocked: Required checklist items pending or lack evidence"]
    CheckItems -- Yes --> CheckVulns{"Are there any<br/>Critical or High vulns in this phase<br/>with status OPEN or FIXED?"}

    CheckVulns -- Yes --> BlockVulns["Blocked: Unverified Critical/High vulnerabilities exist"]
    CheckVulns -- No --> AllowAdvance["Allowed: Gate Criteria Met"]

    BlockCompleted --> LogDecision["Record GateDecision Audit Entry"]
    BlockItems --> LogDecision
    BlockVulns --> LogDecision
    AllowAdvance --> AdvanceStatus["Mark Phase COMPLETED<br/>Advance next phase to IN_PROGRESS"]
    AdvanceStatus --> LogDecision
    LogDecision --> Finish["Return GateResult (allowed, reasons)"]
```

