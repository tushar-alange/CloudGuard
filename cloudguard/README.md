# CloudGuard: Serverless Security Compliance Scanner

CloudGuard is a cloud-native, event-driven security auditing tool designed to automatically monitor AWS environments for configuration risks, missing multi-factor authentication (MFA), active root access keys, and stale credentials. When a compliance flaw or vulnerability is flagged, CloudGuard aggregates the data and dispatches real-time alerts directly to an administrative inbox.

Built using **AWS SAM (Infrastructure as Code)** and containerized with **Docker** for localized environment testing, the system operates entirely on an ephemeral serverless lifecycle—costing exactly $0.00 to run under the AWS Free Tier.

---

## 🧭 Architectural Flow

```text
[EventBridge Cron] ──(Daily Trigger)──> [AWS Lambda] ──(Boto3 Audit)──> [IAM & S3 Services]
                                             │
                                     (Vulnerability Found)
                                             ▼
                                       [Amazon SNS] ──(Secure Email)──> [Admin Inbox]


```


## 🏗️ Core Infrastructure & Services (AWS)

### AWS Lambda
Ephemeral serverless compute execution environment. Runs only when triggered, minimizing operational costs and eliminating server management.

### Amazon EventBridge (CloudWatch Events)
Serverless event orchestration and scheduling service used to automate periodic security scans.

### Amazon SNS (Simple Notification Service)
Fully managed publish/subscribe messaging service used to decouple security findings from real-time alert notifications.

### AWS IAM (Identity and Access Management)
Provides granular execution permissions and enforces the principle of least privilege for all application components.

---

## 🐍 Programming & SDKs

### Python 3.14
Modern backend runtime used to implement the application's scanning, processing, and alerting logic.

### Boto3 (AWS SDK for Python)
Official AWS SDK that enables programmatic interaction with AWS services, allowing automated security audits and account verification.

---

## 🛠️ DevOps & Testing Tooling

### AWS SAM (Serverless Application Model)
Infrastructure as Code (IaC) framework built on AWS CloudFormation for defining, deploying, and managing serverless resources.

### Docker Desktop
Local container runtime used to replicate AWS Lambda execution environments for development, testing, and debugging.

### Git & GitHub
Distributed version control system and remote repository platform used for source code management, collaboration, and project hosting.
