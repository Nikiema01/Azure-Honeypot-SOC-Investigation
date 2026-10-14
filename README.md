# Azure Honeypot SOC Investigation

## Project Overview

This project documents a hands-on cybersecurity investigation of an Azure-hosted Windows honeypot using Microsoft Sentinel, Microsoft Defender for Endpoint, and Kusto Query Language (KQL).

The objective was to investigate security telemetry, identify potentially suspicious activity, evaluate security risks, and document findings using an incident response methodology.

## Tools and Technologies

- Microsoft Azure
- Microsoft Sentinel
- Microsoft Defender for Endpoint
- Log Analytics
- Kusto Query Language (KQL)
- MySQL Audit Logs
- MITRE ATT&CK Framework

## Investigation Areas

**1. Authentication Analysis**

Investigated failed authentication events to assess possible unauthorized access attempts.

**2. Network Traffic Analysis**

Examined RDP traffic on TCP port 3389 and reviewed network connections for potential security risks.

**3. Endpoint Process Investigation**

Analyzed PowerShell execution and searched for suspicious command-line patterns.

**4. Database Security Analysis**

Reviewed MySQL audit events, including account creation and elevated privilege grants.

**5. Threat Mapping**

Used MITRE ATT&CK to categorize observed behaviors and investigative hypotheses.

## Key Takeaways

- Gained hands-on experience analyzing endpoint and network security telemetry.
- Practiced writing KQL queries for security investigations.
- Developed skills in evaluating suspicious events and distinguishing potential threats from confirmed incidents.
- Documented findings, limitations, and security recommendations.

## Full Incident Response Report

[View the Incident Response Report](Azure_Honeypot_Full_Incident_Response_Report.pdf)
