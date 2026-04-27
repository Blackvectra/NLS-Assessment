#
# NLS.FrameworkDictionary.psm1
# NextLayerSec Assessment Framework -- Compliance Mapping Dictionary
#
# Data layer only. No execution logic.
# Import this module to access $script:FrameworkDictionary.
#
# Framework versions mapped:
#   NIST:         SP 800-53 Rev 5 Release 5.2.0 (csrc.nist.gov)
#   CIS:          Controls v8.1 June 2024 (cisecurity.org)
#   HIPAA:        Security Rule 45 CFR 164.312 current enforceable rule
#   HIPAAProposed: NPRM December 27 2024 -- expected final May 2026
#   ISO:          ISO/IEC 27001:2022 Annex A controls (iso.org)
#
# HIPAA NPRM note:
#   Proposed rule eliminates required/addressable distinction.
#   All implementation specifications become mandatory with limited exceptions.
#   Current rule remains enforceable until final rule takes effect.
#   Update workflow: when final rule publishes, move HIPAAProposed citations
#   to HIPAA, update DictionaryVersion, tag release.
#
# Update procedure:
#   1. Open this file only
#   2. Find affected ControlId entries
#   3. Update Citation, Detail, Requirement fields
#   4. Update DictionaryVersion at bottom of file
#   5. Commit and tag release
#
# Author:  NextLayerSec
# Version: 1.0.0
# License: CC BY-ND 4.0 -- https://creativecommons.org/licenses/by-nd/4.0/
#

$script:FrameworkDictionary = @{

    AdminMFA = @{
        Title    = 'Require MFA for administrative roles'
        Category = 'Identity'
        NIST = @{
            Satisfied = @{ Citation = 'IA-2(1), IA-2(2)'; Requirement = 'Required'
                Detail = 'MFA enforced for privileged accounts satisfies IA-2(1) Network Access to Privileged Accounts and IA-2(2) Network Access to Non-Privileged Accounts.' }
            Partial = @{ Citation = 'IA-2(1), IA-2(2)'; Requirement = 'Required'
                Detail = 'MFA registered but not enforced via Conditional Access. IA-2(1) requires enforcement, not registration.' }
            Gap = @{ Citation = 'IA-2(1), IA-2(2), IA-5'; Requirement = 'Required'
                Detail = 'No MFA enforcement. IA-2(1) requires MFA for all privileged account network access. IA-5 requires authenticator management including MFA.' }
        }
        CIS = @{
            Satisfied = @{ Citation = '6.3, 6.5'; Requirement = 'IG1'
                Detail = 'MFA enforced for admin accounts satisfies CIS 6.3 Require MFA for Externally-Exposed Applications and 6.5 Require MFA for Administrative Access.' }
            Partial = @{ Citation = '6.5'; Requirement = 'IG1'
                Detail = 'MFA available but not enforced as a Conditional Access grant control. CIS 6.5 requires enforcement not availability.' }
            Gap = @{ Citation = '6.3, 6.5'; Requirement = 'IG1'
                Detail = 'MFA not enforced for administrative accounts. CIS 6.5 is an IG1 Safeguard -- minimum baseline for all organizations.' }
        }
        HIPAA = @{
            Satisfied = @{ Citation = '§164.312(d)'; Requirement = 'Required'
                Detail = 'MFA enforcement satisfies Person or Entity Authentication. Verifies that a person seeking access is the one claimed.' }
            Partial = @{ Citation = '§164.312(d)'; Requirement = 'Required'
                Detail = 'MFA registered but not consistently enforced. §164.312(d) requires verified enforcement, not availability.' }
            Gap = @{ Citation = '§164.312(d), §164.312(a)(2)(i)'; Requirement = 'Required'
                Detail = 'No MFA enforcement. §164.312(d) requires identity verification for ePHI access. §164.312(a)(2)(i) requires unique user identification.' }
        }
        HIPAAProposed = @{
            Satisfied = @{ Citation = '§164.312(a)(2)(ix), §164.312(d)'; Requirement = 'Required -- NPRM eliminates addressable distinction'
                Detail = 'MFA enforcement satisfies proposed §164.312(a)(2)(ix) Multi-Factor Authentication (newly required under NPRM) and §164.312(d) Person Authentication.' }
            Partial = @{ Citation = '§164.312(a)(2)(ix)'; Requirement = 'Required -- NPRM eliminates addressable distinction'
                Detail = 'MFA not consistently enforced. Proposed rule explicitly requires MFA as a mandatory implementation specification with no addressable flexibility.' }
            Gap = @{ Citation = '§164.312(a)(2)(ix), §164.312(d)'; Requirement = 'Required -- NPRM eliminates addressable distinction'
                Detail = 'No MFA. Proposed rule introduces §164.312(a)(2)(ix) as an explicit MFA requirement. Critical gap against the incoming mandatory standard.' }
        }
    
        ISO = @{
            Satisfied = @{ Citation = 'A.8.5'; Requirement = 'Applicable'
                Detail = 'MFA for privileged accounts satisfies A.8.5 Secure Authentication.' }
            Partial = @{ Citation = 'A.8.5'; Requirement = 'Applicable'
                Detail = 'Partially satisfies A.8.5. Review control configuration.' }
            Gap = @{ Citation = 'A.8.5'; Requirement = 'Applicable'
                Detail = 'Control gap. A.8.5 requires this control to be implemented.' }
        }
    }

    LegacyAuth = @{
        Title    = 'Block legacy authentication protocols'
        Category = 'Identity'
        NIST = @{
            Satisfied = @{ Citation = 'IA-2(6), CM-7'; Requirement = 'Required'
                Detail = 'Legacy auth blocked. IA-2(6) satisfies separate device access requirement. CM-7 requires prohibiting functions not required for business operation.' }
            Partial = @{ Citation = 'IA-2(6), CM-7'; Requirement = 'Required'
                Detail = 'Legacy auth partially restricted. CM-7 requires organizations to prohibit protocols not required for business functions.' }
            Gap = @{ Citation = 'IA-2(6), CM-7, SC-8'; Requirement = 'Required'
                Detail = 'Legacy auth protocols active. CM-7 requires disabling unnecessary protocols. SC-8 requires transmission confidentiality -- legacy auth bypasses modern auth channels.' }
        }
        CIS = @{
            Satisfied = @{ Citation = '4.8, 6.7'; Requirement = 'IG1'
                Detail = 'Legacy auth blocked. CIS 4.8 Uninstall or Disable Unnecessary Services and 6.7 Centralize Access Control both addressed by blocking legacy auth protocols.' }
            Partial = @{ Citation = '4.8'; Requirement = 'IG1'
                Detail = 'Legacy auth not fully blocked. CIS 4.8 requires disabling unnecessary services -- legacy auth protocols qualify.' }
            Gap = @{ Citation = '4.8, 6.7'; Requirement = 'IG1'
                Detail = 'Legacy auth enabled. CIS 4.8 is an IG1 Safeguard. Active legacy auth protocols bypass modern authentication controls.' }
        }
        HIPAA = @{
            Satisfied = @{ Citation = '§164.312(a)(2)(i), §164.312(d)'; Requirement = 'Addressable'
                Detail = 'Blocking legacy auth supports unique user identification §164.312(a)(2)(i) and person authentication §164.312(d) by eliminating protocols that bypass modern auth.' }
            Partial = @{ Citation = '§164.312(a)(2)(i)'; Requirement = 'Addressable'
                Detail = 'Legacy auth not fully blocked. Remaining legacy protocols undermine unique user identification by allowing credential-based access without modern auth challenges.' }
            Gap = @{ Citation = '§164.312(a)(2)(i), §164.312(d), §164.312(e)(1)'; Requirement = 'Addressable'
                Detail = 'Legacy auth active. Protocols like SMTP AUTH, POP3, IMAP bypass MFA and modern auth. Undermines person authentication and transmission security requirements.' }
        }
        HIPAAProposed = @{
            Satisfied = @{ Citation = '§164.312(a)(2)(i), §164.312(d)'; Requirement = 'Required -- NPRM eliminates addressable distinction'
                Detail = 'Legacy auth blocked. Under proposed rule all authentication specifications become required. Blocking legacy auth directly supports mandatory person authentication.' }
            Partial = @{ Citation = '§164.312(a)(2)(i), §164.312(d)'; Requirement = 'Required -- NPRM eliminates addressable distinction'
                Detail = 'Partial legacy auth blocking. Proposed rule removes addressable flexibility -- remaining legacy auth exposure is a mandatory compliance gap.' }
            Gap = @{ Citation = '§164.312(a)(2)(i), §164.312(d), §164.312(a)(2)(ix)'; Requirement = 'Required -- NPRM eliminates addressable distinction'
                Detail = 'Legacy auth active. Under proposed rule this gaps against mandatory person authentication and the new explicit MFA requirement at §164.312(a)(2)(ix).' }
        }
    
        ISO = @{
            Satisfied = @{ Citation = 'A.8.5, A.5.15'; Requirement = 'Applicable'
                Detail = 'Blocking legacy authentication satisfies A.8.5 Secure Authentication and A.5.15 Access Control policy.' }
            Partial = @{ Citation = 'A.8.5, A.5.15'; Requirement = 'Applicable'
                Detail = 'Partially satisfies A.8.5, A.5.15. Review control configuration.' }
            Gap = @{ Citation = 'A.8.5, A.5.15'; Requirement = 'Applicable'
                Detail = 'Control gap. A.8.5, A.5.15 requires this control to be implemented.' }
        }
    }

    SmtpClientAuth = @{
        Title    = 'Disable SMTP client authentication tenant-wide'
        Category = 'Transport'
        NIST = @{
            Satisfied = @{ Citation = 'CM-7, SC-8, IA-2'; Requirement = 'Required'
                Detail = 'SMTP client auth disabled. CM-7 prohibits unnecessary protocols. SC-8 protects transmission integrity. Removes a legacy relay vector that bypasses IA-2 controls.' }
            Partial = @{ Citation = 'CM-7'; Requirement = 'Required'
                Detail = 'SMTP client auth partially restricted. CM-7 requires prohibition of functions not required for business operation. Document exceptions with risk acceptance.' }
            Gap = @{ Citation = 'CM-7, SC-8, IA-3'; Requirement = 'Required'
                Detail = 'SMTP client auth enabled tenant-wide. CM-7 requires disabling unnecessary protocols. IA-3 requires device identification and authentication -- SMTP AUTH bypasses this.' }
        }
        CIS = @{
            Satisfied = @{ Citation = '4.8'; Requirement = 'IG1'
                Detail = 'SMTP client auth disabled. CIS 4.8 requires disabling unnecessary services. SMTP client auth is a legacy relay mechanism not required in modern M365 tenants.' }
            Partial = @{ Citation = '4.8'; Requirement = 'IG1'
                Detail = 'SMTP client auth not fully disabled. CIS 4.8 requires disabling unnecessary services. Document business justification for retained exceptions.' }
            Gap = @{ Citation = '4.8, 9.2'; Requirement = 'IG1'
                Detail = 'SMTP client auth enabled. CIS 4.8 requires disabling. CIS 9.2 requires secure configurations -- enabled SMTP client auth is an insecure default for modern tenants.' }
        }
        HIPAA = @{
            Satisfied = @{ Citation = '§164.312(e)(1), §164.312(e)(2)(ii)'; Requirement = 'Required'
                Detail = 'SMTP client auth disabled. Supports transmission security §164.312(e)(1) by removing a legacy protocol that transmits credentials without modern encryption guarantees.' }
            Partial = @{ Citation = '§164.312(e)(1)'; Requirement = 'Required'
                Detail = 'SMTP client auth not fully disabled. Remaining exposure undermines transmission security requirements where ePHI may transit via legacy SMTP relay.' }
            Gap = @{ Citation = '§164.312(e)(1), §164.312(e)(2)(ii), §164.312(a)(2)(i)'; Requirement = 'Required'
                Detail = 'SMTP client auth enabled. Creates an unencrypted relay vector that violates transmission security. Credentials via SMTP AUTH undermine unique user identification.' }
        }
        HIPAAProposed = @{
            Satisfied = @{ Citation = '§164.312(e)(1), §164.312(e)(2)(ii)'; Requirement = 'Required -- NPRM eliminates addressable distinction'
                Detail = 'SMTP client auth disabled. Satisfies proposed mandatory transmission security requirements. Under NPRM these specifications have no addressable flexibility.' }
            Partial = @{ Citation = '§164.312(e)(1)'; Requirement = 'Required -- NPRM eliminates addressable distinction'
                Detail = 'Partial. Proposed rule makes transmission security fully mandatory -- remaining SMTP client auth exposure is a compliance gap with no addressable alternative.' }
            Gap = @{ Citation = '§164.312(e)(1), §164.312(e)(2)(ii)'; Requirement = 'Required -- NPRM eliminates addressable distinction'
                Detail = 'SMTP client auth enabled. Under proposed rule transmission security is mandatory with no addressable flexibility. Direct compliance gap against the incoming standard.' }
        }
    
        ISO = @{
            Satisfied = @{ Citation = 'A.8.5, A.8.21'; Requirement = 'Applicable'
                Detail = 'Disabling SMTP AUTH satisfies A.8.5 Secure Authentication and A.8.21 Security of Network Services.' }
            Partial = @{ Citation = 'A.8.5, A.8.21'; Requirement = 'Applicable'
                Detail = 'Partially satisfies A.8.5, A.8.21. Review control configuration.' }
            Gap = @{ Citation = 'A.8.5, A.8.21'; Requirement = 'Applicable'
                Detail = 'Control gap. A.8.5, A.8.21 requires this control to be implemented.' }
        }
    }

    ExternalForwarding = @{
        Title    = 'Disable external mail auto-forwarding'
        Category = 'Mail Flow'
        NIST = @{
            Satisfied = @{ Citation = 'AC-4, SI-12, SC-8'; Requirement = 'Required'
                Detail = 'External auto-forwarding disabled. AC-4 enforces information flow control. SI-12 manages information output. Prevents unauthorized external data flow.' }
            Partial = @{ Citation = 'AC-4, SI-12'; Requirement = 'Required'
                Detail = 'Auto-forwarding policy set but individual mailbox forwarding exists. AC-4 requires enforcement across all paths, not just policy-level controls.' }
            Gap = @{ Citation = 'AC-4, AC-17, SI-12'; Requirement = 'Required'
                Detail = 'External auto-forwarding enabled. AC-4 requires preventing unauthorized information flows. High-risk data exfiltration vector commonly exploited in BEC attacks.' }
        }
        CIS = @{
            Satisfied = @{ Citation = '3.6, 9.2'; Requirement = 'IG1'
                Detail = 'External forwarding disabled. CIS 3.6 requires access control on sensitive data. CIS 9.2 requires secure configuration -- disabling auto-forward is a cloud email security baseline.' }
            Partial = @{ Citation = '3.6'; Requirement = 'IG1'
                Detail = 'Policy-level forwarding blocked but mailbox-level forwarding detected. CIS 3.6 requires access control on sensitive data regardless of the forwarding mechanism.' }
            Gap = @{ Citation = '3.6, 3.3, 9.2'; Requirement = 'IG1'
                Detail = 'External forwarding enabled. CIS 3.6 requires access control on sensitive data. Auto-forwarding to external addresses is an uncontrolled data flow.' }
        }
        HIPAA = @{
            Satisfied = @{ Citation = '§164.312(a)(1), §164.308(a)(4)'; Requirement = 'Required'
                Detail = 'External forwarding disabled. Supports access control §164.312(a)(1) and information access management §164.308(a)(4) by preventing unauthorized external ePHI disclosure.' }
            Partial = @{ Citation = '§164.312(a)(1), §164.308(a)(4)'; Requirement = 'Required'
                Detail = 'Partial control. Individual mailbox forwarding to external addresses may constitute an impermissible disclosure of ePHI under access control requirements.' }
            Gap = @{ Citation = '§164.312(a)(1), §164.308(a)(4), §164.308(a)(1)'; Requirement = 'Required'
                Detail = 'External forwarding enabled. Uncontrolled auto-forwarding of email containing ePHI to external addresses is an impermissible disclosure and a risk management failure.' }
        }
        HIPAAProposed = @{
            Satisfied = @{ Citation = '§164.312(a)(1), §164.308(a)(4)'; Requirement = 'Required -- NPRM eliminates addressable distinction'
                Detail = 'External forwarding disabled. Satisfies access control and information access management under proposed rule where all specifications are mandatory.' }
            Partial = @{ Citation = '§164.312(a)(1)'; Requirement = 'Required -- NPRM eliminates addressable distinction'
                Detail = 'Partial. Proposed rule removes addressable flexibility from access control specifications. Individual mailbox forwarding gaps must be remediated.' }
            Gap = @{ Citation = '§164.312(a)(1), §164.308(a)(4)'; Requirement = 'Required -- NPRM eliminates addressable distinction'
                Detail = 'External forwarding enabled. Under proposed rule access control is fully mandatory. Uncontrolled external forwarding of ePHI is a mandatory compliance gap.' }
        }
    
        ISO = @{
            Satisfied = @{ Citation = 'A.5.15, A.8.20'; Requirement = 'Applicable'
                Detail = 'Blocking auto-forwarding enforces A.5.15 Access Control and A.8.20 Networks Security.' }
            Partial = @{ Citation = 'A.5.15, A.8.20'; Requirement = 'Applicable'
                Detail = 'Partially satisfies A.5.15, A.8.20. Review control configuration.' }
            Gap = @{ Citation = 'A.5.15, A.8.20'; Requirement = 'Applicable'
                Detail = 'Control gap. A.5.15, A.8.20 requires this control to be implemented.' }
        }
    }

    MailboxAudit = @{
        Title    = 'Enable mailbox auditing on all mailboxes'
        Category = 'Auditing'
        NIST = @{
            Satisfied = @{ Citation = 'AU-2, AU-3, AU-12'; Requirement = 'Required'
                Detail = 'Mailbox auditing enabled. AU-2 requires audit event definition. AU-3 requires audit record content. AU-12 requires audit record generation on all system components.' }
            Partial = @{ Citation = 'AU-2, AU-12'; Requirement = 'Required'
                Detail = 'Auditing enabled on some mailboxes. AU-12 requires audit record generation on all components -- partial coverage creates blind spots in the audit trail.' }
            Gap = @{ Citation = 'AU-2, AU-3, AU-6, AU-12'; Requirement = 'Required'
                Detail = 'Mailbox auditing disabled. AU-2 requires event logging. AU-6 requires audit review. Without mailbox auditing, insider threat and BEC detection capability is severely degraded.' }
        }
        CIS = @{
            Satisfied = @{ Citation = '8.2, 8.5'; Requirement = 'IG1'
                Detail = 'Mailbox auditing enabled. CIS 8.2 requires collecting audit logs. CIS 8.5 requires detailed audit logs. Captures Owner, Delegate, and Admin mailbox actions.' }
            Partial = @{ Citation = '8.2'; Requirement = 'IG1'
                Detail = 'Partial mailbox audit coverage. CIS 8.2 requires audit log collection across all enterprise assets. Gaps in coverage undermine this safeguard.' }
            Gap = @{ Citation = '8.2, 8.5, 8.11'; Requirement = 'IG1'
                Detail = 'Mailbox auditing disabled. CIS 8.2 is an IG1 Safeguard requiring audit log collection. No logs means no visibility into mailbox-level activity.' }
        }
        HIPAA = @{
            Satisfied = @{ Citation = '§164.312(b)'; Requirement = 'Required'
                Detail = 'Mailbox auditing enabled. Directly satisfies §164.312(b) Audit Controls -- implement mechanisms to record and examine activity in systems that contain or use ePHI.' }
            Partial = @{ Citation = '§164.312(b)'; Requirement = 'Required'
                Detail = 'Partial mailbox audit coverage. §164.312(b) requires audit mechanisms across all systems containing ePHI. Gaps leave ePHI access unmonitored.' }
            Gap = @{ Citation = '§164.312(b), §164.308(a)(1)(ii)(D)'; Requirement = 'Required'
                Detail = 'Mailbox auditing disabled. §164.312(b) Audit Controls is a required standard with no addressable flexibility. Direct HIPAA compliance gap.' }
        }
        HIPAAProposed = @{
            Satisfied = @{ Citation = '§164.312(b)'; Requirement = 'Required'
                Detail = 'Mailbox auditing enabled. Satisfies §164.312(b) under both current and proposed rules. Proposed rule adds specificity to audit requirements but audit controls remain required.' }
            Partial = @{ Citation = '§164.312(b)'; Requirement = 'Required'
                Detail = 'Partial coverage. Proposed rule strengthens audit control requirements. Partial mailbox audit coverage does not satisfy the enhanced mandatory standard.' }
            Gap = @{ Citation = '§164.312(b)'; Requirement = 'Required'
                Detail = 'Mailbox auditing disabled. §164.312(b) is required under both current and proposed rules. Proposed rule adds no flexibility -- mandatory compliance failure.' }
        }
    
        ISO = @{
            Satisfied = @{ Citation = 'A.8.15'; Requirement = 'Applicable'
                Detail = 'Mailbox audit logging satisfies A.8.15 Logging.' }
            Partial = @{ Citation = 'A.8.15'; Requirement = 'Applicable'
                Detail = 'Partially satisfies A.8.15. Review control configuration.' }
            Gap = @{ Citation = 'A.8.15'; Requirement = 'Applicable'
                Detail = 'Control gap. A.8.15 requires this control to be implemented.' }
        }
    }

    UnifiedAuditLog = @{
        Title    = 'Enable unified audit logging'
        Category = 'Auditing'
        NIST = @{
            Satisfied = @{ Citation = 'AU-2, AU-6, AU-9, AU-12'; Requirement = 'Required'
                Detail = 'Unified audit log enabled. AU-2 event identification, AU-6 audit review, AU-9 audit protection, and AU-12 audit generation all supported by centralized audit logging.' }
            Partial = @{ Citation = 'AU-12'; Requirement = 'Required'
                Detail = 'Unified audit log enabled but retention or scope may be insufficient. AU-12 requires audit records for defined events across all system components.' }
            Gap = @{ Citation = 'AU-2, AU-6, AU-12, IR-5'; Requirement = 'Required'
                Detail = 'Unified audit logging disabled. Without centralized logging, incident detection (IR-5), audit review (AU-6), and record generation (AU-12) requirements cannot be met.' }
        }
        CIS = @{
            Satisfied = @{ Citation = '8.2, 8.9, 8.11'; Requirement = 'IG1'
                Detail = 'Unified audit log enabled. CIS 8.2 collection, 8.9 centralized management, and 8.11 retention all addressed by the unified audit log.' }
            Partial = @{ Citation = '8.9'; Requirement = 'IG1'
                Detail = 'Unified audit log enabled but centralization or retention may be incomplete. CIS 8.9 requires centralized log management across all enterprise assets.' }
            Gap = @{ Citation = '8.2, 8.9, 8.11'; Requirement = 'IG1'
                Detail = 'Unified audit logging disabled. CIS 8.2 is an IG1 baseline Safeguard. No unified logging means no centralized visibility into tenant-wide activity.' }
        }
        HIPAA = @{
            Satisfied = @{ Citation = '§164.312(b), §164.308(a)(1)(ii)(D)'; Requirement = 'Required'
                Detail = 'Unified audit log enabled. Satisfies §164.312(b) Audit Controls and supports §164.308(a)(1)(ii)(D) Information System Activity Review.' }
            Partial = @{ Citation = '§164.312(b)'; Requirement = 'Required'
                Detail = 'Unified audit log enabled but may not capture all ePHI access events. §164.312(b) requires recording and examining activity in all systems containing ePHI.' }
            Gap = @{ Citation = '§164.312(b), §164.308(a)(1)(ii)(D)'; Requirement = 'Required'
                Detail = 'Unified audit logging disabled. §164.312(b) is required. Without audit logging, information system activity review §164.308(a)(1)(ii)(D) cannot be performed.' }
        }
        HIPAAProposed = @{
            Satisfied = @{ Citation = '§164.312(b)'; Requirement = 'Required'
                Detail = 'Unified audit log enabled. Proposed rule adds enhanced audit requirements including logging of all ePHI access. Unified audit log is foundational to satisfying these.' }
            Partial = @{ Citation = '§164.312(b)'; Requirement = 'Required'
                Detail = 'Partial. Proposed rule strengthens audit requirements with no addressable flexibility. Gaps in unified audit log coverage are mandatory compliance failures.' }
            Gap = @{ Citation = '§164.312(b)'; Requirement = 'Required'
                Detail = 'Unified audit logging disabled. Proposed rule makes all audit control specifications mandatory. Critical compliance gap against the incoming standard.' }
        }
    
        ISO = @{
            Satisfied = @{ Citation = 'A.8.15, A.8.16'; Requirement = 'Applicable'
                Detail = 'Unified audit logging satisfies A.8.15 Logging and A.8.16 Monitoring Activities.' }
            Partial = @{ Citation = 'A.8.15, A.8.16'; Requirement = 'Applicable'
                Detail = 'Partially satisfies A.8.15, A.8.16. Review control configuration.' }
            Gap = @{ Citation = 'A.8.15, A.8.16'; Requirement = 'Applicable'
                Detail = 'Control gap. A.8.15, A.8.16 requires this control to be implemented.' }
        }
    }

    PopEnabled = @{
        Title    = 'Disable POP3 on all mailboxes'
        Category = 'Protocols'
        NIST = @{
            Satisfied = @{ Citation = 'CM-7, IA-2'; Requirement = 'Required'
                Detail = 'POP3 disabled. CM-7 requires disabling protocols not required for business operation. POP3 is a legacy protocol that bypasses modern auth controls.' }
            Partial = @{ Citation = 'CM-7'; Requirement = 'Required'
                Detail = 'POP3 disabled on most mailboxes. CM-7 requires prohibition across all components -- exceptions should be documented with risk acceptance.' }
            Gap = @{ Citation = 'CM-7, IA-2(6)'; Requirement = 'Required'
                Detail = 'POP3 enabled. CM-7 requires disabling unnecessary protocols. POP3 authenticates with basic credentials and cannot challenge MFA -- creates an IA-2 bypass vector.' }
        }
        CIS = @{
            Satisfied = @{ Citation = '4.8'; Requirement = 'IG1'
                Detail = 'POP3 disabled. CIS 4.8 requires disabling unnecessary services. POP3 is a legacy mail retrieval protocol not required in modern M365 environments.' }
            Partial = @{ Citation = '4.8'; Requirement = 'IG1'
                Detail = 'POP3 not fully disabled. CIS 4.8 requires disabling unnecessary services across all enterprise assets. Remaining enabled mailboxes represent unmitigated risk.' }
            Gap = @{ Citation = '4.8'; Requirement = 'IG1'
                Detail = 'POP3 enabled across mailboxes. CIS 4.8 IG1 Safeguard requires disabling unnecessary services. POP3 is unnecessary in modern M365 tenants.' }
        }
        HIPAA = @{
            Satisfied = @{ Citation = '§164.312(a)(2)(i), §164.312(e)(1)'; Requirement = 'Addressable'
                Detail = 'POP3 disabled. Supports unique user identification §164.312(a)(2)(i) and transmission security §164.312(e)(1) by removing a protocol that bypasses modern auth.' }
            Partial = @{ Citation = '§164.312(a)(2)(i)'; Requirement = 'Addressable'
                Detail = 'POP3 not fully disabled. Remaining enabled mailboxes can bypass unique user identification controls. Document risk acceptance for retained exceptions.' }
            Gap = @{ Citation = '§164.312(a)(2)(i), §164.312(d), §164.312(e)(1)'; Requirement = 'Addressable'
                Detail = 'POP3 enabled. Legacy protocol authenticating with basic credentials bypasses person authentication and transmission security requirements for ePHI mailboxes.' }
        }
        HIPAAProposed = @{
            Satisfied = @{ Citation = '§164.312(a)(2)(i), §164.312(e)(1)'; Requirement = 'Required -- NPRM eliminates addressable distinction'
                Detail = 'POP3 disabled. Under proposed rule all authentication and transmission security specifications become mandatory. Disabling POP3 is required, not addressable.' }
            Partial = @{ Citation = '§164.312(a)(2)(i)'; Requirement = 'Required -- NPRM eliminates addressable distinction'
                Detail = 'POP3 not fully disabled. Proposed rule removes addressable flexibility -- remaining POP3-enabled mailboxes accessing ePHI are mandatory compliance gaps.' }
            Gap = @{ Citation = '§164.312(a)(2)(i), §164.312(e)(1)'; Requirement = 'Required -- NPRM eliminates addressable distinction'
                Detail = 'POP3 enabled. Under proposed rule this gaps against mandatory authentication and transmission security requirements. No addressable alternative available.' }
        }
    
        ISO = @{
            Satisfied = @{ Citation = 'A.8.21, A.8.5'; Requirement = 'Applicable'
                Detail = 'Disabling POP3 satisfies A.8.21 Security of Network Services and A.8.5 Secure Authentication.' }
            Partial = @{ Citation = 'A.8.21, A.8.5'; Requirement = 'Applicable'
                Detail = 'Partially satisfies A.8.21, A.8.5. Review control configuration.' }
            Gap = @{ Citation = 'A.8.21, A.8.5'; Requirement = 'Applicable'
                Detail = 'Control gap. A.8.21, A.8.5 requires this control to be implemented.' }
        }
    }

    ImapEnabled = @{
        Title    = 'Disable IMAP on all mailboxes'
        Category = 'Protocols'
        NIST = @{
            Satisfied = @{ Citation = 'CM-7, IA-2'; Requirement = 'Required'
                Detail = 'IMAP disabled. CM-7 requires disabling protocols not required for operation. IMAP authenticates with basic credentials and cannot process MFA challenges.' }
            Partial = @{ Citation = 'CM-7'; Requirement = 'Required'
                Detail = 'IMAP disabled on most mailboxes. CM-7 requires uniform prohibition -- document risk acceptance for retained exceptions.' }
            Gap = @{ Citation = 'CM-7, IA-2(6)'; Requirement = 'Required'
                Detail = 'IMAP enabled. CM-7 requires disabling unnecessary protocols. IMAP with basic authentication bypasses MFA enforcement and Conditional Access policy evaluation.' }
        }
        CIS = @{
            Satisfied = @{ Citation = '4.8'; Requirement = 'IG1'
                Detail = 'IMAP disabled. CIS 4.8 requires disabling unnecessary services. IMAP is a legacy mail protocol not required in M365 tenants using Outlook and Outlook Mobile.' }
            Partial = @{ Citation = '4.8'; Requirement = 'IG1'
                Detail = 'IMAP not fully disabled. CIS 4.8 requires disabling unnecessary services across all assets. Remaining IMAP-enabled mailboxes are unmitigated legacy auth exposure.' }
            Gap = @{ Citation = '4.8'; Requirement = 'IG1'
                Detail = 'IMAP enabled. CIS 4.8 IG1 Safeguard. IMAP is unnecessary in M365 environments where Outlook provides full mail access with modern authentication.' }
        }
        HIPAA = @{
            Satisfied = @{ Citation = '§164.312(a)(2)(i), §164.312(e)(1)'; Requirement = 'Addressable'
                Detail = 'IMAP disabled. Supports unique user identification and transmission security by removing a legacy protocol that bypasses modern auth for ePHI mailboxes.' }
            Partial = @{ Citation = '§164.312(a)(2)(i)'; Requirement = 'Addressable'
                Detail = 'IMAP not fully disabled. Remaining enabled mailboxes accessing ePHI via IMAP bypass authentication controls. Document risk acceptance for retained exceptions.' }
            Gap = @{ Citation = '§164.312(a)(2)(i), §164.312(d), §164.312(e)(1)'; Requirement = 'Addressable'
                Detail = 'IMAP enabled. Legacy protocol with basic auth bypasses person authentication and transmission security requirements for mailboxes containing ePHI.' }
        }
        HIPAAProposed = @{
            Satisfied = @{ Citation = '§164.312(a)(2)(i), §164.312(e)(1)'; Requirement = 'Required -- NPRM eliminates addressable distinction'
                Detail = 'IMAP disabled. Under proposed rule authentication and transmission security specifications are mandatory. Disabling IMAP is required to satisfy the new standard.' }
            Partial = @{ Citation = '§164.312(a)(2)(i)'; Requirement = 'Required -- NPRM eliminates addressable distinction'
                Detail = 'IMAP not fully disabled. Proposed rule removes addressable flexibility. Remaining IMAP exposure against ePHI mailboxes is a mandatory compliance gap.' }
            Gap = @{ Citation = '§164.312(a)(2)(i), §164.312(e)(1)'; Requirement = 'Required -- NPRM eliminates addressable distinction'
                Detail = 'IMAP enabled. Proposed rule makes legacy protocol exposure a mandatory compliance gap with no addressable alternative pathway.' }
        }
    
        ISO = @{
            Satisfied = @{ Citation = 'A.8.21, A.8.5'; Requirement = 'Applicable'
                Detail = 'Disabling IMAP satisfies A.8.21 Security of Network Services and A.8.5 Secure Authentication.' }
            Partial = @{ Citation = 'A.8.21, A.8.5'; Requirement = 'Applicable'
                Detail = 'Partially satisfies A.8.21, A.8.5. Review control configuration.' }
            Gap = @{ Citation = 'A.8.21, A.8.5'; Requirement = 'Applicable'
                Detail = 'Control gap. A.8.21, A.8.5 requires this control to be implemented.' }
        }
    }

    SafeAttachments = @{
        Title    = 'Enable Safe Attachments with Block action'
        Category = 'Defender for Office 365'
        NIST = @{
            Satisfied = @{ Citation = 'SI-3, SI-8'; Requirement = 'Required'
                Detail = 'Safe Attachments enabled with Block action. SI-3 Malicious Code Protection requires scanning and blocking at entry points. SI-8 Spam Protection addresses email-borne threats.' }
            Partial = @{ Citation = 'SI-3'; Requirement = 'Required'
                Detail = 'Safe Attachments enabled but not in Block mode. SI-3 requires malicious code protection that actively blocks threats -- monitor or audit modes do not satisfy this control.' }
            Gap = @{ Citation = 'SI-3, SI-8'; Requirement = 'Required'
                Detail = 'Safe Attachments not enabled. SI-3 requires malicious code protection at entry points. Email is the primary malware delivery vector -- no Safe Attachments leaves this unmitigated.' }
        }
        CIS = @{
            Satisfied = @{ Citation = '9.6, 10.1'; Requirement = 'IG1'
                Detail = 'Safe Attachments enabled with Block action. CIS 9.6 Block Unnecessary File Types and 10.1 Deploy Anti-Malware Software both addressed.' }
            Partial = @{ Citation = '9.6'; Requirement = 'IG1'
                Detail = 'Safe Attachments enabled but not in Block mode. CIS 9.6 requires blocking malicious file types -- monitor mode does not satisfy this requirement.' }
            Gap = @{ Citation = '9.6, 10.1'; Requirement = 'IG1'
                Detail = 'Safe Attachments not enabled. CIS 9.6 and 10.1 require anti-malware protection. Email attachment scanning is a baseline email security control.' }
        }
        HIPAA = @{
            Satisfied = @{ Citation = '§164.308(a)(1)(ii)(B), §164.308(a)(5)(ii)(B)'; Requirement = 'Required'
                Detail = 'Safe Attachments enabled. Supports risk management §164.308(a)(1)(ii)(B) and protection from malicious software §164.308(a)(5)(ii)(B).' }
            Partial = @{ Citation = '§164.308(a)(5)(ii)(B)'; Requirement = 'Required'
                Detail = 'Safe Attachments not in Block mode. §164.308(a)(5)(ii)(B) requires protection from malicious software including procedures to guard against and report it.' }
            Gap = @{ Citation = '§164.308(a)(1)(ii)(B), §164.308(a)(5)(ii)(B)'; Requirement = 'Required'
                Detail = 'Safe Attachments not enabled. §164.308(a)(5)(ii)(B) Protection from Malicious Software is required. Email-borne malware is a primary threat to ePHI integrity.' }
        }
        HIPAAProposed = @{
            Satisfied = @{ Citation = '§164.308(a)(1)(ii)(B), §164.308(a)(5)(ii)(B)'; Requirement = 'Required'
                Detail = 'Safe Attachments enabled. Proposed rule adds specificity to malware protection. Safe Attachments in Block mode satisfies both current and proposed standards.' }
            Partial = @{ Citation = '§164.308(a)(5)(ii)(B)'; Requirement = 'Required'
                Detail = 'Not in Block mode. Proposed rule strengthens malware protection with no addressable flexibility. Monitor mode does not satisfy the enhanced mandatory standard.' }
            Gap = @{ Citation = '§164.308(a)(1)(ii)(B), §164.308(a)(5)(ii)(B)'; Requirement = 'Required'
                Detail = 'Safe Attachments not enabled. Proposed rule makes malware protection mandatory with enhanced specificity. Critical gap against the incoming standard.' }
        }
    
        ISO = @{
            Satisfied = @{ Citation = 'A.8.7'; Requirement = 'Applicable'
                Detail = 'Safe Attachments satisfies A.8.7 Protection Against Malware.' }
            Partial = @{ Citation = 'A.8.7'; Requirement = 'Applicable'
                Detail = 'Partially satisfies A.8.7. Review control configuration.' }
            Gap = @{ Citation = 'A.8.7'; Requirement = 'Applicable'
                Detail = 'Control gap. A.8.7 requires this control to be implemented.' }
        }
    }

    SafeLinks = @{
        Title    = 'Enable Safe Links URL scanning'
        Category = 'Defender for Office 365'
        NIST = @{
            Satisfied = @{ Citation = 'SI-3, SC-18'; Requirement = 'Required'
                Detail = 'Safe Links enabled. SI-3 Malicious Code Protection satisfied by URL scanning at click time. SC-18 Mobile Code controls URL-based code execution threats.' }
            Partial = @{ Citation = 'SI-3'; Requirement = 'Required'
                Detail = 'Safe Links enabled but scope may not cover internal senders or all applications. SI-3 requires malicious code protection across all entry points.' }
            Gap = @{ Citation = 'SI-3, SC-18'; Requirement = 'Required'
                Detail = 'Safe Links not enabled. URL-based phishing is a primary threat vector. SI-3 requires malicious code protection at entry points -- unscanned URLs are unmitigated.' }
        }
        CIS = @{
            Satisfied = @{ Citation = '9.6, 10.1'; Requirement = 'IG2'
                Detail = 'Safe Links enabled. CIS 9.6 blocks malicious URLs and 10.1 requires anti-malware protection. URL scanning at click time addresses phishing and malware delivery via links.' }
            Partial = @{ Citation = '9.6'; Requirement = 'IG2'
                Detail = 'Safe Links enabled but not covering all scenarios. CIS 9.6 requires comprehensive blocking of dangerous content -- gaps in URL scanning leave residual risk.' }
            Gap = @{ Citation = '9.6, 10.1'; Requirement = 'IG2'
                Detail = 'Safe Links not enabled. URL-based phishing is the leading attack vector. CIS 9.6 and 10.1 require protection against malicious content delivered via links.' }
        }
        HIPAA = @{
            Satisfied = @{ Citation = '§164.308(a)(1)(ii)(B), §164.308(a)(5)(ii)(B)'; Requirement = 'Addressable'
                Detail = 'Safe Links enabled. Reduces phishing risk to ePHI systems. Satisfies malware protection §164.308(a)(5)(ii)(B) and supports risk management §164.308(a)(1)(ii)(B).' }
            Partial = @{ Citation = '§164.308(a)(5)(ii)(B)'; Requirement = 'Addressable'
                Detail = 'Partial Safe Links coverage. Gaps leave phishing vectors unmitigated against ePHI systems. Document risk acceptance for coverage gaps.' }
            Gap = @{ Citation = '§164.308(a)(1)(ii)(B), §164.308(a)(5)(ii)(B)'; Requirement = 'Addressable'
                Detail = 'Safe Links not enabled. URL-based phishing is a primary threat to ePHI confidentiality. Malware protection requirements include protection against phishing-delivered malware.' }
        }
        HIPAAProposed = @{
            Satisfied = @{ Citation = '§164.308(a)(5)(ii)(B)'; Requirement = 'Required -- NPRM eliminates addressable distinction'
                Detail = 'Safe Links enabled. Proposed rule strengthens malware and phishing protection. URL scanning satisfies enhanced mandatory protection standards.' }
            Partial = @{ Citation = '§164.308(a)(5)(ii)(B)'; Requirement = 'Required -- NPRM eliminates addressable distinction'
                Detail = 'Partial Safe Links coverage. Proposed rule removes addressable flexibility from malware protection. Coverage gaps are mandatory compliance failures.' }
            Gap = @{ Citation = '§164.308(a)(5)(ii)(B)'; Requirement = 'Required -- NPRM eliminates addressable distinction'
                Detail = 'Safe Links not enabled. Proposed rule makes phishing and malware protection mandatory. URL scanning is a required control under the incoming standard.' }
        }
    
        ISO = @{
            Satisfied = @{ Citation = 'A.8.7'; Requirement = 'Applicable'
                Detail = 'Safe Links satisfies A.8.7 Protection Against Malware.' }
            Partial = @{ Citation = 'A.8.7'; Requirement = 'Applicable'
                Detail = 'Partially satisfies A.8.7. Review control configuration.' }
            Gap = @{ Citation = 'A.8.7'; Requirement = 'Applicable'
                Detail = 'Control gap. A.8.7 requires this control to be implemented.' }
        }
    }

    AntiPhish = @{
        Title    = 'Enable anti-phishing policy'
        Category = 'Defender for Office 365'
        NIST = @{
            Satisfied = @{ Citation = 'SI-3, AT-2'; Requirement = 'Required'
                Detail = 'Anti-phishing policy enabled. SI-3 Malicious Code Protection satisfied. AT-2 Literacy Training is complemented by technical anti-phishing controls.' }
            Partial = @{ Citation = 'SI-3'; Requirement = 'Required'
                Detail = 'Anti-phishing policy enabled but mailbox intelligence or spoof protection may be disabled. SI-3 requires comprehensive protection including impersonation-based threats.' }
            Gap = @{ Citation = 'SI-3, AT-2'; Requirement = 'Required'
                Detail = 'Anti-phishing policy not enabled. Phishing is the leading initial access vector. SI-3 requires malicious code protection -- technical controls are a required complement to training.' }
        }
        CIS = @{
            Satisfied = @{ Citation = '9.5, 9.6'; Requirement = 'IG1'
                Detail = 'Anti-phishing policy enabled. CIS 9.5 requires implementing email anti-phishing protections. CIS 9.6 addresses blocking of suspicious content.' }
            Partial = @{ Citation = '9.5'; Requirement = 'IG1'
                Detail = 'Anti-phishing policy enabled but key features may be disabled. CIS 9.5 requires implementation of anti-phishing measures -- incomplete configuration reduces effectiveness.' }
            Gap = @{ Citation = '9.5, 9.6'; Requirement = 'IG1'
                Detail = 'Anti-phishing policy not enabled. CIS 9.5 is an IG1 Safeguard requiring anti-phishing protections. Phishing is the leading initial access vector across all sectors.' }
        }
        HIPAA = @{
            Satisfied = @{ Citation = '§164.308(a)(5)(ii)(B), §164.308(a)(1)(ii)(B)'; Requirement = 'Required'
                Detail = 'Anti-phishing enabled. Directly satisfies malware protection §164.308(a)(5)(ii)(B). Phishing is the primary threat to ePHI confidentiality via credential compromise.' }
            Partial = @{ Citation = '§164.308(a)(5)(ii)(B)'; Requirement = 'Required'
                Detail = 'Partial anti-phishing protection. Key features disabled reduce effectiveness. §164.308(a)(5)(ii)(B) requires comprehensive protection from malicious software including phishing.' }
            Gap = @{ Citation = '§164.308(a)(5)(ii)(B), §164.308(a)(1)(ii)(B)'; Requirement = 'Required'
                Detail = 'Anti-phishing not enabled. §164.308(a)(5)(ii)(B) is required. Phishing leading to credential theft and ePHI breach is the most common HIPAA breach vector.' }
        }
        HIPAAProposed = @{
            Satisfied = @{ Citation = '§164.308(a)(5)(ii)(B)'; Requirement = 'Required'
                Detail = 'Anti-phishing enabled. Proposed rule strengthens malware and phishing protection. Anti-phishing policy satisfies enhanced mandatory protection requirements.' }
            Partial = @{ Citation = '§164.308(a)(5)(ii)(B)'; Requirement = 'Required'
                Detail = 'Partial anti-phishing. Proposed rule makes all malware protection specifications mandatory. Incomplete configuration is a mandatory compliance gap.' }
            Gap = @{ Citation = '§164.308(a)(5)(ii)(B)'; Requirement = 'Required'
                Detail = 'Anti-phishing not enabled. Proposed rule makes phishing protection mandatory with no addressable alternative. Critical gap against the incoming standard.' }
        }
    
        ISO = @{
            Satisfied = @{ Citation = 'A.8.7'; Requirement = 'Applicable'
                Detail = 'Anti-phishing policy satisfies A.8.7 Protection Against Malware.' }
            Partial = @{ Citation = 'A.8.7'; Requirement = 'Applicable'
                Detail = 'Partially satisfies A.8.7. Review control configuration.' }
            Gap = @{ Citation = 'A.8.7'; Requirement = 'Applicable'
                Detail = 'Control gap. A.8.7 requires this control to be implemented.' }
        }
    }

    MailboxIntelligence = @{
        Title    = 'Enable mailbox intelligence in anti-phishing policy'
        Category = 'Defender for Office 365'
        NIST = @{
            Satisfied = @{ Citation = 'SI-3, SI-4'; Requirement = 'Required'
                Detail = 'Mailbox intelligence enabled. SI-3 Malicious Code Protection enhanced by behavioral analysis. SI-4 System Monitoring supported by intelligence-driven anomaly detection.' }
            Partial = @{ Citation = 'SI-3'; Requirement = 'Required'
                Detail = 'Mailbox intelligence configured but may not cover all scopes. SI-3 requires comprehensive malicious code protection -- scope gaps reduce impersonation detection.' }
            Gap = @{ Citation = 'SI-3, SI-4'; Requirement = 'Required'
                Detail = 'Mailbox intelligence disabled. Impersonation attacks targeting internal senders go undetected. SI-3 and SI-4 require comprehensive threat detection including behavioral analysis.' }
        }
        CIS = @{
            Satisfied = @{ Citation = '9.5'; Requirement = 'IG2'
                Detail = 'Mailbox intelligence enabled. CIS 9.5 requires implementing anti-phishing protections. Mailbox intelligence enhances impersonation detection beyond static rules.' }
            Partial = @{ Citation = '9.5'; Requirement = 'IG2'
                Detail = 'Mailbox intelligence enabled but scope may be limited. CIS 9.5 anti-phishing should include behavioral intelligence for comprehensive protection.' }
            Gap = @{ Citation = '9.5'; Requirement = 'IG2'
                Detail = 'Mailbox intelligence disabled. CIS 9.5 requires anti-phishing implementation. Disabling reduces detection of internal impersonation and BEC attacks.' }
        }
        HIPAA = @{
            Satisfied = @{ Citation = '§164.308(a)(5)(ii)(B)'; Requirement = 'Addressable'
                Detail = 'Mailbox intelligence enabled. Enhances protection from malicious software by detecting impersonation-based attacks targeting ePHI-handling staff.' }
            Partial = @{ Citation = '§164.308(a)(5)(ii)(B)'; Requirement = 'Addressable'
                Detail = 'Mailbox intelligence partially configured. BEC attacks targeting healthcare staff are a primary ePHI breach vector. Enhanced detection reduces this risk.' }
            Gap = @{ Citation = '§164.308(a)(5)(ii)(B)'; Requirement = 'Addressable'
                Detail = 'Mailbox intelligence disabled. BEC attacks impersonating executives are a leading cause of HIPAA breaches. Disabling leaves impersonation attacks undetected.' }
        }
        HIPAAProposed = @{
            Satisfied = @{ Citation = '§164.308(a)(5)(ii)(B)'; Requirement = 'Required -- NPRM eliminates addressable distinction'
                Detail = 'Mailbox intelligence enabled. Proposed rule strengthens malware and phishing protection. Intelligence-driven detection satisfies enhanced mandatory standard.' }
            Partial = @{ Citation = '§164.308(a)(5)(ii)(B)'; Requirement = 'Required -- NPRM eliminates addressable distinction'
                Detail = 'Partial mailbox intelligence. Proposed rule removes addressable flexibility. Gaps in impersonation detection are mandatory compliance failures.' }
            Gap = @{ Citation = '§164.308(a)(5)(ii)(B)'; Requirement = 'Required -- NPRM eliminates addressable distinction'
                Detail = 'Mailbox intelligence disabled. Under proposed rule malware and phishing protection is mandatory and comprehensive. Disabling behavioral intelligence is a compliance gap.' }
        }
    
        ISO = @{
            Satisfied = @{ Citation = 'A.8.7'; Requirement = 'Applicable'
                Detail = 'Mailbox intelligence satisfies A.8.7 Protection Against Malware.' }
            Partial = @{ Citation = 'A.8.7'; Requirement = 'Applicable'
                Detail = 'Partially satisfies A.8.7. Review control configuration.' }
            Gap = @{ Citation = 'A.8.7'; Requirement = 'Applicable'
                Detail = 'Control gap. A.8.7 requires this control to be implemented.' }
        }
    }

    ZAPSpam = @{
        Title    = 'Enable Zero-Hour Auto Purge for spam'
        Category = 'Defender for Office 365'
        NIST = @{
            Satisfied = @{ Citation = 'SI-3, SI-8'; Requirement = 'Required'
                Detail = 'ZAP for spam enabled. SI-3 Malicious Code Protection and SI-8 Spam Protection both satisfied. ZAP retroactively removes spam after delivery.' }
            Partial = @{ Citation = 'SI-8'; Requirement = 'Required'
                Detail = 'ZAP for spam enabled but may not be configured on all policies. SI-8 Spam Protection requires comprehensive coverage across all mail flows.' }
            Gap = @{ Citation = 'SI-3, SI-8'; Requirement = 'Required'
                Detail = 'ZAP for spam disabled. SI-8 requires controls to limit spam impact. Without ZAP, spam that evades pre-delivery filters remains in mailboxes permanently.' }
        }
        CIS = @{
            Satisfied = @{ Citation = '9.6'; Requirement = 'IG1'
                Detail = 'ZAP for spam enabled. CIS 9.6 requires blocking dangerous email content. ZAP provides retroactive removal of spam that evades initial filtering.' }
            Partial = @{ Citation = '9.6'; Requirement = 'IG1'
                Detail = 'ZAP for spam not fully enabled across policies. CIS 9.6 requires comprehensive blocking -- partial ZAP coverage leaves retroactive remediation gaps.' }
            Gap = @{ Citation = '9.6'; Requirement = 'IG1'
                Detail = 'ZAP for spam disabled. CIS 9.6 requires blocking dangerous email content. ZAP is a critical post-delivery control that removes spam after improved detections fire.' }
        }
        HIPAA = @{
            Satisfied = @{ Citation = '§164.308(a)(5)(ii)(B)'; Requirement = 'Addressable'
                Detail = 'ZAP for spam enabled. Supports protection from malicious software by retroactively removing spam that may contain malicious content targeting ePHI systems.' }
            Partial = @{ Citation = '§164.308(a)(5)(ii)(B)'; Requirement = 'Addressable'
                Detail = 'ZAP for spam partially enabled. Gaps in retroactive spam removal leave malicious content accessible in mailboxes after improved intelligence fires.' }
            Gap = @{ Citation = '§164.308(a)(5)(ii)(B)'; Requirement = 'Addressable'
                Detail = 'ZAP for spam disabled. Spam containing malicious payloads targeting ePHI systems remains in mailboxes after improved detections. Increases malware risk to ePHI.' }
        }
        HIPAAProposed = @{
            Satisfied = @{ Citation = '§164.308(a)(5)(ii)(B)'; Requirement = 'Required -- NPRM eliminates addressable distinction'
                Detail = 'ZAP for spam enabled. Satisfies proposed enhanced malware and threat protection requirements. Retroactive removal is a key post-delivery defense layer.' }
            Partial = @{ Citation = '§164.308(a)(5)(ii)(B)'; Requirement = 'Required -- NPRM eliminates addressable distinction'
                Detail = 'Partial ZAP coverage. Proposed rule makes malware protection mandatory across all scopes. Coverage gaps are mandatory compliance failures.' }
            Gap = @{ Citation = '§164.308(a)(5)(ii)(B)'; Requirement = 'Required -- NPRM eliminates addressable distinction'
                Detail = 'ZAP for spam disabled. Proposed rule makes threat protection mandatory. Disabling retroactive spam removal is a compliance gap against the enhanced mandatory standard.' }
        }
    
        ISO = @{
            Satisfied = @{ Citation = 'A.8.7'; Requirement = 'Applicable'
                Detail = 'Zero-Hour Auto Purge satisfies A.8.7 Protection Against Malware.' }
            Partial = @{ Citation = 'A.8.7'; Requirement = 'Applicable'
                Detail = 'Partially satisfies A.8.7. Review control configuration.' }
            Gap = @{ Citation = 'A.8.7'; Requirement = 'Applicable'
                Detail = 'Control gap. A.8.7 requires this control to be implemented.' }
        }
    }

    ZAPPhish = @{
        Title    = 'Enable Zero-Hour Auto Purge for phishing'
        Category = 'Defender for Office 365'
        NIST = @{
            Satisfied = @{ Citation = 'SI-3, SI-4'; Requirement = 'Required'
                Detail = 'ZAP for phishing enabled. SI-3 Malicious Code Protection and SI-4 System Monitoring both supported. ZAP retroactively removes phishing emails after improved detection.' }
            Partial = @{ Citation = 'SI-3'; Requirement = 'Required'
                Detail = 'ZAP for phishing partially enabled. SI-3 requires comprehensive protection -- gaps leave credential harvesting content accessible after improved intelligence fires.' }
            Gap = @{ Citation = 'SI-3, SI-4'; Requirement = 'Required'
                Detail = 'ZAP for phishing disabled. Phishing emails that evade initial filters remain accessible. SI-3 requires post-delivery remediation as part of malicious code protection.' }
        }
        CIS = @{
            Satisfied = @{ Citation = '9.5, 9.6'; Requirement = 'IG1'
                Detail = 'ZAP for phishing enabled. CIS 9.5 anti-phishing and 9.6 content blocking both strengthened by retroactive removal of phishing content after improved detections.' }
            Partial = @{ Citation = '9.5'; Requirement = 'IG1'
                Detail = 'ZAP for phishing not fully enabled. CIS 9.5 anti-phishing protections require comprehensive coverage including post-delivery remediation.' }
            Gap = @{ Citation = '9.5, 9.6'; Requirement = 'IG1'
                Detail = 'ZAP for phishing disabled. Phishing content evading initial filters remains accessible. CIS 9.5 and 9.6 require comprehensive protection including post-delivery controls.' }
        }
        HIPAA = @{
            Satisfied = @{ Citation = '§164.308(a)(5)(ii)(B), §164.308(a)(1)(ii)(B)'; Requirement = 'Required'
                Detail = 'ZAP for phishing enabled. Directly supports malware protection §164.308(a)(5)(ii)(B). Phishing leading to credential theft and ePHI breach is the primary HIPAA incident type.' }
            Partial = @{ Citation = '§164.308(a)(5)(ii)(B)'; Requirement = 'Required'
                Detail = 'ZAP for phishing partially enabled. Gaps leave phishing content accessible after improved detection. Increases ePHI breach risk from credential compromise.' }
            Gap = @{ Citation = '§164.308(a)(5)(ii)(B), §164.308(a)(1)(ii)(B)'; Requirement = 'Required'
                Detail = 'ZAP for phishing disabled. §164.308(a)(5)(ii)(B) requires protection from malicious software. Phishing is the leading HIPAA breach cause -- retroactive removal is critical.' }
        }
        HIPAAProposed = @{
            Satisfied = @{ Citation = '§164.308(a)(5)(ii)(B)'; Requirement = 'Required'
                Detail = 'ZAP for phishing enabled. Satisfies proposed enhanced phishing and malware protection. Post-delivery remediation is a required component of comprehensive protection.' }
            Partial = @{ Citation = '§164.308(a)(5)(ii)(B)'; Requirement = 'Required'
                Detail = 'Partial ZAP phishing coverage. Proposed rule makes phishing protection mandatory and comprehensive. Gaps are mandatory compliance failures under the incoming standard.' }
            Gap = @{ Citation = '§164.308(a)(5)(ii)(B)'; Requirement = 'Required'
                Detail = 'ZAP for phishing disabled. Proposed rule makes phishing protection mandatory with no addressable flexibility. Critical compliance gap against the incoming standard.' }
        }
    
        ISO = @{
            Satisfied = @{ Citation = 'A.8.7'; Requirement = 'Applicable'
                Detail = 'Zero-Hour Auto Purge for phishing satisfies A.8.7 Protection Against Malware.' }
            Partial = @{ Citation = 'A.8.7'; Requirement = 'Applicable'
                Detail = 'Partially satisfies A.8.7. Review control configuration.' }
            Gap = @{ Citation = 'A.8.7'; Requirement = 'Applicable'
                Detail = 'Control gap. A.8.7 requires this control to be implemented.' }
        }
    }

    ATPSPOTeams = @{
        Title    = 'Enable ATP for SharePoint, Teams, and OneDrive'
        Category = 'Defender for Office 365'
        NIST = @{
            Satisfied = @{ Citation = 'SI-3, SC-28'; Requirement = 'Required'
                Detail = 'ATP for SPO/Teams/ODB enabled. SI-3 Malicious Code Protection extended to collaboration platforms. SC-28 Protection of Information at Rest supported by malware scanning.' }
            Partial = @{ Citation = 'SI-3'; Requirement = 'Required'
                Detail = 'ATP partially configured for collaboration platforms. SI-3 requires malicious code protection across all system entry points including file sharing services.' }
            Gap = @{ Citation = 'SI-3, SC-28'; Requirement = 'Required'
                Detail = 'ATP for collaboration not enabled. Malware uploaded to SharePoint, Teams, or OneDrive spreads undetected. SI-3 requires protection at all content entry points.' }
        }
        CIS = @{
            Satisfied = @{ Citation = '10.1, 10.2'; Requirement = 'IG1'
                Detail = 'ATP for collaboration enabled. CIS 10.1 Deploy Anti-Malware Software and 10.2 Configure Automatic Anti-Malware Signature Updates addressed for collaboration platforms.' }
            Partial = @{ Citation = '10.1'; Requirement = 'IG1'
                Detail = 'ATP partially enabled for collaboration. CIS 10.1 requires anti-malware coverage across all platforms where files are stored or shared.' }
            Gap = @{ Citation = '10.1, 10.2'; Requirement = 'IG1'
                Detail = 'ATP not enabled for collaboration. CIS 10.1 is an IG1 Safeguard. Malware uploaded to SharePoint or Teams spreads through file sharing without detection.' }
        }
        HIPAA = @{
            Satisfied = @{ Citation = '§164.308(a)(5)(ii)(B), §164.312(c)(1)'; Requirement = 'Addressable'
                Detail = 'ATP for collaboration enabled. Protects ePHI in SharePoint and OneDrive from malware. Supports malware protection §164.308(a)(5)(ii)(B) and integrity §164.312(c)(1).' }
            Partial = @{ Citation = '§164.308(a)(5)(ii)(B)'; Requirement = 'Addressable'
                Detail = 'Partial ATP coverage. ePHI stored in SharePoint or OneDrive without ATP is at risk from malware that bypasses email-based controls.' }
            Gap = @{ Citation = '§164.308(a)(5)(ii)(B), §164.312(c)(1)'; Requirement = 'Addressable'
                Detail = 'ATP not enabled for collaboration. ePHI in SharePoint, Teams, and OneDrive is unprotected from malware. Integrity of stored ePHI cannot be assured without scanning.' }
        }
        HIPAAProposed = @{
            Satisfied = @{ Citation = '§164.308(a)(5)(ii)(B), §164.312(c)(1)'; Requirement = 'Required -- NPRM eliminates addressable distinction'
                Detail = 'ATP for collaboration enabled. Proposed rule makes malware protection and integrity controls mandatory. ATP coverage of collaboration platforms satisfies these requirements.' }
            Partial = @{ Citation = '§164.308(a)(5)(ii)(B)'; Requirement = 'Required -- NPRM eliminates addressable distinction'
                Detail = 'Partial ATP coverage. Proposed rule removes addressable flexibility. Gaps in collaboration platform protection are mandatory compliance failures.' }
            Gap = @{ Citation = '§164.308(a)(5)(ii)(B), §164.312(c)(1)'; Requirement = 'Required -- NPRM eliminates addressable distinction'
                Detail = 'ATP not enabled for collaboration. Proposed rule makes malware protection mandatory across all platforms. Critical gap against the incoming mandatory standard.' }
        }
    
        ISO = @{
            Satisfied = @{ Citation = 'A.8.7'; Requirement = 'Applicable'
                Detail = 'ATP for SharePoint/Teams/OneDrive satisfies A.8.7 Protection Against Malware.' }
            Partial = @{ Citation = 'A.8.7'; Requirement = 'Applicable'
                Detail = 'Partially satisfies A.8.7. Review control configuration.' }
            Gap = @{ Citation = 'A.8.7'; Requirement = 'Applicable'
                Detail = 'Control gap. A.8.7 requires this control to be implemented.' }
        }
    }

    DKIM = @{
        Title    = 'Enable DKIM signing for all domains'
        Category = 'Email Authentication'
        NIST = @{
            Satisfied = @{ Citation = 'SC-8, IA-9, SI-10'; Requirement = 'Required'
                Detail = 'DKIM signing enabled. SC-8 Transmission Confidentiality and Integrity satisfied by cryptographic message signing. IA-9 Service Identification and Authentication supported.' }
            Partial = @{ Citation = 'SC-8'; Requirement = 'Required'
                Detail = 'DKIM signing enabled on some domains. SC-8 requires transmission integrity protection across all communication channels -- unsigned domains remain spoofable.' }
            Gap = @{ Citation = 'SC-8, IA-9, SI-10'; Requirement = 'Required'
                Detail = 'DKIM signing disabled. SC-8 requires cryptographic mechanisms to protect message integrity. Without DKIM, outbound email authenticity cannot be cryptographically verified.' }
        }
        CIS = @{
            Satisfied = @{ Citation = '9.1'; Requirement = 'IG1'
                Detail = 'DKIM signing enabled. CIS 9.1 requires approved protocols for email. DKIM is a foundational email authentication protocol required for all sending domains.' }
            Partial = @{ Citation = '9.1'; Requirement = 'IG1'
                Detail = 'DKIM not enabled on all domains. CIS 9.1 requires consistent security across all domains. Unsigned domains are spoofable and undermine the email trust posture.' }
            Gap = @{ Citation = '9.1'; Requirement = 'IG1'
                Detail = 'DKIM signing disabled. DKIM is a baseline email authentication requirement. Without it, domain impersonation attacks are easier and DMARC enforcement is weakened.' }
        }
        HIPAA = @{
            Satisfied = @{ Citation = '§164.312(e)(1), §164.312(e)(2)(ii)'; Requirement = 'Addressable'
                Detail = 'DKIM signing enabled. Satisfies transmission security §164.312(e)(1) by cryptographically signing email. Supports integrity controls for ePHI transmitted via email.' }
            Partial = @{ Citation = '§164.312(e)(1)'; Requirement = 'Addressable'
                Detail = 'DKIM not enabled on all domains. Unsigned domains transmitting ePHI lack cryptographic integrity verification. §164.312(e)(1) applies to all ePHI-bearing email.' }
            Gap = @{ Citation = '§164.312(e)(1), §164.312(e)(2)(ii)'; Requirement = 'Addressable'
                Detail = 'DKIM signing disabled. Transmission security §164.312(e)(1) requires technical measures guarding against unauthorized ePHI access. DKIM provides cryptographic sender verification.' }
        }
        HIPAAProposed = @{
            Satisfied = @{ Citation = '§164.312(e)(1), §164.312(e)(2)(ii)'; Requirement = 'Required -- NPRM eliminates addressable distinction'
                Detail = 'DKIM signing enabled. Proposed rule makes transmission security mandatory. DKIM satisfies cryptographic integrity controls under the enhanced mandatory standard.' }
            Partial = @{ Citation = '§164.312(e)(1)'; Requirement = 'Required -- NPRM eliminates addressable distinction'
                Detail = 'DKIM not on all domains. Proposed rule makes transmission security mandatory. Domains transmitting ePHI without DKIM are mandatory compliance gaps.' }
            Gap = @{ Citation = '§164.312(e)(1), §164.312(e)(2)(ii)'; Requirement = 'Required -- NPRM eliminates addressable distinction'
                Detail = 'DKIM disabled. Proposed rule makes email transmission security mandatory with no addressable alternative. Direct gap against the incoming mandatory standard.' }
        }
    
        ISO = @{
            Satisfied = @{ Citation = 'A.8.24'; Requirement = 'Applicable'
                Detail = 'DKIM signing satisfies A.8.24 Use of Cryptography for message authentication.' }
            Partial = @{ Citation = 'A.8.24'; Requirement = 'Applicable'
                Detail = 'Partially satisfies A.8.24. Review control configuration.' }
            Gap = @{ Citation = 'A.8.24'; Requirement = 'Applicable'
                Detail = 'Control gap. A.8.24 requires this control to be implemented.' }
        }
    }

    DNSSEC = @{
        Title    = 'Enable DNSSEC for all domains'
        Category = 'DNS Security'
        NIST = @{
            Satisfied = @{ Citation = 'SC-20, SC-21, SC-22'; Requirement = 'Required'
                Detail = 'DNSSEC enabled. SC-20 Secure Name/Address Resolution satisfied. SC-21 Recursive Resolution Authentication and SC-22 Architecture for Name Resolution supported.' }
            Partial = @{ Citation = 'SC-20'; Requirement = 'Required'
                Detail = 'DNSSEC not enabled on all domains. SC-20 requires secure name resolution for all organizational domains. Unsigned domains are vulnerable to DNS cache poisoning.' }
            Gap = @{ Citation = 'SC-20, SC-21, SC-22'; Requirement = 'Required'
                Detail = 'DNSSEC not enabled. SC-20 through SC-22 require cryptographic DNS authentication. Without DNSSEC, MX records can be poisoned to redirect email traffic.' }
        }
        CIS = @{
            Satisfied = @{ Citation = '9.2'; Requirement = 'IG2'
                Detail = 'DNSSEC enabled. CIS 9.2 requires maintaining secure configurations. DNSSEC is a required DNS security baseline that cryptographically signs zone records.' }
            Partial = @{ Citation = '9.2'; Requirement = 'IG2'
                Detail = 'DNSSEC not enabled on all domains. CIS 9.2 secure configuration applies across all organizational domains. Unsigned domains represent insecure DNS configuration.' }
            Gap = @{ Citation = '9.2'; Requirement = 'IG2'
                Detail = 'DNSSEC not enabled. CIS 9.2 requires secure DNS configuration. Without DNSSEC, DNS infrastructure is vulnerable to poisoning attacks that redirect email and web traffic.' }
        }
        HIPAA = @{
            Satisfied = @{ Citation = '§164.312(e)(1), §164.308(a)(1)(ii)(B)'; Requirement = 'Addressable'
                Detail = 'DNSSEC enabled. Supports transmission security §164.312(e)(1) by protecting DNS integrity. DNS poisoning redirecting ePHI-bearing email is a transmission security threat.' }
            Partial = @{ Citation = '§164.312(e)(1)'; Requirement = 'Addressable'
                Detail = 'DNSSEC not on all domains. Unsigned domains are vulnerable to DNS poisoning that could redirect ePHI-bearing email to attacker-controlled servers.' }
            Gap = @{ Citation = '§164.312(e)(1), §164.308(a)(1)(ii)(B)'; Requirement = 'Addressable'
                Detail = 'DNSSEC not enabled. DNS cache poisoning can redirect ePHI-bearing email without detection. Transmission security risk that undermines §164.312(e)(1) controls.' }
        }
        HIPAAProposed = @{
            Satisfied = @{ Citation = '§164.312(e)(1), §164.308(a)(1)(ii)(B)'; Requirement = 'Required -- NPRM eliminates addressable distinction'
                Detail = 'DNSSEC enabled. Proposed rule strengthens transmission security. DNSSEC protects DNS integrity as a foundational layer of email transmission security.' }
            Partial = @{ Citation = '§164.312(e)(1)'; Requirement = 'Required -- NPRM eliminates addressable distinction'
                Detail = 'DNSSEC not on all domains. Proposed rule makes transmission security mandatory. Domains without DNSSEC transmitting ePHI are mandatory compliance gaps.' }
            Gap = @{ Citation = '§164.312(e)(1)'; Requirement = 'Required -- NPRM eliminates addressable distinction'
                Detail = 'DNSSEC not enabled. Proposed rule makes transmission security mandatory with no addressable alternative. DNSSEC absence is a compliance gap against the incoming standard.' }
        }
    
        ISO = @{
            Satisfied = @{ Citation = 'A.8.21'; Requirement = 'Applicable'
                Detail = 'DNSSEC satisfies A.8.21 Security of Network Services.' }
            Partial = @{ Citation = 'A.8.21'; Requirement = 'Applicable'
                Detail = 'Partially satisfies A.8.21. Review control configuration.' }
            Gap = @{ Citation = 'A.8.21'; Requirement = 'Applicable'
                Detail = 'Control gap. A.8.21 requires this control to be implemented.' }
        }
    }

    CAPolicy = @{
        Title    = 'Enforce Conditional Access policies'
        Category = 'Conditional Access'
        NIST = @{
            Satisfied = @{ Citation = 'AC-2, AC-3, IA-2, IA-10'; Requirement = 'Required'
                Detail = 'CA policies in enforcement mode. AC-3 Access Enforcement and IA-2 Identification and Authentication satisfied. IA-10 Adaptive Authentication supported by risk-based CA policy.' }
            Partial = @{ Citation = 'AC-3, IA-2'; Requirement = 'Required'
                Detail = 'CA policies exist but some are in report-only mode. AC-3 requires enforcement of approved authorizations -- report-only monitors but does not enforce access control decisions.' }
            Gap = @{ Citation = 'AC-2, AC-3, IA-2'; Requirement = 'Required'
                Detail = 'No enforced CA policies. AC-3 requires enforcing approved access authorizations. Without enforced CA policies, identity-based access control is not operationally active.' }
        }
        CIS = @{
            Satisfied = @{ Citation = '6.3, 6.5, 6.7'; Requirement = 'IG1'
                Detail = 'CA policies enforced. CIS 6.3 MFA for external applications, 6.5 MFA for admin access, and 6.7 Centralize Access Control all supported by enforced Conditional Access.' }
            Partial = @{ Citation = '6.7'; Requirement = 'IG1'
                Detail = 'CA policies in report-only mode. CIS 6.7 requires centralized access control -- report-only does not enforce centralized access decisions.' }
            Gap = @{ Citation = '6.3, 6.5, 6.7'; Requirement = 'IG1'
                Detail = 'No enforced CA policies. CIS 6.3, 6.5, and 6.7 all require enforced access control. Without CA enforcement, identity controls are advisory rather than operational.' }
        }
        HIPAA = @{
            Satisfied = @{ Citation = '§164.312(a)(1), §164.312(a)(2)(i), §164.312(d)'; Requirement = 'Required'
                Detail = 'CA policies enforced. Satisfies access controls §164.312(a)(1), unique user identification §164.312(a)(2)(i), and person authentication §164.312(d) through policy-based access.' }
            Partial = @{ Citation = '§164.312(a)(1), §164.312(d)'; Requirement = 'Required'
                Detail = 'CA policies in report-only mode. Access control and person authentication require enforcement, not monitoring. Report-only does not satisfy HIPAA access control requirements.' }
            Gap = @{ Citation = '§164.312(a)(1), §164.312(a)(2)(i), §164.312(d)'; Requirement = 'Required'
                Detail = 'No enforced CA policies. HIPAA access control standards require technical enforcement for ePHI systems. Policy-based access control is not optional.' }
        }
        HIPAAProposed = @{
            Satisfied = @{ Citation = '§164.312(a)(1), §164.312(a)(2)(i), §164.312(a)(2)(ix), §164.312(d)'; Requirement = 'Required -- NPRM eliminates addressable distinction'
                Detail = 'CA policies enforced. Proposed rule makes all access control and authentication specifications mandatory. Enforced CA policies satisfy multiple enhanced mandatory requirements.' }
            Partial = @{ Citation = '§164.312(a)(1), §164.312(d)'; Requirement = 'Required -- NPRM eliminates addressable distinction'
                Detail = 'CA policies in report-only. Proposed rule makes access control enforcement mandatory with no flexibility. Report-only mode is a mandatory compliance gap under proposed rule.' }
            Gap = @{ Citation = '§164.312(a)(1), §164.312(a)(2)(i), §164.312(a)(2)(ix), §164.312(d)'; Requirement = 'Required -- NPRM eliminates addressable distinction'
                Detail = 'No enforced CA policies. Proposed rule makes access control and MFA mandatory across all ePHI systems. Absence of enforced CA policies is a critical compliance gap.' }
        }
    
        ISO = @{
            Satisfied = @{ Citation = 'A.5.15, A.8.5'; Requirement = 'Applicable'
                Detail = 'Conditional Access satisfies A.5.15 Access Control and A.8.5 Secure Authentication.' }
            Partial = @{ Citation = 'A.5.15, A.8.5'; Requirement = 'Applicable'
                Detail = 'Partially satisfies A.5.15, A.8.5. Review control configuration.' }
            Gap = @{ Citation = 'A.5.15, A.8.5'; Requirement = 'Applicable'
                Detail = 'Control gap. A.5.15, A.8.5 requires this control to be implemented.' }
        }
    }

    OutboundSpam = @{
        Title    = 'Enable outbound spam notification'
        Category = 'Threat Protection'
        NIST = @{
            Satisfied = @{ Citation = 'IR-6, SI-4'; Requirement = 'Required'
                Detail = 'Outbound spam notification enabled. IR-6 Incident Reporting satisfied by automated compromise alerting. SI-4 System Monitoring supported by outbound anomaly detection.' }
            Partial = @{ Citation = 'IR-6'; Requirement = 'Required'
                Detail = 'Outbound spam notification enabled but no recipient configured. IR-6 requires reporting to defined personnel -- unconfigured recipients mean alerts go undelivered.' }
            Gap = @{ Citation = 'IR-6, SI-4, IR-5'; Requirement = 'Required'
                Detail = 'Outbound spam notification disabled. SI-4 requires monitoring for compromise indicators. IR-6 requires incident reporting. Compromised accounts sending spam go undetected.' }
        }
        CIS = @{
            Satisfied = @{ Citation = '8.11, 17.4'; Requirement = 'IG1'
                Detail = 'Outbound spam notification enabled. CIS 8.11 audit log management and 17.4 Incident Response Process both supported by automated compromise alerting.' }
            Partial = @{ Citation = '8.11'; Requirement = 'IG1'
                Detail = 'Outbound spam notification enabled but recipient not configured. CIS 8.11 requires actionable alerting -- unconfigured recipients render this control non-functional.' }
            Gap = @{ Citation = '8.11, 17.4'; Requirement = 'IG1'
                Detail = 'Outbound spam notification disabled. CIS 8.11 requires alerting on suspicious activity. Compromised accounts sending bulk spam is a high-confidence indicator of account compromise.' }
        }
        HIPAA = @{
            Satisfied = @{ Citation = '§164.308(a)(6)(ii), §164.308(a)(1)(ii)(D)'; Requirement = 'Required'
                Detail = 'Outbound spam notification enabled. Supports security incident response §164.308(a)(6)(ii) and information system activity review §164.308(a)(1)(ii)(D).' }
            Partial = @{ Citation = '§164.308(a)(6)(ii)'; Requirement = 'Required'
                Detail = 'Notification enabled but no recipient configured. §164.308(a)(6)(ii) Security Incident Procedures require response to known incidents -- undelivered alerts cannot trigger response.' }
            Gap = @{ Citation = '§164.308(a)(6)(ii), §164.308(a)(1)(ii)(D)'; Requirement = 'Required'
                Detail = 'Outbound spam notification disabled. Compromised accounts accessing ePHI via email go undetected. §164.308(a)(6)(ii) requires identifying and responding to security incidents.' }
        }
        HIPAAProposed = @{
            Satisfied = @{ Citation = '§164.308(a)(6)(ii), §164.308(a)(1)(ii)(D)'; Requirement = 'Required'
                Detail = 'Outbound spam notification enabled. Proposed rule strengthens incident response and monitoring. Automated compromise detection satisfies enhanced mandatory standards.' }
            Partial = @{ Citation = '§164.308(a)(6)(ii)'; Requirement = 'Required'
                Detail = 'Notification enabled but recipient not configured. Proposed rule strengthens incident response -- non-functional alerting is a compliance gap under proposed standard.' }
            Gap = @{ Citation = '§164.308(a)(6)(ii), §164.308(a)(1)(ii)(D)'; Requirement = 'Required'
                Detail = 'Outbound spam notification disabled. Proposed rule makes incident response and monitoring mandatory and more specific. Compliance gap against the incoming standard.' }
        }
    
        ISO = @{
            Satisfied = @{ Citation = 'A.8.16'; Requirement = 'Applicable'
                Detail = 'Outbound spam notification satisfies A.8.16 Monitoring Activities.' }
            Partial = @{ Citation = 'A.8.16'; Requirement = 'Applicable'
                Detail = 'Partially satisfies A.8.16. Review control configuration.' }
            Gap = @{ Citation = 'A.8.16'; Requirement = 'Applicable'
                Detail = 'Control gap. A.8.16 requires this control to be implemented.' }
        }
    }
}


    # ── Extended Check ControlIds ─────────────────────────────
    $script:FrameworkDictionary['DMARC'] = [ordered]@{
        Title    = 'Enforce DMARC policy to p=reject'
        Category = 'Email Authentication'
        NIST = @{
            Satisfied = @{ Citation = 'SI-8, SC-5'; Requirement = 'Required'; Detail = 'DMARC at p=reject. SI-8 Spam Protection and SC-5 Denial of Service Protection satisfied.' }
            Partial   = @{ Citation = 'SI-8, SC-5'; Requirement = 'Required'; Detail = 'DMARC published but not at p=reject. Sender authentication not fully enforced.' }
            Gap       = @{ Citation = 'SI-8, SC-5'; Requirement = 'Required'; Detail = 'No DMARC record. Domain spoofing attacks unmitigated.' }
        }
        CIS = @{
            Satisfied = @{ Citation = '9.1'; Requirement = 'IG1'; Detail = 'DMARC at p=reject satisfies CIS 9.1 email domain protection.' }
            Partial   = @{ Citation = '9.1'; Requirement = 'IG1'; Detail = 'DMARC published but not enforced. CIS 9.1 partially satisfied.' }
            Gap       = @{ Citation = '9.1'; Requirement = 'IG1'; Detail = 'No DMARC. CIS 9.1 not satisfied.' }
        }
        HIPAA = @{
            Satisfied = @{ Citation = '§164.312(e)(1)'; Requirement = 'Addressable'; Detail = 'DMARC enforced. Domain spoofing of ePHI-bearing domains prevented.' }
            Partial   = @{ Citation = '§164.312(e)(1)'; Requirement = 'Addressable'; Detail = 'DMARC not fully enforced. Domain spoofing remains possible.' }
            Gap       = @{ Citation = '§164.312(e)(1)'; Requirement = 'Addressable'; Detail = 'No DMARC. ePHI-bearing domain can be spoofed.' }
        }
    }

    $script:FrameworkDictionary['MTASTS'] = [ordered]@{
        Title    = 'Publish MTA-STS policy for all domains'
        Category = 'Email Authentication'
        NIST = @{
            Satisfied = @{ Citation = 'SC-8'; Requirement = 'Required'; Detail = 'MTA-STS published. SMTP downgrade attacks mitigated. SC-8 Transmission Integrity satisfied.' }
            Partial   = @{ Citation = 'SC-8'; Requirement = 'Required'; Detail = 'MTA-STS partially published. Some domains missing policy.' }
            Gap       = @{ Citation = 'SC-8'; Requirement = 'Required'; Detail = 'No MTA-STS. SMTP connections subject to downgrade attacks. SC-8 not satisfied.' }
        }
        CIS = @{
            Satisfied = @{ Citation = '9.1'; Requirement = 'IG2'; Detail = 'MTA-STS enforces TLS for inbound SMTP.' }
            Partial   = @{ Citation = '9.1'; Requirement = 'IG2'; Detail = 'MTA-STS partially deployed.' }
            Gap       = @{ Citation = '9.1'; Requirement = 'IG2'; Detail = 'No MTA-STS policy. Email transport security not enforced.' }
        }
    }

    $script:FrameworkDictionary['InboundSpamPolicy'] = [ordered]@{
        Title    = 'Harden inbound spam policy'
        Category = 'Threat Protection'
        NIST = @{
            Satisfied = @{ Citation = 'SI-3, SI-8'; Requirement = 'Required'; Detail = 'Inbound spam policy hardened. High confidence spam and phish quarantined.' }
            Partial   = @{ Citation = 'SI-3, SI-8'; Requirement = 'Required'; Detail = 'Inbound spam policy not fully hardened.' }
            Gap       = @{ Citation = 'SI-3, SI-8'; Requirement = 'Required'; Detail = 'Inbound spam policy permissive. SI-3 and SI-8 not fully satisfied.' }
        }
    }

    $script:FrameworkDictionary['MalwareFilterPolicy'] = [ordered]@{
        Title    = 'Harden malware filter policy'
        Category = 'Threat Protection'
        NIST = @{
            Satisfied = @{ Citation = 'SI-3'; Requirement = 'Required'; Detail = 'Malware filter deletes infected messages. ZAP enabled. SI-3 satisfied.' }
            Partial   = @{ Citation = 'SI-3'; Requirement = 'Required'; Detail = 'Malware filter partially hardened. Action or ZAP not fully configured.' }
            Gap       = @{ Citation = 'SI-3'; Requirement = 'Required'; Detail = 'Malware filter not hardened. SI-3 not fully satisfied.' }
        }
        HIPAA = @{
            Satisfied = @{ Citation = '§164.308(a)(5)(ii)(B)'; Requirement = 'Addressable'; Detail = 'Malware protection implemented.' }
            Partial   = @{ Citation = '§164.308(a)(5)(ii)(B)'; Requirement = 'Addressable'; Detail = 'Malware protection partially implemented.' }
            Gap       = @{ Citation = '§164.308(a)(5)(ii)(B)'; Requirement = 'Addressable'; Detail = 'Malware filter not hardened.' }
        }
    }

    $script:FrameworkDictionary['SecurityDefaults'] = [ordered]@{
        Title    = 'Disable Security Defaults when Conditional Access is active'
        Category = 'Conditional Access'
        NIST = @{
            Satisfied = @{ Citation = 'AC-3, IA-2'; Requirement = 'Required'; Detail = 'Security Defaults disabled. CA policies provide granular enforcement.' }
            Partial   = @{ Citation = 'AC-3, IA-2'; Requirement = 'Required'; Detail = 'Security Defaults state unclear. Verify CA policy coverage.' }
            Gap       = @{ Citation = 'AC-3, IA-2'; Requirement = 'Required'; Detail = 'Security Defaults enabled alongside CA. Controls may conflict.' }
        }
    }

    $script:FrameworkDictionary['AuthMethodsPolicy'] = [ordered]@{
        Title    = 'Enable strong authentication methods'
        Category = 'Identity'
        NIST = @{
            Satisfied = @{ Citation = 'IA-2, IA-5'; Requirement = 'Required'; Detail = 'Strong authentication methods enabled. IA-2 and IA-5 satisfied.' }
            Partial   = @{ Citation = 'IA-2, IA-5'; Requirement = 'Required'; Detail = 'Some authentication methods enabled but strongest options not active.' }
            Gap       = @{ Citation = 'IA-2, IA-5'; Requirement = 'Required'; Detail = 'Strong authentication methods not enabled.' }
        }
        HIPAA = @{
            Satisfied = @{ Citation = '§164.312(d)'; Requirement = 'Required'; Detail = 'Strong authentication methods enabled. Person authentication satisfied.' }
            Partial   = @{ Citation = '§164.312(d)'; Requirement = 'Required'; Detail = 'Authentication methods partially configured.' }
            Gap       = @{ Citation = '§164.312(d)'; Requirement = 'Required'; Detail = 'Strong authentication methods not enabled.' }
        }
    }

    $script:FrameworkDictionary['ConsentFramework'] = [ordered]@{
        Title    = 'Disable user consent to applications'
        Category = 'Identity'
        NIST = @{
            Satisfied = @{ Citation = 'AC-3, CM-7'; Requirement = 'Required'; Detail = 'User consent disabled. Admin approval required for all app grants. AC-3 and CM-7 satisfied.' }
            Partial   = @{ Citation = 'AC-3, CM-7'; Requirement = 'Required'; Detail = 'User consent partially restricted. Some app categories still open.' }
            Gap       = @{ Citation = 'AC-3, CM-7'; Requirement = 'Required'; Detail = 'Users can consent to apps. OAuth phishing risk. AC-3 and CM-7 not satisfied.' }
        }
        CIS = @{
            Satisfied = @{ Citation = '5.4'; Requirement = 'IG2'; Detail = 'App consent restricted to admins. CIS 5.4 satisfied.' }
            Partial   = @{ Citation = '5.4'; Requirement = 'IG2'; Detail = 'App consent partially restricted.' }
            Gap       = @{ Citation = '5.4'; Requirement = 'IG2'; Detail = 'Open user consent allows privilege escalation. CIS 5.4 not satisfied.' }
        }
    }

    $script:FrameworkDictionary['BreakGlass'] = [ordered]@{
        Title    = 'Configure break-glass emergency access account'
        Category = 'Identity'
        NIST = @{
            Satisfied = @{ Citation = 'CP-2, AC-2'; Requirement = 'Required'; Detail = 'Break-glass account configured and excluded from CA. CP-2 and AC-2 satisfied.' }
            Partial   = @{ Citation = 'CP-2, AC-2'; Requirement = 'Required'; Detail = 'Break-glass account exists but not excluded from CA. Emergency access may fail.' }
            Gap       = @{ Citation = 'CP-2, AC-2'; Requirement = 'Required'; Detail = 'No break-glass account. Loss of admin access has no recovery path.' }
        }
        HIPAA = @{
            Satisfied = @{ Citation = '§164.312(a)(2)(ii)'; Requirement = 'Required'; Detail = 'Emergency access procedure implemented. §164.312(a)(2)(ii) satisfied.' }
            Partial   = @{ Citation = '§164.312(a)(2)(ii)'; Requirement = 'Required'; Detail = 'Emergency access account exists but configuration incomplete.' }
            Gap       = @{ Citation = '§164.312(a)(2)(ii)'; Requirement = 'Required'; Detail = 'No emergency access procedure. §164.312(a)(2)(ii) not implemented.' }
        }
    }

    # ── Additional Scored Checks ─────────────────────────────
    $script:FrameworkDictionary['StaleAccounts'] = [ordered]@{
        Title    = 'Disable or remove stale user accounts'
        Category = 'Identity'
        NIST = @{
            Satisfied = @{ Citation = 'AC-2'; Requirement = 'Required'; Detail = 'No stale accounts. AC-2 Account Management satisfied -- inactive accounts reviewed and disabled.' }
            Partial   = @{ Citation = 'AC-2'; Requirement = 'Required'; Detail = 'Some stale accounts detected. AC-2 requires timely disabling of inactive accounts.' }
            Gap       = @{ Citation = 'AC-2'; Requirement = 'Required'; Detail = 'Stale accounts present. AC-2 Account Management not satisfied. Inactive accounts expand the attack surface.' }
        }
        CIS = @{
            Satisfied = @{ Citation = '5.3'; Requirement = 'IG1'; Detail = 'No inactive accounts. CIS 5.3 requires disabling dormant accounts within 45 days.' }
            Partial   = @{ Citation = '5.3'; Requirement = 'IG1'; Detail = 'Some inactive accounts. CIS 5.3 not fully satisfied.' }
            Gap       = @{ Citation = '5.3'; Requirement = 'IG1'; Detail = 'Stale accounts not remediated. CIS 5.3 not satisfied.' }
        }
        HIPAA = @{
            Satisfied = @{ Citation = '§164.308(a)(3)(ii)(C)'; Requirement = 'Addressable'; Detail = 'Stale accounts addressed. Termination procedures implemented.' }
            Partial   = @{ Citation = '§164.308(a)(3)(ii)(C)'; Requirement = 'Addressable'; Detail = 'Termination procedures partially implemented.' }
            Gap       = @{ Citation = '§164.308(a)(3)(ii)(C)'; Requirement = 'Addressable'; Detail = 'Stale accounts not addressed. Termination procedures not fully implemented.' }
        }
    }

    $script:FrameworkDictionary['GlobalAdminCount'] = [ordered]@{
        Title    = 'Limit Global Administrator count to 2 or fewer'
        Category = 'Identity'
        NIST = @{
            Satisfied = @{ Citation = 'AC-6, AC-2'; Requirement = 'Required'; Detail = 'Global Admin count within recommended limit. AC-6 Least Privilege and AC-2 Account Management satisfied.' }
            Partial   = @{ Citation = 'AC-6, AC-2'; Requirement = 'Required'; Detail = 'Global Admin count slightly elevated. Review and reduce.' }
            Gap       = @{ Citation = 'AC-6, AC-2'; Requirement = 'Required'; Detail = 'Excessive Global Admins. AC-6 Least Privilege not satisfied. Each GA is a full-tenant compromise path.' }
        }
        CIS = @{
            Satisfied = @{ Citation = '5.4'; Requirement = 'IG1'; Detail = 'Privileged access appropriately scoped. CIS 5.4 satisfied.' }
            Partial   = @{ Citation = '5.4'; Requirement = 'IG1'; Detail = 'Privileged access partially scoped.' }
            Gap       = @{ Citation = '5.4'; Requirement = 'IG1'; Detail = 'Over-provisioned Global Admin accounts. CIS 5.4 not satisfied.' }
        }
        HIPAA = @{
            Satisfied = @{ Citation = '§164.308(a)(3)(ii)(B)'; Requirement = 'Addressable'; Detail = 'Access appropriately scoped. Workforce clearance procedure implemented.' }
            Partial   = @{ Citation = '§164.308(a)(3)(ii)(B)'; Requirement = 'Addressable'; Detail = 'Access partially scoped.' }
            Gap       = @{ Citation = '§164.308(a)(3)(ii)(B)'; Requirement = 'Addressable'; Detail = 'Excessive privileged access. Workforce clearance procedure not enforced.' }
        }
    }

    $script:FrameworkDictionary['SharedMailboxSignIn'] = [ordered]@{
        Title    = 'Disable interactive sign-in on shared mailboxes'
        Category = 'Identity'
        NIST = @{
            Satisfied = @{ Citation = 'AC-2, CM-7'; Requirement = 'Required'; Detail = 'Shared mailbox sign-in disabled. AC-2 Account Management and CM-7 Least Functionality satisfied.' }
            Partial   = @{ Citation = 'AC-2, CM-7'; Requirement = 'Required'; Detail = 'Some shared mailboxes have sign-in enabled.' }
            Gap       = @{ Citation = 'AC-2, CM-7'; Requirement = 'Required'; Detail = 'Shared mailboxes with interactive sign-in. Unmonitored privileged access vector. AC-2 not satisfied.' }
        }
        CIS = @{
            Satisfied = @{ Citation = '5.2'; Requirement = 'IG1'; Detail = 'Shared mailbox accounts not used for interactive login. CIS 5.2 satisfied.' }
            Partial   = @{ Citation = '5.2'; Requirement = 'IG1'; Detail = 'Some shared mailbox accounts allow interactive login.' }
            Gap       = @{ Citation = '5.2'; Requirement = 'IG1'; Detail = 'Shared mailbox accounts allow interactive login. CIS 5.2 not satisfied.' }
        }
        HIPAA = @{
            Satisfied = @{ Citation = '§164.312(a)(2)(i)'; Requirement = 'Required'; Detail = 'Unique user identification enforced. Shared mailboxes not used for interactive access.' }
            Partial   = @{ Citation = '§164.312(a)(2)(i)'; Requirement = 'Required'; Detail = 'Unique user identification partially enforced.' }
            Gap       = @{ Citation = '§164.312(a)(2)(i)'; Requirement = 'Required'; Detail = 'Shared mailbox interactive sign-in violates unique user identification requirement.' }
        }
    }

    $script:FrameworkDictionary['NamedLocations'] = [ordered]@{
        Title    = 'Define named locations for Zero Trust network segmentation'
        Category = 'Conditional Access'
        NIST = @{
            Satisfied = @{ Citation = 'AC-17, SC-7'; Requirement = 'Required'; Detail = 'Named locations defined. AC-17 Remote Access and SC-7 Boundary Protection supported by network-aware CA policies.' }
            Partial   = @{ Citation = 'AC-17, SC-7'; Requirement = 'Required'; Detail = 'Named locations partially configured.' }
            Gap       = @{ Citation = 'AC-17, SC-7'; Requirement = 'Required'; Detail = 'No named locations. CA policies cannot enforce network-based access controls. AC-17 not satisfied.' }
        }
        CIS = @{
            Satisfied = @{ Citation = '6.7'; Requirement = 'IG2'; Detail = 'Network trust boundaries defined. CIS 6.7 centralized access control satisfied.' }
            Partial   = @{ Citation = '6.7'; Requirement = 'IG2'; Detail = 'Network trust boundaries partially defined.' }
            Gap       = @{ Citation = '6.7'; Requirement = 'IG2'; Detail = 'No network trust boundaries defined. CIS 6.7 not satisfied.' }
        }
    }

    $script:FrameworkDictionary['UserMFAGap'] = [ordered]@{
        Title    = 'Ensure all users have MFA registered'
        Category = 'Identity'
        NIST = @{
            Satisfied = @{ Citation = 'IA-2(1), IA-5'; Requirement = 'Required'; Detail = 'All users have MFA registered. IA-2(1) and IA-5 Authenticator Management satisfied.' }
            Partial   = @{ Citation = 'IA-2(1), IA-5'; Requirement = 'Required'; Detail = 'Some users lack MFA registration.' }
            Gap       = @{ Citation = 'IA-2(1), IA-5'; Requirement = 'Required'; Detail = 'Users without MFA cannot satisfy CA MFA grant controls. IA-2(1) not satisfied.' }
        }
        CIS = @{
            Satisfied = @{ Citation = '6.3, 6.5'; Requirement = 'IG1'; Detail = 'All users have MFA registered. CIS 6.3 and 6.5 satisfied.' }
            Partial   = @{ Citation = '6.3, 6.5'; Requirement = 'IG1'; Detail = 'MFA registration incomplete.' }
            Gap       = @{ Citation = '6.3, 6.5'; Requirement = 'IG1'; Detail = 'Users without MFA. CIS 6.3 MFA requirement not satisfied.' }
        }
        HIPAA = @{
            Satisfied = @{ Citation = '§164.312(d)'; Requirement = 'Required'; Detail = 'All users have MFA registered. Person authentication satisfied.' }
            Partial   = @{ Citation = '§164.312(d)'; Requirement = 'Required'; Detail = 'MFA registration incomplete for some users.' }
            Gap       = @{ Citation = '§164.312(d)'; Requirement = 'Required'; Detail = 'Users without MFA violate person authentication requirement.' }
        }
    }

    $script:FrameworkDictionary['ExternalCollaboration'] = [ordered]@{
        Title    = 'Restrict guest invitation permissions'
        Category = 'Identity'
        NIST = @{
            Satisfied = @{ Citation = 'AC-2, AC-3'; Requirement = 'Required'; Detail = 'Guest invitations restricted to admins. AC-2 Account Management and AC-3 Access Enforcement satisfied.' }
            Partial   = @{ Citation = 'AC-2, AC-3'; Requirement = 'Required'; Detail = 'Guest invitations partially restricted.' }
            Gap       = @{ Citation = 'AC-2, AC-3'; Requirement = 'Required'; Detail = 'All users can invite guests. AC-2 and AC-3 not satisfied. Uncontrolled external access.' }
        }
        CIS = @{
            Satisfied = @{ Citation = '5.4'; Requirement = 'IG2'; Detail = 'External access appropriately gated. CIS 5.4 satisfied.' }
            Partial   = @{ Citation = '5.4'; Requirement = 'IG2'; Detail = 'External access partially gated.' }
            Gap       = @{ Citation = '5.4'; Requirement = 'IG2'; Detail = 'Unrestricted guest invitations. CIS 5.4 not satisfied.' }
        }
        HIPAA = @{
            Satisfied = @{ Citation = '§164.308(a)(4)'; Requirement = 'Addressable'; Detail = 'External access controlled. Information access management satisfied.' }
            Partial   = @{ Citation = '§164.308(a)(4)'; Requirement = 'Addressable'; Detail = 'External access partially controlled.' }
            Gap       = @{ Citation = '§164.308(a)(4)'; Requirement = 'Addressable'; Detail = 'Unrestricted external access. Information access management not satisfied.' }
        }
    }

# Dictionary version metadata -- update this when framework versions change
$script:DictionaryVersion = [ordered]@{
    NIST          = 'SP 800-53 Rev 5 Release 5.2.0'
    CIS           = 'CIS Controls v8.1 June 2024'
    HIPAA         = 'HIPAA Security Rule 45 CFR 164.312 current enforceable rule'
    HIPAAProposed = 'HIPAA Security Rule NPRM December 27 2024 proposed rule -- expected final May 2026'
    DMARC = @{
        Title    = 'Enforce DMARC policy to p=reject'
        Category = 'Email Authentication'
        NIST = @{
            Satisfied = @{ Citation = 'SI-8, SC-5'; Requirement = 'Required'
                Detail = 'DMARC at p=reject satisfies SI-8 Spam Protection and SC-5 Denial of Service Protection by preventing domain spoofing.' }
            Partial = @{ Citation = 'SI-8, SC-5'; Requirement = 'Required'
                Detail = 'DMARC at p=quarantine is partial. p=reject is required to fully satisfy SI-8 and prevent domain impersonation.' }
            Gap = @{ Citation = 'SI-8, SC-5, IA-9'; Requirement = 'Required'
                Detail = 'No DMARC enforcement. SI-8 requires spam protection. IA-9 requires service authentication including email authentication.' }
        }
        CIS = @{
            Satisfied = @{ Citation = '9.1'; Requirement = 'IG1'
                Detail = 'DMARC at p=reject satisfies CIS 9.1 Ensure Usage of DNS-Based Email Sender Authentication.' }
            Partial = @{ Citation = '9.1'; Requirement = 'IG1'
                Detail = 'DMARC at p=quarantine partially satisfies CIS 9.1. Advance to p=reject after aggregate report review.' }
            Gap = @{ Citation = '9.1'; Requirement = 'IG1'
                Detail = 'DMARC not configured or at p=none. CIS 9.1 requires domain-based message authentication enforcement.' }
        }
        HIPAA = @{
            Satisfied = @{ Citation = '§164.312(e)(1), §164.312(e)(2)(ii)'; Requirement = 'Required'
                Detail = 'DMARC enforcement satisfies §164.312(e)(1) Transmission Security and §164.312(e)(2)(ii) Encryption and Decryption of ePHI in transit.' }
            Partial = @{ Citation = '§164.312(e)(1)'; Requirement = 'Required'
                Detail = 'Partial DMARC enforcement. §164.312(e)(1) requires measures against unauthorized interception.' }
            Gap = @{ Citation = '§164.312(e)(1)'; Requirement = 'Required'
                Detail = 'No DMARC policy. §164.312(e)(1) Transmission Security requires technical security measures for ePHI.' }
        }
        ISO = @{
            Satisfied = @{ Citation = 'A.8.24'; Requirement = 'Applicable'
                Detail = 'DMARC at p=reject satisfies A.8.24 Use of Cryptography for email authentication.' }
            Partial = @{ Citation = 'A.8.24'; Requirement = 'Applicable'
                Detail = 'Partial DMARC enforcement. Advance to p=reject to fully satisfy A.8.24.' }
            Gap = @{ Citation = 'A.8.24'; Requirement = 'Applicable'
                Detail = 'No DMARC policy. A.8.24 requires cryptographic controls for data integrity.' }
        }
    }

    SecurityDefaults = @{
        Title    = 'Disable Security Defaults when Conditional Access is active'
        Category = 'Conditional Access'
        NIST = @{
            Satisfied = @{ Citation = 'AC-3, IA-2'; Requirement = 'Required'
                Detail = 'Security Defaults disabled with CA active satisfies AC-3 Access Enforcement and IA-2 Identification and Authentication via granular policy control.' }
            Gap = @{ Citation = 'AC-3, IA-2'; Requirement = 'Required'
                Detail = 'Security Defaults and Conditional Access cannot coexist. Security Defaults must be disabled when CA policies are deployed.' }
        }
        CIS = @{
            Satisfied = @{ Citation = '6.7'; Requirement = 'IG2'
                Detail = 'Disabling Security Defaults allows CIS 6.7 Centralize Access Control enforcement via Conditional Access.' }
            Gap = @{ Citation = '6.7'; Requirement = 'IG2'
                Detail = 'Security Defaults conflict with CIS 6.7 Centralize Access Control. Disable to allow CA policy enforcement.' }
        }
        ISO = @{
            Satisfied = @{ Citation = 'A.5.15'; Requirement = 'Applicable'
                Detail = 'CA-controlled access satisfies A.5.15 Access Control policy enforcement.' }
            Gap = @{ Citation = 'A.5.15'; Requirement = 'Applicable'
                Detail = 'Security Defaults prevent granular access control required by A.5.15.' }
        }
    }

    AuthMethodsPolicy = @{
        Title    = 'Enable strong authentication methods'
        Category = 'Identity'
        NIST = @{
            Satisfied = @{ Citation = 'IA-2, IA-5'; Requirement = 'Required'
                Detail = 'Strong auth methods (FIDO2, Authenticator) satisfy IA-2 Identification and Authentication and IA-5 Authenticator Management.' }
            Gap = @{ Citation = 'IA-2, IA-5'; Requirement = 'Required'
                Detail = 'Phishing-resistant methods not enabled. IA-5 requires management of authenticators including enforcement of strong methods.' }
        }
        CIS = @{
            Satisfied = @{ Citation = '6.3, 6.5'; Requirement = 'IG1'
                Detail = 'Strong authentication methods satisfy CIS 6.3 and 6.5 MFA requirements.' }
            Gap = @{ Citation = '6.3'; Requirement = 'IG1'
                Detail = 'Strong methods not configured. CIS 6.3 requires phishing-resistant MFA where available.' }
        }
        ISO = @{
            Satisfied = @{ Citation = 'A.8.5'; Requirement = 'Applicable'
                Detail = 'FIDO2/Authenticator satisfy A.8.5 Secure Authentication requirements.' }
            Gap = @{ Citation = 'A.8.5'; Requirement = 'Applicable'
                Detail = 'Strong methods not enabled. A.8.5 requires secure authentication mechanisms.' }
        }
    }

    ConsentFramework = @{
        Title    = 'Disable user consent to applications'
        Category = 'Identity'
        NIST = @{
            Satisfied = @{ Citation = 'AC-3, CM-7'; Requirement = 'Required'
                Detail = 'Admin-only consent satisfies AC-3 Access Enforcement and CM-7 Least Functionality by preventing unauthorized app access to tenant data.' }
            Gap = @{ Citation = 'AC-3, CM-7'; Requirement = 'Required'
                Detail = 'User consent enabled. AC-3 requires access enforcement. CM-7 requires least functionality -- user consent grants implicit access to org data.' }
        }
        CIS = @{
            Satisfied = @{ Citation = '5.4'; Requirement = 'IG1'
                Detail = 'Admin consent satisfies CIS 5.4 Restrict Administrator Privileges to Dedicated Administrator Accounts.' }
            Gap = @{ Citation = '5.4'; Requirement = 'IG1'
                Detail = 'User consent exposes tenant data to unreviewed applications. CIS 5.4 requires restriction of privilege grants.' }
        }
        ISO = @{
            Satisfied = @{ Citation = 'A.5.15, A.8.2'; Requirement = 'Applicable'
                Detail = 'Admin consent satisfies A.5.15 Access Control and A.8.2 Privileged Access Rights.' }
            Gap = @{ Citation = 'A.5.15, A.8.2'; Requirement = 'Applicable'
                Detail = 'User consent violates A.5.15 and A.8.2 by granting unreviewed application access.' }
        }
    }

    BreakGlass = @{
        Title    = 'Configure break-glass emergency access account'
        Category = 'Identity'
        NIST = @{
            Satisfied = @{ Citation = 'CP-2, AC-2'; Requirement = 'Required'
                Detail = 'Break-glass excluded from CA satisfies CP-2 Contingency Plan and AC-2 Account Management for emergency access continuity.' }
            Gap = @{ Citation = 'CP-2, AC-2'; Requirement = 'Required'
                Detail = 'No break-glass or not excluded from CA. CP-2 requires contingency planning. Loss of admin access during CA failure has no recovery path.' }
        }
        CIS = @{
            Satisfied = @{ Citation = '5.2'; Requirement = 'IG1'
                Detail = 'Break-glass account satisfies CIS 5.2 Use Unique Passwords for emergency access continuity.' }
            Gap = @{ Citation = '5.2'; Requirement = 'IG1'
                Detail = 'No emergency access account. CIS 5.2 and operational continuity require dedicated emergency credentials.' }
        }
        HIPAA = @{
            Satisfied = @{ Citation = '§164.312(a)(2)(ii)'; Requirement = 'Required'
                Detail = 'Break-glass satisfies §164.312(a)(2)(ii) Emergency Access Procedure for ePHI systems.' }
            Gap = @{ Citation = '§164.312(a)(2)(ii)'; Requirement = 'Required'
                Detail = 'No emergency access procedure. §164.312(a)(2)(ii) requires documented emergency access to ePHI.' }
        }
        ISO = @{
            Satisfied = @{ Citation = 'A.8.2'; Requirement = 'Applicable'
                Detail = 'Break-glass satisfies A.8.2 Privileged Access Rights for emergency continuity.' }
            Gap = @{ Citation = 'A.8.2'; Requirement = 'Applicable'
                Detail = 'No emergency access. A.8.2 requires managed privileged access including emergency scenarios.' }
        }
    }

    UserMFAGap = @{
        Title    = 'Ensure all users have MFA registered'
        Category = 'Identity'
        NIST = @{
            Satisfied = @{ Citation = 'IA-2(1), IA-5'; Requirement = 'Required'
                Detail = 'All users MFA-registered satisfies IA-2(1) and IA-5 authenticator management requirements.' }
            Gap = @{ Citation = 'IA-2(1), IA-5'; Requirement = 'Required'
                Detail = 'Users without MFA cannot satisfy CA policy grant controls. IA-2(1) requires MFA. IA-5 requires authenticator management.' }
        }
        CIS = @{
            Satisfied = @{ Citation = '6.3, 6.5'; Requirement = 'IG1'
                Detail = 'All users MFA-registered satisfies CIS 6.3 and 6.5.' }
            Gap = @{ Citation = '6.3, 6.5'; Requirement = 'IG1'
                Detail = 'Unregistered users bypass MFA CA policies. CIS 6.3 requires MFA for all users.' }
        }
        HIPAA = @{
            Satisfied = @{ Citation = '§164.312(d)'; Requirement = 'Required'
                Detail = 'All users with MFA satisfies §164.312(d) Person or Entity Authentication.' }
            Gap = @{ Citation = '§164.312(d)'; Requirement = 'Required'
                Detail = 'Unregistered users cannot satisfy §164.312(d) authentication requirements for ePHI access.' }
        }
        ISO = @{
            Satisfied = @{ Citation = 'A.8.5, A.5.16'; Requirement = 'Applicable'
                Detail = 'All users MFA-registered satisfies A.8.5 Secure Authentication and A.5.16 Identity Management.' }
            Gap = @{ Citation = 'A.8.5, A.5.16'; Requirement = 'Applicable'
                Detail = 'Users without MFA violate A.8.5 and A.5.16 authentication requirements.' }
        }
    }

    ExternalCollaboration = @{
        Title    = 'Restrict guest invitation permissions'
        Category = 'Identity'
        NIST = @{
            Satisfied = @{ Citation = 'AC-2, AC-3'; Requirement = 'Required'
                Detail = 'Restricted guest invitations satisfy AC-2 Account Management and AC-3 Access Enforcement.' }
            Partial = @{ Citation = 'AC-2'; Requirement = 'Required'
                Detail = 'Guest invitations partially restricted. Review policy to ensure only authorized roles can invite external users.' }
            Gap = @{ Citation = 'AC-2, AC-3'; Requirement = 'Required'
                Detail = 'All members can invite guests. AC-2 requires managed external account provisioning.' }
        }
        CIS = @{
            Satisfied = @{ Citation = '5.4'; Requirement = 'IG1'
                Detail = 'Restricted invitations satisfy CIS 5.4 access control requirements.' }
            Gap = @{ Citation = '5.4'; Requirement = 'IG1'
                Detail = 'Open guest invitations violate CIS 5.4 access restriction requirements.' }
        }
        HIPAA = @{
            Satisfied = @{ Citation = '§164.308(a)(4)'; Requirement = 'Required'
                Detail = 'Restricted guest access satisfies §164.308(a)(4) Information Access Management.' }
            Gap = @{ Citation = '§164.308(a)(4)'; Requirement = 'Required'
                Detail = 'Open guest invitations risk unauthorized ePHI access. §164.308(a)(4) requires information access management.' }
        }
        ISO = @{
            Satisfied = @{ Citation = 'A.5.15, A.6.7'; Requirement = 'Applicable'
                Detail = 'Restricted invitations satisfy A.5.15 Access Control and A.6.7 Remote Working.' }
            Gap = @{ Citation = 'A.5.15'; Requirement = 'Applicable'
                Detail = 'Open guest invitations violate A.5.15 Access Control policy.' }
        }
    }

    GlobalAdminCount = @{
        Title    = 'Limit Global Administrator count to 2 or fewer'
        Category = 'Identity'
        NIST = @{
            Satisfied = @{ Citation = 'AC-6, AC-2'; Requirement = 'Required'
                Detail = '2 or fewer GAs satisfies AC-6 Least Privilege and AC-2 Account Management for privileged account minimization.' }
            Gap = @{ Citation = 'AC-6, AC-2'; Requirement = 'Required'
                Detail = 'Excessive GA count violates AC-6 Least Privilege. Each GA is a full-tenant compromise path.' }
        }
        CIS = @{
            Satisfied = @{ Citation = '5.4'; Requirement = 'IG1'
                Detail = 'Minimal GA count satisfies CIS 5.4 Restrict Administrator Privileges.' }
            Gap = @{ Citation = '5.4'; Requirement = 'IG1'
                Detail = 'GA sprawl violates CIS 5.4. Excess privileged accounts expand the attack surface.' }
        }
        HIPAA = @{
            Satisfied = @{ Citation = '§164.308(a)(3)(ii)(B)'; Requirement = 'Addressable'
                Detail = 'Minimal GA count satisfies §164.308(a)(3)(ii)(B) Workforce Clearance Procedure.' }
            Gap = @{ Citation = '§164.308(a)(3)(ii)(B)'; Requirement = 'Addressable'
                Detail = 'Excess GAs violate §164.308(a)(3)(ii)(B) by granting unnecessary access to ePHI systems.' }
        }
        ISO = @{
            Satisfied = @{ Citation = 'A.5.18, A.8.2'; Requirement = 'Applicable'
                Detail = 'Minimal GA count satisfies A.5.18 Access Rights and A.8.2 Privileged Access Rights.' }
            Gap = @{ Citation = 'A.5.18, A.8.2'; Requirement = 'Applicable'
                Detail = 'GA sprawl violates A.5.18 and A.8.2. Privileged access must be minimized and reviewed.' }
        }
    }

    StaleAccounts = @{
        Title    = 'Disable or remove stale user accounts'
        Category = 'Identity'
        NIST = @{
            Satisfied = @{ Citation = 'AC-2'; Requirement = 'Required'
                Detail = 'No stale accounts satisfies AC-2 Account Management including account review, disabling, and removal.' }
            Partial = @{ Citation = 'AC-2'; Requirement = 'Required'
                Detail = 'Stale accounts detected. AC-2 requires periodic account review and disabling of inactive accounts.' }
            Gap = @{ Citation = 'AC-2'; Requirement = 'Required'
                Detail = 'Stale accounts present. AC-2 requires disabling accounts inactive beyond defined thresholds.' }
        }
        CIS = @{
            Satisfied = @{ Citation = '5.3'; Requirement = 'IG1'
                Detail = 'No stale accounts satisfies CIS 5.3 Disable Dormant Accounts.' }
            Gap = @{ Citation = '5.3'; Requirement = 'IG1'
                Detail = 'Stale accounts violate CIS 5.3. Dormant accounts are a lateral movement and persistence vector.' }
        }
        HIPAA = @{
            Satisfied = @{ Citation = '§164.308(a)(3)(ii)(C)'; Requirement = 'Addressable'
                Detail = 'No stale accounts satisfies §164.308(a)(3)(ii)(C) Termination Procedures for workforce members.' }
            Gap = @{ Citation = '§164.308(a)(3)(ii)(C)'; Requirement = 'Addressable'
                Detail = 'Stale accounts indicate incomplete termination procedures under §164.308(a)(3)(ii)(C).' }
        }
        ISO = @{
            Satisfied = @{ Citation = 'A.5.16'; Requirement = 'Applicable'
                Detail = 'No stale accounts satisfies A.5.16 Identity Management including identity lifecycle management.' }
            Gap = @{ Citation = 'A.5.16'; Requirement = 'Applicable'
                Detail = 'Stale accounts violate A.5.16 Identity Management. Inactive identities must be deprovisioned.' }
        }
    }

    MTASTS = @{
        Title    = 'Publish MTA-STS policy for all domains'
        Category = 'Mail Flow'
        NIST = @{
            Satisfied = @{ Citation = 'SC-8'; Requirement = 'Required'
                Detail = 'MTA-STS published satisfies SC-8 Transmission Confidentiality and Integrity by enforcing TLS for inbound SMTP.' }
            Gap = @{ Citation = 'SC-8'; Requirement = 'Required'
                Detail = 'No MTA-STS. SC-8 requires transmission protection. SMTP downgrade attacks bypass TLS without MTA-STS enforcement.' }
        }
        CIS = @{
            Satisfied = @{ Citation = '9.1'; Requirement = 'IG1'
                Detail = 'MTA-STS satisfies CIS 9.1 email sender authentication and transmission security.' }
            Gap = @{ Citation = '9.1'; Requirement = 'IG1'
                Detail = 'No MTA-STS. CIS 9.1 requires email transmission security controls.' }
        }
        ISO = @{
            Satisfied = @{ Citation = 'A.8.24'; Requirement = 'Applicable'
                Detail = 'MTA-STS satisfies A.8.24 Use of Cryptography for email transmission.' }
            Gap = @{ Citation = 'A.8.24'; Requirement = 'Applicable'
                Detail = 'No MTA-STS. A.8.24 requires cryptographic controls for data transmission.' }
        }
    }

    NamedLocations = @{
        Title    = 'Define named locations for Zero Trust network segmentation'
        Category = 'Conditional Access'
        NIST = @{
            Satisfied = @{ Citation = 'AC-17, SC-7'; Requirement = 'Required'
                Detail = 'Named locations satisfy AC-17 Remote Access and SC-7 Boundary Protection by defining network trust zones.' }
            Gap = @{ Citation = 'AC-17, SC-7'; Requirement = 'Required'
                Detail = 'No named locations. CA policies cannot enforce network-based conditions. AC-17 and SC-7 require defined network boundaries.' }
        }
        CIS = @{
            Satisfied = @{ Citation = '6.7'; Requirement = 'IG2'
                Detail = 'Named locations satisfy CIS 6.7 Centralize Access Control with network segmentation.' }
            Gap = @{ Citation = '6.7'; Requirement = 'IG2'
                Detail = 'No named locations. CIS 6.7 requires network-aware access control policies.' }
        }
        ISO = @{
            Satisfied = @{ Citation = 'A.5.15'; Requirement = 'Applicable'
                Detail = 'Named locations satisfy A.5.15 Access Control with network trust segmentation.' }
            Gap = @{ Citation = 'A.5.15'; Requirement = 'Applicable'
                Detail = 'No network segmentation. A.5.15 requires access control based on network context.' }
        }
    }

    InboundSpamPolicy = @{
        Title    = 'Harden inbound spam policy'
        Category = 'Threat Protection'
        NIST = @{
            Satisfied = @{ Citation = 'SI-3, SI-8'; Requirement = 'Required'
                Detail = 'Hardened spam policy satisfies SI-3 Malicious Code Protection and SI-8 Spam Protection.' }
            Gap = @{ Citation = 'SI-3, SI-8'; Requirement = 'Required'
                Detail = 'Default spam policy inadequate. SI-8 requires spam protection controls tuned to organizational requirements.' }
        }
        ISO = @{
            Satisfied = @{ Citation = 'A.8.7'; Requirement = 'Applicable'
                Detail = 'Hardened spam policy satisfies A.8.7 Protection Against Malware.' }
            Gap = @{ Citation = 'A.8.7'; Requirement = 'Applicable'
                Detail = 'Default spam policy. A.8.7 requires adequate malware and spam protection.' }
        }
    }

    MalwareFilterPolicy = @{
        Title    = 'Harden malware filter policy'
        Category = 'Threat Protection'
        NIST = @{
            Satisfied = @{ Citation = 'SI-3'; Requirement = 'Required'
                Detail = 'Hardened malware filter satisfies SI-3 Malicious Code Protection with ZAP and file filtering.' }
            Gap = @{ Citation = 'SI-3'; Requirement = 'Required'
                Detail = 'Default malware filter. SI-3 requires malicious code protection tuned beyond defaults.' }
        }
        HIPAA = @{
            Satisfied = @{ Citation = '§164.308(a)(5)(ii)(B)'; Requirement = 'Addressable'
                Detail = 'Hardened malware filter satisfies §164.308(a)(5)(ii)(B) Protection from Malicious Software.' }
            Gap = @{ Citation = '§164.308(a)(5)(ii)(B)'; Requirement = 'Addressable'
                Detail = 'Default malware filter insufficient for §164.308(a)(5)(ii)(B) ePHI protection requirements.' }
        }
        ISO = @{
            Satisfied = @{ Citation = 'A.8.7'; Requirement = 'Applicable'
                Detail = 'Hardened malware filter satisfies A.8.7 Protection Against Malware.' }
            Gap = @{ Citation = 'A.8.7'; Requirement = 'Applicable'
                Detail = 'Default malware filter. A.8.7 requires active protection against malware.' }
        }
    }

    DictionaryVersion = '1.0.0'
    LastUpdated   = '2026-04-23'
}

function Get-NLSFrameworkDictionary { return $script:FrameworkDictionary }
function Get-NLSDictionaryVersion   { return $script:DictionaryVersion }

Export-ModuleMember -Function Get-NLSFrameworkDictionary, Get-NLSDictionaryVersion
