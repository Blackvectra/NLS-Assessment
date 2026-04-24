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
    }
}

# Dictionary version metadata -- update this when framework versions change
$script:DictionaryVersion = [ordered]@{
    NIST          = 'SP 800-53 Rev 5 Release 5.2.0'
    CIS           = 'CIS Controls v8.1 June 2024'
    HIPAA         = 'HIPAA Security Rule 45 CFR 164.312 current enforceable rule'
    HIPAAProposed = 'HIPAA Security Rule NPRM December 27 2024 proposed rule -- expected final May 2026'
    DictionaryVersion = '1.0.0'
    LastUpdated   = '2026-04-23'
}

function Get-NLSFrameworkDictionary { return $script:FrameworkDictionary }
function Get-NLSDictionaryVersion   { return $script:DictionaryVersion }

Export-ModuleMember -Function Get-NLSFrameworkDictionary, Get-NLSDictionaryVersion
