---
title: "Better know a data source: Process integrity levels"
description: "In this second installment of our Better know a data source series, we’re showcasing process integrity levels."
pubDate: 2021-12-13
readingTime: "10 min read"
tags: ["windows", "detection"]
slug: "better-know-a-data-source-process-integrity-levels"
order: 37
---

### Impossible to spoof, process integrity levels dictate trust between securable objects, offering defenders great visibility into privilege escalation.

> This blog was originally written by me and posted by [Red Canary](https://redcanary.com/blog/process-integrity-levels/).

In this second installment of our [**Better know a data source**](https://redcanary.com/blog/process-command-line/) series, we’re showcasing process integrity levels. Integrity levels define the trust between process/thread and another object (files, processes, threads) and help control what that object can or can’t do on a system. A sudden change in a process’s integrity level might be a sign that an adversary has obtained system privileges.

While an adversary might be able to obtain a higher integrity level, they have no control over its metadata, meaning they can’t masquerade, hide, or otherwise fake it. Process integrity level is a kernel attribute from a kernel object, making it a reliable data point for defenders seeking to weed out malicious activity.

## What are process integrity levels?

Before diving into integrity levels, it’s important to understand the basics of [**access tokens**](https://docs.microsoft.com/en-us/windows/win32/secauthz/access-tokens). Access tokens serve to identify the security context (user security identifier, security identifier, group memberships, and privileges) of a process or thread. Unless a token is explicitly assigned to a thread, all threads will inherit the token of the primary thread (i.e., the first thread started in a process), which is also known as the primary token. All actions the process takes will fall under the security context of that token.

Every token is tied to a logon session. Any time a user logs in, a new token is generated and then applied to any process that user spawns during its logon lifecycle. When a local administrator logs in, two separate logon sessions are created: one for the unelevated token (medium integrity level) and one with the elevated token (high integrity level). These logon sessions are bound to one another and are referred to as a “split token.”

![Figure 1](/images/better-know-a-data-source-process-integrity-levels/IoC6hP4MM3XwPH9F.png)

The image above shows a logon session in which two LogonIDs are specified and tied to the appropriate token. Although this is the same user, there will be another logon session for the elevated token with different LogonID values and a higher integrity level.

Because every token is tied to a logon session, identity logs associated with logon sessions can serve as a link between process events when privilege escalation is performed. You can see an example of this in the **Detection opportunities** section below.

By default, child processes will inherit a copy of their parent’s token, meaning that all processes running under a logon session will have the same token. Token attributes include:

- user
- groups the user is associated with
- token type
- token ID
- user’s privileges
- integrity level

Integrity levels help define the trust between a process/thread and a [**securable object**](https://docs.microsoft.com/en-us/windows/win32/secauthz/securable-objects) (processes, threads, tokens, files, etc. — any object that can have a security descriptor). Because access tokens can be tied to a process or thread, integrity levels can be tied to either of these as well. The only time a thread’s token will be different from the primary token is when a token is explicitly set on a target thread.

Integrity levels are stored as security identifiers (SID) but can be converted to a human readable string that defenders can more easily interpret.

Below are the integrity level [**SIDs defined by Microsoft**](https://docs.microsoft.com/en-US/windows/security/identity-protection/access-control/security-identifiers):

![Note: Although the level Medium Plus doesn’t include a description due to a lack of references, you should still look out for these SIDs.](/images/better-know-a-data-source-process-integrity-levels/H3Lm366p7xENyhZPidjXZQ.png)

## Why focus on process integrity level?

Integrity levels can be applied to securable objects as a way of evaluating the level of access that a source object has to a target object. Monitoring processes spawning from a lower integrity level into a higher integrity level can tip defenders off when a process is about to perform a task that requires higher privileges or when sensitive privileges have been co-opted.

Each integrity level comes with a set of system privileges. By default, the higher integrity level you are, the more system privileges you have on a host and the more access you have to securable objects. This is one of the primary drivers that compels adversaries to find ways to escalate their integrity level. The following example from [**James Forshaw’s**](https://twitter.com/tiraniddo) [**NtObjectManager**](https://www.powershellgallery.com/packages/NtObjectManager) PowerShell module shows the default privileges given to a process of medium integrity level and then again of high integrity level.

**Medium integrity level:**

![Figure 3](/images/better-know-a-data-source-process-integrity-levels/CMdkx8vgL01cAo3G.png)

**High integrity level:**

![Figure 4](/images/better-know-a-data-source-process-integrity-levels/WmvrgVPkMy8iTFmC.png)

These token privileges dictate what you can and can’t do on a machine from a system operations perspective, such as loading drivers, changing the host’s time, impersonating a client, creating a primary token, etc.

As we noted earlier, when an admin logs in, a split token is generated. Unless you explicitly set the process token to a high integrity level, the process will default to the lowest group the user/token is associated with, which for most users will be a medium integrity level. Users must specify when they want to use their administrative privileges, and in most circumstances, [**User Account Control**](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/how-user-account-control-works) (UAC) kicks in to either allow that elevation or not. If the elevation request is successful, the elevated token is granted to that process and the appropriate privileges are applied.

## What users can obtain a high integrity level token?

By default, users who are a part of the Administrators groups can obtain a high integrity level token. However, a high integrity level token can still be applied to a user outside of the Administrators group if a sensitive privilege is explicitly granted to that user.

Adversaries have been known to gain access to [**SeImpersonatePrivilege**](https://docs.microsoft.com/en-us/windows/win32/secauthz/authorization-constants). This privilege allows an attacker to impersonate different clients — such as named pipe clients, [**RPC clients**](https://redcanary.com/blog/msrpc-to-attack/), and COM clients — to act with the security context of a targeted token.

This privilege is given to users within the Administrators group by default. Admins can grant this privilege to a user outside of that group using the User Rights Assignments (URA) within `Group Policy Object - Computer Configuration\Windows Settings\Security Settings\Local Policies\User Rights Assignment.` To do so, the admins would need to add the user to the “impersonate a client after authentication” assignment and start a new logon session with that user.

If the user starts a normal process, they will not have a token that possesses that sensitive privilege. In the screenshot below, I granted `SeImpersonatePrivilege` to `TargetUser`, but when I started a normal PowerShell process, I didn’t have that sensitive privilege. The integrity level of `TargetUser` is “medium.” The examples below are using [**whoami /groups**](https://docs.microsoft.com/en-us/windows-server/administration/windows-commands/whoami).

![Figure 5](/images/better-know-a-data-source-process-integrity-levels/xHAsG_fruwleoPQC.png)

To apply the sensitive privilege `SeImpersonatePrivilege`, the user has to run as an elevated prompt. After doing so, the sensitive privilege and corresponding high integrity level are applied.

To my knowledge, there is no easy way to determine what token privileges should be considered sensitive — other than by looking at how the privileges are used for sensitive system operations. Knowing this, adversaries prefer to set their sights on processes with specific sensitive privileges granted to their token, or, alternatively, by simply targeting accounts in the Administrators group.

## How do adversaries leverage access token process integrity levels?

[**T1134.002: Create Process With Token**](https://attack.mitre.org/techniques/T1134/002/) is a [**MITRE ATT&CK**](https://redcanary.com/mitre-attack/) technique that describes when an adversary targets access tokens of higher integrity levels and creates a process with a copy of the targeted token. This allows attackers to operate under the security context of the targeted user and run a program, access resources, or establish persistence where they otherwise wouldn’t have been able to.

Adversaries will also impersonate another user either by obtaining a copy of the target token or by obtaining the handle to the target token and setting it to a thread within their running process, in turn changing the integrity level for that thread ([**T1134.001: Token Impersonation/Theft**](https://attack.mitre.org/techniques/T1134/001/)). By default this will only work with a token that has a high integrity level process, because that’s the level required to abuse `SeImpersonatePrivilege`.

In general, it is unusual to see a newly spawned process go from a lower integrity level to a higher one (outside of normal UAC elevation) — it could mean that an adversary has obtained a token of a higher integrity level process or has logged in as another user who is of higher integrity level and is using that logon session token. It could also mean that an administrator is using `Start-Process` as a normal everyday activity.

As we explained earlier, it’s impossible for an adversary to directly manipulate integrity level metadata. Therefore, if you’re able to gather integrity level-related telemetry, it can serve as a reliable data source.

## What data sources are available to retrieve process integrity level?

There are a couple of data sources that you can use to gain insight into a process’s integrity level.

## Win32 API:

**Data source:** `GetTokenInformation`
**Relevant field(s)**: `IntegrityLevel`

One way to view the integrity level of a process/thread is to use the [`GetTokenInformation`](https://docs.microsoft.com/en-us/windows/win32/api/securitybaseapi/nf-securitybaseapi-gettokeninformation) Win32 API and pass in the `TokenIntegrityLevel` value into the `TokenInformationClass` parameter. This will specify that you want to enumerate the `TokenIntegrityLevel` attribute within the [`TOKEN_INFORMATION_CLASS`](https://docs.microsoft.com/en-us/windows/win32/api/winnt/ne-winnt-token_information_class) enum. The `TokenIntegrityLevel` attribute is backed by the [`TOKEN_MANDATORY_LABEL`](https://docs.microsoft.com/en-us/windows/win32/api/winnt/ns-winnt-token_mandatory_label) structure, which has an attribute within it called `Label`. `Label` is backed by the [`SID_AND_ATTRIBUTES`](https://docs.microsoft.com/en-us/windows/desktop/api/winnt/ns-winnt-sid_and_attributes) structure that identifies the mandatory integrity level of the token. The SID attribute can be translated to one of the values seen in the table above.

Here is [**an example**](https://gist.github.com/jsecurity101/5ef14a0b537af36ce448b28c707c6976) of what this can look like:

```powershell
PS > Get-IntegrityLevel
Title               : Displaying Process/Primary Information
ProcessName         : powershell
SessionId           : 1
PID                 : 2800
TokenIntegrityLevel : MEDIUM_MANDATORY_LEVEL
```

## Windows Process Auditing:

**Data source:** [**Windows Security Log Event ID 4688**](https://docs.microsoft.com/en-us/windows/security/threat-protection/auditing/event-4688)
**Relevant field(s)**: Mandatory Label
**Example data:**

```
Creator Subject:
	Security ID:		MARVEL\thor
	Account Name:		thor
	Account Domain:		MARVEL
	Logon ID:		0x2FC7277
 
Target Subject:
	Security ID:		NULL SID
	Account Name:		-
	Account Domain:		-
	Logon ID:		0x0
 
Process Information:
	New Process ID:		0x1b54
	New Process Name:	C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe
	Token Elevation Type:	%%1938
	Mandatory Label:		Mandatory Label\Medium Mandatory Level
	Creator Process ID:	0x16b0
	Creator Process Name:	C:\Windows\explorer.exe
	Process Command Line:
```

## Sysmon:

**Data source:** [**Event ID 1: Process creation**](https://www.ultimatewindowssecurity.com/securitylog/encyclopedia/event.aspx?eventid=90001)
**Relevant field[s]:** `IntegrityLevel`
**Example data:**

```
Relevant Field[s]: IntegrityLevel
Example Data:
UtcTime: 2021-10-28 01:19:37.643
ProcessGuid: {68e97739-faa9-6179-9394-0f0300000000}
ProcessId: 6996
Image: C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe
FileVersion: 10.0.17134.1 (WinBuild.160101.0800)
Description: Windows PowerShell
Product: Microsoft® Windows® Operating System
Company: Microsoft Corporation
OriginalFileName: PowerShell.EXE
CommandLine: "C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe" 
CurrentDirectory: C:\Users\thor\
User: MARVEL\thor
LogonGuid: {68e97739-fa73-6179-7772-fc0200000000}
LogonId: 0x2FC7277
TerminalSessionId: 2
IntegrityLevel: Medium
Hashes: SHA1=1B3B40FBC889FD4C645CC12C85D0805AC36BA254,MD5=95000560239032BC68B4C2FDFCDEF913,SHA256=D3F8FADE829D2B7BD596C4504A6DAE5C034E789B6A3DEFBE013BDA7D14466677,IMPHASH=741776AACCFC5B71FF59832DCDCACE0F
ParentProcessGuid: {68e97739-fa75-6179-1c86-fd0200000000}
ParentProcessId: 5808
ParentImage: C:\Windows\explorer.exe
ParentCommandLine: C:\Windows\Explorer.EXE
```

## Microsoft Defender for Endpoint (MDE):

**Data source:** [**DeviceProcessEvents**](https://docs.microsoft.com/en-us/microsoft-365/security/defender/advanced-hunting-deviceprocessevents-table)
**Relevant field[s]:** `ProcessIntegrityLevel`, `InitiatingProcessIntegrityLevel`
**Example data:**

```
Timestamp:	2021-10-28T01:19:37.7098154Z
DeviceId:	4444706065525f7093e60eeca71e8a48d2e8448f
DeviceName:	asgard-wrkstn.marvel.local
ActionType:	ProcessCreated
FileName:	powershell.exe
FolderPath:	C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe
SHA1:	1b3b40fbc889fd4c645cc12c85d0805ac36ba254
SHA256:	d3f8fade829d2b7bd596c4504a6dae5c034e789b6a3defbe013bda7d14466677
MD5:	95000560239032bc68b4c2fdfcdef913
FileSize:	447488
ProcessVersionInfoCompanyName:	Microsoft Corporation
ProcessVersionInfoProductName:	Microsoft® Windows® Operating System
ProcessVersionInfoProductVersion:	10.0.17134.1
ProcessVersionInfoInternalFileName:	POWERSHELL
ProcessVersionInfoOriginalFileName:	PowerShell.EXE
ProcessVersionInfoFileDescription:	Windows PowerShell
ProcessId:	6996
ProcessCommandLine:	"powershell.exe" 
ProcessIntegrityLevel:	Medium
ProcessTokenElevation:	TokenElevationTypeLimited
ProcessCreationTime:	2021-10-28T01:19:37.6431454Z
AccountDomain:	marvel
AccountName:	thor
AccountSid:	S-1-5-21-3637186843-3378876361-2759896766-1104
AccountUpn:	
AccountObjectId:	
LogonId:	0
InitiatingProcessAccountDomain:	marvel
InitiatingProcessAccountName:	thor
InitiatingProcessAccountSid	: S-1-5-21-3637186843-3378876361-2759896766-1104
InitiatingProcessAccountUpn:	
InitiatingProcessAccountObjectId:	
InitiatingProcessLogonId:	null
InitiatingProcessIntegrityLevel:	Medium
InitiatingProcessTokenElevation:	TokenElevationTypeLimited
InitiatingProcessSHA1:	e4d846417f2836d1a2c2a8f25c61620fddb4893b
InitiatingProcessSHA256:	a6327254f8808e99e3378d16bbf8e564d733879f55b3461acd9a036fc46f5aea
InitiatingProcessMD5:	ea043f4a77826199143350288dad220c
InitiatingProcessFileName:	explorer.exe
InitiatingProcessFileSize:	4098912
InitiatingProcessVersionInfoCompanyName:	Microsoft Corporation
InitiatingProcessVersionInfoProductName:	Microsoft® Windows® Operating System
InitiatingProcessVersionInfoProductVersion:	10.0.17134.1098
InitiatingProcessVersionInfoInternalFileName:	explorer
InitiatingProcessVersionInfoOriginalFileName:	EXPLORER.EXE
InitiatingProcessVersionInfoFileDescription:	Windows Explorer
InitiatingProcessId:	5808
InitiatingProcessCommandLine:	Explorer.EXE
InitiatingProcessCreationTime:	2021-10-28T01:18:45.9993865Z
InitiatingProcessFolderPath	: c:\windows\explorer.exe
InitiatingProcessParentId:	4256
InitiatingProcessParentFileName:	userinit.exe
InitiatingProcessParentCreationTime:	2021-10-28T01:18:45.8917635Z
InitiatingProcessSignerType	Unknown:
InitiatingProcessSignatureStatus:	Unknown
ReportId:	6685
AppGuardContainerId:	
AdditionalFields:
```

## How do I generate integrity level metadata for sensor and detection validation?

Within the [**AtomicTestHarnesses**](https://redcanary.com/blog/introducing-atomictestharnesses/) PowerShell module, there is a function called `Invoke-ATHCreateProcessWithToken` that generates telemetry to test optics, detection gaps, and technique knowledge. This module will simulate the behavior of targeting a token then creating a process with a duplicated copy of that targeted token. It will terminate all processes created and close any handles that were opened as a result of this activity. It will then print out an accessible view of data that relates to the activity so that it can easily be tested against the optics available to the users/analysts.

```
PS > Invoke-ATHCreateProcessWithToken
 
 
TechniqueID              : T1134.002
TestSuccess              : True
TestGuid                 : a8e88199-1036-4ceb-9845-c556bc09ded9
TestCommand              : Invoke-ATHCreateProcessWithToken
SourceUser               : MARVEL\thor
SourceExecutableFilePath : C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe
SourceExecutableFileHash : D3F8FADE829D2B7BD596C4504A6DAE5C034E789B6A3DEFBE013BDA7D14466677
SourceProcessId          : 8952
GrantedRights            : QueryLimitedInformation
ImpersonatedUser         : NT AUTHORITY\SYSTEM
LogonType                :
TargetExecutableFilePath : C:\Windows\system32\winlogon.exe
TargetExecutableFileHash : 10098BBE7EFD4B16014493F7D26E593E06910CC36D4BA4A3E59FCF8C15E4F1D7
TargetProcessId          : 588
NewProcessExecutablePath : C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe
NewProcessCommandline    : powershell.exe -nop -Command Write-Host a8e88199-1036-4ceb-9845-c556bc09ded9; Start-Sleep
                           -Seconds 2; exit
NewProcessExecutableHash : D3F8FADE829D2B7BD596C4504A6DAE5C034E789B6A3DEFBE013BDA7D14466677
NewProcessId             : 5828
```

## Detection opportunities

The following [**Microsoft Defender for Endpoint**](https://redcanary.com/products/mdr-for-endpoints/microsoft-defender-for-endpoint/) (MDE) queries identify when lower integrity level processes spawn a higher integrity level process or a potentially impersonated login. These will only work for instances where a new process is spawned. Currently, we aren’t aware of any scalable optics or analytics that would give insight into times when token impersonation happens on a thread level. See [**Access Token Manipulation: Token Impersonation/Theft**](https://attack.mitre.org/techniques/T1134/001/) for more.

## Detecting parent-child process integrity level disparities

This MDE query looks for high integrity level processes spawning a system integrity level process and/or low integrity level process spawning high or system integrity level process.

```
DeviceProcessEvents
    | where InitiatingProcessIntegrityLevel != ProcessIntegrityLevel and (InitiatingProcessIntegrityLevel == "Low" or InitiatingProcessIntegrityLevel == "High")
    | project Timestamp, DeviceName, InitiatingProcessAccountName, InitiatingProcessFileName, InitiatingProcessIntegrityLevel, AccountName, FileName, ProcessIntegrityLevel, InitiatingProcessParentId
```

## Detecting login impersonation

As in the previous MDE query, this detection logic looks for integrity level disparities between parent and child processes. However, here we’re also looking for a corresponding command line with the `seclogon` (secondary logon) string. The `seclogon` string is a good indication of logging on as another user and abusing their security context. This logic will show when a process was spawned with [**CreateProcessWithLogon**](https://docs.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-createprocesswithlogonw).

```
DeviceProcessEvents
    | where (InitiatingProcessIntegrityLevel != ProcessIntegrityLevel and (InitiatingProcessIntegrityLevel == "Low" or InitiatingProcessIntegrityLevel == "High")) or (InitiatingProcessAccountName != AccountName and ProcessIntegrityLevel == "Medium" and InitiatingProcessCommandLine contains "seclogon") 
| project Timestamp, DeviceName, InitiatingProcessAccountName, InitiatingProcessFileName, InitiatingProcessIntegrityLevel, AccountName, FileName, ProcessIntegrityLevel
```

## Another way to detect login impersonation

You can also use identity events to look for logins where the `InitiatingProcessCommandLine` tag has `seclogon` (secondary logon). This telemetry also suggests the use of [**CreateProcessWithLogon**](https://docs.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-createprocesswithlogonw).

```
DeviceLogonEvents
| where Protocol == "Negotiate" and InitiatingProcessCommandLine contains "seclogon"
| project InitiatingProcessAccountName, AccountName, Protocol, LogonType, InitiatingProcessId, LogonId
| join ( 
    DeviceProcessEvents
    	| project InitiatingProcessId, InitiatingProcessLogonId, AccountName, FileName
)
on InitiatingProcessId, AccountName
| project-rename TargetProcessId = InitiatingProcessId1
| project-rename TargetUser = AccountName1
| project InitiatingProcessAccountName, Protocol, LogonType, TargetUser, LogonId, TargetProcessId, FileName
```

## References

- Windows Internals Part 1, Chapter 7 (7th Edition)
- [**Abusing Access Tokens for UAC Bypasses**](https://www.youtube.com/watch?v=UTvOfmtNVKI&t=1016s) by** [James Forshaw](https://twitter.com/tiraniddo)**
- [**A Token’s Tale**](https://googleprojectzero.blogspot.com/2015/02/a-tokens-tale_9.html) by[** James Forshaw**](https://twitter.com/tiraniddo)
- Conversations with [**Matt Hand**](https://twitter.com/matterpreter)
- [**Understanding and Defending Against Access Token Theft: Finding Alternatives to winlogon.exe**](https://posts.specterops.io/understanding-and-defending-against-access-token-theft-finding-alternatives-to-winlogon-exe-80696c8a73b) — [**Justin Bui**](https://twitter.com/slyd0g)
