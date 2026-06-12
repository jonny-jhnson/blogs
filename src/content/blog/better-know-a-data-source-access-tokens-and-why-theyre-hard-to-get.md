---
title: "Better know a data source: Access tokens (and why they’re hard to get)"
description: "Detection engineers are frequently beset with the challenge of detecting a technique for which optics are poor, non-existent, or difficult to collect at scale."
pubDate: 2022-04-20
readingTime: "12 min read"
tags: ["windows", "detection"]
slug: "better-know-a-data-source-access-tokens-and-why-theyre-hard-to-get"
order: 33
---

> *This blog was originally written by me and posted by [Red Canary.](https://redcanary.com/blog/access-tokens/)*

Detection engineers are frequently beset with the challenge of detecting a technique for which optics are poor, non-existent, or difficult to collect at scale. [**Access Token Manipulation**](https://attack.mitre.org/techniques/T1134/) (T1134) is a great example of a technique where one such telemetry gap or challenge exists.

In this installment of [**Better Know a Data Source**](https://redcanary.com/blog/amsi/), we’re going to dive deep into access tokens, exploring the potential value they provide, the challenges they present, why it isn’t reasonable to collect all token-related telemetry, and how practitioners or vendors can best instrument their tools to enable new detection optics.

Token-related telemetry could be a boon for defenders seeking better detection coverage for token impersonation and theft, but it’s very difficult to collect at this time. For background, check out the MITRE ATT&CK page for [**T1134.001: Access Token Manipulation: Token Impersonation/Theft**](https://attack.mitre.org/techniques/T1134/001/), our previous work on [**process integrity levels**](https://redcanary.com/blog/process-integrity-levels/), or the work of [**James Forshaw**](https://twitter.com/tiraniddo) (specifically this [**blog**](https://googleprojectzero.blogspot.com/2015/02/a-tokens-tale_9.html) and this [**talk**](https://www.youtube.com/watch?v=UTvOfmtNVKI&t=844s)).

## What are access tokens?

Access tokens are [**securable objects**](https://docs.microsoft.com/en-us/windows/win32/secauthz/securable-objects) that specify the security context of Windows processes and threads. The security context of a securable object consists of the user’s [**security identifier **](https://docs.microsoft.com/en-us/windows/win32/secauthz/security-identifiers)(SID), group membership, and [**privileges**](https://docs.microsoft.com/en-us/windows/win32/secauthz/privileges). These can all be thought of as token attributes.

Let’s break down two types of access tokens:

- **Primary tokens** are applied to a process. By default, when a thread attempts to interact with a securable object, this token is checked to validate the authorization attributes of that user. This token belongs to the user account that created the process.
- **Impersonation tokens** are applied at the thread level, allowing a thread to interact with a securable object under a different security context than that of the primary token.

Unless a token is explicitly set for a thread, all threads inherit the token of the primary thread (i.e., the first thread started in a process) and all actions the process takes will fall under the security context of the primary token.

## Why do we care?

Everything a user account does on a system ties back to an access token. These tokens then relate back to the logon sessions where the access token was generated in the first place. In other words, nearly all activity in Windows can be tied back to an identity using access tokens, and therefore, having the ability to track a token back to its source provides invaluable visibility for incident response, detection, and more.

Adversaries commonly impersonate, steal, or otherwise abuse tokens. Token impersonation in particular comes in many different flavors, so let’s examine the behavior in its simplest form: *a source process obtains a handle to a target process’s token (running under a different security context) and applies it to a thread within the source process.*

![Figure 1](/images/better-know-a-data-source-access-tokens-and-why-theyre-hard-to-get/WZoRyJZgcZLNs598.jpg)

This allows an attacker to act on behalf of the target’s more highly privileged token and perform activities they wouldn’t have been able to otherwise.

As far as we know, no vendor currently has explicit telemetry that can definitively determine that token impersonation is happening at scale. To that point, it’s disappointing when you identify an optic that could help detect an attack or adversary technique, but you can’t find a log source that readily collects the telemetry you want. However, as defenders, we’re equipped to understand why optics gaps exist and, ideally, what would be required to obtain the desired optics.

## What would it take to obtain access token telemetry?

The majority of telemetry we see from vendors comes from kernel notification routines (e.g., [**PsSetCreateProcessNotifyRoutine**](https://docs.microsoft.com/en-us/windows-hardware/drivers/ddi/ntddk/nf-ntddk-pssetcreateprocessnotifyroutine)), consuming events from [**ETW providers**](https://blog.palantir.com/tampering-with-windows-event-tracing-background-offense-and-defense-4be7ac62ac63), function hooking, and mini-filter drivers (typical for file system monitoring), to name a few sources.

There are two primary data collection strategies: pull or push methods. A pull method involves functions being called on a periodic basis to pull the desired data. A push method gathers data on-demand in response to a specific trigger. Both strategies have their respective pros and cons, so we’ll examine both.

## The pull method

The first thing we want to understand is which attributes offer the most potential value to a detection engineer. There are a couple of ways to see what token attributes are available, including by parsing symbols using WinDbg (a popular debugging tool), but Microsoft also provides documentation within the `TOKEN_INFORMATION_CLASS` enumeration type. Unfortunately, it’s not always the case that Microsoft supplies documentation of complex kernel data structures.

Within WinDbg, however, the address of the token can be accessed within [**EPROCESS structures**](https://docs.microsoft.com/en-us/windows-hardware/drivers/kernel/eprocess). Every user-mode process is backed by a kernel data structure known as an EPROCESS. There are various fields that make up this structure. These fields are basically the attributes that make up a process. These attributes can be values, embedded structures, or pointers to other structures. The attribute that we are interested in is `Token`. Within the WinDbg output, we can see that `Token` is accessed via an [**`_EX_FAST_REF` structure.**](https://www.nirsoft.net/kernel_struct/vista/EX_FAST_REF.html) This can be seen with the output below:

```
dt nt!_EPROCESS
   +0x000 Pcb : _KPROCESS
   +0x438 ProcessLock : _EX_PUSH_LOCK
   +0x440 UniqueProcessId : Ptr64 Void
   +0x448 ActiveProcessLinks : _LIST_ENTRY
   +0x458 RundownProtect : _EX_RUNDOWN_REF
   +0x460 Flags2 : Uint4B
   +0x460 JobNotReallyActive : Pos 0, 1 Bit
   +0x460 AccountingFolded : Pos 1, 1 Bit
   +0x460 NewProcessReported : Pos 2, 1 Bit
   +0x460 ExitProcessReported : Pos 3, 1 Bit
   +0x460 ReportCommitChanges : Pos 4, 1 Bit
   +0x460 LastReportMemory : Pos 5, 1 Bit
   +0x460 ForceWakeCharge : Pos 6, 1 Bit
   .........
   +0x4b8 Token : _EX_FAST_REF
   +0x4c0 MmReserved : Uint8B
   +0x4c8 AddressCreationLock : _EX_PUSH_LOCK
   +0x4d0 PageTableCommitmentLock : _EX_PUSH_LOCK
   +0x4d8 RotateInProgress : Ptr64 _ETHREAD
   +0x4e0 ForkInProgress : Ptr64 _ETHREAD
   +0x4e8 CommitChargeJob : Ptr64 _EJOB
   +0x4f0 CloneRoot : _RTL_AVL_TREE
```

This `EX_FAST_REF` structure is made up of 3 members:

- `Object` points to a kernel object
- `RefCnt` tracks active references to an object
- `Value` states the value of the token structure

To find the token structure, we’ll want to look at the `Object` attribute. Within WinDbg, if you target a specific process and print its attributes using the `!process` command, it will show you the virtual memory address of the token object for that process. However, since we care about how a vendor would go about getting these optics, we are going to step through it with debugger commands.

Let’s look at this in real time and walk through what it would take to get one token attribute.

## The setup

We attached the kernel-mode (`kd`) variety of the WinDbg debugger to a target host in order to enumerate the token attributes of a spawned process. The token attribute we’re looking for is known as the `LogonID` (`TOKEN!AuthenticationId`), which relates back to a logon session of a user who was successful. This is a common attribute we see within a lot of telemetry sensors. Here are the steps you can follow to collect it:

- Obtain the virtual address of the EPROCESS structure.
- Parse the EPROCESS structure for that process.
- Dereference the values within the EPROCESS token attribute structure: `_EX_FAST_REF`.
- Dereference the TOKEN structure from the `Object` member of the `_EX_FAST_REF`.
- Extract the TOKEN attribute of choice ≈

### Obtain the virtual address of the target process

If the PID of the target process is 6320, you would run the following within WinDbg:

```
kd> !process 0n6320
```

This will spit out a lot of great information, but the thing we care most about is `PROCESS <Virtual Memory Address>`, the address of the corresponding EPROCESS structure.

```
PROCESS ffffc087622cd0c0
```

### Parse the EPROCESS structure for that process

We then take the virtual address of the EPROCESS structure and look for the token attribute that exists within the EPROCESS structure by using `dt` (display type) in WinDbg. The output informs us that `_EX_FAST_REF` is stored at an offset of 0x4b8 from the beginning of the EPROCESS structure.

*Note: these offsets are subject to change across Windows versions.*

```
dt nt!_EPROCESS token ffffc087622cd0c0
   +0x4b8 Token : _EX_FAST_REF
```

### Dereference the values within the EPROCESS token attribute structure: `_EX_FAST_REF`

We will use `dt` again to pull the information from `_EX_FAST_REF`

```
dt nt!_EX_FAST_REF ffffc087622cd0c0+0x4b8
```

Within the following output, we have three values: `Object`, `RefCnt`, and `Value`. Again, we care the most about Object, but we can’t just pull this value because it isn’t the true pointer address to the token structure. `_EX_FAST_REF` uses [**unions**](https://docs.microsoft.com/en-us/cpp/cpp/unions?view=msvc-170) that enable [**memory conservation**](https://docs.microsoft.com/en-us/cpp/cpp/unions?view=msvc-170) by allowing all members to share the same memory location. This is easy to tell because all of the offsets are 0.

```
+0x000 Object : 0xffff8108`2cd08778 Void
   +0x000 RefCnt : 0y1000
   +0x000 Value : 0xffff8108`2cd08778
```

To get the true pointer value to the token structure, subtract `RefCnt` from `Object`.

```
kd> ?(0xffff8108`2cd08778- 0y1000)
Evaluate expression: -139602865125520 = ffff8108`2cd08770
```

If you input the right value then the following step’s output will not hold a bunch of null or garbage values.

### Dereference the TOKEN structure from the `Object` member of the `_EX_FAST_REF`

```
kd> dt nt!_TOKEN ffff8108`2cd08770
   +0x000 TokenSource : _TOKEN_SOURCE
   +0x010 TokenId : _LUID
   +0x018 AuthenticationId : _LUID
   +0x020 ParentTokenId : _LUID
   +0x028 ExpirationTime : _LARGE_INTEGER 0x7fffffff`ffffffff
   +0x030 TokenLock : 0xffffc087`60d5d590 _ERESOURCE
   +0x038 ModifiedId : _LUID
   +0x040 Privileges : _SEP_TOKEN_PRIVILEGES
   +0x058 AuditPolicy : _SEP_AUDIT_POLICY
   +0x078 SessionId : 1
   +0x07c UserAndGroupCount : 0x10
   +0x080 RestrictedSidCount : 0
   +0x084 VariableLength : 0x200
   +0x088 DynamicCharged : 0x1000
   +0x08c DynamicAvailable : 0
   +0x090 DefaultOwnerIndex : 0
   +0x098 UserAndGroups : 0xffff8108`2cd08c00 _SID_AND_ATTRIBUTES
   +0x0a0 RestrictedSids : (null)
   +0x0a8 PrimaryGroup : 0xffff8108`2cf36350 Void
   +0x0b0 DynamicPart : 0xffff8108`2cf36350 -> 0x501
   +0x0b8 DefaultDacl : 0xffff8108`2cf3636c _ACL
   +0x0c0 TokenType : 1 ( TokenPrimary )
   +0x0c4 ImpersonationLevel : 0 ( SecurityAnonymous )
   +0x0c8 TokenFlags : 0x2a00
   +0x0cc TokenInUse : 0x1 ''
   +0x0d0 IntegrityLevelIndex : 0xf
   +0x0d4 MandatoryPolicy : 3
   +0x0d8 LogonSession : 0xffff8108`29c932d0 _SEP_LOGON_SESSION_REFERENCES
   +0x0e0 OriginatingLogonSession : _LUID
   +0x0e8 SidHash : _SID_AND_ATTRIBUTES_HASH
   +0x1f8 RestrictedSidHash : _SID_AND_ATTRIBUTES_HASH
   +0x308 pSecurityAttributes : 0xffff8108`2d133590 _AUTHZBASEP_SECURITY_ATTRIBUTES_INFORMATION
   +0x310 Package : (null)
   +0x318 Capabilities : (null)
   +0x320 CapabilityCount : 0
   +0x328 CapabilitiesHash : _SID_AND_ATTRIBUTES_HASH
   +0x438 LowboxNumberEntry : (null)
   +0x440 LowboxHandlesEntry : (null)
   +0x448 pClaimAttributes : (null)
   +0x450 TrustLevelSid : (null)
   +0x458 TrustLinkedToken : (null)
   +0x460 IntegrityLevelSidValue : (null)
   +0x468 TokenSidValues : (null)
   +0x470 IndexEntry : 0xffff8108`2d778a40 _SEP_LUID_TO_INDEX_MAP_ENTRY
   +0x478 DiagnosticInfo : (null)
   +0x480 BnoIsolationHandlesEntry : (null)
   +0x488 SessionObject : 0xffffc087`5e631db0 Void
   +0x490 VariablePart : 0xffff8108`2cd08d00
```

Here we can see the primary token attributes provided to us. The majority of them are backed by other enums or structures that we would have to dereference to get the proper value. The `LogonId` is one of those attributes where the actual attribute is called `AuthenticationId`, and it’s backed by the [**local identifier**](https://docs.microsoft.com/en-us/windows/win32/api/winnt/ns-winnt-luid) (LUID) structure. Fortunately, this is relatively easy to enumerate.

### Extract the TOKEN attribute of choice

To enumerate the `AuthenticationId` attribute, take the value of the TOKEN structure and the offset of the `AuthenticationId` attribute and call `dt` to display the LUID structure value.

```
dt nt!_LUID ffff8108`2cd08770+0x018
   +0x000 LowPart  : 0x19deb
   +0x004 HighPart : 0n0
```

Based on the LUID [**documentation**](https://docs.microsoft.com/en-us/windows/win32/api/winnt/ns-winnt-luid), focus on the `LowPart` attribute. The value of the `AuthenticationId` is `0x19deb`. You can verify this using the [**NtObjectManager**](https://github.com/googleprojectzero/sandbox-attacksurface-analysis-tools/tree/master/NtObjectManager) research tool provided by [**James Forshaw**](http://twitter.com/tiraniddo):

![Figure 2](/images/better-know-a-data-source-access-tokens-and-why-theyre-hard-to-get/fOSEG1mZX2WmMDJ9.png)

Above we can see Windows Security Event 4624 pulling the `AuthenticationId` attribute (called `LogonId` within the event) with `NtObjectManager`. Both have the same value as the output we got within WinDbg.

There are other token attributes that are even harder to gather due to the nested enums and structures. Obtaining the `IntegrityLevel` is one. Yarden Shafir wrote a good blog on enumerating this value: Exploiting a “Simple” Vulnerability, Part 2 – What If We Made Exploitation Harder?

### API hooking!

I mentioned at the beginning of this section that in order to pull this information, vendors would have to do a combination of API hooking and data structure parsing. We have seen the relevant data structures at this point, but what API could we hook? In all likelihood, a vendor would want to hook the `NtQueryInformationToken` kernel-mode function. This is one of the few native functions that Microsoft [**documents for us**](https://docs.microsoft.com/en-us/windows-hardware/drivers/ddi/ntifs/nf-ntifs-ntqueryinformationtoken).

This function uses the [`TOKEN_INFORMATION_CLASS`](https://docs.microsoft.com/en-us/windows-hardware/drivers/ddi/ntifs/ne-ntifs-_token_information_class) enumeration to pull token attributes, which ultimately still requires you to go through all the same structures we went through to get the attribute values above.

However, for those who are curious, there’s a way to do this in user-mode (although it shouldn’t be used for realtime collection, but is useful for point-in-time collection). The Win32 API version of `NtQueryInformationToken` is [`GetTokenInformation`](https://docs.microsoft.com/en-us/windows/win32/api/securitybaseapi/nf-securitybaseapi-gettokeninformation).

Here’s the script I wrote to pull token attribute information:

```
PS C:\> Invoke-TokenCollection -ProcessId 5764
[*] Impersonating SYSTEM
[*] System impersonation passed
[*] Current User: NT AUTHORITY\SYSTEM

Title : Displaying Process/Primary Information
ProcessName : powershell
SessionId : 1
PID : 5764
ProcessTokenUserName : DESKTOP-T4KGJQR\TestUser
ProcessTokenSid : S-1-5-21-3526241117-3673060432-1951554585-1000
ProcessTokenOwnerSid :  S-1-5-21-3526241117-3673060432-1951554585-1000
ProcessTokenOwner : DESKTOP-T4KGJQR\TestUser
ProcessTokenType : TokenPrimary
ProcessTokenId : 10923619
TokenIntegrityLevel : MEDIUM_MANDATORY_LEVEL

[*] Reverting back to original user
[*] Current User: DESKTOP-T4KGJQR\TestUser
```

[**Jared Atkinson**](https://twitter.com/jaredcatkinson) has a similar script called [**Get-AccessToken**](https://gist.github.com/jaredcatkinson/17698b39efd72f976a6a846ec3a8eacd) that I recommend checking out.

Here’s what it would look like to retrieve token attributes from a process:

![Figure 3](/images/better-know-a-data-source-access-tokens-and-why-theyre-hard-to-get/XfeU9rGMvqe-ulcP.png)

*Note: This diagram shows the process flow for obtaining TOKEN information starting from user-mode. If a driver was implemented, then the process would start in kernel-mode where the first function called is `ZwQueryInformationToken` (functionally the same as `NtQueryInformationToken`).*

The above only shows what it would take to get information from the perspective of a process primary token, but to see impersonation tokens, we need insight on a thread level. So imagine enumerating all of those structures AND enumerating each thread within a process to see if it was impersonating or not. If it is impersonating, then you have to go and find the user it’s impersonating, which is even more intensive.

From a high level, here’s what it would take:

1. Enumerate a process’s information.
2. Enumerate active threads of that process (a list of all threads that belong to a process is stored in the `ThreadListHead` attribute and these values are linked to the `ETHREAD.ThreadListEntry` attribute).
3. If the thread is impersonating, then check the `ActiveImpersonationInfo` attribute within `ETHREAD`, which will have a value of 1.
4. If the thread is impersonating, examine the `ClientSecurity` attribute (backed by the [`PS_CLIENT_SECURITY_CONTEXT`](https://www.nirsoft.net/kernel_struct/vista/PS_CLIENT_SECURITY_CONTEXT.html) structure), which will point to the impersonation token.
5. Enumerate the TOKEN structure and attributes with the passed-in token address to figure out what security context the thread is running under.

![Figure 4](/images/better-know-a-data-source-access-tokens-and-why-theyre-hard-to-get/iE8MWXbO1rJvzl7a.png)

## The push method

This strategy will have the components of the pull method above but will start with a trigger. The process will look something like this:

1. Driver is implemented.
2. [`ObRegisterCallbacks`](https://docs.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-obregistercallbacks) routine registers a notification routine (pre-operation callback—[`ObPreOperationCallback`](https://docs.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/ns-wdm-_ob_pre_operation_information), for example). This routine is put in place so that the kernel notifies this function when a handle is requested to a process, thread, or desktop (trigger) prior to issuing or denying the handle.
3. [`ObPreOperationCallback`](https://docs.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/ns-wdm-_ob_pre_operation_information) will take action on Process Type handle operations and then implement all the code needed to obtain the desired information (call to [`Se/ZwQueryInformationToken`](https://docs.microsoft.com/en-us/windows-hardware/drivers/ddi/ntifs/nf-ntifs-zwqueryinformationtoken)). The steps here will be similar to the above pull method, but since it’s in the kernel, only kernel functions will be called to complete the enumeration of the tokens related to source and target process and threads.

*Note: The pre-operation callback is used so that some type of action (logging, in this example) can take place before the handle is granted. There are post-operation callbacks, but the desired action will happen after the handle operation has been completed.*

## To review

Both of these strategies would require evaluating the token structure for every process and every active thread that performs an open handle operation to another process or thread-type object (assuming no exclusion logic is applied). That will cause a lot of noise and f ingestion and/or storage issues. Thus, as of today,it isn’t necessarily feasible to collect these token-related optics at scale.

## What token attributes are already collected for us?

Although token information from a thread level is hard to collect in a cost-effective fashion, a lot of data sources provide token attributes in general. Refer to the metadata below from various events.

### Windows Security Event 4624

```
SubjectUserSid
SubjectUserName
SubjectLogonId
TargetUserSid
TargetUserName
TargetLogonId
ImpersonationLevel
TargetLinkedLogonId
ElevatedToken
```

### Windows Security Event 4688

```
SubjectUserSid
SubjectUserName
SubjectLogonId
TokenElevationType
TargetUserSid
TargetUserName
TargetLogonId
MandatoryLevel
```

### Microsoft Defender for Endpoint: `DeviceLogonEvents`

```
AccountName
AccountSid
LogonId
InitiatingProcessTokenElevation
```

### Microsoft Defender for Endpoint: `DeviceProcessEvents`

```
ProcessIntegrityLevel
ProcessTokenElevation
AccountName
AccountSid
LogonId
InitiatingProcessAccountName
InitiatingProcessAccountSid
InitiatingProcessIntegrityLevel
```

Although the optics listed above are great, they will not give insight into token impersonation techniques. To truly detect token impersonation, you have to collect token telemetry at the thread level.

## Conclusion

As threat researchers, we should continually strive to find new optics — or improve existing ones — if they can help us better observe, detect, and prevent emergent or existing adversary tradecraft. When we identify poor optics or optics that aren’t readily available, we need to figure out why that is, so we can work toward a better solution. This access token research makes it abundantly clear why relevant telemetry is hard to come by. Even so, the methodology described in this article offers important insight into the inner workings of Windows internals and the interplay between detection value and cost.

## References

1. As I researched this blog, [**Matt Hand**](https://twitter.com/matterpreter) was a tremendous resource for all things Windows Internals and WinDbg. A thank you to him for his mentorship during this process.
2. [**Windows Internals**](https://docs.microsoft.com/en-us/sysinternals/resources/windows-internals) Part 1, Chapters 3 & 4
3. [**A Process Is No One**](https://www.blackhat.com/docs/eu-17/materials/eu-17-Atkinson-A-Process-Is-No-One-Hunting-For-Token-Manipulation-wp.pdf) by [**Jared Atkinson**](https://twitter.com/jaredcatkinson) and [**Robby Winchester**](https://twitter.com/robwinchester3)
