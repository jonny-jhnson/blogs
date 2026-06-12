---
title: "Mastering Windows Access Control: Understanding SeDebugPrivilege"
description: "A deep dive into SeDebugPrivilege - which Windows security checks it actually bypasses, which ones it doesn't, and what that means for offensive and defensive work."
pubDate: 2023-12-18
readingTime: "11 min read"
tags: ["windows", "reverse engineering"]
slug: "mastering-sedebugprivilege"
order: 17
---

Originally posted on the [Binary Defense page](https://www.binarydefense.com/resources/blog/mastering-windows-access-control-understanding-sedebugprivilege/), but was authored by me.

## Introduction

Understanding Windows internals has always been fascinating to me because whether someone does offensive or defensive work, understanding this information should be the foundation of that work. System privileges are one of the Windows OS components that you see used for various purposes but not a lot of great understanding of why it is being used. SeDebugPrivilege is a great example of this.

I have seen a lot of open-sourced tooling enable SeDebugPrivilege but haven’t seen many dive into why this privilege is of such interest. I think it is widely known that SeDebugPrivilege skips *some* OS security checks, but I have never seen anyone mention which OS security checks it skips and which ones it doesn’t. While diving into this I found out that the Mandatory Integrity Control (MIC), and ACE checks (both Discretionary Access and Conditional Access) are the ones bypassed, while protection checks and 3rd party pre-operation callbacks are not. This is good information for anyone wanting to know when to use SeDebugPrivilege to obtain more access to a process or thread object. Let’s dive into this a bit more in-depth.

For those not familiar — SeDebugPrivilege is a special privilege that when assigned gives a token [high integrity](https://medium.com/@jsecurity101/better-know-a-data-source-process-integrity-levels-8338f3b74990). This is given to users of the Administrator’s group by default but can be handed out individually as well. This privilege is often used in offensive tooling because it is known to pass over certain Windows access checks.

SeDebugPrivilege matters when accessing process and thread objects. Accessing certain objects, namely processes, is a very common action performed by adversaries and offensive engineers. The level of access one may have to a process typically depends on the following factors:

- The integrity level of both the source and target process’s token
- The security descriptor that is set on the target process — which includes the integrity level of the object itself, as well as its trust level
- Protection level checks (source and target process)
- 3rd party object callbacks

This post is meant to guide what access checks SeDebugPrivilege bypasses, and which are still validated against. This post won’t be a full guide on the security reference monitor (SRM) or how process access checks happen step by step. If you are curious about this, I highly recommend reading the Windows Internals book, specifically chapter 7 of part 1.

## The Internals

Within Windows, most threads are going to get a handle to a process via the Win32 API [OpenProcess](https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-openprocess) or the native function [NtOpenProcess](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntddk/nf-ntddk-ntopenprocess). When opening a handle to a target process an access mask is passed through to represent the level of access the thread wants to the target. This is pre-defined by Microsoft as [Process Access Rights](https://learn.microsoft.com/en-us/windows/win32/procthread/process-security-and-access-rights?redirectedfrom=MSDN).

Note: OpenProcess isn’t the only way to get a handle to a process. There is an interesting alternative to this by leveraging [NtGetNextProcess](https://github.com/winsiderss/systeminformer/blob/67ff76fcd6dc4b62548d041452301a7c40863012/phnt/include/ntpsapi.h#L1425), which bypasses API hooks if vendors are leveraging them. To read more about this, please visit James Forshaw’s blog [In-Console-Able](https://googleprojectzero.blogspot.com/2015/05/). We won’t dive any more into this in this post, but it is worth mentioning.

This OpenProcess request transitions into the kernel through a syscall and eventually executes PsOpenProcess. PsOpenProcess executes the necessary functions to evaluate if the source user has the appropriate rights to get the desired access to the target. If you are not familiar with the high-level access evaluation process for objects is:

- Perform a [Mandatory Integrity Control](https://learn.microsoft.com/en-us/windows/win32/secauthz/mandatory-integrity-control) (MIC)
- Validates that lower integrity level programs aren’t improperly accessing higher integrity level programs.
- [Discretionary Access Control Checks](https://learn.microsoft.com/en-us/windows/win32/secauthz/dacls-and-aces) (DACL)
- Checks to see what access is allowed or denied.
- Trust Level Access Checks
- [Trust Labels](https://jsecurity101.medium.com/exploring-token-members-part-2-2a09d13cbb3) are stored within an object’s SACL, which is checked against an access tokens TrustLevelSid. Typically given to objects that want to prevent non-protected processes from having certain access. You can read more about this from the slides of Alex Ionescu and James Forshaw’s talk [Unknown Known DLLs](http://publications.alex-ionescu.com/Recon/Recon%202018%20-%20Unknown%20Known%20DLLs%20and%20other%20code%20integrity%20trust%20violations.pdf) and also a previous blog I created [Exploring Token Members](https://jsecurity101.medium.com/exploring-token-members-part-2-2a09d13cbb3).
- Perform ProtectedProcess Checks
- Process objects, however (as well as thread objects) have a 4th access check that is also done, through the Open Procedure of the process object type.
- Validates that if a process is attempting to access a protected process, it is also running at an equal or higher protection level.
- 3rd party pre-object (process & thread) callback checks.
- Additionally, process objects are also subject to 3rd party object callbacks. I mentioned this in a previous blog [Understanding Telemetry: Kernel Callbacks](https://medium.com/@jsecurity101/understanding-telemetry-kernel-callbacks-1a97cfcb8fb3), but some 3rd party applications will leverage a pre-operation callback within a driver to strip certain access to a given process. This is common with EDR vendors, virtual machine applications, etc. A basic example of this can be found within the [ProcCallback](https://github.com/jsecurity101/ProcCallback/blob/23b315c6decd7a9cc567bf0a4755f596b34365ea/Source/Source.cpp#L188) project I created where I am limiting access to PROCESS_QUERY_LIMITED_ACCESS for a given process.

If the above checks pass, then a handle is returned to the thread for that thread or any other thread within the process to use.

These checks serve to validate proper access to resources and make sure there isn’t any unwilled access granted. However, there might be a time when a debugger wants to access a given process or thread — this is why SeDebugPrivilege exists. To attach a program like WinDbg to a program to debug any issues, but it wouldn’t be able to do so if all the previous checks mentioned were properly evaluated. What if one wanted to debug a SYSTEM-level process? They couldn’t do so from a HIGH or MEDIUM integrity level process.

*Note: The example below will look at the LSASS process, this assumes that LSASS is not running as a protected process (PsProtectedSignerLsa-Light) which is default in Windows 11 with secure boot and can be enabled in Windows 10.*

Let’s look at the process of accessing a SYSTEM-level process. Below is the LSASS process’s security descriptor. I am showing the information via WinDbg because I find it clean, and we can see the SACL and DACL at the same time:

```rust
lkd> !sd 0xffffca00`f1428162 & -10 1 
->Revision: 0x1 
->Sbz1    : 0x0 
->Control: 0x8014 
            SE_DACL_PRESENT 
            SE_SACL_PRESENT 
            SE_SELF_RELATIVE 
->Owner   : S-1-5-32-544 (Alias: BUILTIN\Administrators) 
->Group   : S-1-5-18 (Well Known Group: NT AUTHORITY\SYSTEM) 
->Dacl    :  
->Dacl    : ->AclRevision: 0x2 
->Dacl    : ->Sbz1       : 0x0 
->Dacl    : ->AclSize    : 0x3c 
->Dacl    : ->AceCount   : 0x2 
->Dacl    : ->Sbz2       : 0x0 
->Dacl    : ->Ace[0]: ->AceType: ACCESS_ALLOWED_ACE_TYPE 
->Dacl    : ->Ace[0]: ->AceFlags: 0x0 
->Dacl    : ->Ace[0]: ->AceSize: 0x14 
->Dacl    : ->Ace[0]: ->Mask : 0x001fffff 
->Dacl    : ->Ace[0]: ->SID: S-1-5-18 (Well Known Group: NT AUTHORITY\SYSTEM) 
->Dacl    : ->Ace[1]: ->AceType: ACCESS_ALLOWED_ACE_TYPE 
->Dacl    : ->Ace[1]: ->AceFlags: 0x0 
->Dacl    : ->Ace[1]: ->AceSize: 0x18 
->Dacl    : ->Ace[1]: ->Mask : 0x00121411 
->Dacl    : ->Ace[1]: ->SID: S-1-5-32-544 (Alias: BUILTIN\Administrators) 
->Sacl    :  
->Sacl    : ->AclRevision: 0x2 
->Sacl    : ->Sbz1       : 0x0 
->Sacl    : ->AclSize    : 0x30 
->Sacl    : ->AceCount   : 0x2 
->Sacl    : ->Sbz2       : 0x0 
->Sacl    : ->Ace[0]: ->AceType: SYSTEM_AUDIT_ACE_TYPE 
->Sacl    : ->Ace[0]: ->AceFlags: 0xc0 
->Sacl    : ->Ace[0]:             TRUST_PROTECTED_FILTER_ACE_FLAG 
->Sacl    : ->Ace[0]:             SUCCESSFUL_ACCESS_ACE_FLAG 
->Sacl    : ->Ace[0]:             FAILED_ACCESS_ACE_FLAG 
->Sacl    : ->Ace[0]: ->AceSize: 0x14 
->Sacl    : ->Ace[0]: ->Mask : 0x00000010 
->Sacl    : ->Ace[0]: ->SID: S-1-1-0 (Well Known Group: localhost\Everyone) 
 
->Sacl    : ->Ace[1]: ->AceType: SYSTEM_MANDATORY_LABEL_ACE_TYPE 
->Sacl    : ->Ace[1]: ->AceFlags: 0x0 
->Sacl    : ->Ace[1]: ->AceSize: 0x14 
->Sacl    : ->Ace[1]: ->Mask : 0x00000003 
->Sacl    : ->Ace[1]: ->SID: S-1-16-16384 (Label: Mandatory Label\System Mandatory Level)
```

Above we can we the following:
Owner: BUILTIN\Administrators

DACL:

- Access Allowed ACE:
- AllAccess to NT AUTHORITY\SYSTEM
- Terminate, VmRead, QueryInformation, QueryLimitedInformation, ReadControl, Synchronize to BUILTIN\Administrators

SACL:

- System Audit ACE
- if anyone requests a handle with VmRead rights. Regardless of if the request failed or was successful.
- System Mandatory ACE
- States that the IL of the process is SYSTEM and NoReadUp & NoWriteUp. Meaning no one lower than SYSTEM can read or write to the process.

According to the DACL, anyone in the Administrators has rights — QueryInformation + VmRead, which is sufficient to read the memory of LSASS’s memory. However, the System Mandatory ACE is very clear that any integrity level lower than SYSTEM is not going to be able to read memory from this process. This will get blocked on the first check within the Mandatory Integrity Control, before the evaluation of the discretionary access checks. If you want to read more about Integrity Levels, I suggest the 2 following resources:

- Windows Internals Book Part 1 Chapter 7
- [Better know a data source: Process integrity levels](https://medium.com/@jsecurity101/better-know-a-data-source-process-integrity-levels-8338f3b74990)

Based on that information, someone would need to be running as SYSTEM to read the memory of LSASS. However, we know that processes running under High IL with SeDebugPrivilege enabled can read LSASS memory, why is that? How is this access evaluated differently? Before I begin, I highly recommend reading the following two blogs as they will touch on a lot of the same information I am about to touch on and, in some cases, they go a bit more in-depth than I do. I used them to learn more about this topic, so they are great resources.

- [Reversing Windows Internals (Part 1) — Digging Into Handles, Callbacks & ObjectTypes](https://rayanfam.com/topics/reversing-windows-internals-part1/) by [Mohammad Sina Karvandi](https://twitter.com/Intel80x86)
- [The Evolution of Protected Processes Part 2: Exploit/Jailbreak Mitigations, Unkillable Processes and Protected Services](https://www.alex-ionescu.com/wip-draft-the-evolution-of-protected-processes-part-2-exploitjailbreak-mitigations-unkillable-processes-and-protected-services/)by [Alex Ionescu](https://twitter.com/aionescu)

*Note: The code I will show is from a Windows 10 box, the flow is similar within Windows 11 but there are some differences in the code flow. *One of the functions PsOpenProcess calls is [ObOpenObjectByPointer](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntifs/nf-ntifs-obopenobjectbypointer). This can be seen in the following HexRays output:

![Figure 1](/images/mastering-sedebugprivilege/5q52eLOsmpRC4I55.png)

This function’s goal is to get a handle on an object. [ObOpenObjectByPointer](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntifs/nf-ntifs-obopenobjectbypointer) makes a lot of internal calls to evaluate access, but before we get into that I want to talk about one of its input parameters — PACCESS_STATE PassedAccessState. The [ACCESS_STATE](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/ns-wdm-_access_state) structure reports the progress of access to an object in progress. One way it does this is through the PreviouslyGrantedAccess and RemainingGrantedAccess members. As you might have guessed PreviouslyGrantedAccess is access granted to the callee to the target object that has already been granted, whereas RemainingGrantedAccess still needs to be evaluated. This is important because right before [ObOpenObjectByPointer](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntifs/nf-ntifs-obopenobjectbypointer) is called there is a privilege evaluation performed via SePrivilegeCheck to see if the callee has [SeDebugPrivilege](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntifs/nf-ntifs-seprivilegecheck) enabled. If SeDebugPrivilege is enabled a check against the ACCESS_STATE’s member — RemainingGrantedAccess (this is the desired access the callee specified). If the RemainingGrantedAccess that was passed in contains MAXIMUM_ALLOWED (0x2000000) then set PreviouslyGrantedAccess to ProcessAllAccess (0x1FFFFF). If not, then set PreviouslyGrantedAccess to the RemainingGrantedAccess value. Afterward, set RemainingGrantedAccess to 0. Effectively saying — access has already been granted to the target object and there is nothing else to evaluate. This is the meat and potatoes of what will help determine which checks are made later.

We can see this within the function SeAccessCheckWithHintWithAdminlessChecks, called by SeAccessCheck. It checks to see if DesiredAccess is null, then validates that PreviouslyGrantedAccess is not null, then sets GrantedAccess to PreviouslyGrantedAccess, which was set in the image above.

![Figure 2](/images/mastering-sedebugprivilege/rBZQBza1v8QIlSZK.png)

This causes SeAccessCheckWithHintWithAdminlessChecks to not perform:

- MIC checks via SepMandatoryIntegrityChecks
- Discretionary Checks via SepAccessChecks
- TrustLevelACE via SepTrustLevelCheck & RtlSidDominatesForTrust

Let’s look at this in practice within a couple of scenarios:

1. Access to LSASS as an Administrator with SeDebugPrivilege enabled while passing in MAXIMUM_ALLOWED. Based on the code, I should be able to obtain an ALL_ACCESS handle.

```bash
PS > $lsassProcess = Get-NtProcess -Name lsass.exe -Access MaximumAllowed
PS > $lsassProcess.GrantedAccess
AllAccess
```

2. Access to LSASS as an Administrator with SeDebugPrivilege enabled while passing in QUERY_LIMITED_INFORMATION. Based on the code, I should be able to obtain a QUERY_LIMITED_INFORMATION only handle.

```bash
PS > $lsassProcess = Get-NtProcess -Name lsass.exe -Access QueryLimitedInformation
PS > $lsassProcess.GrantedAccess
QueryLimitedInformation
```

Both of those worked as expected, now let’s look at something a bit more interesting. Access to a protected process, like MsMpEng.exe.

1. Access to MsMpEng as an Administrator with SeDebugPrivilege enabled while passing in MAXIMUM_ALLOWED. Based on the code, I should be able to obtain an ALL_ACCESS handle.

```bash
MaximumAllowed
PS > $msmpengProcess.GrantedAccess
```

This returned NULL. Weird right? Let’s take another shot.

2. Access to LSASS as an Administrator with SeDebugPrivilege enabled while passing in QUERY_LIMITED_INFORMATION. Based on the code, I should be able to obtain a QUERY_LIMITED_INFORMATION only handle.

```bash
PS > $msmpengProcess = Get-NtProcess -Name MsMpEng.exe -Access QueryLimitedInformation
PS > $msmpengProcess.GrantedAccess
QueryLimitedInformation
```

So, when it comes from a non-protected process trying to access a protected process, something is limiting that access. After talking to Alex Ionescu and going a bit further into the code — I realized that there is still more evaluation than what we previously saw. Although SeDebugPrivilege skips checks for MIC and Discretionary Checks, it doesn’t skip the protection level check from the function PspProcessOpen. This gets called via a function pointer within ObpIncrementHandleCountEx. There is a bit more into how this function pointer works, object type callbacks, etc. but I differ to Mohammad’s [blog](https://rayanfam.com/topics/reversing-windows-internals-part1/) again if you want to do some reading on that.

Now I won’t dive into this function much as Alex has already done a great job at explaining this in his blog — [The Evolution of Protected Processes Part 2: Exploit/Jailbreak Mitigations, Unkillable Processes and Protected Services](https://www.alex-ionescu.com/wip-draft-the-evolution-of-protected-processes-part-2-exploitjailbreak-mitigations-unkillable-processes-and-protected-services/), but it will essentially check to see if the callee is of the correct protection level to get a handle to the target. The general rule is — if the callee is of equal or higher protection level than the target then the access will be granted.

## Wrapping Up

I know I just went over a lot above and it could be difficult to follow. So, to summarize, with SeDebugPrivilege enabled the following checks occur when requesting access to processes and threads:

- ProtectedProcess
- PreOperation callbacks through a driver (if applicable)

If SeDebugPrivilege is not enabled the following checks occur:

- MIC
- DACL
- Trust Level Access
- ProtectedProcess
- PreOperation callbacks through a driver (if applicable)

The last thing I want to point out is that the same checks apply to threads. SeDebugPrivilege will skip the same access checks (MIC and DACL) for threads as it does processes. The same protection checks happen as well but with PspThreadOpen versus PspProcessOpen.

## Defensive Knowledge

While this post was mainly focused on how SeDebugPrivilege bypasses certain security checks, it is good to note that attackers like to enable this privilege a lot to obtain better access to process and thread objects. You will find a lot of C2 agents have built-in code to do this on the fly, as well as mimikatz has a command to enable SeDebugPrivilege. There is value in watching when processes enable this privilege. Natively on Windows, the log [4703](https://medium.com/@jsecurity101/understanding-telemetry-kernel-callbacks-1a97cfcb8fb3) can be used to see when a privilege is enabled. There are some false positives to be wary of — a good example is the PowerShell process by default (when run from an administrative prompt) will enable SeDebugPrivilege. Is this one reason why attackers used to use PowerShell a lot? It is possible.

## Acknowledgments

I would like to thank [Alex Ionescu](https://rayanfam.com/topics/reversing-windows-internals-part1/) for taking the time to review this blog, provide feedback, and answer questions.

### Resources:

- [Reversing Windows Internals (Part 1) — Digging Into Handles, Callbacks & ObjectTypes](https://rayanfam.com/topics/reversing-windows-internals-part1/) by [Mohammad Sina Karvandi](https://twitter.com/Intel80x86)
- [The Evolution of Protected Processes Part 2: Exploit/Jailbreak Mitigations, Unkillable Processes and Protected Services](https://www.alex-ionescu.com/wip-draft-the-evolution-of-protected-processes-part-2-exploitjailbreak-mitigations-unkillable-processes-and-protected-services/)by [Alex Ionescu](https://twitter.com/aionescu)
- Windows Internals Book Part 1 Chapter 7
