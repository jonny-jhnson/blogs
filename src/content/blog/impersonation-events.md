---
title: "Behind the Mask: Unpacking Impersonation Events"
description: "Microsoft continuously marches forward in providing us security events that uncovers activity that has long been used by attackers."
pubDate: 2024-12-04
readingTime: "6 min read"
tags: ["windows", "detection"]
slug: "impersonation-events"
order: 9
---

## Introduction

Microsoft continuously marches forward in providing us security events that uncovers activity that has long been used by attackers. In this write-up I want to document and talk about 3 new events that are provided in the Threat-Intelligence (TI) ETW Provider:

1. **THREATINT_PROCESS_IMPERSONATION_UP** (EID 33)
2. **THREATINT_PROCESS_IMPERSONATION_REVERT** (EID 34)
3. **THREATINT_PROCESS_IMPERSONATION_DOWN **(EID 36)

These events became publicly available in Windows 24H2 and have previously been in preview builds for the past couple of years. With these events now being in 24H2 defenders have a good way of picking up on token impersonation attacks. However, there are some caveats that should be mentioned about these events.

## About the Events

Token impersonation is commonly used by attackers to act as another user to execute their malicious code. Up until these events surfaced there hasn’t been a great way to detect this behavior. I did a write-up called “[Better know a data source: Access tokens (and why they’re hard to get)](https://medium.com/@jsecurity101/better-know-a-data-source-access-tokens-and-why-theyre-hard-to-get-7bc951eae0b9)” on potential methods that could be used to identify this behavior, as well as implemented two ways within JonMon:

1. Survey based: survey processes that have an impersonation thread
2. Leverage [PsReferenceImpersonationToken](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntifs/nf-ntifs-psreferenceimpersonationtoken) when actions like handle creations or registry creations occurred.

However, these aren’t great and were really just substitutes. Microsoft decided to implement these events within the [PsImpersonateClient](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntifs/nf-ntifs-psimpersonateclient) function in the kernel which is what all impersonation based functions eventually call. The 3 events are broken up as the following -

**THREATINT_PROCESS_IMPERSONATION_UP**

ProcessA impersonates ProcessB by applying ProcessB’s access token to a thread under ProcessA. ProcessA has a thread running as ProcessB’s access token and that token has a higher integrity level than ProcessA’s primary token. A practical example would be if one had a PowerShell process running as a high integrity level process and impersonates winlogon’s token where that token is running as system integrity. This is the most common use case for token impersonation.

**THREATINT_PROCESS_IMPERSONATION_REVERT**

Process was impersonating another user and after completing their desired task called RevertToSelf, removing the impersonation token from their currently running thread. This is very common with adversaries — impersonating a user then reverting back to their original running context.

**THREATINT_PROCESS_IMPERSONATION_DOWN**

Similar to *THREATINT_PROCESS_IMPERSONATION_UP *but instead of impersonating a token with a higher integrity level, one decides to impersonate a user with a lower integrity level. Say if one is running as SYSTEM and wants to impersonate a domain user for resource access this is when someone would impersonate downwards.

## Enabling Events

As many know, impersonation happens frequently natively on Windows. Due to this, Microsoft requires that a bit flag be set on the source process’s (process performing the impersonation) EPROCESS structure under the member Flags3. Specifically, the last bit flag — the 32nd (EnableProcessImpersonationLogging — (0x80000000)).

```
kd> dt nt!_EPROCESS
 +0x000 Pcb : _KPROCESS
 ...
 +0x5fc Flags3 : Uint4B
 ...
 +0x5fc EnableProcessSuspendResumeLogging : Pos 19, 1 Bit
 +0x5fc EnableThreadSuspendResumeLogging : Pos 20, 1 Bit
 +0x5fc SecurityDomainChanged : Pos 21, 1 Bit
 +0x5fc SecurityFreezeComplete : Pos 22, 1 Bit
 +0x5fc VmProcessorHost : Pos 23, 1 Bit
 +0x5fc VmProcessorHostTransition : Pos 24, 1 Bit
 +0x5fc AltSyscall : Pos 25, 1 Bit
 +0x5fc TimerResolutionIgnore : Pos 26, 1 Bit
 +0x5fc DisallowUserTerminate : Pos 27, 1 Bit
 +0x5fc EnableProcessRemoteExecProtectVmLogging : Pos 28, 1 Bit
 +0x5fc EnableProcessLocalExecProtectVmLogging : Pos 29, 1 Bit
 +0x5fc MemoryCompressionProcess : Pos 30, 1 Bit
 +0x5fc EnableProcessImpersonationLogging : Pos 31, 1 Bit
 ...
```

To set this, one has to be running as a protected process (PsProtectedSignerAntimalware-Light or higher) and can use the [ProcessEnableLogging](https://github.com/winsiderss/systeminformer/blob/8ae38191c5e54a1e722cf4956441170313b9e986/phnt/include/ntpsapi.h#L275) constant when calling NtSetInformationProcess. The ProcessEnableLogging constant is backed by [PROCESS_LOGGING_INFORMATION](https://github.com/winsiderss/systeminformer/blob/8ae38191c5e54a1e722cf4956441170313b9e986/phnt/include/ntpsapi.h#L1130) structure which is not public via the Windows SDK, but is provided by [SystemInformer](https://github.com/winsiderss/systeminformer/tree/8ae38191c5e54a1e722cf4956441170313b9e986). I had to adjust it slightly to get the EnableProcessImpersonationLogging to set:

```cpp
typedef union _PROCESS_LOGGING_INFORMATION
{
 ULONG Flags;
 struct
 {
 ULONG EnableReadVmLogging : 1;
 ULONG EnableWriteVmLogging : 1;
 ULONG EnableProcessSuspendResumeLogging : 1;
 ULONG EnableThreadSuspendResumeLogging : 1;
 ULONG EnableLocalExecProtectVmLogging : 1;
 ULONG EnableRemoteExecProtectVmLogging : 1;
 ULONG EnableProcessImpersonationLogging : 1;
 ULONG Reserved : 25;
 };
} PROCESS_LOGGING_INFORMATION, * PPROCESS_LOGGING_INFORMATION;
```

Then setting the flag is as easy as:

```c
PROCESS_LOGGING_INFORMATION ProcessLoggingInformation = { 0 };

ULONG ReturnLength = 0;

status = NtQueryInformationProcess(hProcess, ProcessEnableLogging, &ProcessLoggingInformation, sizeof(ProcessLoggingInformation), &ReturnLength);

if (status != 0)
{
   std::wcout << L"Failed to query logging information" << std::endl;
}
 
if (ProcessLoggingInformation.EnableProcessImpersonationLogging != 1)
{
 ProcessLoggingInformation.EnableProcessImpersonationLogging = 1;

 status = NtSetInformationProcess(hProcess, ProcessEnableLogging, &ProcessLoggingInformation, sizeof(ProcessLoggingInformation));
 if (status != 0)
  {
   std::wcout << L"Failed to set logging information" << std::endl;
   return status;
  }
 }
```

One thing to note — there was a slight oversight on Microsoft’s end when setting up this feature, as they allow someone to set this bit flag but querying it will always come back as FALSE or 0. I reported this to Microsoft and they are fixing it! So future versions should return back if the bitflag is set or not. I might do a follow-up blog on how I found this in the near future 🙂.

**Note:** My testing box is version 22631.4460, so if you have this version or lower you won’t be able to properly query this bitflag.

## Event Examples:

Let’s walk through an example of each event when its logged. One thing to note — these events have been slightly modified to be easier to read/understand and now all event keys are shown to save space and help with readability.

**Use Case: High IL process impersonating a SYSTEM Process (Impersonate Up):**

```
Event ID: 33 (THREATINT_PROCESS_IMPERSONATION_UP)
Key: CallingProcessId Value: 0x3a84
Key: CallingProcessCreateTime Value: 133777432470885593
Key: CallingProcessStartKey Value: 5066549580793016
Key: CallingProcessSignatureLevel Value: 2
Key: CallingProcessSectionSignatureLevel Value: 2
Key: CallingProcessProtection Value: 0
Key: CallingThreadId Value: 0xaa0
Key: CallingThreadCreateTime Value: 133777445665611761
Key: PreviousTokenQueryResult Value: 0x0
Key: PreviousTokenType Value: 0x1
Key: PreviousTokenElevation Value: 0x1
Key: PreviousTokenElevationType Value: 0x2
Key: PreviousTokenImpersonationLevel Value: 0x0
Key: PreviousTokenUser Value: TestUser
Key: PreviousTokenTrustLevelCount Value: 0x0
Key: PreviousTokenIntegrityLevel Value: 0x3000 (S-1-16-12288 / HIGH IL)
Key: PreviousTokenSessionId Value: 0x2
Key: PreviousTokenLowBoxNumber Value: 0x0
Key: PreviousTokenAuthenticationId Value: 523286
Key: PreviousTokenGroupsCount Value: 0xf
Key: CurrentTokenQueryResult Value: 0x0
Key: CurrentTokenType Value: 0x2
Key: CurrentTokenElevation Value: 0x1
Key: CurrentTokenElevationType Value: 0x1
Key: CurrentTokenImpersonationLevel Value: 0x2
Key: CurrentTokenUser Value: SYSTEM
Key: CurrentTokenTrustLevelCount Value: 0x0
Key: CurrentTokenIntegrityLevel Value: 0x4000 (S-1-16-16384 / SYSTEM IL)
Key: CurrentTokenSessionId Value: 0x1
Key: CurrentTokenLowBoxNumber Value: 0x0
Key: CurrentTokenAuthenticationId Value: 999
Key: CurrentTokenGroupsCount Value: 0x5
```

**Use Case: SYSTEM process impersonating a High IL Process (Impersonate Down):**

```
Event ID: 36 (THREATINT_PROCESS_IMPERSONATION_DOWN)
Key: CallingProcessId Value: 0x3190
Key: CallingProcessCreateTime Value: 133777463180506954
Key: CallingProcessStartKey Value: 5066549580793267
Key: CallingProcessSignatureLevel Value: 2
Key: CallingProcessSectionSignatureLevel Value: 2
Key: CallingProcessProtection Value: 0
Key: CallingThreadId Value: 0x345c
Key: CallingThreadCreateTime Value: 133777463180506990
Key: PreviousTokenQueryResult Value: 0x0
Key: PreviousTokenType Value: 0x1
Key: PreviousTokenElevation Value: 0x1
Key: PreviousTokenElevationType Value: 0x1
Key: PreviousTokenImpersonationLevel Value: 0x0
Key: PreviousTokenUser Value: SYSTEM
Key: PreviousTokenTrustLevelCount Value: 0x0
Key: PreviousTokenIntegrityLevel Value: 0x4000 (S-1-16-16384 / SYSTEM IL)
Key: PreviousTokenSessionId Value: 0x2
Key: PreviousTokenLowBoxNumber Value: 0x0
Key: PreviousTokenAuthenticationId Value: 999
Key: PreviousTokenGroupsCount Value: 0x5
Key: CurrentTokenQueryResult Value: 0x0
Key: CurrentTokenType Value: 0x2
Key: CurrentTokenElevation Value: 0x1
Key: CurrentTokenElevationType Value: 0x2
Key: CurrentTokenImpersonationLevel Value: 0x2
Key: CurrentTokenUser Value: TestUser
Key: CurrentTokenTrustLevelCount Value: 0x0
Key: CurrentTokenIntegrityLevel Value: 0x3000 (S-1-16-12288 / HIGH IL)
Key: CurrentTokenSessionId Value: 0x2
Key: CurrentTokenLowBoxNumber Value: 0x0
Key: CurrentTokenAuthenticationId Value: 523286
Key: CurrentTokenGroupsCount Value: 0xf
```

**Use Case: Impersonating process reverting back to its original context (Revert):**

```
Event ID: 34 (THREATINT_PROCESS_IMPERSONATION_REVERT)
Key: CallingProcessId Value: 0x3190
Key: CallingProcessCreateTime Value: 133777463180506954
Key: CallingProcessStartKey Value: 5066549580793267
Key: CallingProcessSignatureLevel Value: 2
Key: CallingProcessSectionSignatureLevel Value: 2
Key: CallingProcessProtection Value: 0
Key: CallingThreadId Value: 0x345c
Key: CallingThreadCreateTime Value: 133777463180506990
```

It is clear that this event doesn’t have as much metadata as the previous two events. It seems this event is meant to be used in conjunction with one of the other two events to see if the process reverted back to its original context. I would have liked to see similar information as the above events, but for those wondering how you can correlate this event to the other two — use the CallingProcessId and CallingThreadId fields.

## Conclusion

It’s really cool to see Microsoft enhance the Threat-Intelligence ETW provider and it be events around tradecraft that adversaries have been using for years. This is a massive step in my opinion on helping defenders see the activity that matters. This event will be tough to use though as it requires someone running as a protected process (either Microsoft or an EDR) to enable this event on processes, which has its own challenges. Currently I have not found any default processes that have this bit enabled. A recommendation I have is for those that can enable this bit flag on unsigned processes that start that are running as a High IL process or higher. This has provided some great results to me so far in my testing. It’s obviously not perfect, one could also enable it for suspicious processes launched out of weird directories and what not. There are a lot of options.

I hope you found this write-up helpful, if you have any questions please feel free to reach out!
