---
title: "What the Fork: Exploring Telemetry Gaps in Microsoft’s 4688 Event"
description: "A walk through process forking on Windows, how an adversary might leverage it, how you can identify this behavior, and where the 4688 event's metadata falls short."
pubDate: 2024-04-04
readingTime: "4 min read"
tags: ["windows", "detection", "reverse engineering"]
slug: "what-the-fork-exploring-telemetry-gaps-in-microsofts-4688-event"
order: 13
---

*Originally posted: [What the Fork: Exploring Telemetry Gaps in Microsoft’s 4688 Event | Prelude (preludesecurity.com)](https://www.preludesecurity.com/blog/what-the-fork-exploring-telemetry-gaps-in-microsofts-4688-event) but authored by me.*

Recently, the Prelude research team was looking into adversarial capabilities related to process forking. One of the steps within our research methodology is to identify potential telemetry sources that could be used to detect this behavior. Due to how forking works on Windows, this process was relatively difficult and required a bit of reverse engineering. In this write-up, I will walk through the basics of forking, how an adversary might leverage it, how you can identify this behavior, and how the metadata exposed today isn’t the most comprehensive.

## Background

Process forking is a capability that allows a developer to create a clone of another running process after obtaining a handle to the desired process. One use case of forking is dumping LSASS, as [Bill Demirkapi](https://twitter.com/BillDemirkapi) outlined in his [blog post](https://billdemirkapi.me/abusing-windows-implementation-of-fork-for-stealthy-memory-operations/), Abusing Windows’ Implementation of Fork() for Stealthy Memory Operations. As Bill points out, someone only needs to obtain a handle to lsass.exe with [PROCESS_CREATE_PROCESS](https://learn.microsoft.com/en-us/windows/win32/procthread/process-security-and-access-rights) rights in order to fork LSASS. To do this, an attacker either needs to have Administrator privileges and enable [SeDebugPrivilege](https://learn.microsoft.com/en-us/windows/win32/secauthz/enabling-and-disabling-privileges-in-c--) (more information can be found in a previous write-up [here](https://medium.com/@jsecurity101/mastering-windows-access-control-understanding-sedebugprivilege-28a58c2e5314)) or their code must be running as NT AUTHORITY\SYSTEM. After obtaining the LSASS handle, it can be passed in as the 4th input parameter (ParentHandle) to the function [NtCreateProcessEx.](https://github.com/winsiderss/systeminformer/blob/9f440fe6de25ea59013eddaba2bc1c0bf7fb5615/phnt/include/ntpsapi.h#L1353)

```c
NTSTATUS
NTAPI
NtCreateProcessEx(
    _Out_ PHANDLE ProcessHandle,
    _In_ ACCESS_MASK DesiredAccess,
    _In_opt_ POBJECT_ATTRIBUTES ObjectAttributes,
    _In_ HANDLE ParentProcess,
    _In_ ULONG Flags, // PROCESS_CREATE_FLAGS_*
    _In_opt_ HANDLE SectionHandle,
    _In_opt_ HANDLE DebugPort,
    _In_opt_ HANDLE TokenHandle,
    _Reserved_ ULONG Reserved // JobMemberLevel
    );
```

One important thing to note is that [NtCreateProcessEx](https://github.com/winsiderss/systeminformer/blob/9f440fe6de25ea59013eddaba2bc1c0bf7fb5615/phnt/include/ntpsapi.h#L1353) is only responsible for creating the process, which is essentially just a container for threads and other relevant information that doesn’t start any threads itself. This means that when the function completes, the process object created is not actually running. This is one of, if not the primary, reasons why the available telemetry is limited.

## Telemetry

## Kernel Mode Process Creation Callbacks

For those unfamiliar, EDR’s commonly register callback routines in their kernel mode drivers (via the [PsSetCreateProcessNotifyRoutine](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntddk/nf-ntddk-pssetcreateprocessnotifyroutine) function) to be notified when new processes are created. Each registered callback function is invoked by the kernel via [PspCallProcessNotifyRoutines](https://medium.com/yarden-shafir/yes-more-callbacks-the-kernel-extension-mechanism-c7300119a37a), which is called by one of these two functions:

- PspInsertThread
- PspExitProcess

**Note**: Since we are talking about process creation here, we will focus on PspInsertThread, but note that PspExitProcess is used to inform callbacks of process termination.

If we follow the flow of execution within the PspInsertThread function, we will find that it is executed during the normal flow of functions like NtCreateUserProcess or PspCreateThread, but interestingly, it will not get executed when NtCreateProcessEx is called. Does this mean that NtCreateProcessEx results in a gap in coverage?

## Are you sure, Microsoft?

While investigating alternative sources of telemetry, we found that the Microsoft-Windows-Security-Auditing ETW Provider (or Windows Security Event) will log this activity within the [4688](https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/event-4688) event. Internally, there is an undocumented function called by PspInsertProcess, SeAuditProcessCreation, which is responsible for collecting all necessary process creation information to expose within the metadata of the 4688 events. Let’s see what this looks like in practice:

![Figure 1](/images/what-the-fork-exploring-telemetry-gaps-in-microsofts-4688-event/sZu1Ja19rRYvkalV.png)

A couple of things stand out in the event:

1. The information related to the user and logon session are correct
2. The event shows that the new LSASS process is created as SYSTEM
3. The event shows that the creator process name is “lsass.exe”, which isn’t correct. It should be “Fork.exe.”

Although we can tell that the data is logged, the metadata isn’t entirely correct.

## There is hope…

Before we go further, let’s break apart the different processes in place as this will become important below.

- Acting Process: Fork.exe
- Target Process: lsass.exe (handle passed into the ParentHandle parameter in NtCreateProcessEx)
- Forked Process: lsass.exe

When SeAuditProcessCreation is executed within PspInsertProcess, a pointer to the EPROCESS structure of the forked process (lsass.exe) was passed in as the first parameter. Within SeAuditProcessCreation, the InheritedFromUniqueProcessId member (offset 0x540) of this structure was used to get the parent process ID of the forked process, which actually holds the PID of the target process because the handle to LSASS was passed into NtCreateProcessEx via the ParentHandle parameter. This explains why the creator process information is incorrect, but why is the creator logon information correct?

Within SeAuditProcessCreation, a call to SeCaptureSubjectContext is made. This function grabs the security context of the calling thread, which will be Fork.exe’s token in our example. This means that Microsoft is retrieving the correct token information, but not the right process information for the event.

## Conclusion

While looking at adversarial capabilities, the Prelude research team always takes time to look into existing and potential future telemetry sources that can be used to identify attacker activity. Our research processes identified a clear but undocumented gap in Microsoft’s 4688 security event that can lead to faulty assumptions and missed detections. We hope that this post inspires you to dig further into your data sources and challenge your assumptions about correctness.

## References & Additional Resources

- [Abusing Windows’ Implementation of Fork() for Stealthy Memory Operations](https://billdemirkapi.me/abusing-windows-implementation-of-fork-for-stealthy-memory-operations/) by [Bill Demirkapi](https://twitter.com/BillDemirkapi)
- [Yes, More Callbacks — The Kernel Extension Mechanism](https://medium.com/yarden-shafir/yes-more-callbacks-the-kernel-extension-mechanism-c7300119a37a) by [Yarden Shafir](https://twitter.com/yarden_shafir)
- [SystemInformer](https://www.systeminformer.com/)’s codebase
