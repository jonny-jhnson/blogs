---
title: "Uncovering Windows Events Part 2"
description: "In part 1 of this series, I touched on how data is the foundation for defensive capabilities and the importance for defenders to understand where and how telemetry is being generated."
pubDate: 2022-12-14
readingTime: "4 min read"
tags: ["windows", "detection"]
slug: "uncovering-windows-events-part-2"
order: 26
---

### The Methodology

In part 1 of this series, I touched on how data is the foundation for defensive capabilities and the importance for defenders to understand where and how telemetry is being generated. Along with these concepts, a project was released called [TelemetrySource ](https://github.com/jsecurity101/TelemetrySource)that encompasses both Windows Security and Sysmon events and how those events are being generated.

As a previous post covers the methodology taken to uncover Sysmon events, this post will cover the method that was taken to discover how Windows Security events are generated. This process will use IDA/Hex-Rays and WinDbg Preview heavily. I will try to explain concepts along the way, but I will have to skip over some to save time.

## The Process

There are 2 ways that can identify how telemetry is being generated:

1. Static Analysis (which was the primary methodology used for this project).
2. Dynamic Analysis (which I leveraged to verify a lot of my findings).

It is common for some to be more comfortable with static analysis over dynamic analysis and vice versa. Still, I want to point out the importance of leveraging both forms of analysis.

The process I will show below will be in user mode, but events logged in kernel mode can be found with a similar approach.

**Honorable Note: **We will eventually run into the function `ntdll!EtwWriteUMSecurityEvent`. When initially starting this project — I mentioned it to Matt Graeber; within some of his research, he found this function and said it might be helpful. It is the cornerstone of this work; completion would have been tricky without this knowledge. So thank you Matt!!!

## Static Analysis

Below is a video that was created to help walk through the reversing process. I do not proclaim to be a great reverse engineer — I have a lot to learn so if anyone has feedback, please reach out! A lot of the functions we will come across will be undocumented, but the leaked W[indows XP source code](https://github.com/Rahib777-7/winxpscodes/blob/a2f6d7c93aa4f11efc51147566d5961c59a8ef89/Source/XPSP1/NT/public/internal/ds/inc/authzi.h) helps us annotate these functions.

<https://cdn.embedly.com/widgets/media.html?src=https%3A%2F%2Fwww.youtube.com%2Fembed%2Fn-kguUYTe0M%3Ffeature%3Doembed&display_name=YouTube&url=https%3A%2F%2Fwww.youtube.com%2Fwatch%3Fv%3Dn-kguUYTe0M&image=https%3A%2F%2Fi.ytimg.com%2Fvi%2Fn-kguUYTe0M%2Fhqdefault.jpg&key=a19fcc184b9711e1b4764040d3dc5c07&type=text%2Fhtml&schema=youtube>

Note: Big thank you to [Luke Paine](https://twitter.com/v3r5ace) for helping me create this video :).

Within a previous blog, [WMI Internals Part 3: Beyond COM](https://medium.com/specter-ops-posts/wmi-internals-part-3-38e5dad016be), I showed how the PowerShell command [`Register-ScheduledTask`](https://learn.microsoft.com/en-us/powershell/module/scheduledtasks/register-scheduledtask?view=windowsserver2022-ps) eventually leads to a RPC function [`SchRpcRegisterTask`](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-tsch/849c131a-64e4-46ef-b015-9d4c599c5167). I didn’t go much further on this in the previous post, but one common thing that can be found with RPC functions that have its own ETW provider associated is code related to logging that functions activity. The same applies for situations where the Security provider logs actions for certain behaviors, scheduled tasks happen to be one of those activities logged.

As we saw in the video, the call `EtwWriteUMSecurityEvent` is eventually made. This call eventually makes a call to `NtTraceEvent`, which is very typical for ETW write functions. After the video, we know how the event [4798: Scheduled Task Was Created is generated](https://www.bing.com/search?q=event%20id%204698&qs=n&form=QBRE&=%25eManage%20Your%20Search%20History%25E&sp=-1&pq=event%20id%204698&sc=10-13&sk=&cvid=7EB8F05BDAC24D1FB36B5E07AF1597AC&ghsh=0&ghacc=0&ghpl=).

## Dynamic Analysis

A separate approach can be taken, where we leverage WinDbg Preview to break on `EtwWriteUMSecurityEvent`. This is a cool way to both verify our static analysis, but also speed up discovery. For this example, we will look at [Event 4624 — An account was successfully logged on](https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/event-4624). We are using this as an example because following the [`SchRpcRegisterTask `](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-tsch/849c131a-64e4-46ef-b015-9d4c599c5167)example would be quite complex. Might do another blog in the future just for this :).

As we saw within the static analysis portion, `EtwWriteUMSecurityEvent `is exported within ntdll.dll and imported within lsasrv.dll, loaded by lsass.exe. So, to be successful we need to set up[ kernel debugging](https://learn.microsoft.com/en-us/windows-hardware/drivers/debugger/windbg-kernel-mode-preview) and attach to the LSASS process. Once we have a kernel debug session, we can attach to the LSASS process by running the following:

```
!process 0n712 //PID
```

We need to grab the EPROCESS virtual address value and insert into the following command to invasively debug LSASS.

```
.process /i ffffaa82fdfc1080 //EPROCESS VA
```

We will have to press g to continue, this is required when interactively debugging a process. Next, we need to load user-mode symbols. This will load the appropriate symbols that are loaded within LSASS. We won’t be able to break on `EtwWriteUMSecurityEvent` otherwise. This can be done via the following command:

```
.reload /user
```

Lastly, let’s set a conditional breakpoint on `ntdll!EtwWriteUMSecurityEvent`:

```
bp /w "((nt!_EVENT_DESCRIPTOR *)@$curthread.Registers.User.rcx)->Id == 0x1210" ntdll!EtwWriteUMSecurityEvent
```

Let’s break this command down a little:

- [`Bp /w `](https://learn.microsoft.com/en-us/windows-hardware/drivers/debugger/setting-a-conditional-breakpoint)— saying “break when”
- `((nt!_EVENT_DESCRIPTOR *)@$curthread.Registers.User.rcx)->Id == 0x1210"` — The first argument passed into `EtwWriteUMSecurityEvent `is [PCEVENT_DESCRIPTOR](https://learn.microsoft.com/en-us/windows/win32/api/evntprov/ns-evntprov-event_descriptor) EventDescriptor. So we are saying break on `ntdll!EtwWriteUMSecurityEvent` when RCX (First value) where member ID of type EVENT_DESCRIPTOR is 0x1210/4624.

We press `g` to continue until that conditional break happens. We will have to log a user in to be successful in triggering the breakpoint. Once the break happens, we can press `k` to see the call stack. Callstack should look like the following:

![Figure 1](/images/uncovering-windows-events-part-2/JTwqDMgYBTLheT8m.png)

As we can see, `SspiSrv!SspirLogonUser` seems to be the operational function that is hit to trigger this event creation of 4624. We could go a step further and see what all logon functions end up calling `SspiSrv!SspirLogonUser,` [`LsaLogonUser`](https://learn.microsoft.com/en-us/windows/win32/api/ntsecapi/nf-ntsecapi-lsalogonuser)for example. This would require some extra analysis because SspirLogonUser is actually a RPC call. I suggest looking at sspicli.dll if you are interested in trying out this exercise.

## Conclusion

The hope for this blog was to expose the methodology taken to find the operational functions of Windows Security events. Analysis both statically and dynamically hold separate benefits depending on the use-case they are being used for .I have found both useful in a lot of research I perform.

Please keep an eye out for the 3rd blogging coming out soon, where we can walk through some offensive findings during this discovery process.

## Resources

- Windows Source Code: [https://github.com/Rahib777-7/winxpscodes/tree/a2f6d7c93aa4f11efc51147566d5961c59a8ef89/Source/XPSP1/NT](https://github.com/Rahib777-7/winxpscodes/tree/a2f6d7c93aa4f11efc51147566d5961c59a8ef89/Source/XPSP1/NT)
- Matt Graeber
- Geoff Chappel: [https://www.geoffchappell.com/studies/windows/win32/ntdll/api/etw/writeumsecurityevent.htm](https://www.geoffchappell.com/studies/windows/win32/ntdll/api/etw/writeumsecurityevent.htm)
