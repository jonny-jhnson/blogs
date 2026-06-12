---
title: "Refining Detection: New Perspectives on ETW Patching Telemetry"
description: "Not long ago I wrote a blog called Understanding ETW Patching where I walked through how ETW patching is a hyper-focused version of a function patch."
pubDate: 2024-06-12
readingTime: "7 min read"
tags: ["windows", "detection", "reverse engineering"]
slug: "refining-detection-new-perspectives-on-etw-patching-telemetry"
order: 11
---

## Introduction

Not long ago I wrote a blog called [Understanding ETW Patching](https://medium.com/@jsecurity101/understanding-etw-patching-9f5af87f9d7b) where I walked through how ETW patching is a hyper-focused version of a function patch. In the Defenders portion I mention how an approach to seeing this activity could be seeing a provider DLL loaded within a process but no ETW events being emitted. This isn’t a great approach because it will only work for a targeted provider. You can read more about this initial thought in this [tweet](https://x.com/jsecurity101/status/1734986839151292439). Since then, I have dived a bit deeper and this post, although short, will discuss this approach.

## Local ETW Patching

As discussed in my previous [post](https://medium.com/@jsecurity101/understanding-etw-patching-9f5af87f9d7b), a common way to patch out events being emitted is by focusing on the ntdll functions, specifically [EtwEventWrite](https://learn.microsoft.com/en-us/windows/win32/devnotes/etweventwrite) or [NtTraceEvent](https://www.geoffchappell.com/studies/windows/km/ntoskrnl/api/etw/traceapi/event/index.htm). The steps to accomplish this are as follows:

1. Load the DLL: Load the DLL that contains the function you want to patch, if it isn’t already loaded.
2. Obtain a Function Pointer: Get a function pointer to the desired function.
3. Change Memory Protection: Change the memory region’s protection value to allow write access.
4. Apply the Patch: Write in the patch.
5. Restore Memory Protection: Optionally, change the memory region’s protection value back to its original setting.

As you can see, after obtaining the function pointer, someone can not simply patch these bytes arbitrarily. The protection level of the memory address for both functions must first be changed. This would be possible if those functions had write permissions on their memory region, but as we will see in a moment they do not.

Memory regions have [protection constants](https://learn.microsoft.com/en-us/windows/win32/Memory/memory-protection-constants) that limit the actions that can be performed on them. For these functions, you will see that writing to that memory section is not supported unless the protection value is modified. Below we can see the memory region’s protection value of these functions.

```c
0:012> !vprot ntdll!EtwEventWrite
BaseAddress: 00007ffaafbbf000
AllocationBase: 00007ffaafb90000
AllocationProtect: 00000080 PAGE_EXECUTE_WRITECOPY
RegionSize: 0000000000103000
State: 00001000 MEM_COMMIT
Protect: 00000020 PAGE_EXECUTE_READ
Type: 01000000 MEM_IMAGE

0:012> !vprot ntdll!NtTraceEvent
BaseAddress: 00007ffaafc30000
AllocationBase: 00007ffaafb90000
AllocationProtect: 00000080 PAGE_EXECUTE_WRITECOPY
RegionSize: 0000000000092000
State: 00001000 MEM_COMMIT
Protect: 00000020 PAGE_EXECUTE_READ
Type: 01000000 MEM_IMAGE
```

This indicates that code within these sections can be read and executed, but not written to. Therefore, when patching either of these functions, the protection value must be changed, typically to PAGE_EXECUTE_READWRITE (0x40/60), using [VirtualProtect](https://learn.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-virtualprotect). Telemetry collected prior to the [VirtualProtect](https://learn.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-virtualprotect) operation is likely not a reliable indicator of function patching. Even the [VirtualProtect](https://learn.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-virtualprotect) operation isn’t directly indicative of function patching. However, if telemetry data for [VirtualProtect](https://learn.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-virtualprotect) is available, it could offer sufficient context within the metadata to speculate whether function patching has taken place.

Within the ETW Threat Intelligence Provider there is an event — THREATINT_PROTECTVM_LOCAL (EID: 7) that seems to give us telemetry when VirtualProtect was performed locally. We can tell this by looking at the [TelemetrySource](https://github.com/jsecurity101/TelemetrySource) project of by running [EtwInspector](https://github.com/jsecurity101/ETWInspector):

![Figure 1](/images/refining-detection-new-perspectives-on-etw-patching-telemetry/Y_Cd6Jz2XuFfBvhZ.png)

After further investigation we can confirm that there are events for when someone changes the protection level of a region of memory:

**Pre-Patch: Changing the protection value from PAGE_EXECUTE_READ (0x20) to PAGE_EXECUTE_READWRITE (0x40).**

![Figure 2](/images/refining-detection-new-perspectives-on-etw-patching-telemetry/-lz06SVh9236wYgV.png)

There is some valuable information in this event, specifically:

- **BaseAddress **— the memory address where the protection value was changed.
- **RegionSize Value** — 2. This shows that the protection of only 2 bytes were changed. This is unusually low and from what I found this value is oftentimes 4096 or higher. This will be the case if someone changes the bytes to (0xc3, 0x00) which is the return value in x64 systems.
- **ProtectionMask** — Shows the value was changed to PAGE_EXECUTE_READWRITE.
- **Last ProtectionMask** — Shows the value was changed from PAGE_EXECUTE_READ.
- **Callstack** — shows that VirtualProtect was called.

**Post-Patch: Changing the protection value from PAGE_EXECUTE_READWRITE (0x20) to PAGE_EXECUTE_READ (0x40).**

![Figure 3](/images/refining-detection-new-perspectives-on-etw-patching-telemetry/TxweUSUfMn-jybbV.png)

The post protection value doesn’t have to take place. However, it’s a good signal if someone wants to see when the protection value was changed to one value then back. This is very odd for someone to do. Because we can’t see the actual bytes being changed this could help with false positives.

Now you might be thinking — what about the actual patching of the bytes? Initially I thought that WriteProcessMemory would work, but then realized that when someone calls the C function — memcpy/memmove doesn’t actually end up calling WriteProcessMemory. We will still explore this below in remote patching.

## Detection Ideas:

1. Collect Event ID 7: Local Virtual Protect — Initial ProtectionMask Change

- Look for the common number of bytes that are patched (RegionSize Value) in functions you care about in x64/x86. A good example is with EtwEventWrite in x64 the number of bytes that are patched are 2 because often the return value is patched in once the function gets executed.
- Look for when the New ProtectionMask has been opened to PAGE_READWRITE (0x04) or PAGE_EXECUTE_READWRITE (0x40)

2. Collect Event ID 7: Local Virtual Protect — Reverting the ProtectionMask

- Someone doesn’t have to change the protection value back to the original value, but that is common practice. Honestly seeing the protection mask go from a more locked down mask like 0x20 to 0x40 then back to 0x20 is pretty suspicious. So watching for 2 EID 7’s where the same memory address has its protection mask changed back and forth like that could yield high results.

## Remote ETW Patching

Remote patching is more uncommon but not unheard of and a good project to check out for this would be [RemotePatcher](https://github.com/Hagrid29/RemotePatcher). This is because it is a lot riskier to perform remote function patching, due to the likelihood of getting detected. Because memcpy/memmove doesn’t support the writing of bytes within a remote process, [WriteProcessMemory](https://learn.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-writeprocessmemory) has to be used, RemotePatcher does this in the [patchAMSI](https://github.com/Hagrid29/RemotePatcher/blob/29f478c758714e48c88d3e3ce5a2177c3076b924/RemotePatcher/RemotePatcher.cpp#L8C6-L8C15) function.

![Figure 4](/images/refining-detection-new-perspectives-on-etw-patching-telemetry/-oeeish3PDt1FqiJ.png)

Now, we can see that [NtProtectVirtualMemory](https://ntdoc.m417z.com/ntprotectvirtualmemory) is called twice, once to change the protection value to PAGE_READWRITE (0x04) and then back to the original value. The difference is that NtWriteVirtualMemory is called. We can tell within [TelemetrySource](https://github.com/jsecurity101/TelemetrySource) that this will lead to event ID 14 within the ETW TI Provider. Let’s take a look at this:

![Figure 5](/images/refining-detection-new-perspectives-on-etw-patching-telemetry/LN6EXaYS6GNIGcAM.png)

What is cool about the events shown above is that it’s clear there’s a process that accessed a remote process, changed the memory region protection values, wrote data to the target process and then change the protection values back. This sequence of operations doesn’t happen frequently in Windows.

## Detection Ideas:

1. Collect Event ID 2: Remote Virtual Protect — Initial ProtectionMask Change

- Look for when the New ProtectionMask has been opened to PAGE_READWRITE (0x04) or PAGE_EXECUTE_READWRITE (0x40)

2. Collect Event ID 2: Remote Virtual Protect — Reverting the ProtectionMask

- Someone doesn’t have to change the protection value back to the original value, but that is common practice. Honestly seeing the protection mask go from a more locked down mask like 0x20 to 0x40 then back to 0x20 is pretty suspicious. So watching for 2 EID 2’s where the same memory address has its protection mask changed back and forth like that could yield high results.

3. Collect Event ID 14: Write Process Memory — writing the bytes for the patch

- Watching this in the context of a remote VirtualProtect being performed before and after the memory write would be suspicious
- Keep in mind this might be hard to discern if this is ETW Patching, but this definitely could be used for Process Injection visibility regardless. This technically could be considered process injection since data is being written into a target process.

## Conclusion

In this post, I wanted to briefly explore ETW patching and a practical approach to observing this activity. Local patching is much more common than remote patching. Unfortunately, because memcpy and memmove do not call [WriteProcessMemory](https://learn.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-writeprocessmemory), identifying the actual patch locally is extremely difficult. However, detecting changes in the protection masks for the memory region where the patch will take place remains a good indicator.

It is uncommon to see these protection masks change from read/execute to read/write/execute. Additionally, the number of bytes changing in such events is usually lower than in other common VirtualProtect events, which often involve 4096 bytes or more. Keep in mind that, as seen in RemotePatcher, someone could change the protection value of a 4096-byte memory region to blend in.

If you are wanting to implement this approach, I recommend analyzing the data to identify patterns where multiple operations occur in sequence, rather than just a single operation. Additionally, examine all possible protection values an attacker might change, especially those that include write permissions. I hope this information is helpful. Please feel free to reach out if you have any ideas to share or questions to ask.

*Thanks to [Arash Parsa](https://x.com/waldoirc) for reaching out and prompting me to revisit and document this topic.*
