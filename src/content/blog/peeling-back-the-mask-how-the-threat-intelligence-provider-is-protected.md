---
title: "Peeling Back the Mask: How the Threat Intelligence Provider is Protected"
description: "If you’re an offensive or defensive engineer, a Windows endpoint engineer, or a Windows researcher, chances are you’ve come across Microsoft’s Threat-Intelligence ETW provider and understand the immense value it offers for telemetry."
pubDate: 2025-09-29
readingTime: "6 min read"
tags: ["windows", "reverse engineering", "detection"]
slug: "peeling-back-the-mask-how-the-threat-intelligence-provider-is-protected"
order: 6
---

## Introduction

If you’re an offensive or defensive engineer, a Windows endpoint engineer, or a Windows researcher, chances are you’ve come across Microsoft’s [Threat-Intelligence ETW provider](https://medium.com/@jonny-johnson/behind-the-mask-unpacking-impersonation-events-fca909e08d00) and understand the immense value it offers for telemetry. It’s also well known that collecting from this provider requires running as a protected process — specifically at the PsProtectedSignerAntimalware-Light (PPL) level — something most EDRs rely on. What I haven’t seen discussed in detail, however, is how that enforcement check is actually performed. This blog aims to walk through exactly that.

## ETW Security

Event Tracing for Windows (ETW) supports two types of securable objects:

1. **EtwRegistration** — this object is created when registers an ETW provider
2. **EtwConsumer** — this object is created when someone creates an ETW trace session within their consumer

These objects are supported via security descriptors that are stored in the registry under: `HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\WMI\Security`and their access rights can be broken as such:

```c
enum EventTraceRights {
WMIGuidQuery = 0x00000001, // WMIGUID_QUERY
WMIGuidSet = 0x00000002, // WMIGUID_SET
WMIGuidNotification = 0x00000004, // WMIGUID_NOTIFICATION
WMIGuidReadDescription = 0x00000008, // WMIGUID_READ_DESCRIPTION
WMIGuidExecute = 0x00000010, // WMIGUID_EXECUTE
TracelogCreateRealtime = 0x00000020, // TRACELOG_CREATE_REALTIME
TracelogCreateOnDisk = 0x00000040, // TRACELOG_CREATE_ONDISK
TracelogGuidEnable = 0x00000080, // TRACELOG_GUID_ENABLE
TracelogAccessKernelLogger = 0x00000100, // TRACELOG_ACCESS_KERNEL_LOGGER
TracelogLogEvent = 0x00000200, // TRACELOG_LOG_EVENT
TracelogAccessRealtime = 0x00000400, // TRACELOG_ACCESS_REALTIME
TracelogRegisterGuids = 0x00000800, // TRACELOG_REGISTER_GUIDS
TracelogJoinGroup = 0x00001000, // TRACELOG_JOIN_GROUP
// Standard access rights
Delete = 0x00010000, // DELETE
ReadControl = 0x00020000, // READ_CONTROL
WriteDac = 0x00040000, // WRITE_DAC
WriteOwner = 0x00080000, // WRITE_OWNER
Syncronize = 0x00100000, // SYNCHRONIZE
StandardRightsRead = 0x00020000, // STANDARD_RIGHTS_READ (same as ReadControl)
// Access system security bit
AccessSystemSecurity = 0x01000000, // ACCESS_SYSTEM_SECURITY
// Maximum allowed bit
MaximumAllowed = 0x02000000, // MAXIMUM_ALLOWED
// Generic access rights
GenericRead = 0x80000000, // GENERIC_READ
GenericWrite = 0x40000000, // GENERIC_WRITE
GenericExecute = 0x20000000, // GENERIC_EXECUTE
GenericAll = 0x10000000, // GENERIC_ALL
// Combined access rights
WMIGuidAllAccess = 0x00121FFF // Combination of multiple flags
};
```

Not all providers and trace sessions have custom security descriptors, a lot leverage the “default” security descriptor (DefaultTraceSecurityGuid):

`O:BAG:BAD:(A;;0x1800;;;WD)(A;;0x120fff;;;SY)(A;;0x120fff;;;LS)(A;;0x120fff;;;NS)(A;;0x120fff;;;BA)(A;;LC;;;MU)(A;;0xee5;;;LU)(A;;0x1800;;;AC)(A;;0x1800;;;<known-sid>)`

Or

```c
Rights : TracelogRegisterGuids, TracelogJoinGroup
AccessControlType : Allow
IdentityReference : Everyone
IsInherited : False
InheritanceFlags : None
PropagationFlags : None
Rights : WMIGuidQuery, WMIGuidSet, WMIGuidNotification, WMIGuidReadDescription, WMIGuidExecute,
TracelogCreateRealtime, TracelogCreateOnDisk, TracelogGuidEnable, TracelogAccessKernelLogger,
TracelogLogEvent, TracelogAccessRealtime, TracelogRegisterGuids, StandardRightsRead, Syncronize
AccessControlType : Allow
IdentityReference : NT AUTHORITY\SYSTEM
IsInherited : False
InheritanceFlags : None
PropagationFlags : None
Rights : WMIGuidQuery, WMIGuidSet, WMIGuidNotification, WMIGuidReadDescription, WMIGuidExecute,
TracelogCreateRealtime, TracelogCreateOnDisk, TracelogGuidEnable, TracelogAccessKernelLogger,
TracelogLogEvent, TracelogAccessRealtime, TracelogRegisterGuids, StandardRightsRead, Syncronize
AccessControlType : Allow
IdentityReference : NT AUTHORITY\LOCAL SERVICE
IsInherited : False
InheritanceFlags : None
PropagationFlags : None
Rights : WMIGuidQuery, WMIGuidSet, WMIGuidNotification, WMIGuidReadDescription, WMIGuidExecute,
TracelogCreateRealtime, TracelogCreateOnDisk, TracelogGuidEnable, TracelogAccessKernelLogger,
TracelogLogEvent, TracelogAccessRealtime, TracelogRegisterGuids, StandardRightsRead, Syncronize
AccessControlType : Allow
IdentityReference : NT AUTHORITY\NETWORK SERVICE
IsInherited : False
InheritanceFlags : None
PropagationFlags : None
Rights : WMIGuidQuery, WMIGuidSet, WMIGuidNotification, WMIGuidReadDescription, WMIGuidExecute,
TracelogCreateRealtime, TracelogCreateOnDisk, TracelogGuidEnable, TracelogAccessKernelLogger,
TracelogLogEvent, TracelogAccessRealtime, TracelogRegisterGuids, StandardRightsRead, Syncronize
AccessControlType : Allow
IdentityReference : BUILTIN\Administrators
IsInherited : False
InheritanceFlags : None
PropagationFlags : None
Rights : WMIGuidNotification
AccessControlType : Allow
IdentityReference : BUILTIN\Performance Monitor Users
IsInherited : False
InheritanceFlags : None
PropagationFlags : None
Rights : WMIGuidQuery, WMIGuidNotification, TracelogCreateRealtime, TracelogCreateOnDisk,
TracelogGuidEnable, TracelogLogEvent, TracelogAccessRealtime, TracelogRegisterGuids
AccessControlType : Allow
IdentityReference : BUILTIN\Performance Log Users
IsInherited : False
InheritanceFlags : None
PropagationFlags : None
Rights : TracelogRegisterGuids, TracelogJoinGroup
AccessControlType : Allow
IdentityReference : APPLICATION PACKAGE AUTHORITY\ALL APPLICATION PACKAGES
IsInherited : False
InheritanceFlags : None
PropagationFlags : None
Rights : TracelogRegisterGuids, TracelogJoinGroup
AccessControlType : Allow
IdentityReference : <Known-SID>
IsInherited : False
InheritanceFlags : None
PropagationFlags : None
```

*Note: Moving forward, I will just show the SDDL string of the security descriptor for readability.*

I wrote a .NET tool a while back, called [EtwInspector](https://github.com/jonny-jhnson/ETWInspector), one can use to pull the security descriptor of a provider or a trace session.

For providers:

```powershell
PS > $provider = Get-EtwProviders -ProviderName Microsoft-Windows-Security-Auditing
PS > $provider.RegisteredProviders.securityDescriptor.sddl
O:BAG:BAD:(A;;0x1800;;;WD)(A;;0x120fff;;;SY)(A;;0x120fff;;;LS)(A;;0x120fff;;;NS)(A;;0x120fff;;;BA)(A;;LC;;;MU)(A;;0xee5;;;LU)(A;;0x1800;;;AC)(A;;0x1800;;;<known sid>)
```

For trace sessions:

```powershell
PS > Get-EtwTraceSessions -SessionName DefenderAuditLogger | Select-Object -ExpandProperty Security
O:BAG:BAD:(A;;0x120fff;;;SY)(A;;WP;;;SY)
```

Being that these objects are securable, one can easily deny access to certain groups from performing certain ETW operations. Let’s look at an EtwProvider example.

Below I registered a custom ETW provider (Test) with default rights

Let’s say I change these rights that deny all access to everyone.

```
PS C:\Users\TestUser\Desktop> $Provider.RegisteredProviders.securityDescriptor.sddl
O:BAG:BAD:(D;;0x121fff;;;WD)

PS C:\Users\TestUser\Desktop> $Provider.RegisteredProviders.securityDescriptor.Access
Rights : WMIGuidAllAccess
AccessControlType : Deny
IdentityReference : Everyone
IsInherited : False
InheritanceFlags : None
PropagationFlags : None
```

If I were to go and create a trace session with this provider, it would fail:

```
PS C:\Users\TestUser> logman create trace TestSession -p Test 0xffffffffffffffff 0xff -ets
Error:
Access is denied.
Try running this command as an administrator.
```

These ETW objects don’t support SACLs…kind of…it’s a long story — future blog, so that limits one being able to leverage a constraint mask such as a TrustLevel ACE or a Mandatory Label ACE. That leaves restricting access solely within the security descriptor…kind of. Let’s look at the protections around the Threat-Intelligence provider.

## Under the Hood

The security mechanisms around ETW are important when trying to understand where the security check for the Microsoft-Windows-Threat-Intelligence provider. For those that aren’t aware, the Microsoft-Windows-Threat-Intelligence ETW provider is registered in the kernel so the registration itself can not be tampered with. That being said, out of the two checks the one that makes the most sense that would play a part in restricting access to this provider would be the provider’s security descriptor. One would think there would be *potentially* *some* restrictions on the providers security descriptor, but that isn’t the case:

```
O:BAG:BAD:(A;;0x120fff;;;SY)(A;;0x120fff;;;BA)
Rights : WMIGuidQuery, WMIGuidSet, WMIGuidNotification, WMIGuidReadDescription, WMIGuidExecute,
TracelogCreateRealtime, TracelogCreateOnDisk, TracelogGuidEnable, TracelogAccessKernelLogger,
TracelogLogEvent, TracelogAccessRealtime, TracelogRegisterGuids, StandardRightsRead, Syncronize
AccessControlType : Allow
IdentityReference : NT AUTHORITY\SYSTEM
IsInherited : False
InheritanceFlags : None
PropagationFlags : None
Rights : WMIGuidQuery, WMIGuidSet, WMIGuidNotification, WMIGuidReadDescription, WMIGuidExecute,
TracelogCreateRealtime, TracelogCreateOnDisk, TracelogGuidEnable, TracelogAccessKernelLogger,
TracelogLogEvent, TracelogAccessRealtime, TracelogRegisterGuids, StandardRightsRead, Syncronize
AccessControlType : Allow
IdentityReference : BUILTIN\Administrators
IsInherited : False
InheritanceFlags : None
PropagationFlags : None
```

However, that isn’t the case. The security descriptor of this provider is wide open for anyone that is an administrator or SYSTEM user. You might be curious, was there a [TrustLevel ACE](https://medium.com/@jonny-johnson/exploring-token-members-part-2-2a09d13cbb3)? No there wasn’t, I discovered that it seems the EtwRegistration object doesn’t support constraint masks.

I then started to wonder — is there another check within the kernel that could be taking effect? Because the security descriptor wasn’t being modified, this led me walking back EnableTraceEx. EnableTraceEx is the Win32 API used to enable a trace within a trace session, it commonly looks like [this](https://github.com/jonny-jhnson/JonMon/blob/ce5de1c7c647b972da096acee57540bb72854dd5/JonMon-Service/etwMain.cpp#L285C9-L296C10):

```c
EnableTraceEx2(
hTrace,
&ThreatIntel_Provider,
EVENT_CONTROL_CODE_ENABLE_PROVIDER,
TRACE_LEVEL_INFORMATION,
matchAnyKeyword,
0,
0,
&enableTraceParameters
)
```

Interestingly enough, what I found was that this makes a call to [EtwSendNotification](https://www.geoffchappell.com/studies/windows/win32/ntdll/api/etw/notify/send.htm), which sends a [ETW_NOTIFICATION_HEADER](https://www.geoffchappell.com/studies/windows/km/ntoskrnl/inc/api/ntetw/etw_notification_header.htm) data block to the kernel via [NtTraceControl](https://ntdoc.m417z.com/nttracecontrol). When [EtwSendNotification](https://www.geoffchappell.com/studies/windows/win32/ntdll/api/etw/notify/send.htm) calls [NtTraceControl](https://ntdoc.m417z.com/nttracecontrol), it does so with the EtwTraceControlCode of 17/EtwSendDataBlock. This eventually brings us to the function EtwpCheckNotificationAccess.

```c
NTSTATUS __fastcall EtwpCheckNotificationAccess(GUID *provider, GUID *tracesession)
{
NTSTATUS result; // eax MAPDST
__int64 provider_guid_check; // rax
// Check provider access
result = EtwpCheckGuidAccess(provider, TRACELOG_GUID_ENABLE);
if ( result >= 0 )
{
// Check trace session access
result = EtwpCheckGuidAccess(tracesession, TRACELOG_GUID_ENABLE);
if ( result >= 0 )
{
// Check if provider GUID matches threat intelligence provider
// Compare first 8 bytes of GUID
provider_guid_check = *(_QWORD *)&provider->Data1 - s_ProviderThreatInt;
if ( *(_QWORD *)&provider->Data1 == s_ProviderThreatInt )
provider_guid_check = *(_QWORD *)provider->Data4-0x44D38D4D0F04D8F1LL;
if ( !provider_guid_check )
return EtwCheckSecurityLoggerAccess(
(PEPROCESS *)KeGetCurrentThread()->ApcState.Process,
KeGetCurrentThread()->PreviousMode);
}
}
return result;
}
```

EtwpCheckNotificationAccess evaluates if the provider that the trace session wants to enable matches the Threat-Intelligence ETW provider (f4e1897c-bb5d-5668-f1d8–040f4d8dd344), if it matches it checks the logger’s (the consumer processes) process protection level via `EtwCheckSecurityLoggerAccess` and lastly `RtlTestProtectedAccess`:

```c
NTSTATUS __fastcall EtwCheckSecurityLoggerAccess(_EPROCESS *CallingProcess, char PreviousMode)
{
// If request came from UserMode
if ( PreviousMode )
// Does the CallingProcess have the PS_PROTECTION_ANTIMALWARE_LIGHT protected process value
return RtlTestProtectedAccess(CallingProcess->Protection, PS_PROTECTION_ANTIMALWARE_LIGHT) == 0 ? 0xC0000022 : 0;
else
return 0;
}
```

## Conclusion

Although this is a relatively short post, I wanted to document and share how I approached digging into the security check behind the Threat-Intelligence ETW provider. At first, I assumed the enforcement would be tied to the provider’s security descriptor, but that quickly proved false since the descriptor is quite permissive. Tracing deeper into the kernel revealed the real enforcement happens in EtwpCheckNotificationAccess, where access is restricted to processes running at the PsProtectedSignerAntimalware-Light (PPL) level.

My goal wasn’t just to show the end result, but to walk through the reasoning and investigation process — starting with security descriptors, questioning assumptions, and eventually following the call stack into the kernel. Hopefully this not only clarifies how Microsoft enforces access to this provider, but also serves as an example of how to approach similar Windows internals research questions.

## Resources

[EtwSendNotification](https://www.geoffchappell.com/studies/windows/win32/ntdll/api/etw/notify/send.htm) by Geoff Chappell

[Exploiting a “Simple” Vulnerability — Part 1.5 — The Info Leak](https://windows-internals.com/exploiting-a-simple-vulnerability-part-1-5-the-info-leak/) by [Yarden Shafir](https://x.com/yarden_shafir)
