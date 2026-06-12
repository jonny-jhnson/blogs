---
title: "Exploring Impersonation through the Named Pipe Filesystem Driver"
description: "Impersonation happens often natively in Windows, however, adversaries also use it to run code in the context of another user."
pubDate: 2023-05-03
readingTime: "9 min read"
tags: ["windows", "reverse engineering"]
slug: "npfs-impersonation"
order: 22
---

## Introduction

Impersonation happens often natively in Windows, however, adversaries also use it to run code in the context of another user. Recently I was researching named pipe impersonation which naturally led me digging into the Win32 API [ImpersonateNamedPipeClient](https://learn.microsoft.com/en-us/windows/win32/api/namedpipeapi/nf-namedpipeapi-impersonatenamedpipeclient). I had never really dug into how ImpersonateNamedPipeClient worked under the hood, so I wanted to do so. During analysis, I saw that a call to [NtFsControlFile](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntifs/nf-ntifs-ntfscontrolfile) was made:

![Figure 1](/images/npfs-impersonation/ID7ooOK883qYYm4InMypRQ.png)

NtFsControlFile is a function that allows the caller to send a value (FSCTL_PIPE_IMPERSONATE (0x11001C) in the above decompilation), known as a file system control ([FSCTL](https://learn.microsoft.com/en-us/windows-hardware/drivers/ifs/about-fsctls)) code, to a file system driver. Upon initial analysis of this function I was reminded of another function — [DeviceIoControl](https://learn.microsoft.com/en-us/windows/win32/api/ioapiset/nf-ioapiset-deviceiocontrol). DeviceIoControl serves a similar purpose in the sense that it allows someone to send an input/output control code (known as an [IOCTL](https://learn.microsoft.com/en-us/windows/win32/devio/device-input-and-output-control-ioctl-)) to a driver. IOCTLs and FSCTL codes are the same thing, but FSCTLs are a type of IOCTL that are specific to file system drivers. I have encountered this function before so it provided some familiarity with the general architecture of drivers, control codes, and other related concepts, however; I have never interacted with file system drivers themselves.

This post covers file system drivers, specifically the named pipe driver (npfs.sys), as well as shows a proof of concept for calling NtFsControlFile directly to perform named pipe impersonation instead of calling the Win32 API, ImpersonateNamedPipeClient.

This won’t be an indepth dive into device drivers, file system drivers, or minifilters. Instead I want to explain some concepts that I learned that I think will be relevant and important to understanding file system operations, specific to named pipes.

## Internals

Microsoft exposes a set of APIs that allow applications to interact with drivers — DeviceIoControl (Win32 API), [NtDeviceIoControlFile](https://learn.microsoft.com/en-us/windows/win32/api/winternl/nf-winternl-ntdeviceiocontrolfile) (NT API), and NtfsControlFile (NT API). Both functions communicate with different types of drivers but the general communication between the application and the driver are the same. Eventually both make a call to [IofCallDriver](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-iofcalldriver). This function allows the caller to send an input/output request packet (IRP) to the specific driver. IofCallDriver takes in two parameters:

1. A pointer to the [DEVICE_OBJECT](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/ns-wdm-_device_object) structure which is an object that acts as an interface with which the user-mode caller can communicate. Device objects are linked to a driver which will execute the request.
2. A pointer to an [IRP](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/ns-wdm-_irp) structure which packages up the call information about the call to the driver.

The DEVICE_OBJECT is going to hold where the call is going to whereas the IRP is going to hold the relevant information about the request for the driver. An IRP is a kernel-based dynamic structure. This structure holds the I/O stack which is backed by the [IO_STACK_LOCATION ](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/ns-wdm-_io_stack_location)structure that holds information about the functions (known as major and minor functions) being invoked and the appropriate parameters. Major functions are represented as IRP_MJ_ which informs the driver of the operation it should execute. The name of the [major function](https://learn.microsoft.com/en-us/windows-hardware/drivers/kernel/irp-major-function-codes) is well-documented in the WDM header with their name and their corresponding number.

Here is a small list of those:

```cpp
#define IRP_MJ_CREATE                   0x00
#define IRP_MJ_CREATE_NAMED_PIPE        0x01
#define IRP_MJ_CLOSE                    0x02
#define IRP_MJ_READ                     0x03
#define IRP_MJ_WRITE                    0x04
#define IRP_MJ_QUERY_INFORMATION        0x05
#define IRP_MJ_SET_INFORMATION          0x06
#define IRP_MJ_QUERY_EA                 0x07
#define IRP_MJ_SET_EA                   0x08
#define IRP_MJ_FLUSH_BUFFERS            0x09
#define IRP_MJ_QUERY_VOLUME_INFORMATION 0x0a
#define IRP_MJ_SET_VOLUME_INFORMATION   0x0b
#define IRP_MJ_DIRECTORY_CONTROL        0x0c
#define IRP_MJ_FILE_SYSTEM_CONTROL      0x0d
#define IRP_MJ_DEVICE_CONTROL           0x0e
```

There might be some major functions that look familiar above, but since we are talking about named pipes, let’s look at [IRP_MJ_CREATE_NAMED_PIPE](https://learn.microsoft.com/en-us/windows-hardware/drivers/ifs/irp-mj-create-named-pipe). This IRP is sent when CreateNamedPipe(A/W) is called. This Win32 API transitions into the kernel via the [NtCreateNamedPipeFile](https://learn.microsoft.com/en-us/windows/win32/devnotes/nt-create-named-pipe-file) syscall. NtCreateNamedPipeFile doesn’t perform any file system operations but instead it receives the call from user-mode and forwards it to the appropriate driver via IofCallDriver call. IofCallDriver sends the request to the driver responsible for the named pipe creation, npfs.sys.

**Call stack:**

![Figure 2](/images/npfs-impersonation/JbhqpdfMmoaiNmXOolX-Lg.png)

**IRP:**

![Figure 3](/images/npfs-impersonation/dasEMoa5RoqVKP7eby2j9Q.png)

**Note: **There is even more that could be exposed in WinDbg like the parameters to the IRP_MJ_CREATE_NAMED_PIPE call, the security context, etc. This is all stored in the IO_STACK_LOCATION.

Another good example of this is when [CreateFile](https://learn.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-createfilea)(A/W) is called, this will transition into the kernel via [NtCreateFile](https://learn.microsoft.com/en-us/windows/win32/api/winternl/nf-winternl-ntcreatefile) and will eventually make a call to IofCallDriver to communicate with ntfs.sys (or another file system driver) to create the file object:

![Figure 4](/images/npfs-impersonation/J6psTT45WN3sLK1D-HENGQ.png)

Chapter 11 in the 2nd Part of the Windows Internals book breaks this down well if you are interested in learning more.

## Device I/O Control Functions

Earlier I mentioned DeviceIoControl and NtfsControlFile. These are special functions because they relate to unique IRP major functions. Here are the IRP major functions they point to:

- DeviceIoControl — [IRP_MJ_DEVICE_CONTROL](https://learn.microsoft.com/en-us/windows-hardware/drivers/kernel/irp-mj-device-control) (0xe)
- NtfsControlFile — [IRP_MJ_FILE_SYSTEM_CONTROL](https://learn.microsoft.com/en-us/windows-hardware/drivers/ifs/irp-mj-file-system-control) (0xd)

NtfsControlFile and DeviceIoControl look very similar in functionality but used differently in practice. Simply put, DeviceIoControl is for normal device drivers whereas NtfsControlFile is for file system drivers. DeviceIoControl requires a handle to the device which holds a driver object. NtfsControlFile passes in a handle to a [FILE_OBJECT](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/ns-wdm-_file_object) because the action is being executed on that object and later will pass through the filter manager (FltMgr) which will extract the device type and know which file system driver to pass it to.

Since we are primarily talking about file system drivers in this post we will continue using functions/terminology specific for file system drivers. However; it is good to note the majority of the concepts are the same.

When a file system driver wants to expose any functionality, it’ll create an internal function implementing that functionality and register it as a major function handler. As an example, below we can see a number of registered major functions within the NpFs driver object:

![Figure 5](/images/npfs-impersonation/-9mkHVL0XmCEVzEM0HUt6A.png)

When a user-mode application wants to execute that functionality, they will call the NtfsControlFile function and pass in the control code which will eventually go to the appropriate file system driver where it will execute its IRP_MJ_FILE_SYSTEM_CONTROL function and in turn execute the internal function associated with the FSCTL code.

We will see an example of this below when ImpersonateNamedPipeClient is called and again in the code I provide where I call NtfsControlFile directly.

## ImpersonateNamedPipeClient

ImpersonateNamedPipeClient is a Win32 API that allows a named pipe server to impersonate the token of client processes connecting to the server’s named pipe. This is different than other token impersonation techniques as it requires something or someone else to connect to you before you can steal the token, whereas other capabilities (ImpersonateLoggedOnUser, CreateProcessWithToken, CreateProcessWithLogon, etc) allow for the impersonation of a token by targeting a process, usually ones that are running in a higher integrity level.

Examples in PowerShell can be found in following Atomic Test Harnesses:

- [Invoke-ATHTokenImpersonation](https://github.com/redcanaryco/AtomicTestHarnesses/blob/master/Windows/TestHarnesses/T1134.001_TokenImpersonation/TokenImpersonation.ps1)
- [Invoke-ATHCreateProcessWithToken](https://github.com/redcanaryco/AtomicTestHarnesses/blob/master/Windows/TestHarnesses/T1134.002_CreateProcessWithToken/CreateProcessWithToken.ps1)

## NtfsControlFile

As previously mentioned, ImpersonateNamedPipeClient makes a call to NtfsControlFile where it passes in the FSCTL code 0x11001C. Control codes are defined by the CTL_CODE macro which can be found in the ntfis.h:

![Figure 6](/images/npfs-impersonation/6SkN1NU6QVkZ4RfE6cV90w.png)

This can be confusing, but let’s manually parse this out. The binary format of 0x11001C is 000100010000000000011100.

```sql
DeviceType (shift left 16 bits / 8 bits):
0001 0001 == 11 (FILE_DEVICE_NAMED_PIPE)
Access (shift left 14 bits / 2 bits)
00 == FILE_ANY_ACCESS
Function (shift left 2 bits / 12 bits):
000000000111 == 7
Method (last 2 bits):
00 == METHOD_BUFFERED
```

Note: An easier way to do this is via this [IOCTL calculator](https://github.com/EvanMcBroom/ioctl-parser) or by using [!ioctldecode](https://learn.microsoft.com/en-us/windows-hardware/drivers/debugger/-ioctldecode) in WinDbg (thank you Yarden for showing me this WinDbg way!).

Going back to the NTFS header, this value is documented as the FSCTL_PIPE_IMPERSONATE control code.

So why does this FSCTL matter? Remember that NtfsControlFile is eventually going to make a call into IofCallDriver, which passes in the IRP structure as previously mentioned. This IRP holds the relevant information about the call being sent to a device driver, one of which is the Major Function being invoked and the parameters that are packaged with that Major Function. For drivers when they expose a FSCTL code they are exposing this through the IRP_MJ_FILE_SYSTEM_CONTROL Major Function.

The driver then is going to call the IoGetCurrentIrpStackLocation to get the stack location in the IRP. This is important because under Parameters. FileSystemControl, you can see the parameters passed into this major function, one of which is the FSCTL code:

![Figure 7](/images/npfs-impersonation/zAjqypLKu20I_TbJMQa5OA.png)

This call leads to the NPFS FileSystemControl function NpCommonFileSystemControl. Internally, this function checks the FSCTL code and executes an internal function, in this case NpImpersonate:

![Figure 8](/images/npfs-impersonation/EIW6ehruQWKh7795-i79ZQ.png)

NpImpersonate then calls [SeImpersonateClientEx](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntifs/nf-ntifs-seimpersonateclientex) which in turn calls PsImpersonateClient to impersonate the token of the thread that is connecting to the named pipe.

One thing to note is that there are quite a few FSCTLs exposed in npfs.sys that could be used for things like named pipe peeking, connecting to a named pipe, etc. Luckily it seems all of them are exposed in the NTFS header within the SDK.

## Proof of Concept

When I see an opportunity to call either a lower level call instead of a Win32 API or the ability to send a control code to a driver, I try to take it. The proof of concept is simple as it changes ImpersonateLoggedOnUser out for NtfsControlFile in a named pipe server implementation. Once NtfsControlFile completes successfully, the user will have impersonated the client that connected to the “npfs” named pipe (i.e., \\pipe\npfs).

![Figure 9](/images/npfs-impersonation/H7J22agaNlJxgxzc9XRQDg.png)

The code for this POC can be found on my GitHub at: [https://github.com/jsecurity101/RandomPOCs/tree/main/NtfsControlFile](https://github.com/jsecurity101/RandomPOCs/tree/main/NtfsControlFile)

## Function Flow

I have provided the function call stack for those that are interested:

[![](https://mermaid.ink/img/pako:eNp1ktuOgjAQhl8Fe60vwMUmykFRISbsXm33opEBiT2Qtm7WGN99yxCL7oa5-NL0_5jC0Bs5qgpISBrNulPwHlMZuFp-UiJtxfmssKmJlLRa8bTlQMnXYKzQmIy3Ll70lXKbN7pf-SxyWc2taPTMpZ1v4IV46J2pOmKcx7r9Bu3DpA-72swK92TVH1pejQXxt0k6epESQslpdT2qmehAGyWZHb9lM7xOCU9hxFuQNvnxUjZIB_NP8sruMZPikJYvE9k_kqE-DOjc_ZanLa_mr-oOtAQ-JRdTg6RyHywWb8ESmSNXyAK5RUbIGLlDJsgUuUZukBmZEwFasLZyd-nWn06JPYFwUwzdsmL6TAmVd-exi1XlVR5JaPUF5uTSVW5WccvcFRQkrBk3cP8F_VTGsA?type=png)](https://mermaid.live/edit#pako:eNp1ktuOgjAQhl8Fe60vwMUmykFRISbsXm33opEBiT2Qtm7WGN99yxCL7oa5-NL0_5jC0Bs5qgpISBrNulPwHlMZuFp-UiJtxfmssKmJlLRa8bTlQMnXYKzQmIy3Ll70lXKbN7pf-SxyWc2taPTMpZ1v4IV46J2pOmKcx7r9Bu3DpA-72swK92TVH1pejQXxt0k6epESQslpdT2qmehAGyWZHb9lM7xOCU9hxFuQNvnxUjZIB_NP8sruMZPikJYvE9k_kqE-DOjc_ZanLa_mr-oOtAQ-JRdTg6RyHywWb8ESmSNXyAK5RUbIGLlDJsgUuUZukBmZEwFasLZyd-nWn06JPYFwUwzdsmL6TAmVd-exi1XlVR5JaPUF5uTSVW5WccvcFRQkrBk3cP8F_VTGsA)

## Conclusion

I think oftentimes the thought of interacting directly with a driver to perform an action is overlooked. As an industry this has been touched on but most recently talk has been around interfacing with technologies like RPC, COM, etc. It is important to note that through device objects user mode applications can interact with drivers as well and depending on the functionality that the driver supports those actions could be useful to the callee. Although this isn’t a vulnerability or a vulnerable driver, this has been seen with other vulnerable drivers quite a bit.

This was also a fun project that gave me an opportunity to learn about file system drivers and how one may interact with them. I wanted to share this process as well as expose that when dealing with files there are ways one can interact directly with a file system driver to execute some functionality.

In the future I might do a write-up about the differences between file system drivers and file system filter drivers as well as an in-depth look into how someone can capture information about file system activity both from a driver perspective as well as ETW.

## Remarks

A very big thank you to [Yarden Shafir](https://twitter.com/yarden_shafir) for answering some very critical questions, providing me with resources to learn this topic, as well as giving me inspiration to write this post.

## References:

- [https://github.com/LordNoteworthy/windows-internals/blob/master/windows-nt-device-driver-development.md#the-io-manager-1](https://github.com/LordNoteworthy/windows-internals/blob/master/windows-nt-device-driver-development.md#the-io-manager-1)
- [https://learn.microsoft.com/en-us/windows-hardware/drivers/kernel/introduction-to-i-o-control-codes](https://learn.microsoft.com/en-us/windows-hardware/drivers/kernel/introduction-to-i-o-control-codes)
- [https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-fscc/4dc02779-9d95-43f8-bba4-8d4ce4961458](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-fscc/4dc02779-9d95-43f8-bba4-8d4ce4961458)
- Windows Internals Book, Part 2 Chapter 11
- [https://fsfilters.blogspot.com/](https://fsfilters.blogspot.com/)
- [https://medium.com/specter-ops-posts/mimidrv-in-depth-4d273d19e148](https://medium.com/specter-ops-posts/mimidrv-in-depth-4d273d19e148)
