---
title: "Changing Primary Tokens Session ID"
description: "Recently I was handed some malware to look at and during analysis I came across an interesting code block that was dealing with setting the SessionId token member."
pubDate: 2024-01-08
readingTime: "7 min read"
tags: ["windows", "reverse engineering"]
slug: "changing-primary-tokens-session-id"
order: 15
---

## Introduction

Recently I was handed some malware to look at and during analysis I came across an interesting code block that was dealing with setting the SessionId token member. This immediately got me interested. This blog post will focus on a small portion of this malware’s capability and will explain how the malware won’t execute as the author would have wanted.

If you are wanting to follow along or look at this malware here is the SHA256 hash of the binary:

**abca9b8e515c398de2f34816a17f1ef1db8ecc961c2505e063f57476f7bf4054**

## The Malware

When performing analysis I came across the following code block. There is a lot going on in here, so let’s break it down. The malware first gets a HANDLE to their current token so that they can enable the [SeAssignPrimaryTokenPrivilege](https://learn.microsoft.com/en-us/windows/security/threat-protection/security-policy-settings/replace-a-process-level-token) token privilege. This is done by calling [OpenThreadToken](https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-openthreadtoken) and if that function fails, [OpenProcessToken](https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-openprocesstoken) is called. One thing to note here is that SeAssignPrimaryTokenPrivilege is only supplied to SYSTEM level tokens, so we can assume that the code currently running is executing as SYSTEM.

```c
CurrentThread = GetCurrentThread();
 if ( !OpenThreadToken(CurrentThread, MAXIMUM_ALLOWED, 0, &TokenHandle))
 {
 CurrentProcess = GetCurrentProcess();
 if ( !OpenProcessToken(CurrentProcess, MAXIMUM_ALLOWED, &hExistingToken))
 goto PreCleanup;
 }
 if ( !hExistingToken )
 {
 ProcessHandle = NULL;
 Ntdll = NULL;
 goto PreCleanup;
 }
 LookupPrivilegeValueW(0i64, L"SeAssignPrimaryTokenPrivilege", &Luid);
 NewState.Privileges[0].Luid = Luid;
 NewState.PrivilegeCount = 1;
 NewState.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
 if ( !AdjustTokenPrivileges(hExistingToken, 0, &NewState, sizeof(NewState), 0i64, 0i64)
<snip>
```

Next, the author initializes a security descriptor and NULLs out the DACL. This security descriptor is applied to the duplicated token that is created via [DuplicateTokenEx](https://learn.microsoft.com/en-us/windows/win32/api/securitybaseapi/nf-securitybaseapi-duplicatetokenex). Within the [DuplicateTokenEx](https://learn.microsoft.com/en-us/windows/win32/api/securitybaseapi/nf-securitybaseapi-duplicatetokenex) function the malware is duplicating their token (which is SYSTEM and has SeAssignPrimaryTokenPrivilege enabled) to create a new primary token. This newly created primary token’s session ID is changed via [SetTokenInformation](https://learn.microsoft.com/en-us/windows/win32/api/securitybaseapi/nf-securitybaseapi-settokeninformation).

```c
|| (InitializeSecurityDescriptor(pSecurityDescriptor, 1u),
 SetSecurityDescriptorDacl(pSecurityDescriptor, 1, 0i64, 0),
 TokenAttributes.lpSecurityDescriptor = pSecurityDescriptor,
 TokenAttributes.nLength = sizeof(TokenAttributes),
 TokenAttributes.bInheritHandle = 0,
 !DuplicateTokenEx(hExistingToken, 0x2000000u, &TokenAttributes, SecurityAnonymous, TokenPrimary, &phNewToken))
 || !SetTokenInformation(phNewToken, TokenSessionId, &TokenInformation, 4u) )
 {
 goto PreCleanup;
 }
<snip>
```

Afterwards a function pointer is created for [NtSetInformationProcess](https://github.com/winsiderss/systeminformer/blob/699b210372eb83734e0cd59805f7544813ac3872/phnt/include/ntpsapi.h#L1464) via [LoadLibraryW](https://learn.microsoft.com/en-us/windows/win32/api/libloaderapi/nf-libloaderapi-loadlibraryw)/[GetProcAddress](https://learn.microsoft.com/en-us/windows/win32/api/libloaderapi/nf-libloaderapi-getprocaddress) and then the desired token above is assigned to a remote process via NtSetInformationProcess leveraging the ProcessAccessToken value (0x9) within the [PROCESSINFOCLASS](https://github.com/winsiderss/systeminformer/blob/699b210372eb83734e0cd59805f7544813ac3872/phnt/include/ntpsapi.h#L225) enumeration class.

```c
ProcessHandle = OpenProcess(PROCESS_ALL_ACCESS, 0, ProcessId); //ProcessId passed in as a parameter
 if ( ProcessHandle )
 {
 hThread = OpenThread(THREAD_ALL_ACCESS, 0, ThreadId); //ThreadId passed in as a parameter
 if ( hThread )
 {
 ProcessAccessTokenStruct.Token = phNewToken;
 ProcessAccessTokenStruct.Thread = NULL;
 ntdll = LoadLibraryW(L"ntdll.dll");
 if ( ntdll)
 {
 NtSetInformationProcess = GetProcAddress(LibraryW, "NtSetInformationProcess");
 if ( NtSetInformationProcess )
 NtSetInformationProcess(
 ProcessHandle,
 ProcessAccessToken,
 &ProcessAccessTokenStruct,
 sizeof(ProcessAccessTokenStruct));
```

What does all this mean? It seems as if the author is assuming that the malware is running as SYSTEM. This assumed for 2 reasons:

1. Author is enabling SeAssignPrimaryTokenPrivilege which is only exposed to SYSTEM level tokens. They need this to assign a token to another process via NtSetInformationProcess.
2. In order to change the session id of a token [Microsoft documentation](https://learn.microsoft.com/en-us/windows/win32/api/winnt/ne-winnt-token_information_class) says “If TokenSessionId is set with [SetTokenInformation](https://learn.microsoft.com/en-us/windows/desktop/api/securitybaseapi/nf-securitybaseapi-settokeninformation), the application must have the Act As Part Of the Operating System privilege”. The privilege related to “Act As Part Of the Operating System” is SeTcbPrivilege, which is only given to SYSTEM level tokens.

It’s not sure what session id they are attempting to set the new token to due to it being passed in as a variable, but we can assume it’s different than the original session id of that process. This malware is very broken up, meaning there isn’t much context as to what the rest of the malware is doing. This code seems to be more “preparation” code to quickly set the stage for a bigger post-exploitation payload/malware. Because the malware is assumed to be running as SYSTEM they might be trying to change out of SessionID 0.

Why would an attacker want to change this? Perhaps to blend in with other normal processes, get user interaction, to get access to other [desktop objects](https://learn.microsoft.com/en-us/windows/win32/winstation/desktops), etc. We won’t dive too much into that or what [Windows Stations](https://learn.microsoft.com/en-us/windows/win32/winstation/window-stations) are. The Windows Internals Part 2 book has a great section on this in chapter 1.

## Reproducing

After seeing this I wanted to reproduce the code to see what the benefits someone would get if they did change the session id of a token. In doing so I found that there were two issues:

1. In order to set the primary token to a process, the process and all of its threads must be suspended. This led me to believe that the malware above was either creating a new process in a suspended state or suspended another process. No way of telling which it was because the DLL wasn’t creating any processes or showed any signs of suspending threads. After bringing this up to [Yarden Shafir](https://twitter.com/yarden_shafir), she let me know that it could be perhaps the malware was exploiting a SYSTEM-level process and they wanted their “main” malware to run as SYSTEM in session ID 1 to get access to desktop objects and have user interaction which is typical of ransomware behavior. Thanks Yarden for teaching me that!
2. I was seeing the OS was changing the session id value back to the original session id of the process. Here is an image to show what I mean:

![Figure 1](/images/changing-primary-tokens-session-id/mV__UjQ4GbTeIjQ8.png)

In the output above, you can see that I am impersonating a SYSTEM-level process (PID 912), enabling SeAssignPrimaryTokenPrivilege, duplicating the token to create a primary token, creating the process in a suspended state, checking the session ID of the newly created process (2), checking to see what my newly duplicated token session id was (0), setting my desired token to the process, resuming the process, and the session id was changed back to 2. It should be noted that the same happens if I attempt to break out of a non-interactive session (session id 0):

![Figure 2](/images/changing-primary-tokens-session-id/pnJea-mbz1e5IRxYaNzUUw.png)

My initial thought was that when the call of NtSetInformationProcess gets passed down to the kernel, there was some check to change the session id back to its original state. I reached out to [James Forshaw](https://twitter.com/tiraniddo) (someone who knows all about tokens) and he confirmed this. Let’s look at how this works exactly.

## The Windows Code

Let’s dive into the Windows code to discover what is going on under the hood. The function [ntdll!NtSetInformationProcess](https://github.com/winsiderss/systeminformer/blob/17c58464ae2719fa0315d82fd4dabec6e2db0c8c/phnt/include/ntpsapi.h#L1464) is a native function that leads to the kernel function ntoskrnl!NtSetInformationProcess. Different functionality is then executed based on the value passed into the PROCESSINFOCLASS parameter. When 0x9 or ProcessAccessToken is passed in the function PspAssignPrimaryToken is called.

```c
PspAssignPrimaryToken(
PEPROCESS Process,
HANDLE Token,
PACCESS_TOKEN Token
)
```

Many things happen within PspAssignPrimaryToken, but a call to SeExchangePrimaryToken is eventually made.

```c
SeExchangePrimaryToken(
PEPROCESS Process,
PACCESS_TOKEN NewToken,
PACCESS_TOKEN *OldToken
)
```

What is interesting is within the first couple lines of this code a call is made to set a variable name “SessionId”, which is done though the function call: MmGetSessionIdEx. So I dove into this function to see how it was getting the session. After some researching and kernel debugging I was able to untangle this function to the following code block:

```c
ULONG MmGetSessionIdEx(_EPROCESS *Process)
{
 _MM_SESSION_SPACE *SessionId; // rax
 Session = Process->Session;
 if ( !Session || (Process->Flags3.SystemProcess) != 0 )
 return -1;
 else
 return Session->SessionId;
}
```

As you can see the SessionId value is pulled via a member within the EPROCESS structure called Session. This member is a pointer to a [MM_SESSION_SPACE](https://www.nirsoft.net/kernel_struct/vista/MM_SESSION_SPACE.html) structure, where the 3rd attribute at offset 0x8 holds a ULONG value containing the process’s session id. I never knew about this structure or that the EPROCESS structure holds the session id. I thought all of that was kept within the Token.

The SessionId value is then passed into the SepSetTokenSessionById function. This function is in charge of checking to see if the token and process session id’s are the same and if they are not then the session id within the token will be set to the target process object’s session id:

```c
if(TokenSessionId != ProcSessionId)
{
TokenSessionId = ProcSessionId
}
```

Where TokenSessionId is the SessionId within the Token and ProcSessionId is the SessionId obtained from MmGetSessionIdEx/MmGetSessionId above.

There we have it! The OS changes the session ID back to what the process object holds, which explains why in my first code output above the final session id isn’t 0 like I was expecting it to be.

## Conclusion

Microsoft documentation mentions that a developer may change the session id within a token, although that is true it isn’t valuable unless the session id equals the session id held within the process object. So although this malware seemed to be doing something cool it wouldn’t have worked properly unless they were changing their token session id to equal the process’s session id which would require:

- Suspension of all the threads within that process
- Some way of getting thread execution within that process via injection or something similar

The code I created to replicate this activity can be found [here](https://github.com/jsecurity101/RandomPOCs/tree/main/TokenActions/TokenActions). There is a way to change Session Ids of a process through NtSetInformationProcess via the ProcessSessionInformation value. However, I will touch more on this in a future blog.

Lastly, thank you to [Matt Hand](https://twitter.com/matterpreter) and [Yarden Shafir](https://twitter.com/yarden_shafir) for taking the time to review and provide feedback to this post.
