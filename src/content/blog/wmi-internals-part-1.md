---
title: "WMI Internals Part 1"
description: "Recently I have taken up an interest in WMI internals and thought I would write a blog series on some of my findings."
pubDate: 2022-07-05
readingTime: "8 min read"
tags: ["windows", "reverse engineering"]
slug: "wmi-internals-part-1"
order: 31
---

### Understanding the Basics

Recently I have taken up an interest in WMI internals and thought I would write a blog series on some of my findings. This first release will cover the fundamentals of WMI and how to track back WMI activity to the WMI provider host process (WmiPrvse.exe), the executable responsible for executing WMI activity. This post is meant to give the information needed to understand part 2 of this series, which will cover the relationship between WMI and COM. That being said, this post will not cover everything WMI related — like permanent WMI event subscriptions, for example.

***Disclaimer:** A lot of this information isn’t new, so I would like to give credit early and direct everyone to the **Resources **section below. As those write-ups/conversations helped my understanding of this technology tremendously.*

## WMI Vocabulary

Microsoft wanted to have their own technology that allowed them to gather information and manage assets across the enterprise, to accomplish this they implemented their own version of [Web-Based Enterprise Management](https://docs.microsoft.com/en-us/windows/win32/wmisdk/about-wmi) which they called [Windows Management Instrumentation (WMI](https://docs.microsoft.com/en-us/windows/win32/wmisdk/about-wmi)). WMI allows users and administrators to obtain information about objects, which in turn give information about things like the environment, computer, processes, etc. WMI also allows administrators to create their own objects, i.e. create a process, services, etc. In order to be successful at this, WMI uses the [Common Information Model (CIM)](https://docs.microsoft.com/en-us/windows/win32/wmisdk/common-information-model), which is a standard to represent various objects like the ones mentioned above. These objects are considered “managed objects”.

WMI has 4 main components:

- **WMI Providers: **COM servers that monitor managed objects. [These providers](https://docs.microsoft.com/en-us/windows/win32/wmisdk/wmi-providers) consist of a DLL (COM server) and a [Managed Object Format](https://docs.microsoft.com/en-us/windows/win32/wmisdk/managed-object-format--mof-) (MOF) file which serves as a definition for a WMI class. These providers are typically DLLs and can be found in `C:\Windows\System32\wbem\*`
- **Managed Objects: **WMI class that represents objects like — processes, services, operating system, etc.
- **WMI Infrastructure: **This is the WMI service (Winmgmt). This service holds two components:

1. The CIM Object Manager (CIMOM). This component handles the connection between management applications and providers. This is considered the WMI Core.
2. The on-disk database “store” is known as the WMI/CIMOM Object Repository. The repository is organized by WMI namespaces. These namespaces look like root\cim2 and hold a collection of providers. The repository can be found at: C:\Windows\System32\wbem\Repository\

- **Management Application (also considered a WMI Consumer): **The client application that interacts with the WMI infrastructure. This can be a regular binary (EXE), a VBScript, a PowerShell script, etc. We will see an example of this within the walkthrough.

Before moving on I would like to go back to the WMI service (Winmgmt) and speak as to how it is implemented and how tasks are carried out.

The WMI service (WinMgmt) is stored within **wmisvc**.dll which is loaded and runs inside of **svchost**.exe. We can see this if we look at WinMgmt configuration within the registry:

![Figure 1](/images/wmi-internals-part-1/4yL5BkWjyOpksUzx.png)

As well as confirm this within Process Explorer:

![Figure 2](/images/wmi-internals-part-1/xzSWQL9gGOhQsG_N.png)

You might have seen another WMI binary on disk called WmiPrvSe (WMI Provider Host). This binary is used to load the correct COM servers (WMI providers) so that it may execute the task it was instructed to. This binary is launched via** C:\Windows\system32\wbem\wmiprvse.exe -secured -Embedding**, where its parent is a svchost process with the CommandLine of: **C:\Windows\system32\svchost.exe -k DcomLaunch -p**. This svchost is launched under services.exe.

An example of how a WMI call is made at a high level:

- WMI service (wmisvc.dll) is launched within the SVCHOST process via (**C:\Windows\system32\svchost.exe -k netsvcs -p -s Winmgmt**)
- Management application (powershell.exe) executes WMI method
- WmiPrvSe is launched via **C:\Windows\system32\wbem\wmiprvse.exe -Secured -Embedding**, under the DCOMLaunch svchost process
- The WMI services loads the appropriate WMI provider into WmiPrvSe
- WmiPrvSe executes the function expressed by the method

There is a lot more that happens underneath the hood of WMI that include COM/RPC. Please see the Windows Internals book Part 2, specifically Chapter 10 for more information on this.

## WMI Walkthrough

For me, WMI made a lot more sense after playing with the various cmdlets exposed through Windows. Let’s do that.

First we need to identify which WMI class/method we want to interact with. Luckily there are two different WMI cmdlet types exposed to us via PowerShell. The [WMI cmdlets and the CIM cmdlets](https://docs.microsoft.com/en-us/powershell/scripting/learn/ps101/07-working-with-wmi?view=powershell-7.2). The CIM cmdlets are the “newer” and more preferred way of interacting with WMI, but the WMI cmdlets still hold their place, which we will see later.

I want to see if there is a WMI class that allows me to create a process. To do that I am going to see if there are any classes that expose a method that contains Create in it, to do so I run the following:

```powershell
PS > Get-CimClass -MethodName *Create*


   NameSpace: ROOT/cimv2

CimClassName                        CimClassMethods      CimClassProperties
------------                        ---------------      ------------------
Win32_Process                       {Create, Terminat... {Caption, Description, InstallDate, Name...}
Win32_BaseService                   {StartService, St... {Caption, Description, InstallDate, Name...}
Win32_Service                       {StartService, St... {Caption, Description, InstallDate, Name...}
...
```

Here we can see that there is a WMI class called ***Win32_Process*** that holds a method called ***Create***. This classes provider lives within the ***ROOT/cimv2*** namespace. However; we currently don’t know what the WMI provider is, so let’s find that out next.

WMI providers, as mentioned above, are essentially just COM servers. Which means that they are stored in the registry behind a class identifier (CLSID). By obtaining a [provider instance](https://docs.microsoft.com/en-us/windows/win32/wmisdk/--win32provider) and filtering on the WMI class we are curious about, we may pull that CLSID out.

```powershell
PS > (Get-CimInstance __Provider -Filter "Name = '$(([WmiClass] 'Win32_Process').Qualifiers['provider'].Value)'").CLSID
{d63a5850-8f16-11cf-9f47-00aa00bf345c}
```

We can then search for that CLSID within the HCKR hive in the registry:

```powershell
PS > Get-ItemPropertyValue -Path "Registry::HKEY_CLASSES_ROOT\CLSID\{d63a5850-8f16-11cf-9f47-00aa00bf345c}\InprocServer32\" -Name '(default)'
C:\WINDOWS\system32\wbem\cimwin32.dll
```

Great, now we have a lot of great information about the WMI class and method we want to invoke:

**WMI Class**: Win32Process
**Method**: Create
**Provider:** cimwin32.dll
**Namespace**: ROOT/cimv2

Lastly, I need to see the parameters I need to pass through in order to successfully create the process. There are a couple of ways to achieve this but let’s first see if we can leverage the WMI cmdlets to give us this information.

```powershell
PS > (Get-CimClass -ClassName Win32_Process).CimClassMethods['Create'].Parameters
Name                       CimType Qualifiers                                 ReferenceClassName
----                       ------- ----------                                 ------------------
CommandLine                 String {ID, In, MappingStrings}
CurrentDirectory            String {ID, In, MappingStrings}
ProcessStartupInformation Instance {EmbeddedInstance, ID, In, MappingStrings}
ProcessId                   UInt32 {ID, MappingStrings, Out}
```

Great, here I can see that there are 3 “In” parameters (**CommandLine**, **CurrentDirectory**, **ProcessStartupInformation**) and 1 “Out” parameter (**ProcessId**). To get more information about the parameters I need to pass to a method I typically open up the provider’s MOF file. In this case `C:\Windows\System32\wbem\cimwin32.mof` .

After getting to the point of where the Win32_Process class is defined we see a lot of great information:

```
[Dynamic,Provider("CIMWin32") : ToInstance,SupportsCreate,CreateBy("Create"),SupportsDelete,DeleteBy("DeleteInstance"),Locale(1033) : ToInstance,UUID("{8502C4DC-5FBB-11D2-AAC1-006008C78BC7}") : ToInstance]
class Win32_Process : CIM_Process
{
[Read : ToSubclass,Privileges{"SeDebugPrivilege"} : ToSubclass,MappingStrings{"Win32API|Tool Help Structures|MODULEENTRY32|szExePath"} : ToSubclass] string ExecutablePath;
[Read : ToSubclass,Privileges{"SeDebugPrivilege"} : ToSubclass,MappingStrings{"Win32|WINNT.H|QUOTA_LIMITS|MaximumWorkingSetSize"} : ToSubclass] uint32 MaximumWorkingSetSize;
[Read : ToSubclass,Privileges{"SeDebugPrivilege"} : ToSubclass,MappingStrings{"Win32|WINNT.H|QUOTA_LIMITS|MinimumWorkingSetSize"} : ToSubclass] uint32 MinimumWorkingSetSize;
...
```

Firstly, there are a lot of read instructions, which showcases that we can probably use this same class to get a process object by instantiating the Win32_Process class. We will do this later, what we care about now however is the Create method. We see there is a “Constructor” [qualifier](https://docs.microsoft.com/en-us/windows/win32/wmisdk/standard-qualifiers) which means that there is a call that will create an instance of this class. Looking at the information for the Constructor method, we see it refers to **Create**.

```
[Constructor,Static,Implemented,Privileges{"SeAssignPrimaryTokenPrivilege", "SeIncreaseQuotaPrivilege", "SeRestorePrivilege"} : ToSubclass,ValueMap{"0", "2", "3", "8", "9", "21", ".."} : ToSubclass,MappingStrings{"Win32API|Process and Thread Functions|CreateProcess"} : ToSubclass] uint32 Create([In : ToSubclass,MappingStrings{"Win32API|Process and Thread Functions|lpCommandLine "} : ToSubclass] string CommandLine,[In : ToSubclass,MappingStrings{"Win32API|Process and Thread Functions|CreateProcess|lpCurrentDirectory "} : ToSubclass] string CurrentDirectory,[In : ToSubclass,MappingStrings{"WMI|Win32_ProcessStartup"} : ToSubclass] Win32_ProcessStartup ProcessStartupInformation,[Out : ToSubclass,MappingStrings{"Win32API|Process and Thread Functions|CreateProcess|lpProcessInformation|dwProcessId"} : ToSubclass] uint32 ProcessId);
```

This definition has the same information that the WMI cmdlet holds, except it says that one parameter (**ProcessStartupInformation**) is passed in via a **Win32_ProcessStartup** instance. Taking a look at this class, I can see that I can create my own instance of this class, specify a wide range of **ProcessStartup **options. One that stood out was the ***ShowWindow** *parameter.

```
[Abstract,Locale(1033) : ToInstance,UUID("{8502C4DB-5FBB-11D2-AAC1-006008C78BC7}") : ToInstance]
class Win32_ProcessStartup : Win32_MethodParameterClass
{

[Write : ToSubclass,MappingStrings{"Win32API|Process and Thread Structures|STARTUPINFO|wShowWindow"} : ToSubclass] uint16 ShowWindow;
...
class Win32_ProcessStartup : Win32_MethodParameterClass
{
[Description("The ShowWindow property specifies how the window is to be displayed to the user.") : Amended ToSubclass,Values{"SW_HIDE", "SW_NORMAL", "SW_SHOWMINIMIZED", "SW_SHOWMAXIMIZED", "SW_SHOWNOACTIVATE", "SW_SHOW", "SW_MINIMIZE", "SW_SHOWMINNOACTIVE", "SW_SHOWNA", "SW_RESTORE", "SW_SHOWDEFAULT", "SW_FORCEMINIMIZE"} : Amended ToSubclass] uint16 ShowWindow;
```

There is an option to specify **Sw_Hidden** (or value 0). Let’s do that because I figured that starting a hidden notepad process is what any regular hacker would do.

First let’s create a Win32_ProcessStartup instance with the hidden parameter and pass it in.

```powershell
PS> $Win32_ProcessStartupClass = Get-CimClass -ClassName Win32_ProcessStartup
PS > $ProcessStartupInformation = New-CimInstance -CimClass $Win32_ProcessStartupClass -Property @{'ShowWindow' = 0} -ClientOnly #0 = SW_HIDDEN
```

Lastly, let’s invoke the Create method:

```
PS > Invoke-CimMethod -ClassName Win32_Process -MethodName Create -Arguments @{CommandLine='notepad.exe'; CurrentDirectory='C:\'; ProcessStartupInformation=$ProcessStartupInformation}
ProcessId ReturnValue PSComputerName
- - - - - - - - - - - - - - - - - -
2432 0
```

After invoking this, we can see that this process was spawned under WmiPrvse.exe:

![Figure 3](/images/wmi-internals-part-1/NKRHH8GxR9oHcYYG.png)

If we look at the WmiPrvse.exe binary, we see that the Win32_Process provider DLL — cimwin32.dll was loaded:

![Figure 4](/images/wmi-internals-part-1/m8-MmLJhmqD0N0kO.png)

Before we close out, remember earlier when we saw that we could get a WMI instance of a process via Win32_Process as well? Let’s see if we can do that to get information about our newly created notepad process:

```powershell
PS > Get-CimInstance -ClassName Win32_Process -Filter "ProcessId = 15444"
ProcessId Name HandleCount WorkingSetSize VirtualSize
 - - - - - - - - - - - - - - - - - - - - - - - - - -
15444 notepad.exe 190 13496320 2203470827520
```

You can also achieve this via `Get-WMIObject`:

```powershell
PS > Get-WmiObject -Class Win32_Process -Filter "ProcessId = 15444"
```

![Figure 5](/images/wmi-internals-part-1/G9SOTwVK37obWlsd.png)

## Conclusion:

During this post I wanted to set a baseline of knowledge that will carry on to other posts in this series “WMI Internals”. I find this important so that everyone has the same vocabulary and basic understanding of how things work. What I showed today wasn’t anything new but will be showcased in less basic examples in the following posts. There were some things purposefully left out for WMI, but I urge everyone to go to the resource section and check out the work of some phenomenal researchers. Thanks for tuning in, part 2 will dive deeper into WMI and COM relationships.

## Resources:

- Matt Graeber’s BlackHat talk — [Abusing Windows Management Instrumentation (WMI)](https://www.youtube.com/watch?v=0SjMgnGwpq8)
- Microsoft Documentation:
- [About WMI](https://docs.microsoft.com/en-us/windows/win32/wmisdk/about-wmi)
- [WMI Architecture](https://docs.microsoft.com/en-us/windows/win32/wmisdk/wmi-architecture)
- [WMI Infrastructure](https://docs.microsoft.com/en-us/windows/win32/wmisdk/wmi-infrastructure)
- Windows Internals Part 2 Chapter 10
- Conversations with [Matt Graeber](https://twitter.com/mattifestation) and [Alex Ionescu](https://twitter.com/aionescu).
