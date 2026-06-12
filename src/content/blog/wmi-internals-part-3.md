---
title: "WMI Internals Part 3"
description: "In a previous blog post of mine — WMI Internals Part 2: Reversing a WMI Provider I walked through how the WMI architecture is foundationally built upon COM and in turn how WMI classes can end up invoking COM methods to perform actions."
pubDate: 2022-09-12
readingTime: "6 min read"
tags: ["windows", "reverse engineering"]
slug: "wmi-internals-part-3"
order: 28
---

### Beyond COM

In a previous blog post of mine — WMI Internals Part 2: Reversing a WMI Provider I walked through how the WMI architecture is foundationally built upon COM and in turn how WMI classes can end up invoking COM methods to perform actions. I used the `PS_ScheduledTask `WMI class as an example and how when an instance of this class is created the COM method `ITaskServices:NewTask `is invoked.

This blog will take this process a step further and look at what happens after the COM method `ITaskServices:NewTask`. This isn’t directly WMI related, however I found the last blog didn’t have a definitive ending and believe this blog will help do that.

## Brief Background:

Without going deep into COM/DCOM/RPC/ALPC internals — if you aren’t familiar, the Component Object Model (COM) is used in several technologies as an abstraction layer around Remote Procedure Calls (RPC) interfaces. Meaning, if you see COM methods invoked it shouldn’t be a surprise to see RPC invoked afterwards. Similar to COM, the same applies for Distributed COM (DCOM) as the call transport takes place over RPC. Alex Ionescu walks through these concepts well in his talk “[All About The Rpc, Lrpc, Alpc, And Lpc In Your Pc](https://youtu.be/UNpL5csYC1E)”. If you haven’t listened to that talk, I highly recommend it.

## Walkthrough:

If we take a look at the `ITaskServices:NewTask `method on Microsoft documentation we see that it says: “Returns an empty task definition object to be filled in with settings and properties and then registered using the `ITaskFolder::RegisterTaskDefinition` method”. I believe it is generally true that we should not always take this documentation as law, but I have proved that the above is true via dynamic analysis. As the function flow from NewTask to RegisterTaskDefinition is slightly complex and would take away from the actual purpose of this blog if we mapped this flow, we will start at ITaskFolder::RegisterTaskDefinition.

**Step 1 — Find the ITaskFolder COM Server:**

Luckily Microsoft has documented this well. The COM server is stored in taskschd.dll.

![Figure 1](/images/wmi-internals-part-3/fdqhzLKlQ08zafWS.png)

**Step 2 — Identify/analyze the `ITaskFolder::RegisterTaskDefinition` method definition:**

Upon opening IDA and searching for the term RegisterTaskDefinition in the functions window, we come across a function called — `RegisterTaskDefinition@?QITaskFolder`:

![Figure 2](/images/wmi-internals-part-3/mb-NPMmMPH3ngpT8.png)

This function simply seems to be a wrapper that ends up calling `TaskFolderImp::Register`. After analyzing this function, there are some calls into some interesting functions like `TaskFolderImpl::GetNewTaskPath` and `TaskDefinitionImpl::get_RawXmlText`, but what really stands out is a call to `UniSession::RegisterTask`:

![Figure 3](/images/wmi-internals-part-3/UCMeepNMBnRvpDvn.png)

After opening this function there is an immediate call to `RpcSession::RegisterTask`. This seems to be exactly what we are looking for in terms of trying to identify how the scheduled task gets registered.

![Figure 4](/images/wmi-internals-part-3/BpeKn-dlX80j0bnH.png)

This call is quite simple as its purpose is to invoke the NdrClientCall3 API. If you aren’t familiar with the NdrClientCall APIs, they are commonly used to invoke RPC procedures. If we can track which RPC interface/Opnum that was invoked, we can verify how the scheduled task is being registered.

![Figure 5](/images/wmi-internals-part-3/c3CciUntVtihR0-Y.png)

There are 2 parameters that get passed into NdrClientCall3 that will help us identify what call is being made:

- pProxyInfo — A pointer to the proxy information for that RPC call.
- nProcNum — the value of the procedure number/opnum to be invoked.

Let’s first look at the pProxyInfo. This is the argument that will hold the RPC Interface UUID. In the above photo of the NdrClientCall3 definition, we see that pProxyInfo is a pointer to the `MIDL_STUBLESS_PROXY_INFO` structure. If we google that structure, we run into a page from a Microsoft github repo -

![Figure 6](/images/wmi-internals-part-3/iQ4yQnZCKk9qLrQm.png)

After clicking on — [MIDL_STUB_DESC](https://docs.microsoft.com/en-us/windows/win32/api/rpcndr/ns-rpcndr-midl_stub_desc), we see we are closer as the first structure member `RpcInterfaceInformation `is exposed. This will hold the interface structure information via — “For a nonobject RPC interface on the server-side, it points to an RPC server interface structure. On the client-side, it points to an RPC client interface structure. It is null for an object interface.” Since this is on the client side — we are looking for a RPC Client interface structure, which brings us to this — [RPC_CLIENT_INTERFACE](https://docs.microsoft.com/en-us/windows/win32/api/rpcdcep/ns-rpcdcep-rpc_client_interface)

![Figure 7](/images/wmi-internals-part-3/yF7BFqk-T_agnHeD.png)

We can see that the 2nd member holds the RPC InterfaceId, which will be a UUID value. So to break down what we just did -

- pProxyInfo (RCX) holds the RPC Interface ID within the structure — MIDL_STUBLESS_PROXY_INFO. (Pointer 1 — offset 0)
- The first member (pStubDesc) within MIDL_STUBLESS_PROXY_INFO holds a pointer to MIDL_STUB_DESC (pointer 2 — offset 0)
- The first member (RpcInterfaceInformation) within MIDL_STUB_DESC holds a pointer to RPC_CLIENT_INTERFACE (pointer 3 — offset 0)
- The 2nd member within RPC_CLIENT_INTERFACE holds the InterfaceId (offset 4, InterfaceId is 16 bytes long).

If we follow this within IDA, we eventually get to a view like this, where the InterfaceID starts at 000000018005A3C4.

![Figure 8](/images/wmi-internals-part-3/Rg72SpnOIbTT1Ept.png)

There are a couple ways to obtain the InterfaceID (UUID), we are going to pull the values from the hex view and then convert them with PowerShell. Again, the UUID is 16 bytes so we will just pull that — `49 59 D3 86 C9 83 44 40 B4 24 DB 36 32 31 FD 0C` and toss into PowerShell to convert -

![Figure 9](/images/wmi-internals-part-3/KR8vtgEdDa03Sbl5.png)

If we google the UUID `86D35949-83C9-4044-B424-DB363231FD0C`, we come across the RPC Interface [ITaskSchedulerService](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-tsch/fbab083e-f79f-4216-af4c-d5104a913d40). Now we know the Interface invoked, we need to find the procedure that was invoked. If we go back to NdrClientCall3, we see that RDX should hold the value. In this case, the value is 1. If we look for Opnum 1 within the [ITaskSchedulerService](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-tsch/fbab083e-f79f-4216-af4c-d5104a913d40) interface we run across [SchRpcRegisterTask](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-tsch/849c131a-64e4-46ef-b015-9d4c599c5167).

![Figure 10](/images/wmi-internals-part-3/5WAdRNc3GuqRGhdL.png)

After following that process of analysis we can identify that if someone creates a scheduled task via the WMI class — `PS_ScheduledTask `that the COM Method `ITaskServices::NewTask` is invoked and eventually `ITaskFolder:RegisterTaskDefinition`, which invokes the RPC procedure `SchRpcRegisterTask`.

## Conclusion:

We ended the last blog post on a bad foot. Although we were able to see what COM method was invoked after using the WMI class — PS_ScheduledTask, we never finished the process of what happened after that. This post was meant to focus on everything after that point. This is important for any defensive engineer who is trying to break down any technique to its core. It’s easy for us to stay at a relatively high level and detect at the highest layer we see, but if we can dig further down, we might find the core function leveraged to achieve a behavior.

As most are aware, there is scheduled task telemetry in both an ETW provider and the Window Security Event. A future blog post will take this further in identifying how those logs are generated and if we can rely on those events.

I hope this walkthrough was helpful for anyone wanting to go from a COM -> RPC layer. I hope to expose more of these capabilities in the future.
