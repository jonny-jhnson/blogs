---
title: "WMI Internals Part 2"
description: "In a previous post WMI Internals Part 1: Understanding the Basics I walked through some of the basic internal information behind WMI."
pubDate: 2022-08-15
readingTime: "6 min read"
tags: ["windows", "reverse engineering"]
slug: "wmi-internals-part-2"
order: 29
---

### Reversing a WMI Provider

In a previous post [WMI Internals Part 1: Understanding the Basics](https://medium.com/@jsecurity101/wmi-internals-part-1-41bb97e7f5eb) I walked through some of the basic internal information behind WMI. The purpose of that post was to provide the appropriate background to understand this post, which will break down how it is common for WMI classes to invoke COM methods to perform the action requested.

Understanding how to extract these technologies and perform binary analysis to see them flow into each other enables us to better understand attacks that might rely on these technologies. This is equally important to defenders as it is to offensive professionals.

**A Note: **Originally when thinking about this post I was going to start at a WMI class and then break down various functions leading into the invocation of a COM method. However; when searching for good examples I came across a PowerShell function that ends up calling a WMI class, so we will actually start there.

## Walkthrough

> **Step 1: Identify the PowerShell command. In our example we will focus on scheduled tasks and specifically Register-ScheduledTask:**

![Figure 1](/images/wmi-internals-part-2/ujK-5olby6KgkAaq3rtVgA.png)

The above command shows us that [Register-ScheduledTask](https://docs.microsoft.com/en-us/powershell/module/scheduledtasks/register-scheduledtask?view=windowsserver2022-ps) is a function, not a PS cmdlet. To understand this function more, let’s pull what we can out of *Get-Command*. After viewing the code for this function it is clear that after the call we will get an output type of `Microsoft.Management.Infrastructure.CimInstance#MSFT_ScheduledTask`but after digging a bit more we can see that by default this function uses a ParameterSetName “User”, which eventually leads the invocation of the `RegisterByUser` method which seems to be done through the `PS_ScheduledTask` class.

Previous to this I had never ran across a PowerShell command that did this so I talked to [Matt Graeber](https://twitter.com/mattifestation) and he let me know this was a cmdlet definition XML (CDXML). Not to get into this too much but a [CDXML](https://docs.microsoft.com/en-us/previous-versions/windows/desktop/wmi_v2/cdxml-overview) file defines a mapping between a PowerShell cmdlet and a WMI class/method. CDXML is an auto-generated script wrapper for a WMI class.

> **Step 2: Find the CDXML:**

After some digging I found that the cdxml file for PS_ScheduledTask was found in: `C:\Windows\System32\WindowsPowerShell\v1.0\Modules\ScheduledTasks\PS_ScheduledTask_v1.0.cdxml`. Within this file it shows that the WMI class name is: `PS_ScheduledTask` found in the `Root/Microsoft/Windows/TaskScheduler` WMI namespace.

![Figure 2](/images/wmi-internals-part-2/dU8rp9yjtuS6iYJLUqqk2g.png)

> **Step 3: Find the WMI Provider for the PS_ScheduledTask class:**

![Get-CimClass -Namespace root/Microsoft/Windows/TaskScheduler -ClassName PS_ScheduledTask | Select-Object -ExpandProperty CimClassQualifiers](/images/wmi-internals-part-2/tC1A8GMQhFofnGOa_3imAw.png)

The following command will call the **TaskScheduler **namespace to filter through provider names. Once it matches **ScheduledTaskProv **it will print out a GUID value. This is the CLSID that will point us to the appropriate binary of the WMI Provider.

![Figure 4](/images/wmi-internals-part-2/5oACyBtfPMnK7VteHAQsvw.png)

> **Step 4: Get the WMI provider binary:**

![Figure 5](/images/wmi-internals-part-2/9N-atNaj2neVH6HXVzzbhA.png)

Now I know that **schedprov**.dll is the WMI provider for the `PS_ScheduledTask:RegisterByUser` Method.

**Note:** This is a quick way to get this information and querying the registry could achieve the same goal.

> **Step 5: Analyze WMI Provider (schedprov.dll):**

After opening up in IDA, if we open up the function window and search for *RegisterByUser* we see there is a function called: `PS_ScheduledTask_Invoke_RegisterByUser`.

![Figure 6](/images/wmi-internals-part-2/uVjTJZ0a5P-PfxBYAdpPAQ.png)

As we can see, there is an immediate jump to another function called` ScheduledTask_Invoke_RegisterByUser`. After looking at this function block, we see a section that calls [CoCreateInstance](https://docs.microsoft.com/en-us/windows/win32/api/combaseapi/nf-combaseapi-cocreateinstance).

![Figure 7](/images/wmi-internals-part-2/au153picVjJyWTglB2mczg.png)

This function is in charge of creating a COM Class object. This function contains 5 parameters, but the 3 we care about are:

- rclsid (Parameter 1) — “The CLSID associated with the data and code that will be used to create the object.”
- rrid (Parameter 4) — “A reference to the identifier of the interface to be used to communicate with the object.”
- ppv (Parameter 5) — “Address of pointer variable that receives the interface pointer requested in riid.”

If we look, IDA filled in the CLSID (**CLSID_TaskScheduler — 0F87369F-A4E5–4CFC-BD3E-73E6154572DD**) value with the proper symbols. Next, we see the GUID that represents which COM Interface this action comes from. Using [OleViewDotNet ](https://github.com/tyranid/oleviewdotnet)we can see this value corresponds to ITaskService.

![Figure 8](/images/wmi-internals-part-2/buNbnTqTLzK6DzWE.png)

Lastly, if we want to find what COM methods we want to invoke we have to follow ppv. On the assumption that CoCreateInstance was successful another code block is jumped into which contains the code below. If we follow the code from earlier we see that certain offsets of ppv get called, which leads me to believe after applying the right structure we should be able to see which methods are being invoked. A decompiled and assembly example are shown below.

After knowing that the ITaskServices Interface was called, I started to look explicitly for calls related to creating a new task. After doing jumps into a couple of `CreateNewTaskDefnition` functions, I was able to find the NewTask method invoked. Shown below.

## Decompiled Example

If we know that ppv holds the offset of the COM method invoked then we can apply that structure to ppv and see the methods called.

![Figure 9](/images/wmi-internals-part-2/7Y_hgSMHpE79BetoQOBfpA.png)

We can see after the structure is applied that [**ITaskService::NewTask**](https://docs.microsoft.com/en-us/windows/win32/api/taskschd/nf-taskschd-itaskservice-newtask) is called.

## Assembly Example

PPV and var_218 hold the same memory location. We see var_218 being dereferenced twice and then an offset of 50h is called. This offset relates to what COM method is being invoked within the **ITaskService** interface.

![Figure 10](/images/wmi-internals-part-2/_0WsxTAgHzuiyyq6wn1wTw.png)

By making sure the proper type libraries are applied we can add the structure type *ITaskServiceVtbl*. We can then hover over 50h and apply the structure offset to see that this relates to the*** **ITaskServiceVtbl.Connect* method. Following the same methodology we can see that eventually *ITaskServiceVtbl.NewTask** ***was called later in the code.

![Figure 11](/images/wmi-internals-part-2/2DO9s4ZaX2RMBrMTuhBUPA.png)

After googling for [ITaskService::NewTask](https://docs.microsoft.com/en-us/windows/win32/api/taskschd/nf-taskschd-itaskservice-newtask), I was able to identify this Microsoft document that outlines this COM method:

![Figure 12](/images/wmi-internals-part-2/tCNrgX-a0pxIqbSE.png)

## Bringing it all together

After applying binary analysis to the WMI Provider binary (**schedprov.dll**) we were able to identify that the WMI class `PS_ScheduledTask` ends up invoking the COM method *NewTask::ITaskService*. The flow of functions we encountered today can be seen below:

![Figure 13](/images/wmi-internals-part-2/oTjnpxniTpSyfl18XKqr2A.png)

The purpose of this post was to highlight how some technologies end up calling others to accomplish a task under the hood. It should be noted that not every WMI class will work just like this, even though WMI is built upon and structured like COM, the class might just end up calling a Win32 API to accomplish its task. Attacks rely on technologies the operating system exposes, understanding these concepts help us understand those technologies better and in turn those attacks.

If you are following along within the code or the MSFT documentation you might be wondering if there is another component after this. You would be correct if you think so. The next blog will go walkthrough how to take this a step further and go from COM methods being invoked calling RPC methods.

## Hat Tip

Thank you to [Matt Graeber](https://twitter.com/mattifestation) and [Alex Ionescu](https://twitter.com/aionescu) for reviewing this blog. As always, I appreciate your guys’ time and being willing to help people grow!
