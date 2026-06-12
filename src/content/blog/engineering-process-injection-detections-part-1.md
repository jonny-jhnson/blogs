---
title: "Engineering Process Injection Detections - Part 1: Research"
description: "Often within detection engineering, we come across an attack technique that we want to create a detection for but don’t know where to start the process to effectively do so."
pubDate: 2020-03-06
readingTime: "8 min read"
tags: ["windows", "detection"]
slug: "engineering-process-injection-detections-part-1"
order: 45
---

## **Introduction:**

Often within detection engineering, we come across an attack technique that we want to create a detection for but don’t know where to start the process to effectively do so. Do we find or create an attack proof of concept? Do we research the underlying technology of the attack? Do we run the attack and then correlate the events with the malicious activity to create some analytic logic? What are some aspects of the attack that stays the same across all implementations of the attack? What changes? These are all questions that commonly come up when addressing an attack.

This process I will walk through in this blog uses a concept known as Capability Abstraction, where we will peel back the underlying technology that makes an attack possible. This concept was outlined by Jared Atkinson in his blog [Capability Abstraction](https://posts.specterops.io/capability-abstraction-fbeaeeb26384). If you haven’t yet read this blog I suggest doing so as we will be using this methodology throughout this blog.

These are procedures we want to complete within the detection process, but sometimes it can be hard to optimize a process so that we maximize our efforts.

In this blog series, I will go over the methodology I use to create detections. We will focus on one technique, [Process Hollowing](https://attack.mitre.org/techniques/T1093/), which will be broken up into three parts:

- **Part 1: Research**
- **Part 2: Data Modeling**
- **Part 3: Analytic Logic**

This blog series will work alongside a project that Josh Prager ([Bouj33 Boy](https://medium.com/u/63c7e5a7c6a2)), [David Polojac](https://medium.com/u/7d242549adf1), and I worked on called [**Detecting Process Injection Techniques**](https://github.com/jsecurity101/Detecting-Process-Injection-Techniques). This process is meant to be able to be applied to other techniques, but the “Detecting Process Injection Techniques” project will be used as an example throughout this series.

## **Research:**

The first step to creating any detection is choosing an attack technique to detect. This could come from an article, a threat feed, the [MITRE ATT&CK](https://attack.mitre.org/) knowledge base, a real incident, red team tests or other resources. The goal when doing this is to choose one technique. Sometimes the selected technique is too broad, so we have to break it down to “sub-techniques”. Process Injection is a great example of this. There are many different variants of this technique, that we would want to break it down into sub-techniques — DLL Injection, Reflective DLL Injection, etc. Focusing on a sub-technique enables you to identify what is in scope for your detection. If you define your detection around too many sub-techniques simultaneously, it’s easy to lose focus and accuracy in the final detection.

Once a technique or sub-technique is chosen, I tend to see if the [MITRE ATT&CK](https://attack.mitre.org/) framework has any information. This jump-starts my initial research before diving into the underlying technology.

![MITRE ATT&CK description of Process Hollowing](/images/engineering-process-injection-detections-part-1/6tgm8e-BoWc3ZTDn.png)

The above description gives me an initial idea of how process hollowing is defined and how this attack works; however, I still need more context to create an operational detection. Within the same page on MITRE, there is a ***Detection*** and* **References*** section. The** *Detection*** section states that:

> *“Monitoring API calls may generate a significant amount of data and may not be directly useful for defense unless collected under specific circumstances for known bad sequences of calls, since benign use of API functions may be common and difficult to distinguish from malicious behavior. API calls that unmap process memory, such as ZwUnmapViewOfSection or NtUnmapViewOfSection, and those that can be used to modify memory within another process, such as WriteProcessMemory, may be used for this technique.”*

This section mentions different API calls that are utilized to perform Process Hollowing. Although this is inherently interesting, the ***Detection*** section does not provide enough context to dive into the API calls yet.

Next, let’s take a look through some of the ***References*** MITRE mentions. One I come across of particular interest in this article by** Endgame**: [***Ten Process Injection Techniques: A Technical Survey Of Common And Trending Process Injection Techniques***](https://www.endgame.com/blog/technical-blog/ten-process-injection-techniques-technical-survey-common-and-trending-process)

![Ten Process Injection Techniques by Endgame](/images/engineering-process-injection-detections-part-1/m7lE9R9XI8gz83MJ.png)

This article’s description contained more details than MITRE’s report initially contained. Some points of interest I can extract are:

- Malware unmaps (hollows out) legitimate code from memory of the target process
- Malware overwrites the memory space of the target process with a malicious executable

This gives me additional insight at a high-level how process hollowing is executed. However, I need to go further into what makes process hollowing possible in order to create a robust detection.

![Ten Process Injection Techniques by Endgame: Process Hollowing](/images/engineering-process-injection-detections-part-1/vsHCIB5WpDZZShA4.png)

Under each process injection technique, Endgame provided a technical debrief of how the attack is working. The description is helpful because of the additional context I could utilize for detection purposes. From this information I can gather:

- A process is created using the [CreateProcess](https://docs.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-createprocessa) Win32 API in a suspended state ([CREATE_SUSPENDED](https://docs.microsoft.com/en-us/windows/win32/procthread/process-creation-flags)).
- The adversary needs to unmap memory within the target process. Done by utilizing [ZwUnmapViewOfSection](https://docs.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-zwunmapviewofsection) or [NtUnmapViewOfSection](https://docs.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-zwunmapviewofsection).
- The loader will utilize [VirtualAllocEx](https://docs.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-virtualallocex) to allocate memory for the malware within the target process.
- [WriteProcessMemory](https://docs.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-writeprocessmemory) is used to write the malware sections into the target process space.
- [ResumeThread](https://docs.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-resumethread) is called to take the primary thread out of the suspended state to allow the process to run.

Before I dive into these functions, I want to track a few more questions:

1. When some of these API calls are being utilized, what data can we expect to see?
2. What are the implicit and explicit behaviours of this attack? What are the things that the attacker can and can’t change and still be able to perform this attack effectively?

To start the process of answering these questions, I navigated to the Microsoft Documentation for one of the API calls used. I am going to use [CreateProcessA](https://docs.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-createprocessa) as an example.

![CreateProcessA](/images/engineering-process-injection-detections-part-1/jBimi89810EYwWJi.png)

Now I want to see what [CreateProcessA](https://docs.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-createprocessa) is being utilized for and if an attacker could use any other Win32 API calls to perform the same task of creating a process. Digging further into this documentation I can see what this API is effectively doing, along with other API calls that could be used to create a process. Also, remember this process is created in a suspended thread, but what does this mean?

![Process Creation Flags](/images/engineering-process-injection-detections-part-1/kCoprWZNO6OrXO-e.png)

![Create_Suspended Flag](/images/engineering-process-injection-detections-part-1/Cd6lKPtcViD-neVl.png)

Although this description is relatively small, it provides the necessary context:

1. The Create_Suspended flag can be passed to any of the following API calls.
2. [CreateProcessA](https://docs.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-createprocessa)
3. [CreateProcessAsUser](https://docs.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-createprocessasusera)
4. [CreateProcessWithLogonW](https://docs.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-createprocesswithlogonw)
5. [CreateProcessWithTokenW](https://docs.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-createprocesswithtokenw)
6. When this flag is passed through, it affects the primary thread of the process.
7. The primary thread does not run until [ResumeThread](https://docs.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-resumethread) is called.

***Note: **You would want to repeat this process for the rest of the API and function calls listed above. A good way to do this research is to look at some proof of concept code examples. Github has a wealth of them.*

> *Going through this process allows me to understand the technology behind the attack. This process enables me to understand the different variants by which an attacker could change function or API calls while keeping the same behaviour of the attack. As defenders, this is more important than we might think. Being able to peel back different layers of the technology by which an attacker can perform a specific behaviour, gives us the ability to mould our detections more efficiently. Another avenue of abstraction is we could peel back the layers further to look at documented API calls, undocumented API calls, and Syscalls and find the root commonality between them.*

Now that we have additional context from researching these API and function calls, I want to know what type of logs will fire when this behaviour is performed. I want to make the least amount of assumptions as possible when creating this detection. To do so, I am going to do some research on what events will fire when a process is created. For this example, I will utilize the Sysmon data sensor.

![Sysmon Event ID: 1](/images/engineering-process-injection-detections-part-1/laaOXsQaaESTqI0M.png)

[Sysmon](https://docs.microsoft.com/en-us/sysinternals/downloads/sysmon) creates an event anytime a process is created on a host. As a detection engineer, this isn’t sufficient, because I want to know how these events are being fired and how an attacker could possibly bypass this logging source. This enables me to identify any blind spots and assumptions when creating this detection. In other words, I need to trust my logging sensor, and the only way to do that is to know how exactly it works.

Last year I created a project called: [Mapping Windows API’s to Sysmon Events](https://posts.specterops.io/uncovering-the-unknowns-a47c93bb6971), that mapped out how Sysmon was performing its logging. This project goes through what API’s are being funnelled through a given Event Registration Mechanism (ERM) and how Sysmon utilizes that process to create a specific event ID. For more information on this project visit:

The following shows how Sysmon creates the process creation event:

![Process Creation Event Mapping](/images/engineering-process-injection-detections-part-1/xNxyxjqVK7AwkcT0.png)

This mapping shows me how Sysmon logs process creation events. Additionally, I can see how an attacker might be able to avoid generating these events. A couple of ideas of how this can happen are, but not limited to:

- Use a different API call to create a process
- Tamper with the ERM

Once I have done this for all the API and function calls, I can begin to perform this attack as a proof of concept for my detection logic. I can then use the POC as a way to build and continuously test my detection logic. We can also use this POC to identify the proper log events we will want to correlate for our detection. Stay tuned for part two of this blog series where we’ll discuss this in full.

## **Conclusion:**

Research often gets overlooked when it comes to Detection Engineering, but it is the foundation by which we have to create our detections. For us to develop robust detection, we have to understand the underlying technology by which this attack can be performed. Jared Atkinson in a recent post went over [Capability Abstraction](https://posts.specterops.io/capability-abstraction-fbeaeeb26384). This is the concept of peeling back the layers as to how a tool, function, or an attack is working. This allows us, as detection engineers, to look at those abstractions and utilize them in our detection efforts.

Abstraction starts with research. It can lead us down rabbit holes for discovering different API calls, functions, and logging capabilities, which maximizes our detection efforts so that we are not blindly going through logs when looking for activity. It helps us identify the false positives that might occur, the assumptions we are making, along with the blind spots that can come to light when creating this detection.

This is a methodology that the detection engineering team at SpecterOps follows and practices, both with our clients and personal research endeavours. We found it would be of value to show a walkthrough of this process after the methodology was introduced. Stay tuned for parts 2 and 3, where I will go over how to quarantining malicious activity, create correlations within the data, how to choose what type of detection we want to create ([Detection Spectrum](https://posts.specterops.io/detection-spectrum-198a0bfb9302)), and writing the analytic for those detections (Detection in Depth)!
