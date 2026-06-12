---
title: "Uncovering Windows Events Part 1"
description: "Data is the foundation by which defense is built upon."
pubDate: 2022-11-14
readingTime: "6 min read"
tags: ["windows", "detection"]
slug: "uncovering-windows-events-part-1"
order: 27
---

### **TelemetrySource**

Data is the foundation by which defense is built upon. This data can come from various telemetry sources — native logging, Endpoint Detection and Response (EDR) tools, network logging, etc. The data from these sources give us insight into activity happening with a given machine — user’s logging in, processes being created, incoming network traffic, etc. Knowing this, I have always wondered

- How is this data generated?
- How do we know we can ***trust ***this data when it is generated
- How can attackers evade event generation, minimizing the evidence of their presence?

These questions have led me down the path of discovering where this data comes from once it is generated and exposed to me.

One of the most common events within Windows comes from Windows Security Events. Due to interfacing with Security Events so often, along with my interest in how this data is generated, I decided to answer the above questions by reversing the generation of these events.

This post will walk through a high-level overview of a new project called [**TelemetrySource**](https://github.com/jsecurity101/TelemetrySource). This project exposes to defenders as it relates to Security Events, and what def enders can do with this information.

There will be two other posts within this series where one will go over a lower-level walk-through of the methodology/process I took to uncover these findings and the other will highlight offensive tradecraft made possible through this research endeavor.

## TelemetrySource

[**TelemetrySource**](https://github.com/jsecurity101/TelemetrySource) is an open-source project that is being released which will provide mapping for how various sources generate telemetry to expose to defenders. I released a similar project that was focused on mapping [**APIs to Sysmon Events**](https://github.com/jsecurity101/Windows-API-To-Sysmon-Events) back in 2019. This project has been moved within TelemetrySource for easier management and expansion.

## Microsoft-Windows-Security-Auditing

Outside of Sysmon events, TelemetrySource showcases how 37 `Microsoft-Windows-Security-Auditing` (Windows Security) Events are generated. The desire is to expose how other events are generated over time, however the project was scoped to release events relating to the following audit sub-categories:

- Audit Logon
- Audit Logoff
- Audit File System
- Audit Kernel Object
- Audit Registry
- Audit Removable Storage
- Audit Directory Service Access
- Audit SAM
- Audit Special Logon
- Audit Sensitive Privilege Use
- Audit Non-Sensitive Privilege Use
- Audit Process Creation
- Audit Process Termination
- Audit Handle Manipulation
- Audit Security System Extension
- Audit Other Object Access Events
- Audit Computer Account Management
- Audit Other Object Access Events
- Audit Kerberos Authentication Service
- Audit Kerberos Service Ticket Operations
- Audit User Account Management
- Audit Detailed File Share
- Other System Events

Within the Microsoft-Windows-Security-Auditing section contains a link to a **[Google Sheet](https://docs.google.com/spreadsheets/d/1d7hPRktxzYWmYtfLFaU_vMBKX2z98bci0fssTYyofdo/edit?usp=sharing) **that shows a code flow for the event generation.

![Figure 1](/images/uncovering-windows-events-part-1/DuIsIY70QmOlyjv7.png)

The code flow is made up of three sections:

1. **Operational Functions** — Higher-level functions that perform an operation that Microsoft embeds an Event Processing Function in.
2. **Event Processing Functions** — Undocumented Microsoft functions used to start the event auditing process. It is important to note — if this function isn’t hit then the correlating event won’t be generated.
3. **Event Emission Function** — Either `ntdll!EtwWriteUMSecurityEvent` or `nt!EtwWriteKMSecurityEvent` which will start the process of writing events to the `Microsoft-Windows-Security-Auditing` ETW Provider.

What does this mean? Let’s look at [**EventID 4688 — Process Creation**](https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/event-4688) as an example:

**Operational Functions:**

1. NtCreateUserProcess, PspInserProcess
2. PsCreateMinimalProcess, PspInsertProcess
3. PspCreateProcess, PspInsertProcess

Each one of those 3 options are kernel-level code flows that occur when a process is created, think of them as different paths that are taken. At the end of each path holds a function (`PspCreateProcess`) that makes a call to an Event Processing Function (`SeAuditProcessCreation`) that starts the process of collecting the necessary information to create the event. This function will “build” the event and pass that off to the Event Emission Function — `EtwWriteKMSecurityEvent `which writes the event to the `Microsoft-Windows-Security-Auditing` provider. If there was a way to create a process without calling `PspInsertProcess`, that alternative path would not end up calling `SeAuditProcessCreation `and in turn wouldn’t generate the 4688 event.

Any event trace session that is subscribed to the `Microsoft-Windows-Security-Auditing` provider would then be able to obtain those events, EventLog-Security being the built-in trace session which connects those events to the Windows Event Log.

**A Note: ***Within this project you will see two Event Emission Functions — `EtwWriteKMSecurityEvent `and `EtwWriteUMSecurityEvent`. You might see the difference between the 2 functions as “KM/UM”. If your assumption is that one function was built for user-mode (UM) and the other kernel-mode (KM), you would be correct. While initially starting this project Matt Graeber told me about the user-mode function `ntdll!EtwWriteUMSecurityEvent`. This information really excelled my research, so a big thank you to him for exposing this information to me and being awesome 🙂.*

The `Microsoft-Windows-Security-Auditing` section will also have DrawIO files attached for each flow documented within the [**Google Sheet**](https://docs.google.com/spreadsheets/d/1d7hPRktxzYWmYtfLFaU_vMBKX2z98bci0fssTYyofdo/edit?usp=sharing). I chose DrawIO files as they are easy to update and anyone can see those files as long as the VSCode they have connected to GitHub has the **[DrawIO Extension](https://marketplace.visualstudio.com/items?itemName=hediet.vscode-drawio).** This can be done locally or on the web within GitHub if you click on DrawIO file and click on the `Open In github.dev` option.

Here is an example from the **4688 **event above:

![Figure 2](/images/uncovering-windows-events-part-1/heh8TiM7U6JZSLtV.png)

## Defenders Usage

I have always found the way defenders can trust the data exposed to them is to understand the means by which it is generated and what the event relies on as its trigger. Our confidence in detections is naive at best if we don’t trust the data upon which the detection is built.

I really tried to use this trust factor when trying to find ways that this research could be practically useful for defenders, which led me to the following questions:

1. For each event, does the generation happen in user or kernel-mode?
2. What function was in charge of starting the auditing process?
3. What was the operational flow that led to the event generation?

These questions all helped shape the end product of this research, which serves to answer those questions. Of course, other offensive hypotheses arise related to this research, but that will be discussed in the 3rd part of this series. Let me guide you through where those answers can be found within the project:

1. For each event, does the generation happen in user or kernel-mode?
2. The Event Emission function will hold a `EtwWrite*SecurityEvent` function. UM = user-mode and KM = kernel-mode.
3. What function was in charge of starting the auditing process?
4. Under the Event Processing function within the Google Sheet holds a function in brackets, this function is in charge of starting the necessary collection/packaging of information for the event creation.
5. What was the operational flow that led to the event generation?
6. This can be found under the Operational functions within the Google Sheet and also within the DrawIO files. It is good to note, in situations that operational flows were in kernel-mode I didn’t trace those up to user-mode. Meaning, if we look at the process creation example above, I didn’t trace that up to Win32 APIs like CreateProcessW.

My hope is that defenders can take this information and future versions to help them understand and discern the trustworthiness of the data they are creating their detections for, but also understand the operational flow the event is built upon. This research is meant to inform defensive capabilities and flip the bit of being more confident in the capabilities a certain telemetry source has versus another, if one is built better for another source then leveraging the other event instead.

If anyone has suggestions by which they think this project could be updated to help defenders, please reach out and let’s have a discussion. I am open to feedback.

## Conclusion

This post was meant to expose a new open-source project I am releasing, [**TelemetrySource**](https://github.com/jsecurity101/TelemetrySource). [**TelemetrySource**](https://github.com/jsecurity101/TelemetrySource) is meant to showcase how various sources that events can be obtained and how they are obtained. Right now, the two sources are Sysmon (which will be updated soon) and Window Security Events (`Microsoft-Windows-Security-Auditing` ETW Provider). Future iterations will have updates to both of the mentioned sources, research into other ETW Providers and how they obtain their data.

Please stay tuned for the next part of this series where I will deep dive into my process/methodology for uncovering my findings.
