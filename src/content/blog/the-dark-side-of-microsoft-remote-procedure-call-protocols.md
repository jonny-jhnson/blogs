---
title: "The dark side of Microsoft Remote Procedure Call protocols"
description: "A look at how adversaries abuse Microsoft RPC (MSRPC) for privilege escalation - and where the detection opportunities sit, from PetitPotam to PrintNightmare."
pubDate: 2021-11-22
readingTime: "6 min read"
tags: ["windows", "detection"]
slug: "the-dark-side-of-microsoft-remote-procedure-call-protocols"
order: 38
---

*Story was first released on the [Red Canary Publication](https://redcanary.com/blog/msrpc-to-attack/).*

> *[MSRPC to ATT&CK](https://github.com/jsecurity101/MSRPC-to-ATTACK) is a one-stop shop for learning more about Remote Procedure Calls, how adversaries abuse them, and how you can detect related malicious activity.*

Microsoft Remote Procedure Call (MSRPC) is an interprocess communication protocol mechanism that adversaries can abuse to perform a wide range of malicious actions. Just this year, two major attacks leveraged MSRPC to accomplish privilege escalation — [PetitPotam](https://github.com/topotam/PetitPotam) and [PrintNightmare](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2021-34527). These aren’t the first attacks to leverage MSRPC, and they won’t be the last.

This blog introduces a project called [MSRPC to ATT&CK](https://github.com/jsecurity101/MSRPC-to-ATTACK), which maps commonly used MSRPC protocols to corresponding MITRE ATT&CK® techniques and sub-techniques, providing context about each protocol. Read on to learn why this project exists, what type of information it contains, and how defenders can use this resource.

## What is MSRPC?

MSRPC is Microsoft’s implementation of the Distributed Computing Environment/Remote Procedure Calls ([DCE\RPC](https://en.wikipedia.org/wiki/DCE/RPC)) call system, used for creating and facilitating communication between distributed client and server programs. Users can interact with MSRPC remotely (the scenario implied in the rest of this post) or locally by leveraging Advanced Local Procedure Call (ALPC). ALPC and the majority of other MSRPC components are out of scope for this article. If you’d like to know more about RPC components, SpecterOps published an extensive [research paper](https://specterops.io/assets/resources/RPC_for_Detection_Engineers.pdf) (full disclosure: I wrote it) and [James Forshaw](https://twitter.com/tiraniddo) wrote a noteworthy [blog](https://googleprojectzero.blogspot.com/) for Google Project Zero and has developed an extensive library of RPC-related information.

As previously mentioned, attackers leverage various MSRPC protocols for many purposes including, but not limited to, the following:

- [User enumeration](https://www.blackhillsinfosec.com/password-spraying-other-fun-with-rpcclient/)
- [Service / system enumeration](https://0xffsec.com/handbook/services/msrpc/)
- [Credential dumping](https://www.picussecurity.com/resource/blog/picus-10-critical-mitre-attck-techniques-t1003-credential-dumping)
- [Lateral movement](https://posts.specterops.io/offensive-lateral-movement-1744ae62b14f)
- [Privilege escalation](https://dirkjanm.io/exploiting-CVE-2019-1040-relay-vulnerabilities-for-rce-and-domain-admin/)

Historically, it’s been difficult to leverage RPC-based telemetry to perform detection at scale. The telemetry from an endpoint perspective is poor. Sure, there’s the Event Tracing for Windows (ETW) [Microsoft-Windows-RPC](https://github.com/repnz/etw-providers-docs/blob/master/Manifests-Win7-7600/Microsoft-Windows-RPC.xml) provider, but if sensors are leveraging this provider at scale, then the end user has no control over its configuration. This means you can’t collect the RPC telemetry you might want or need, which leads to scalability issues.

There’s also [Windows Security Event 5156](https://docs.microsoft.com/en-us/windows/security/threat-protection/auditing/event-5156), but that’s more of an implicit representation of MSRPC activity because it’s actually a [Windows Filtering Platform](https://docs.microsoft.com/en-us/windows/win32/fwp/windows-filtering-platform-start-page) (WFP) log that doesn’t include the specific RPC attributes that would help identify which protocol/interface is being leveraged. This data would help discern what is happening on an endpoint. A similar thing can be said with process-based network events, a data source collected by many endpoint detection and response (EDR) products. It might have attributes showing which binary received the call, the source and destination IPs of the call, and the transport protocol it used, but these events are missing key attributes like the method (RPC function) that was invoked.

That leaves us with network-based telemetry, which generally does have the information we need. Zeek, for example, will specify the protocol being used, the transport protocol used (TCP/IP / Named Pipes), the method being invoked, and the source/destination hosts. However, that leaves a gap of knowledge from a host perspective. You know a specific operation was called through network telemetry, but you might not have visibility into what the adversary actually did on the endpoint. This begs a few questions:

- What binary was used to execute this method?
- What if an environment doesn’t have great network telemetry?
- How do defenders know how to relate activity back to the originating MSRPC protocol?

## MSRPC to ATT&CK

The fundamental point of this project is to enumerate commonly abused MSRPC protocols and to provide information associated with those protocols — including unique identifiers, server binary data, and indicators of activity (IOA) like common network connection patterns — that defenders can use to develop detection and prevention strategies. Of course, this project is mapped to MITRE via the [ATT&CK Navigator](https://mitre-attack.github.io/attack-navigator/#layerURL=https%3A%2F%2Fgist.githubusercontent.com%2Fjsecurity101%2Ffd45241a8a809ec02e335e02f4220fa7%2Fraw%2Fef6751e70c6d0e7e15ed7cc7cc2dfa082fe82270%2Frpc-mapping.json):

![Figure 1](/images/the-dark-side-of-microsoft-remote-procedure-call-protocols/hvZQ4fpcH1B54PqU.png)

This project currently covers 13 MSRPC protocols. As time goes on, I hope to add more. Each protocol will link to a Markdown document with the following categories:

## Protocol name

The Microsoft official name for this protocol, along with an embedded link to Microsoft’s documentation of this protocol. Some examples include:

- [MS-SCMR](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-scmr/705b624a-13de-43cc-b8a2-99573da3635f)
- [MS-DRSR](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-drsr/f977faaa-673e-4f66-b9bf-48c640241d47)
- [MS-TSCH](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-tsch/21e8e86e-ee5a-469d-917f-28a41f3c25a4)

## Interface UUID

A 128-bit value universally unique identifier (UUID) that identifies the MSRPC interface being used. The interface is basically the bridge between the client and the server. The RPC client must implement the interface, and the RPC server must expose the same exact interface — otherwise communication will not occur. Each interface has explicit methods or functions associated with it. These interfaces must be called in order to use those exposed functions.

## Server binary

All the code needed to interface with a MSRPC protocol is precompiled and stored within the “RPC server.” Most often we see these binaries with `.dll` & .`exe` extensions. If the server code is stored within a dynamic link library (DLL), then it’s typically loaded by an EXE, so that it can interface and register with the RPC at runtime. This section contains the name of the binary housing the server code and the correlating binary that loads it (assuming that first binary is a DLL).

## Endpoint

Specifies the transport protocol ([ncacn_np](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-rpce/7063c7bd-b48b-42e7-9154-3c2ec4113c0d) and/or [ncacn_ip_tcp](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-rpce/95fbfb56-d67a-47df-900c-e263d6031f22)) being used for this protocol.

## ATT&CK relation

Links to the MITRE ATT&CK sub-technique/technique associated with the protocol.

## Indicators of activity (IOA)

These IOAs represent telemetry that you can expect tools like Zeek or EDR products to generate in response to related RPC activity. We’re using IOA purposefully here, distinguishing it from indicators of compromise (IOCs) as it doesn’t necessarily imply malice or severity.

Since every organization is different and relies on different tools, data sources, and security controls, we wanted to provide IOAs that comprise both network and host-based telemetry.

Network sources will include information on transport protocols, the binaries that are connected to, corresponding methods/functions, and any other noteworthy attributes.

Host sources will include information like registry modifications, image loads, process creation events, file shares, identity logs, and more.

## Prevention opportunities

MSRPC protocol abuse often results from a failure to implement the correct preventive measures. Such oversights could include patching delinquency, disabling services or NTLM, misconfiguring RPC filters or group permissions, or failing to set up any variety of other preventive controls. This information can help organizations understand what they can do to stop this activity from happening within their environment.

## Notes

Generalized notes I found relevant regarding any of the above categories. This could be suggestions to change the DACL within the RPC filters, information regarding current threats, or other miscellaneous things.

## Useful resources

Great reading material on the topic at hand, including documentation from MITRE and Microsoft and useful blog posts.

## How can I use this?

I intended this project to be a one-stop shop for MSRPC security context. Here are three of my main objectives:

- **Increase visibility into this overlooked data source. **Right now, there aren’t great RPC-explicit optics outside of network sensors. If an analyst runs across a binary communicating with many pipes that correlate to MSRPC protocols that expose methods allowing for enumeration, this project will help them confirm that someone is leveraging X protocol to achieve Y action.
- **Educate users about specific protocols. **MSRPC to ATT&CK can be used like an encyclopedia, with comprehensive context about specific protocols and links to other relevant resources.
- **Compile all preventative measures in one place. **Preventive measures are shared across Microsoft’s documentation, Twitter, and other miscellaneous tooling people have released. I wanted to collect all of that information and highlight specifics for the protocol of interest. If an organization decides not to take any of the preventive measures I mention, defenders may still gain insight into future detection opportunities.
