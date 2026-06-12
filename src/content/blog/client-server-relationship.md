---
title: "The Client/Server Relationship — A Match Made In Heaven"
description: "A walk through the client/server relationship at the heart of RPC and COM activity, and why that context is critical for detection engineering and incident response."
pubDate: 2023-10-11
readingTime: "8 min read"
tags: ["windows", "detection", "reverse engineering"]
slug: "client-server-relationship"
order: 18
---

*This blog was written by [Jonny Johnson,](https://twitter.com/jsecurity101) Senior Researcher of Adversarial Techniques and Capabilities at Binary Defense, and co-authored with [Charlie Clark](https://twitter.com/exploitph) and [Andrew Schwartz](https://twitter.com/4ndr3w6S) from [TrustedSec](https://www.trustedsec.com/). Blog was originally released by TrustedSec and [BinaryDefense](https://www.binarydefense.com/resources/blog/the-client-server-relationship-a-match-made-in-heaven/).*

## 1. Introduction

One thing often forgotten is that detection engineering isn’t always centered around 1 action to 1 query but also to drive effective incident response to optimize the triage of an alert. This is best served with context. We often say, ‘context is king,’ because this exposes a story that helps defenders understand the intent behind the actions. Context doesn’t always surround one process but potentially multiple processes, network connections, and different hosts. Context paints the picture for responders to best measure how to handle the event/incident that they are answering to. It is through context that the defensive team can get a better understanding of the attack they are facing and ultimately attribution.

Charlie and Andrew have been trying to bring more offensive and defensive awareness around Kerberos, and Jonny has helped close the gaps by leveraging Windows OS internals. In this post we will share the joint effort of how we have researched different Kerberos-based attacks and how we have used multiple events to gain better understanding for defensive purposes. These approaches are not widely used, and we consider them relatively novel. Please keep in mind that these recommendations are somewhat generalized and might need organizational tuning.

## 2. Correlation

As we further our detection engineering efforts, it is important to identify *what* we want to detect and *how* we will be able to accomplish that. Historically, detections have been created from a 1:1 ratio of one action to one event. With more advanced threats, like Kerberos-based attacks, that strategy simply isn’t ideal. Many people have created detections based on Window Security Event ID 4769, but what does that event tell us? Simply that a service ticket was requested, which by itself is not malicious.

We want to find intent. Which is a really hard thing to track down. How do we do this? We find out who was the user that requested the ticket, along with the process. Correlation. How do we do this? Before we can do this, we need to understand a concept that we like to call — client/server interaction. We use this to refer to what the attack is doing and how it transitions between processes, users, and computers.

Client: The binary file that requests an action. This could be on the same host or meant to be transmitted across the wire to another host to finish execution.

Server: The binary file that accepts the request and executes the behavior. Again, this server binary file could be on the same host as the client, or it could be on a different host completely.

The client/server binary file could be the same binary file as well. Situations like executing token (thread) impersonation are good examples where everything stays within the same process container. The point here is to understand the purpose that each binary file can play within the attack flow and then identifying the behaviors being transmitted between the two. Within the Common Kerberos Attack Use Cases section, we will see practical examples of this, but to simplify this here, let’s look at an example:

Someone wants to create a service, so they use sc.exe to do so. This doesn’t create the service, but it requests a service to be created. The process services.exe goes through the proper code flow to accept and finish that request. So, in this scenario, sc.exe would be the client whereas services.exe is the server. Which do we use for detection? Historically, people have used sc.exe, but that is controlled by the attacker, and services.exe can create a lot of false positives and be loud. Detections for service creation have been found to be precise based off open-source tooling or known APTs. This leaves a lot of potential gaps. How do we get around this? Why don’t we leverage both events? We won’t show a query or detection logic for this, since the point is to get the reader thinking about correlation.

At this point you might be asking — how do we do correlation well? There are some events that are better fit as ‘primary’ events where they serve as the foundation of the detection. [Window Security Event ID 4769](https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/event-4769) would be an example of this for service ticket requests. You need that event to definitively say a service ticket was requested. Then we have ‘secondary’ events that serve to provide context. Logon events, process network communications, and process creation are three of our favorite events for context, as they can be used to track where the communication came from and who made the request. It is good to note that there are some secondary events that can be used by themselves as a primary source, depending on the detection’s goal.

This isn’t to say that the 1:1 ratio detection strategy is bad, because it isn’t. And there are a lot of situations where that strategy is adequate. However, for more complex or behavioral detections where there needs to be multiple data sources combined to say that when an action was performed it was malicious, we need to use correlation. Let’s look at this within our Kerberos use cases.

### 2.1 Common Kerberos Attack Use Cases

There have been hundreds of blogs posts on the various Kerberos attacks. As such, this post will not go into the background of all of them, but we can apply our client/server correlation methodology to understand when these attacks may have occurred in an environment.

2.1.1 ASKTGT

![Figure 1](/images/client-server-relationship/WF6zEwnvHLigLTgg.jpg)

*Figure 1 — Example 1 of Kerberos Correlation in Splunk*

2.1.2 S4U2Self/opsec, S4U2Self & U2U

![Figure 2](/images/client-server-relationship/qqTjJIuzaYvuit-7.jpg)

*Figure 2 — Example 2 of Kerberos Correlation in Splunk*

The queries above are not deemed production ready but more of examples of how someone can apply correlation into Kerberos-based attacks to see additional context. If you want to create more production-ready detection, there might need to be some tuning applied. An example can be found in this [gist](https://gist.github.com/jsecurity101/4f82d1ec608671bdf722a43b9291a8ba).

We can see in this query how we have applied server-side telemetry (server/DC) with client-side (workstation) to see who requested service tickets. This can be applied to many of the ‘common’ Kerberos-based attacks that are executed, such as [Kerberoasting](https://attack.mitre.org/techniques/T1558/003/), [AS-REP Roasting,](https://attack.mitre.org/techniques/T1558/004/) ASKTGS, or ASKTGT. However, our methodology can really be applied to almost any attack involving a client/server relationship. The imagination is only limited by the reader!

### 2.2 U2U

Let’s look at another use case. Recent tooling developed attack paths involving [UnPAC the hash](https://www.thehacker.recipes/ad/movement/kerberos/unpac-the-hash) ([Shadow Credentials](https://www.thehacker.recipes/ad/movement/kerberos/shadow-credentials) and [Golden Certificates](https://www.thehacker.recipes/ad/persistence/ad-cs/golden-certificate)), [Sapphire Tickets](https://www.thehacker.recipes/ad/movement/kerberos/forged-tickets/sapphire), and [RBCD from SPN-less accounts](https://www.thehacker.recipes/ad/movement/kerberos/delegations/rbcd#rbcd-on-spn-less-users), all of which take advantage of U2U.

A U2U ticket is encrypted with the TGT session key of the TGT provided as an additional ticket, so it’s an ST to the account the additional TGT belongs to but as the account of the usual provided TGT. The ENC-TKT-IN-SKEY KDC option is required in the TGS-REQ body to tell the KDC to use the session key in the supplied additional ticket, but any other option could be used. In our experience, U2U requests are incredibly uncommon in normal operations; however, there have been incorrect implementations of S4U2Self that include the ENC-TKT-IN-SKEY option.

We can use a modified version of Rubeus and a quick PowerShell script to request a service ticket with U2U and every potential KDC option combination.

![Figure 3](/images/client-server-relationship/IBNkB1MoQk1V7D-W.jpg)

*Figure 3 — U2U KDC Option Fuzzing*

From the above fuzzing, we can see that *all* U2U service tickets will end in either an 8 or a c, which means that the fourth bit is always switched ‘on’.

To avoid any incorrect implementations of S4U2Self (i.e., false positives), we can exclude any service accounts with an SPN, meaning the request must have been a U2U. To perform this validation, we conduct an LDAP lookup on the service account to check for an SPN. However, this means the detection can be bypassed by using an account with an SPN to do the U2U, but this is the price you pay in trying to remove all false positives. An exception may happen in the unlikely event that the SPNs for the service account were removed between when the ticket was requested and when the LDAP search was made, whereby an additional check could be made to see if the account had been modified in LDAP to attempt to avoid this. You have the option to not perform this, but then you risk false positives and potential alert fatigue.

Below is a POC that uses XPath to query the Event Logs on both the client and the domain controller, as well as performing the LDAP lookup to exclude any account with an SPN. Using both hosts with the Advanced Auditing policy enabled, we can make use of the below Windows Security Event IDs as well as look for Service Ticket Options where the fourth bit is on.

- [4624](https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/event-4624) (Client)
- [4688](https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/event-4688) (Client)
- [4769](https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/event-4769) (DC)
- [5154](https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/event-5154) (Client)
- [5156](https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/event-5156) (Client)

![Figure 4](/images/client-server-relationship/C-Sgnm5W1UVV22eY.jpg)

*Figure 4 — U2U POC Correlation*

The POC above goes beyond the simple client/server correlation to demonstrate the power of making correlations and returning rich information. First, it makes the client/server correlation to get the process information from the client. It then attempts to extract as much as it can of the process, network, and session information from within the session that launched the process. This results in a rich amount of information that can be quickly reviewed by an analyst looking into anomalous behavior.

## 3. Conclusion

Just like the rest of the world, detection has to evolve. This is done by finding new strategies to find attacks. With all of the obfuscation and complexity within attacks these days, one way we have found to accomplish detection in a robust manner is through correlation. We haven’t seen many people talk about correlation in depth and expanding past precise detections, especially as related to Kerberos-based attacks, so we wanted to showcase some research we have done to help others potentially detect these behaviors themselves.

## References

[https://ipc-research.readthedocs.io/en/latest/subpages/RPC.html](https://ipc-research.readthedocs.io/en/latest/subpages/RPC.html)

[https://www.youtube.com/watch?t=10552&v=dFw5eoWSXWg](https://www.youtube.com/watch?t=10552&v=dFw5eoWSXWg)
