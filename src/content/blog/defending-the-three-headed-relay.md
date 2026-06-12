---
title: "Defending the Three Headed Relay"
description: "A look at the Kerberos Relaying attacks made popular by KrbRelayUp - what's actually being relayed, what defenders should be looking for, and where existing detections might be missing the mark."
pubDate: 2022-05-09
readingTime: "9 min read"
tags: ["windows", "detection"]
slug: "defending-the-three-headed-relay"
order: 32
---

*A joint blog written by [Andrew Schwartz](https://twitter.com/4ndr3w6S), [Charlie Clark](https://twitter.com/exploitph), and [Jonny Johnson](https://twitter.com/jsecurity101)*

## Introduction

For the past couple of weeks it has become apparent that Kerberos Relaying has set off to be one of the hottest topics of discussion for the InfoSec community. Although this attack isn’t new and was discovered months ago by [James Forshaw](https://twitter.com/tiraniddo), it has recently taken off because a new tool called [KrbRelayUp ](https://github.com/Dec0ne/KrbRelayUp)has come to surface that takes James’ [work](https://googleprojectzero.blogspot.com/2021/10/using-kerberos-for-authentication-relay.html) and automates that process for anyone wanting to exploit this activity. This tool however doesn’t only exploit James’ work, but also work from [Elad Shamir](https://twitter.com/elad_shamir) around [S4U2Self/S4U2Proxy](https://shenaniganslabs.io/2019/01/28/Wagging-the-Dog.html), while using code from [Rubeus](https://github.com/GhostPack/Rubeus) by [Will Schroeder](https://twitter.com/harmj0y). We as a group (Andrew, Charlie, and Jonny) found this interesting as we saw many detections coming out for “Kerberos Relay” that might not actually detect “Kerberos Relay” if the action was performed by itself, but more of post-exploitation actions — say in the S4U activity.

During this blog post we will take a look into Kerberos Relay, break out the different attack paths one could take, and talk about the different defensive opportunities tied to this activity and other activities leading up to Kerberos Relay or after.

## Kerberos Relay Explained

Kerberos relaying was described in detail in [James Forshaws](https://twitter.com/tiraniddo) blog post “[Using Kerberos for Authentication Relay Attacks](https://googleprojectzero.blogspot.com/2021/10/using-kerberos-for-authentication-relay.html)”. The primary focus of Kerberos relaying is to intercept an AP-REQ and relay it to the service specified within the service principal name (SPN) used to request the service ticket (ST). The biggest discovery within James’ research is that using certain protocols a victim client can be coerced to authenticate to an attacker using Kerberos while allowing an SPN to be specified that differs from the service that the client is connecting to. This means that the client will request a ST for an SPN of the attacker’s choosing, create an AP-REQ containing that ST and send it to the attacker. The attacker can then forward this AP-REQ to the target service, disregard the resulting AP-REP (unless the attacker needs to relay this back to the client for some reason) and at this point establish an authenticated session as the victim client.

While there are other potential ways Kerberos relaying can happen, (ie. like man-in-the-middle (MITM) attacks), the primary focus of this post will be on coercing a client to authenticate to the attacker as the method of receiving the AP-REQ. The process is essentially as follows:

Attacker coerces victim client auth with target service SPN -> client requests ST to SPN specified -> client sends AP-REQ to attacker -> attacker extracts AP-REQ sends to target service -> attacker establishes session as victim client

![Figure 1](/images/defending-the-three-headed-relay/V4UB_4sTyV64iVR1.png)

There are some caveat’s to this process. The first being protections enabled on the target service. As with NTLM relaying, if the target service has signing/sealing or channel binding enforced, relaying Kerberos authentication will not work. The second caveat is the protections supported by the client. With some target protocols, if the client indicates support for certain protections, the server will enable those protections, again making Kerberos relaying not possible without some other bug in the implementation.

## Potential Attack Paths with Kerberos Relay

There are several potential attack paths that Kerberos relaying allows for. Many of these were documented by James in his initial blog post. As alluded to previously, there are 2 main considerations when discussing Kerberos relaying attack paths:

1. The protocol used to trigger the authentication from the victim client
2. The protocol used by the service the authentication is being relayed to

**Trigger Protocol**

As discussed, the main requirement for the trigger protocol is the ability for the attacker to specify an arbitrary SPN, or at least a partially attacker controlled SPN, when triggering the authentication. Protocols known to potentially have this requirement are:

- IPSec and AuthIP
- MSRPC
- DCOM
- HTTP
- LLMNR
- MDNS

**Service Protocol**

Depending on the protections enabled on the server, the following protocols are known to be target service protocols for Kerberos relaying:

- LDAP/LDAPS
- HTTP
- SMB

Potentially many combinations of these protocols could be used as attack paths for Kerberos relaying. This presents many attack paths, for instance, relaying to an LDAP server could allow for modification of LDAP objects or relaying to an AD CS HTTP web enrolment endpoint could allow for requesting an authentication certificate.

## Detecting Kerberos Relay

Before diving straight into detections, queries, and indicators of activity for these behaviors we think it is important to touch on what we are looking at for detection and why. It is fairly easy to take a tool that performs some behavior then immediately go look at the logs to see what telemetry exists. This isn’t a terrible approach, it just isn’t the only one and not the one we take.

We (Charlie, Andrew, and Jonny) like to approach this detection piece a little differently by breaking up a tool’s capability, understanding what it is trying to accomplish, understanding the technologies tied to an attack and their capabilities, and identifying what actions (if any) apply to other techniques. We then like to find the core behavior the attack is built on and identify what pieces of that action is or can be controlled by an attacker. This process helps us identify which behaviors are explicitly tied to the attack and which might relate to an action that was performed prior to the attack or after. One thing we don’t want to do is create detection explicitly tied to the tool, but to the attack. We are using the tool as a starting point of understanding the attack and the various variants an attacker may take to accomplish these actions.

That being said, every attack will have a pre, intra, and post action. These actions are extracted during the research process and help us scope what capabilities we are trying to detect. Let us explain.

In order for an attack to be run, an attacker must do ***something* **that gives them the ability to perform that action. This could be a number of things, let’s use the following as an example of pre-action activity:

- Gain access to a domain user
- Compromise/obtain a foothold on a box
- Run a LDAP query for reconnaissance
- Escalate to a local administrator/High IL

You then have the actual attack (intra-action):

- Kerberoast
- Dump LSASS
- Access Token Impersonation

Finally, the attacker is going to ***do*** something with whatever output the attack gives them — being the post-action:

- Logs on as user
- Impersonates user

Here is a visual representation of this:

![Figure 2](/images/defending-the-three-headed-relay/c_m55xLzXpuPiO7N.png)

This allows us to apply a detection layering approach when creating detections for these behaviors because there is going to be something within the pre-action that we can relate to the intra-action, and similarly the intra-action to the post-action. Due to this we can change the diagram up a little bit:

![Figure 3](/images/defending-the-three-headed-relay/53KevmqBp8Iybru8.png)

As you can probably tell by now, every post-action leads into a pre-action. It restarts the attack flow. We see this below with Kerberos Relay. One potential post-action is to perform S4U2Self/S4U2Proxy. Kerberos Relay has now become a pre-action to this activity and a post-action could be that an attacker is using that ability to login, talk to the SCM to create a service and run a process as SYSTEM.

If we just run the attack and look directly at the logs it is easy to start making assumptions. So before we run the attack we can break out what we are looking for, then go look for it. This allows us to truly understand what layer we are applying a detection, which inherently will help us understand what level of coverage we have.

We can now apply this to Kerberos Relay in the next section.

## Detection Queries

Some of the attacks within the pre/intra/post actions were applied due to how KrbRelayUp was exploiting this activity. The attacker doesn’t always have to take these exact paths and some of the specifics may change, for example — below we show a detection for the COM server initialization/TCP connection. An attacker could use a different protocol like HTTP/LDAP. Although we didn’t create queries for each one of these scenarios we wanted to share the different pre/intra/post-action detections someone could create.

**Pre-Kerberos Relay Detections:**

- Initial domain user foothold (No detection added as there are so many options)
- LDAP queries to identify potential SPNs available
- Computer account added via LDAP (Using Microsoft Defender for Endpoint DeviceEvents)

```
DeviceEvents
| where ActionType contains "LdapSearch" and (InitiatingProcessParentFileName !has ("services.exe") or InitiatingProcessAccountName !in ("local service", "system"))
| extend SearchFilter= extractjson("$.SearchFilter", AdditionalFields)
| where SearchFilter contains "sAMAccountName" and SearchFilter contains "$"
| summarize count() by Timestamp, InitiatingProcessAccountName,InitiatingProcessParentFileName, InitiatingProcessFileName, SearchFilter, InitiatingProcessCommandLine, AdditionalFields, InitiatingProcessLogonId
```

**Note:** This query was created via MDE and will look for when a computer account is created via LDAP, for this attack this is totally **optional**. To perform this specific attack path, the attacker only requires the credentials of *any *computer object or a user object with an SPN. There are many other ways to potentially obtain one.

- Computer Account added via Splunk and Window Security Event ID 4741:

```
index=windows sourcetype=Security EventCode=4741 AND SAM_Account_Name = "*$"
```

Going a step further would be to correlate the 4741 with Windows Security Event ID 4673. As Andrew wrote in his [post](https://www.trustedsec.com/blog/an-attack-path-mapping-approach-to-cves-2021-42287-and-2021-42278/) the event details in 4673 contain the four (4) SPN’s that are also created when a computer account is created with certain attack tools (in their present state as of writing this post). [Kevin Robertson ](https://twitter.com/kevin_robertson)first blogged about the 4 SPN’s being generated in his post, “[MachineAccountQuota is USEFUL Sometimes: Exploiting One of Active Directory’s Oddest Settings.](https://www.netspi.com/blog/technical/network-penetration-testing/machineaccountquota-is-useful-sometimes/)” Many publicly available Open Source Tools (OSTs) incorporate the same 4 SPNs into their tooling.

```
index=windows (EventCode=4741 MSADChangedAttributes=*(*HOST/*) AND *(*RestrictedKrbHost/*) New_UAC_Value=0x80) OR (EventCode=4673 Privileges=SeMachineAccountPrivilege) 
| eventstats values(Process_Name),values(Privileges),values(EventCode) as EventCode by Logon_ID 
| search EventCode=4741
| rex field=_raw "(Message=(?<Message>[a-zA-z ].*))" 
| eval datetime=strftime(_time, "%m-%d-%Y %H:%M:%S.%Q") 
| stats count values(datetime),values(Process_Name),values(Privileges),values(EventCode),values(MSADChangedAttributes),values(Message),values(Account_Domain),values(Security_ID),values(SAM_Account_Name),values(DNS_Host_Name) by Logon_ID 
| search count >=2 
| rename values(*) as * 
| eval Effecting_Account=mvindex(Security_ID,1) 
| eval New_Computer_Account_Name=mvindex(Security_ID,0) 
| table datetime,Account_Domain,Effecting_Account,Logon_ID,New_Computer_Account_Name,DNS_Host_Name,Message,MSADChangedAttributes,Process_Name,Privileges,EventCode
```

**Intra-Kerberos Relay Detections:**

- DCOM Server connection with TCP connection to localhost (Using Splunk and Window Security Event ID 5156):

```
index=windows sourcetype=Security EventCode=5156 Direction=Inbound AND Source_Address=::1 AND Destination_Address=::1 AND Process_ID !=4 AND Protocol=6
```

**Post-Kerberos Relay Detections:**

- RBCD Exploitation (Using Splunk and Window Security Event ID 5136/4768/4769)

```
index=windows sourcetype="Security" ((EventCode=5136 AND "msDS-AllowedToActOnBehalfOfOtherIdentity") AND (Type="Value Added" OR Type="Value Deleted")) OR EventCode=4768 OR EventCode=4769 
| eval alt_type=mvindex(Type,2) 
| eval datetime=strftime(_time, "%m-%d-%Y %H:%M:%S.%Q") 
| bucket _time span=11m
| stats dc(EventCode) as eventcodes,values(EventCode),values(datetime),values(LDAP_Display_Name),values(host),values(Account_Domain),values(Client_Address),values(Service_Name),values(Service_ID),values(Ticket_Options),values(Class),values(Ticket_Encryption_Type),values(alt_type) by _time 
| rename values(*) as *
| where eventcodes >=3
| table _time,datetime,host,Account_Domain,Client_Address,Service_Name,Service_ID,Ticket_Options,Ticket_Encryption_Type,Class,LDAP_Display_Name,alt_type,EventCode,eventcodes
```

It should be noted that this detection query has limitations given its use of *bucket _time span*. We employed the use of this time feature as there was not an easy way (i.e. by Logon ID) to correlate the three events. The only common variable we discovered between these three different events observed was time, specifically all within a 15 second window. While this query worked in our lab with our specific dataset, we would like to point out that by grouping the events by time in a bucket, events can possibly occur outside the span of the bucket as we don’t know WHEN the event will take place. As such the event could occur in the middle of the bucket or it could be on the “edge.” A thank you to [Greg Rivas](https://twitter.com/_not_greg) for helping create the above SPL query.

During the writing of this post the author of KrbRelayUp added support for Shadow Credentials, which performs slightly different post-actions than we have specified above. However; it is good to note that Shadow Credentials is still a post-action potential attack that can be leveraged.

## Mitigations

1. Limit MAQ attribute and/or restrict the SeMachineAccountPrivilege to a specific group rather than Authenticated Users
2. [Extended Protection for Authentication (EPA)](https://msrc-blog.microsoft.com/2009/12/08/extended-protection-for-authentication/)/Protocol Signing/Sealing and Channel Binding
3. Disabling mDNS/LLMNR
4. Require authenticated IPsec/IKEv2
5. Disabling Disable NTLM

A thank you to James Forshaw for vocalizing some of these mitigations when introducing this [attack](https://googleprojectzero.blogspot.com/2021/10/using-kerberos-for-authentication-relay.html).

## Conclusion

During this write-up we wanted to give a brief explanation of Kerberos Relay, how this can be exploited, and the various levels of detection/prevention that could be applied. Although we didn’t go over every pre/post-exploitation scenario an attacker could take, we wanted to highlight the importance of thinking about attacks from a pre/intra/post-action perspective. This helps us identify the scope of our detections, which will then allow us to identify at what depth we are applying the detection.

We hope this was helpful and a huge thank you to James Forshaw again for his previous work on this.

## References

- [https://googleprojectzero.blogspot.com/2021/10/using-kerberos-for-authentication-relay.html](https://googleprojectzero.blogspot.com/2021/10/using-kerberos-for-authentication-relay.html)
- [https://googleprojectzero.blogspot.com/2021/10/windows-exploitation-tricks-relaying.html](https://googleprojectzero.blogspot.com/2021/10/windows-exploitation-tricks-relaying.html)
- [https://dirkjanm.io/relaying-kerberos-over-dns-with-krbrelayx-and-mitm6/](https://dirkjanm.io/relaying-kerberos-over-dns-with-krbrelayx-and-mitm6/)
- [https://github.com/Dec0ne/KrbRelayUp](https://github.com/Dec0ne/KrbRelayUp)
- [https://github.com/cube0x0/KrbRelay](https://github.com/cube0x0/KrbRelay)
