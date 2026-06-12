---
title: "Uncovering Adversarial LDAP Tradecraft"
description: "A deep dive into adversarial LDAP tradecraft - exposing the telemetry available for LDAP activity and offering guidance on detecting malicious behavior, co-authored with the TrustedSec research team."
pubDate: 2023-12-18
readingTime: "9 min read"
tags: ["windows", "detection"]
slug: "uncovering-adversarial-ldap-tradecraft"
order: 16
---

A Write-Up by TrustedSec’s Research Lead [Carlos Perez](https://twitter.com/Carlos_Perez) and Binary Defense’s Research Lead [Jonathan Johnson](https://twitter.com/jsecurity101). Originally posted on the [Binary Defense page](https://www.binarydefense.com/resources/blog/uncovering-adversarial-ldap-tradecraft/).

## Introduction

While it is important to discover new tradecraft, it is equally important to explore well-established and widely used techniques. The Binary Defense research team collaborated with the [TrustedSec](https://trustedsec.com/research) research team to dive into adversarial Lightweight Directory Access Protocol (LDAP) tradecraft. This blog outlines the results of our research, provides a tool for exposing LDAP telemetry, and offers guidance on detecting malicious LDAP activity.

## Background

With Windows 2000, Microsoft released Active Directory (AD) which serves as a central directory to handle single sign-on for Windows domains and Group Policy as a management solution. Group Policy’s ease of use and configuration management capabilities cemented its use in all corporate environments. One of the key technologies used in AD as part of this stack is LDAP, providing the directory information to find configuration information, devices, users, and services. For over 20 years, it has served as one of the main enumeration targets in post-exploitation for attackers looking to understand their environment and to abuse it to achieve their goals.

The LDAP service in most environments runs on the domains Domain Controllers (DC). Hosts and users on those hosts leverage LDAP from the moment the machine starts, services are leveraged, and events on the moment the host shuts down by updating its information before turning off.

Before we dive in, we’d like to point out some existing great write-ups on how red teams like to use LDAP within engagements:

- [LDAP Queries for Offensive and Defensive Operations](https://www.politoinc.com/post/ldap-queries-for-offensive-and-defensive-operations) by [Erica Zelic](https://twitter.com/EricaZelic)
- [ADExplorer on Engagements](https://trustedsec.com/blog/adexplorer-on-engagements) by [Oddvar Moe](https://twitter.com/Oddvarmoe)

## Normal Behavior

Depending on the activity you have in your organization, LDAP searches can be quite normal. We have found in most cases LDAP queries will be coming from users like SYSTEM, Network Service, and Local Service. That isn’t to say that only legitimate queries come from these accounts or that malicious queries only come from non-SYSTEM accounts. An adversary could escalate to SYSTEM and query LDAP.

The purpose of the research is to identify the attacker in the early stages of enumeration right after it gains access, and it looks to understand the target network and identify attack paths to leverage.

When it comes to common LDAP queries, we found that within the test environment there were 13,963 LDAP queries within a 7-day period. Most if not all the queries related to the access of a specific service for the host or user, and the processing of Group Policy for the host. Of those LDAP queries with objectClass=* made up 12,577 of those, so roughly 90%. Keep in mind that includes all users. We mention this because below we will mention common things we have seen from adversaries and red teams but objectClass=* is a part of that because when tools like [ADExplorer](https://learn.microsoft.com/en-us/sysinternals/downloads/adexplorer) are used to get a snapshot of all of AD. In the detection section we have ways to identify this activity, so don’t worry.

## Adversarial Behavior

What we have found is that if adversaries and red teams aren’t targeting a specific container or object class (which we will discuss in a moment), they will attempt to grab everything to process outside of the target environment for speed. A good example of this is if an attacker is leveraging tools like ADExplorer from Sysinternals. When this happens the LDAP query will often contain either objectClass=* or objectGuid=*. This isn’t necessarily ideal because depending on the size of the organization this could be a lot of data to pull back and it could interrupt communications between a C2 and the workstation the agent is running on. We want to point out that this is a possibility and there is attribution between attacker behavior and those LDAP searches, but we want to focus on malicious activity that excludes those queries that we have identified.

Below we are going to give examples of some noteworthy LDAP searches that we think the consumers of this write-up should be most aware of and find interesting, but keep in mind it will be a tiny subset of the queries an attacker would run in an environment. Something that would make malicious behavior stand out even more is the volume and the variety of queries many attackers automate with existing toolsets in PowerShell and .NET.

## Kerberoasting:

We won’t go into what Kerberoasting is, but one thing to note that if an attacker doesn’t first know the service account, they want to obtain a service ticket for then they will first query AD for service accounts. Here are some examples using the [Rubeus](https://github.com/GhostPack/Rubeus)[kerberoast](https://github.com/GhostPack/Rubeus/blob/5db3150243649ed737170736767cda3e6ba9dc28/Rubeus/lib/Roast.cs#L537) flag:

*All Service Accounts:*

```scss
(&(samAccountType=805306368)(servicePrincipalName=*)(!samAccountName=krbtgt)(!(UserAccountControl:1.2.840.113556.1.4.803:=2)))
```

As you can see the LDAP query is unique and easy to spot. However, an LDAP search will not occur if the attacker targets a specific service principal name (SPN). If the adversary requests a service ticket of a specific encryption type, you can see the search change a little bit as well. The following excludes [AES](https://techcommunity.microsoft.com/t5/core-infrastructure-and-security/decrypting-the-selection-of-supported-kerberos-encryption-types/ba-p/1628797) tickets.

*Non-AES Supported Service Accounts:*

```scss
(&(samAccountType=805306368)(servicePrincipalName=*)(!samAccountName=krbtgt)(!(UserAccountControl:1.2.840.113556.1.4.803:=2))(!msds-supportedencryptiontypes:1.2.840.113556.1.4.804:=24))
```

*Only AES Supported Service Accounts:*

```scss
(&(samAccountType=805306368)(servicePrincipalName=*)(!samAccountName=krbtgt)(!(UserAccountControl:1.2.840.113556.1.4.803:=2))(msds-supportedencryptiontypes:1.2.840.113556.1.4.804:=24))
```

## Reconnaissance:

One of the most common uses of LDAP we have seen is for enumeration of various users, groups, password expiration times, etc. The following are examples. They are not meant to be pure LDAP queries someone can run but examples of what can exist within a query to obtain certain information.

*Basic Users:*

```scss
(objectCategory=Person) or (objectclass=user)
```

*Domain Administrators Group:*

```scss
(&(objectclass=group)(samaccountname=*domain admins*))
```

*Any Administrators Group:*

```scss
(&(objectclass=group)(samaccountname=*admins*))
```

*LAPS Passwords:*

```scss
(ms-MCS-AdmPwd=*)
```

*PKI Enrollment (Pulled from Certify by Lee and Will):*

```scss
(objectCategory=pKIEnrollmentService)
```

*Certification Authority:*

```scss
(objectCategory=certificationAuthority
```

There are plenty more known LDAP queries that have been known to return valuable information for adversaries, these just name a few. A more comprehensive list can be found [here](https://gist.github.com/jsecurity101/9c7e94f95b8d90f9252d64949562ba5d). The point here is to know that LDAP can and is used by attackers to get information back, as well as be used to set and modify information.

One advantage as a defender is that in a typical Windows domain environment, the type of queries performed in regular operation is standard, making it easy to develop a strategy where normal behavior is filtered out and only logs outliers. Making this an ever more precise rule set that would make it even harder for an adversary to try to blend in is to mix other metadata like process and user.

## Telemetry

When it comes to telemetry that can be used for LDAP, the real value comes from the Windows-LDAP-Client ETW provider. This provider will pick up on client activity — ie the process that made the request. This ETW provider is good but does have some limitations which we will touch on in a moment. There are a couple of vendors out there with LDAP telemetry that are using this ETW provider. Microsoft Defender for Endpoint (MDE) exposed LDAP data through the DeviceEvents:LdapSearch table. What if you hold a telemetry sensor like Sysmon? Sysmon doesn’t collect LDAP telemetry, so we wanted to create something that could work side by side with Sysmon.

## LDAPMon + Sysmon

[LDAPMon](https://github.com/jsecurity101/LDAPMon) was a tool created by Jonny Johnson that is meant to give insight into LDAP client activity. Right now, this is a research proof-of-concept that collects the Windows-LDAP-Client ETW provider and is meant to be joined with a sensor that has some type of process creation event, Sysmon for example. In the future Carlos and Jonny plan on releasing a more production-ready version with a configuration file so that people can drop on their machines and use it as a full-time collection sensor. Below are examples of activities that LDAPMon can be used to pick up activity on. All examples will have correlating queries which can be found here.

### Execute-Assembly + Rubeus

We wanted to expose this type of activity because it is common for some C2’s like Cobalt Strike to spawn a process, execute some activity, and then terminate the process. The pseudo logic behind this query is the following:

1. Process A executes LDAP query.
2. Parent Process of A has a TCP or a named pipe connection that is being called back to.

TCP:

![Figure 1](/images/uncovering-adversarial-ldap-tradecraft/wuL4SNLTA5V-P7HE.png)

Named Pipe:

![Figure 2](/images/uncovering-adversarial-ldap-tradecraft/kGDVh9vCJI7s2UFN.png)

### [InlineExecute-Assembly](https://github.com/anthemtotheego/InlineExecute-Assembly) + Rubeus

Activity, like execute-assembly, has been picked up by detections more and more over the years. To solve this issue Shawn ([@anthemtotheego](https://twitter.com/anthemtotheego)) created a way to load .NET into your current process and execute that activity. This changes the detection strategy a little bit:

1. Process A executes LDAP query.
2. Process A has a TCP (not ports 389 or 636) or a named pipe connection back to a C2.

Keep in mind, this does allow an adversary to run under the radar if you are explicitly removing a port like 636. If you’re not using LDAPS then looking for 636 connections might be valuable. We want to prevent any [logical evasion](https://medium.com/specter-ops-posts/evadere-classifications-8851a429c94b) opportunities for an attacker.

TCP:

![Figure 3](/images/uncovering-adversarial-ldap-tradecraft/z0EchH2Nct5PCnYT.png)

Named Pipe:

![Figure 4](/images/uncovering-adversarial-ldap-tradecraft/Iep0M4bIsVbvksDY.png)

### Group Membership Addition

The Windows-LDAP-Client ETW doesn’t show when a value is set through LDAP, unfortunately. However, we wanted to point out that when a value is set there is still a LDAP query made and we can pick up on that activity.

![Figure 5](/images/uncovering-adversarial-ldap-tradecraft/GpUxUJ8P8azN-IfM.png)

These are all just examples of how this data can be spotted. Ultimately when it comes to looking for LDAP activity, we recommend starting with the following:

1. Remove System, Local Service, and Network Service accounts.
2. Baseline processes that are making requests, along with what parent image they are coming from and their command-line.
3. Leverage user, process, parent process, command-line, LDAPQuery counts when performing baselining.
4. Look for outliers.
5. Check network connections coming from the process that is making the LDAP request (not port 389 or 636) or if the parent has any network connections. This will help with activity performed with Execute-Assembly or InlineExecute-Assembly.
6. Use a targeted approach to see the activity, but slowly move broader.

*Note: When it comes to baselining, be sure to not remove VSCode processes because there is an extension within VSCode called [LDAP Explorer](https://marketplace.visualstudio.com/items?itemName=fengtan.ldap-explorer) that can be used to make LDAP queries.*

When relying on LDAP telemetry it is good to note that unfortunately the LDAP client ETW provider may be patched via [EtwEventWrite](https://learn.microsoft.com/en-us/windows/win32/devnotes/etweventwrite) within ntdll.dll. This is because the DLL that holds LDAP functionality (wldap32.dll) is loaded within every process that makes a LDAP request. When the call to log the activity is made it passes that information to the [EtwEventWrite](https://learn.microsoft.com/en-us/windows/win32/devnotes/etweventwrite)function. A POC created by Jonny Johnson can be found [here](https://github.com/jsecurity101/RandomPOCs/tree/main/LDAPPatch). An alternative is to use the –etw flag within InlineExecute-Assembly, which also patches the [EtwEventWrite](https://learn.microsoft.com/en-us/windows/win32/devnotes/etweventwrite) function. A blog detailing this find will come later and some other findings will come at a later point.

## Conclusion

As we continue to identify adversarial tradecraft, it is good practice to look at techniques that although might not be the “latest and greatest” but have been functionally sound for a long time. LDAP queries are exactly that type of tradecraft. It’s reliable and few are looking for malicious usage. We wanted to expose some of this tradecraft and strategies we use to identify this activity. We hope the reader found this blog helpful and please reach out if there are any questions.

## Resources

- [https://qa.social.technet.microsoft.com/wiki/contents/articles/5392.active-directory-ldap-syntax-filters.aspx](https://qa.social.technet.microsoft.com/wiki/contents/articles/5392.active-directory-ldap-syntax-filters.aspx)
- [https://learn.microsoft.com/en-us/previous-versions/windows/desktop/ldap/lightweight-directory-access-protocol-ldap-api](https://learn.microsoft.com/en-us/previous-versions/windows/desktop/ldap/lightweight-directory-access-protocol-ldap-api)
- [https://trustedsec.com/blog/adexplorer-on-engagements](https://trustedsec.com/blog/adexplorer-on-engagements)
- [https://www.politoinc.com/post/ldap-queries-for-offensive-and-defensive-operations](https://www.politoinc.com/post/ldap-queries-for-offensive-and-defensive-operations)
