---
title: "Better know a data source: Logon sessions"
description: "A walk through Windows logon sessions - what they are, how they're tied to tokens and processes, and how defenders can use that link to tell the full story around suspicious activity."
pubDate: 2022-07-26
readingTime: "11 min read"
tags: ["windows", "detection"]
slug: "logon-sessions"
order: 30
---

> Written by Jonathan Johnson and [Brian Donohue](https://redcanary.com/authors/brian-donohue)

*Originally posted: [https://redcanary.com/blog/logon-sessions/](https://redcanary.com/blog/logon-sessions/)*

> Logon sessions can help defenders tell the whole story of everything that happens around, before, and after a suspicious process event.

Process telemetry has dominated the detection space since the invention of [**endpoint detection and response**](https://redcanary.com/solutions/endpoint-detection-and-response/) (EDR) tooling. This makes sense, as processes and related metadata are what we collect, develop detection analytics with, and use for investigation and triage.

Why is this the case, though? Well, for one, it works — much better, in fact, than the indicator-centric approach that preceded it. However, our reliance on process telemetry is also a reflection of the tools and capabilities we have available (i.e., EDR tools are really good at recording process-related information). If we want detection and response to evolve, we have to constantly ask ourselves if there are new data sources that we can operationalize to complement or even supplant the traditional process-centric approach. In this article, we’re going to explore logon session telemetry, a data source that probably won’t replace process based detection outright — but that could complement it in a major way.

In tandem with process-based detection, logon session data reveals a richer story, allowing defenders to reliably and quickly identify when multiple processes or actions relate back to the same user account. Tying suspicious processes and actions back to a user account through logon session telemetry, in turn, would allow us to analyze previous account activity and paint a fuller picture of the adversary’s chain of custody, so to speak, from the moment they logged on to the moment we caught them.

## What are logon sessions?

Anytime a user successfully logs into Windows, the authentication package (e.g., [**MSV1_0**](https://docs.microsoft.com/en-us/windows/win32/secauthn/msv1-0-authentication-package), [**Kerberos**](https://docs.microsoft.com/en-us/windows/win32/secauthn/kerberos-ssp-ap), etc.) generates a [**logon session**](https://docs.microsoft.com/en-us/windows/win32/secauthn/lsa-logon-sessions) that is passed to the [**Local Security Authority**](https://docs.microsoft.com/en-us/windows/win32/secgloss/l-gly) (LSA) (stored in the [**LSASS**](https://redcanary.com/threat-detection-report/techniques/lsass-memory/) process) along with other relevant security information about the user. The LSA then creates an access token for that user. The token includes a Locally Unique Identifier ([**LUID**](https://docs.microsoft.com/en-us/windows/win32/api/ntdef/ns-ntdef-luid)) called a LogonId. You can pull the LogonId from two different places within the TOKEN structure: `AuthenticationId` and `LogonSession.LogonId` members. Let’s take a look at this from within WinDbg, first `AuthenticationId`:

```
lkd> dt -b nt!_TOKEN ffffd6866ca2e060 AuthenticationId
   +0x018 AuthenticationId : _LUID
lkd> dt -b nt!_LUID ffffd6866ca2e060+0x018
   +0x000 LowPart          : 0x1c30b7
   +0x004 HighPart         : 0n0
```

Next, the `LogonSession.LogonId` member:

```
lkd> dt nt!_TOKEN ffffd6866ca2e060 LogonSession
   +0x0d8 LogonSession : 0xffffd686`6d90e2e0 _SEP_LOGON_SESSION_REFERENCES
lkd> dt nt!_SEP_LOGON_SESSION_REFERENCES ffffd6866ca2e060+0x0d8
   +0x000 Next             : 0xffffd686`6d90e2e0 _SEP_LOGON_SESSION_REFERENCES
   +0x008 LogonId          : _LUID
   +0x010 BuddyLogonId     : _LUID
...
lkd> dt nt!_LUID 0xffffd686`6d90e2e0+0x008
   +0x000 LowPart          : 0x1c30b7
   +0x004 HighPart         : 0n0
```

Depending on the user, there may be two logon sessions. For example, if a local administrator or a user with sensitive privileges logs in, they are assigned a logon session for their medium integrity level (IL) session and another for their high IL session. Both of these sessions are applied to a different token but are linked via the `LogonSession.BuddyLogonId` access token attribute. Let’s pull the High IL LogonId for the user that is logged in on the example above:

```
lkd> dt nt!_LUID 0xffffd686`6d90e2e0+0x010
   +0x000 LowPart          : 0x1c3091
   +0x004 HighPart         : 0n0
```

*Note: If we were looking at the token structure from the High IL token perspective, then the `BuddyLogonId` would apply to the medium IL LogonId.*

We see above that the LogonId’s come in the form of four bytes (0x1c30b7) even though the LUID structure is an eight-byte (64-bit) value. That’s because the LogonId is being pulled from the LowPart, which is four bytes (32-bits).

## Tracking logon sessions

Logon sessions stay “alive” until the user logs out, so LogonIds make it possible to follow a user’s activity from the point an alert fires all the way back to their initial login, which would allow defenders to see more of the activity undertaken by user account that eventually performed the malicious activity.

Let’s create a theoretical example for this: say user Brian Donohue is a local administrator on `rudy.seaseme.local`. When Brian successfully logs in, two logon sessions are generated for him: one for his medium IL session and one for his high IL session.

![Figure 1](/images/logon-sessions/7VebxB_OOS-Jdfff.png)

Let’s say Brian opens Notepad to write down the password he’s going to use to log into the account of another user, named Jimmy. That notepad process will run under Brian’s medium IL context. In fact, any process Brian starts will get a medium IL token/session, unless Brian specifically chooses to “run as administrator,” which would then trigger User Access Control (UAC) and take the context of high IL.

Brian then opens PowerShell and runs `runas.exe` to launch `cmd.exe` and perform some nefarious action as the user Jimmy. The activity chain will be the following:

![Figure 2](/images/logon-sessions/dtQU4QoUGbnljHDV.png)

As you can see, everything that happened is tied back to Brian’s logon session. This is important because it allows us to trace the malicious activity presumably performed by Jimmy back to Brian’s user account, whereas a purely process-based approach might lead us to believe that Jimmy’s user account was singularly responsible for the malicious activity.

You can also apply user account-related information to threads as well as processes. As we’ve discussed in a [**previous blog post**](https://redcanary.com/blog/access-tokens/), processes and threads can run under different contexts, meaning a logon session can be tied to a different thread than that of the process within which it’s contained.

It seems admittedly rare that logon session data would be the primary telemetry source for detection, but it’s often useful as a secondary telemetry source that provides additional context that analysts can use during investigation.

## An abstract example

By complementing existing collection sources with logon sessions, we can gain a deeper understanding of the telemetry we currently rely on for detection and response. In the absence of logon session telemetry, our understanding was that a process performed some (presumably malicious or suspicious) action. Let’s use processes and named pipes as an example. See the following illustration, which shows our visibility without logon session telemetry:

![Figure 3](/images/logon-sessions/S2pJWpSXFN8GFhHy.png)

With logon session data we can now start to build a fuller picture and understanding of what is actually going on. Something or someone is controlling that process before it takes that action. In this case, let’s say it’s a user account. A user account is controlling that process and initiated some function that instructed the process to create/connect to that named pipe. This is illustrated below.

![Figure 4](/images/logon-sessions/btJPHh1wH9gxxSH6.png)

Logon session telemetry presents a bigger picture, revealing multiple processes and actions that might be tied back to the same user account. Identifying that account and pulling its activity could expose other adversary behavior that we didn’t catch within the detection process.

Defenders won’t often be able to exclusively use logon session telemetry for detection — although it might provide robust detection for things like brute force password attempts, impossible travel alerting, and Explicit LogonType. However, logon session telemetry is almost always beneficial for providing context around a detection.

Leveraging this data can help expedite detection and response because analysts won’t have to guess, make assumptions about, or attempt to manually determine who initiated a malicious action. All the time that an analyst might’ve spent guessing whether or not processes and actions are related to a confirmed threat detection could now be spent on other important matters, like remediation.

Ultimately, if we can speed up triage and investigation even just a little bit, then analysts can potentially remediate incidents sooner. In other words, logon session telemetry has the potential to help us triage, investigate, and remediate more efficiently and effectively.

## A concrete example

We ran a test where we dropped a malicious agent and ran some basic actions from that agent to demonstrate how a defender might use LogonIDs to quickly gather context during an investigation.

After detecting one or more of our malicious actions, a defender can readily obtain the LogonID tagged to that detection and quickly review any other actions associated with that same logon session. Within [**Microsoft Defender for Endpoint**](https://redcanary.com/integrations/microsoft-security/), you can analyze the relevant logon session with the following Kusto query:

```
search in (DeviceProcessEvents, DeviceEvents, DeviceLogonEvents)
    LogonId == "3035479" or InitiatingProcessLogonId == "3035479"
    | extend PipeName= extractjson("$.PipeName", AdditionalFields)
    | extend ServiceName= extractjson("$.ServiceName", AdditionalFields)
    | extend ServiceType= extractjson("$.ServiceType", AdditionalFields)
| summarize by Timestamp, DeviceName, ActionType, InitiatingProcessLogonId, LogonId, FileName, ProcessCommandLine, PipeName, ServiceName, ServiceType
```

Now, as the following image shows, a defender can see all of the potentially suspicious actions our user account initiated around the time we dropped the malicious agent on the host machine.

![Figure 5](/images/logon-sessions/GndSzBngdm4Yae4_.png)

## Collecting logon session data

You can collect LogonId from event logs or tools like [**James Foreshaw’s**](https://twitter.com/tiraniddo?lang=en) [**NtObjectManager**](https://github.com/googleprojectzero/sandbox-attacksurface-analysis-tools/tree/main/NtObjectManager) and Sysinternals `logonsessions.exe`. Before moving into the event logs that provide this data, let’s take a look at the `logonsessions.exe` tool to see what type of information it provides.

```
PS C:\Users\TestUser> C:\Tools\SysinternalsSuite\logonsessions.exe
LogonSessions v1.41 - Lists logon session information
Copyright (C) 2004-2020 Mark Russinovich
Sysinternals - www.sysinternals.com
[0] Logon session 00000000:000003e7:
    User name:    WORKGROUP\DESKTOP-02SN8AH$
    Auth package: NTLM
    Logon type:   (none)
    Session:      0
    Sid:          S-1-5-18
    Logon time:   5/21/2022 4:30:44 PM
    Logon server:
    DNS Domain:
    UPN:
[1] Logon session 00000000:0000acab:
    User name:
    Auth package: NTLM
    Logon type:   (none)
    Session:      0
    Sid:          (none)
    Logon time:   5/21/2022 4:30:44 PM
    Logon server:
    DNS Domain:
    UPN:
.....
[12] Logon session 00000000:00a30110:
    User name:    DESKTOP-02SN8AH\TestUser
    Auth package: NTLM
    Logon type:   RemoteInteractive
    Session:      2
    Sid:          S-1-5-21-3038318105-1090508391-2814755547-1001
    Logon time:   5/22/2022 5:08:12 PM
    Logon server: DESKTOP-02SN8AH
    DNS Domain:
    UPN:
[13] Logon session 00000000:03d954c6:
    User name:    DESKTOP-02SN8AH\TestUser
    Auth package: NTLM
    Logon type:   Network
    Session:      0
    Sid:          S-1-5-21-3038318105-1090508391-2814755547-1001
    Logon time:   5/25/2022 5:54:34 AM
    Logon server: DESKTOP-02SN8AH
    DNS Domain:
    UPN:
[14] Logon session 00000000:04742f65:
    User name:    DESKTOP-02SN8AH\TestUser
    Auth package: NTLM
    Logon type:   Network
    Session:      0
    Sid:          S-1-5-21-3038318105-1090508391-2814755547-1001
    Logon time:   5/25/2022 12:27:07 PM
    Logon server: DESKTOP-02SN8AH
    DNS Domain:
    UPN:
```

`logonsessions.exe` is a great tool for anyone performing an investigation. This tool allows the user to obtain all the following and more:

- the LogonId, via the Logon Session field (take low part)
- the username of the user the session is tied to
- the logon type the user logged into the host with
- the Session ID
- the user’s SID

Many other events collect LogonId as well. Below are some examples from Window Security Events, Sysmon, and Microsoft Defender for Endpoint

## Window Security Events

The beauty of Window Security Events is that a large volume of their events have a LogonId tag. This makes tracking activity easier and consistent. Let’s look at a couple:

**Event ID 4624: An account successfully logged on**

![Figure 6](/images/logon-sessions/eIiS-kUwpf4QA_MX.png)

Within this event, we can see a magnitude of logon-based data that’s particularly useful for tracing a logon back to a host after we confirm malicious activity. This would provide context in instances where an adversary seems to have moved laterally onto the host, providing information like the type of authentication package they used, what box they moved from, and more.

This log indicates that the session is not tied to a High IL token, since the *Elevated Token* field is marked as No. However; further down we can also see the “Linked LogonId” tag holds the BuddyLogonId value we discussed earlier, which is holding the LogonId value of the logon session tied to a High IL token.

**Event ID 4688: A new process has been created**

![Figure 7](/images/logon-sessions/89UoAQhC54OBvbBE.png)

As seen above, the event log marks the PowerShell process creation with the LogonId of the user who created this process. The LogonId value in the above event is tied to a Medium IL token. This can be confirmed by both the LogonId value and the *Mandatory Label* value.

**Event ID 5145: A network share object was checked to see whether client can be granted desired access**

![Figure 8](/images/logon-sessions/G-fTEdKyPu9WF6Km.png)

This event is useful for many reasons, particularly its visibility into share/named pipe data. After launching [**PsExec**](https://docs.microsoft.com/en-us/sysinternals/downloads/psexec), it connects to the *IPC$* share and creates a named pipe called `PSEXECSVC`. You can see this activity in the log, in addition to a LogonId tag that we can use to tie this information together with the relevant logon event and any other process creation events that are tied to this session.

It would be prohibitively verbose to go over every event that has the LogonId tag. However, it’s worthwhile knowing that these tags are widely available and offer valuable investigatory and detective context.

## Sysmon

Many Sysmon events contain a LogonId tag as well as a value known as “LogonGUID.” The latter is a custom value created by Sysmon that’s a combination of LogonId, Logon Time, and Truncated Machine GUID. Red Canary’s Director of Threat Research [**Matt Graeber**](https://redcanary.com/authors/matt-graeber/) has done research on [**how these values are derived**](https://twitter.com/mattifestation/status/1015748125221314560?s=20&t=37yabeGn77zMRht79Lb49g). We won’t go over every event with this tag, but let’s go over a common event.

**Sysmon Event ID 1: Process Create**

![Figure 9](/images/logon-sessions/_GZwguc_ZeQlstT_.png)

This is a record of the PsExec behavior we discussed earlier. We can tell that it’s related by tying the LogonId value with the ones above: `0xB8CED1C`. We can also see the LogonGuid value, which is a useful value in Sysmon because it’s unique and never reused.

## Microsoft Defender for Endpoint (MDE)

Lastly, let’s explore the LogonID related data that MDE provides. MDE’s LogonId values are output in an integer rather than a hex format, unlike some of the events we examined earlier. This is because MDE converts this data after retrieving it.

We’re not going to show everything in MDE that includes the LogonId or `InitiatingProcessLogonId` tag, but the following table shows some of the MDE event types where session telemetry could prove particularly useful during an investigation.

![Figure 10](/images/logon-sessions/WpU5pDpoVZzKSwjGUH2kzQ.png)

## Filling in the spaces between frames

Logon session telemetry offers defenders an alternative data source to reliably tie malicious actions to user accounts. Although it won’t supplant process-based detection altogether, it’s immediately beneficial for gathering context during the triage and investigation phases of analysis. Logon session analysis can help tell the whole story of an incident, as opposed to the bits and pieces provided by a singularly process-based approach. Metaphorically, it’s like the difference between watching a film and looking at photographs.

Logon session telemetry empowers analysts to reliably and quickly associate user accounts and events in a way that would otherwise require tracking timestamps, host IDs, process IDs, and more.

Admittedly, we still have a lot to learn about this telemetry source, and we hope to eventually apply it to network events, thread activity, registry events, and more. In the meantime, we hope that defenders take logon sessions into consideration while expanding their collection sources.

## Hat tip

Last but not least, a huge thank you to [**Jared Atkinson**](https://twitter.com/jaredcatkinson) for his insight and research. As we continue to evolve, it’s important that we question our bias, and we appreciate Jared’s time and insights.
