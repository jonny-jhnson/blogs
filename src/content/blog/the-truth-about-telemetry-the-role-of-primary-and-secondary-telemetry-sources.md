---
title: "The Truth About Telemetry: The Role of Primary and Secondary Telemetry Sources"
description: "Detection Engineers, Threat Hunters, and SOC Analysts all rely on one critical thing to do their jobs effectively — telemetry."
pubDate: 2025-03-17
readingTime: "7 min read"
tags: ["detection", "windows"]
slug: "the-truth-about-telemetry-the-role-of-primary-and-secondary-telemetry-sources"
order: 8
---

Detection Engineers, Threat Hunters, and SOC Analysts all rely on one critical thing to do their jobs effectively — telemetry. However, while they all need telemetry, they may require different types of data or use the same data for different purposes. This demand drives EDR products to collect and provide diverse telemetry sources, often striving for a balance that serves all these functions — a “happy middle ground,” so to speak.

But not all telemetry is created equal. Some data points serve as foundational pillars for detections, while others enrich, contextualize, and refine findings. This distinction leads us to categorize telemetry into primary and secondary telemetry sources.

Understanding this classification is essential for optimizing detection engineering, investigation workflows, and even performance tuning within security tooling. In this blog, we’ll break down the concept and explore how different telemetry sources fit into the framework of primary and secondary telemetry.

Before diving deeper, I’d like to define what I mean by a “telemetry source.” Many are familiar with the term data source, which typically refers to a data-generating sensor such as Sysmon or Microsoft Defender for Endpoint.

- An event category represents the type of event being collected — e.g., registry events.
- An event subcategory describes the specific action within that category — e.g., registry key creation.
- The event itself is the structured data generated from the source, category, and subcategory.

In this blog, I’ll be using the term “telemetry source” to refer to the combination of a data source, an event category, and an event subcategory. This nuance is important because within detection engineering one might say “I want registry events”, but what they are meaning is — “I want my sensor to collect registry key creation events so that I can see x activity”. So there needs to be a term that combines the true ask.

![Figure 1](/images/the-truth-about-telemetry-the-role-of-primary-and-secondary-telemetry-sources/iBnuHwqgCNIZAJFV.png)

## What Are Primary and Secondary telemetry sources?

## Primary telemetry sources: The Anchors of Detection

A **primary telemetry source** is a telemetry point that serves as the direct trigger or anchor for a detection. These are the data points that, by themselves, can indicate a security-relevant event worthy of investigation. They form the backbone of security alerts and rules.

**Characteristics of primary telemetry sources:**

- They contain actionable and definitive indicators of activity.
- They can serve as the **main detection mechanism** (e.g., “if X occurs, generate an alert”).
- They often correlate directly with attacker tactics, techniques, and procedures (TTPs).

**Examples of primary telemetry sources:**

- **Process creation events:** Detecting malicious process execution (e.g., `cmd.exe /c whoami` spawned by an external binary).
- **File events:** Monitoring for specific files to be created or files to be modified (ransomware canaries)

## Secondary telemetry sources: Context and Enrichment

A **secondary telemetry source** is a supporting telemetry point that enhances, enriches, or validates a primary telemetry source. While secondary sources alone may not be strong enough to justify an alert, they provide the necessary **context** to improve detection fidelity and investigation accuracy. Essentially secondary telemetry sources can help “complete” the story.

**Characteristics of secondary telemetry sources:**

- They provide additional details to strengthen or weaken a hypothesis.
- They help reduce false positives and improve detection accuracy.
- They enhance triage and response by offering **contextual breadcrumbs**.

**Examples of secondary telemetry sources:**

- **Parent-child process relationships:** While a process creation event is primary, knowing *which* process spawned it (e.g., powershell.exe spawned from winword.exe) gives additional context.
- **Command-line arguments:** Has been used for precise alerting and they provide crucial evidence in combination with process execution.

## When Is a telemetry source Both Primary and Secondary?

Some telemetry sources can play both roles, depending on how they are used. Take **process creation events** as an example:

- As a **primary source**, it serves as the anchor of a detection:
- **Example:** Process creation alert when cmd.exe launches with a suspicious script execution flag (/c).
- As a **secondary source**, it provides context to another detection:
- **Example:** A file write event is detected on C:\Windows\System32\drivers\etc\hosts, and process creation logs show that the modification was made by powershell.exe — a strong indicator of malicious intent.

Another example is **named pipes**:

- **Primary:** Seeing a svchost.exe process launch a well-known default named pipe
- **Secondary:** When investigating a suspicious process, you see that it is leveraging a weird looking named pipe that isn’t tied to any legitimate services running.

There is also the ability to use the same source multiple times to turn it into a primary source or an anchor (more on this below). An example of this could be logon events. See 1 logon event might not be sufficient enough to identify if malicious behavior has occurred, but what if you use logon events multiple times on top of each other? We see this a lot with brute force detections where one looks for 4–5 failed logon events over a certain amount of time and then a successful logon. Keep in mind though, these use cases are usually pretty limited.

## Why Does This Matter?

## Product Requests: Prioritizing the Right Telemetry

Understanding the distinction between primary and secondary telemetry sources helps drive informed product requests for telemetry. The most valuable telemetry sources are those that can serve as both primary and secondary sources, offering flexibility in detection and investigation. On the other hand, purely secondary sources tend to be less valuable on their own due to their contextual limitations.

A good example of this, although this could be a controversial opinion, would be an endpoint network event. Say something like a Sysmon Event ID 3. Sure, you could create a detection looking for unusual processes talking to DC over the kerberos port (88) to help see some kerberos based attacks like kerberoasting. However, in large organizations that could be a lot of false positives and be quite a noisy detection. In my opinion, this would better serve as a secondary source to join on with other events like 4768/4769’s. A good example is from a blog I wrote with Charlie Clark and Andrew Schwartz — [The Client/Server Relationship — A Match Made In Heaven](https://jsecurity101.medium.com/the-client-server-relationship-a-match-made-in-heaven-219fe934a51b). I think it is easy for there to be a misunderstanding of these events, just because some telemetry *could* be a primary source doesn’t mean it *should** ***be.

It’s easy for Detection and Response teams to say, “We need X telemetry source because it will help us in all these ways!” — only to realize later that, in practice, the data is too limited to be actionable. By recognizing whether a telemetry source can function as an anchor (primary) or just as context (secondary), teams can make better-informed decisions about what telemetry is truly essential.

## Detection Creation: Every Detection Needs an Anchor

Every detection must have a clear anchor — a primary telemetry source that concisely indicates what action occurred. This could be:

- A process was created
- A file was deleted
- A registry value was modified

However, primary sources alone are often not enough to classify behavior as malicious. This is where secondary telemetry sources come into play, adding the necessary context to strengthen detections:

- **Primary:** powershell.exe was executed

Secondary: It was launched with an encoded command

- **Primary:** A file was created
- Secondary: The filename contained the .ransom extension
- **Primary:** A registry value was modified
- Secondary: The modification was made by an unusual user account

As you move further right on the [detection spectrum](https://posts.specterops.io/detection-spectrum-198a0bfb9302#:~:text=Instead%20of%20using%20loaded%20terms%20like%20brittle%2C%20simple%2C,%E2%80%9Cprecise%E2%80%9D%20logic%20while%20the%20other%20represents%20%E2%80%9Cbroad%E2%80%9D%20logic.), layering multiple secondary telemetry sources becomes more common. This layered approach reduces false positives, improves fidelity, and enhances investigative workflows. More on this in a following blog post.

## SOC Triage: Applying the Primary-Secondary Model

While this blog has primarily discussed primary and secondary sources within detection engineering, the same concept is equally critical in SOC triage.

In playbook-driven workflows, most of the data obtained after an alert fires falls into the category of secondary telemetry sources — because they add context rather than directly triggering detections.

A great example of this is a [triage notebook](https://github.com/jsecurity101/Automated-Detection-Pipeline/blob/master/SourceCode/Notebooks/Service%20Creation%20(T1543.003)/Service_Creation_Triage.ipynb) I built a while back. It takes detection data and layers additional secondary sources on top, helping analysts make faster, more informed decisions about alert classification. Below is an image example of what the triage notebook is trying to achieve, more could be added for even more context.

![Figure 2](/images/the-truth-about-telemetry-the-role-of-primary-and-secondary-telemetry-sources/zrpStViS09pwtZ2S.png)

## Making Telemetry Work for You

Understanding the difference between primary and secondary telemetry sources isn’t just a theoretical exercise — it’s a practical framework that enhances detection efficacy, investigation workflows, and security operations. Primary telemetry sources act as the anchors for detection, while secondary telemetry sources provide the necessary context to reduce false positives, strengthen findings, and support investigative decisions.

For detection engineers, this distinction helps in designing high-fidelity detections that trigger on strong, actionable signals while leveraging secondary sources to refine accuracy. Threat hunters can pivot off primary events and use secondary data to complete the attack narrative. SOC analysts can optimize their triage and response playbooks by layering contextual sources, ensuring that alerts are enriched and actionable rather than just noisy signals.

The next time you’re working on a detection rule, crafting a playbook, or evaluating new telemetry sources, ask yourself: Is this telemetry source a primary signal of malicious activity, or is it an enrichment layer that adds clarity? I think so many of us do this subconsciously already, but being clear with this intent helps drive very educated decisions within our planning in product, detections, and triage workflows.

## Acknowledgements

I think it is important when coming up with new ideas/ways to explain known ideas to reach out to leaders in the industry on that topic. That being said, I want to say thank you to the following people who read and provided feedback on this topic:

- [Andrew Schwartz](https://x.com/4ndr3w6S)
- [Justin Ibarra](https://x.com/br0k3ns0und)
- [Jared Atkinson](https://x.com/jaredcatkinson)
- [Olaf Hartong](https://x.com/olafhartong)
