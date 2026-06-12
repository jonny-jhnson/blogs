---
title: "Dataset Prioritization"
description: "A common issue within the investigation process is alert fatigue."
pubDate: 2021-07-20
readingTime: "9 min read"
tags: ["detection", "windows"]
slug: "dataset-prioritization"
order: 39
---

## Introduction:

A common issue within the [investigation ](https://posts.specterops.io/introducing-the-funnel-of-fidelity-b1bb59b04036)process is [alert fatigue](https://www.atlassian.com/incident-management/on-call/alert-fatigue#:~:text=Alert%20fatigue%E2%80%94also%20known%20as,the%20sheer%20number%20of%20alerts.). Alert fatigue leads to the delay of incident handling and/or alerts being lost or passed over due to the high volume of events being funneled to analysts. To combat this issue, many organizations attempt to classify events within the detection hypothesis phase (e.g. excluding “normal” activity or by looking for anomalous events) and/or combining the detection and triage phase (If **x** action occurs with **y** attribute then **alert**).

All three solutions have the same potential issue — pre-classification of the dataset leads to misclassification. When misclassification occurs, the ability to identify a true positive alert is lessened. For example, if we look for “anomalous” events we potentially miss the events of when an attacker is using “normal” administrative procedures to achieve an action. A solution to this is to classify on intent.

Due to the difficulty of this, many teams will classify the action that took place. However, focusing on intent allows us to strip away any presupposition we might have when it comes to the dataset we are investigating. A way to start classifying for intent is to separate the detection, triage, and investigation processes. I won’t go in-depth about each process as Jared Atkinson wrote this [blog](https://posts.specterops.io/introducing-the-funnel-of-fidelity-b1bb59b04036) and gave this [talk](https://www.youtube.com/watch?v=CRtmeWCbRZQ), both of which give fantastic descriptions of these processes. Nonetheless, here is a brief description:

**Detection (Manually Created, Automatically Ran):**

In this stage, the minimum necessary action a user needs to perform to achieve a behavior/technique is identified. An analytic is created to trigger this action. Once the analytic is triggered, a substructure dataset is created.

![Figure 1](/images/dataset-prioritization/DF57MXBklduEQTRl.png)

This substructure dataset doesn’t provide enough insight to properly classify using the actor’s intent. This is where additional context can become beneficial.

**Triage (Automatically Run):**

This phase intakes a substructure dataset, applies various data attributes that relate back to the action taken place (e.g. was there a remote connection that took place with the action, what is the reputation of the binary, who executes the action, IP addresses associated, command line information, direct feedback from the user regarding if they performed the action, etc).

![Figure 2](/images/dataset-prioritization/ee_zodAlUKeXGNpQ.png)

Once these contextual pieces are matched with their respective substructure dataset, a priority hierarchy is applied based on the associated attributes. The result is a compounded dataset that applies the substructure dataset with the contextual values and priority hierarchy.

![Figure 3](/images/dataset-prioritization/_jPhHOL760TgJW62.png)

This allows us to see alerts in a hierarchical way without missing out on true positive alerts that might be classified as “low” in the priority scoring.

One thing to note — the priority hierarchy **is not** the same as a severity score. Severity scores apply gravity to a certain dataset. This gravity can cause a bias towards that dataset and its attributes. This can cause dangerous pre- or misclassification situations as previously discussed.

**Investigation (Manually Performed):**

The final step we’ll cover intakes the compounded dataset and requires analysts to investigate based on a priority list. Each alert will be handled respectively, and the classification of the dataset is selected. Classification requires manual analysis as more insight can be applied to the compounded dataset.

For example say two scheduled tasks are created, triggering a substructure analytic. This action being flagged doesn’t make it inherently good or bad because the actor is just leveraging components and functionality provided by the operating system — in this case, scheduled tasks. However, the context behind what the user did with this capability can help provide insight into that user’s intent.

Let’s explore this more conceptually. One task was created locally, the other remotely. Within the compounded dataset the remote scheduled task is higher on the priority list. Does this make it more malicious? Not necessarily. We just know that based on the priority scoring associated with this behavior the remote task that was created should be looked at first. Say that the local scheduled task has an action to run an executable (e.g. an agent/implant) as SYSTEM that is providing a callback to the attacker, the remote task is running a binary that is checking to see if some software needs updating. Now can we apply a classification? If not, we are a lot closer. We wouldn’t know what the executable was doing without a manual investigation.

Depending on the analytic platform being used, it might not be able to show who the scheduled task creator is versus the user running the actual action. In this instance, investigation is again needed to pull this information.

**Note: **There have been attempts to classify events in an automated fashion, but these automated engines are still subjective and dependent on heuristics unique to the environment in which the classifier is deployed. I haven’t seen a great way to objectively create a severity scoring engine, however, Josh Prager talks about strategies [here](https://www.youtube.com/watch?v=DpE21yWBNrE).

## Practical Use Case:

Continuing with our previous example, scheduled tasks are a functionality that has been around for a while and is still widely used by attackers to perform persistence and privilege execution. The use case we’ll discuss takes advantage of implementations that leverage the **ITaskSchedulerServices** interface.

Within this post, I won’t go into substantial depth about scheduled tasks internals, but I will leave some write-ups within the **References** section that could be utilized if you wanted to get more familiar with the technique. This post will assume research has been done on this particular technique, which allows us to get into the classification.

After research has been performed its been identified that when a scheduled task is created a registry event is created within the subkey: **HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tree**.

This is what we will rely on as our substructure analytic, which outputs a dataset.

![Figure 4](/images/dataset-prioritization/BwjxQdqxZ7kafVIj.png)

The activity that triggered the substructure analytic can be seen above. There still isn’t enough context to help determine intent. This dataset can be passed over to triage to apply the context needed to gain the required insight related to the actor’s intent.

## Adding Context:

When it comes to context it is important to note that the more we can apply, the better.

Below is a compounded event without data pulled from the following attributes:

- Registry Attributes
- Network Events (Pulls server-side data from Sysmon)
- RPC events (server-side and client-side using Window Security Events and Zeek)
- Process Creation Events
- Based on the attributes applied, a priority score is set

1st half of **Compounded_df**:

![Figure 5](/images/dataset-prioritization/0_cnKoZRERnYhYxd.png)

2nd half of **Compounded_df**:

![Figure 6](/images/dataset-prioritization/V0efNwuosp-rCflS.png)

Potential issues could inhibit the ability to obtain the insight needed to attain the ideal priority list. There are different factors to keep in mind that could obstruct the desired outcome:

- Data collection
- Data standardization
- The ability of the analytic platform to add these contextual pieces back to the substructure dataset or perform flexible analytics.

If context can’t be added to the dataset due to one of the issues stated above, it doesn’t mean that the context doesn’t exist — it just might have to be manually obtained. However, the key is that we are not dropping any events due to attributes not existing within the dataset.

For example, we can see that within the event where **TargetObject **= **AdminTasks**, we can’t see a **SourceImage**, **ClientImage**, or **CommandLine **due to how the analytics were performed. That doesn’t mean these attributes don’t exist, they just need to be searched for specifically either manually or in another query within the investigation process.

These contextual attributes will affect the priority that a certain event might place within the compounded dataset.

![Figure 7](/images/dataset-prioritization/u4Kl5OYLUa7OXadc.png)

This priority scoring is heavily based upon remote connection as it relates back to the event. However, it is important to note that the priority hierarchy is inherently subjective. With every subjective resolution, there is an associated risk. The risk in this situation is that if a task is created locally with **svchost.exe **it will be lower on the priority list. There can be other processes applied to help offset that risk. In this instance, within the Investigation playbook. It is recommended that those events be reviewed before pre-classification.

**Note:** Priority scoring should change on a technique basis.

## Classifying Events:

As discussed, classification can be tricky, and when pre-maturely applied it can cause a list of issues. Within the investigation, the analyst has a priority by which they look at the passed over events, combatting potential true positive drop off. This forces thorough analysis to be performed on an event so that a proper classification can be applied.

This isn’t an investigation post, so I won’t be going over how to properly investigate an alert. However, if you are curious Chris Sanders has a great training course [here](https://chrissanders.org/training/investigationtheory/). I do, however, want to emphasize the reward that comes to obtaining this information **BEFORE **classifying the intent of action while highlighting the importance behind exhausting every means there is to apply understanding to an event. We want to look at any binaries, processes, network events, etc. that could be used to give us that understanding.

Let’s look at an example starting with the process creation event for **SVCHOST **as it relates to the registry creation event “**AdminTasks**”. After analysis, this event can be seen, indicating that **SCHTASKS **was run by Powershell:

![Figure 8](/images/dataset-prioritization/Ek6AVH3fD5QZ7vWV.png)

Seeing that the task runs at boot and is executed by SYSTEM still doesn’t provide enough context to determine if this is malicious activity, but it definitely is intriguing. Next, let’s look at files:

XML files are created to support the configuration of scheduled tasks. The following folders these files can be seen are:

- **C:\Windows\System32\Tasks**
- **C:\Windows\Tasks**
- **C:\Windows\SYSWOW64\Tasks**

We want to look at this as it will provide insight into:

- The author of the scheduled task
- The principal (the user that is running the task)
- The task frequency
- The target (i.e. the binary or script the task will execute when triggered)

The following screenshot contains an example XML configuration file that relates to **AdminTasks**:

![Figure 9](/images/dataset-prioritization/nxG-7uaZEWI3Lhyg.png)

We can identify the binary being executed with this task. After looking at the binary, we can see it is a C2 agent which is used to keep a persistence connection on the host (**Note: **this analysis isn’t going to be shown). Now that we know the intent behind this behavior, classification can now be applied to this event.

## Conclusion:

I’ve seen many environments rely too heavily on precise indicators and anomaly detections. These are easy wins and are valuable due to their low false-positive rate However, too often the coverage is stopped there. Creating a broader detection is going to fire more, meaning more events are going to be passed through the triage and investigation pipeline. This requires more work by the analysts. To reduce that workload, classification mechanisms have been put into place to attempt to drop false positive alerts. The mission of reducing false positives shouldn’t come at the risk of allowing potential true positives to slip by.

Applying these mechanisms prematurely removes the ability to obtain the proper information needed to determine the intent of the action. Applying a priority hierarchy versus a classification score within triage enables analysts to analyze each event with purpose and strategy.

References:

- [https://posts.specterops.io/abstracting-scheduled-tasks-3b6451f6a1c5](https://posts.specterops.io/abstracting-scheduled-tasks-3b6451f6a1c5)
- [https://www.ired.team/offensive-security/persistence/t1053-schtask](https://www.ired.team/offensive-security/persistence/t1053-schtask)
