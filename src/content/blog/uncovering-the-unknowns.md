---
title: "Uncovering The Unknowns"
description: "From a defensive perspective, one of the most dangerous things we apply to security is assumptions."
pubDate: 2019-10-09
readingTime: "10 min read"
tags: ["detection"]
slug: "uncovering-the-unknowns"
order: 46
---

### Mapping Windows API’s to Sysmon Events

> “There are known knowns. These are things we know that we know. There are known unknowns. That is to say, there are things that we know we don’t know. But there are also unknown unknowns. There are things we don’t know we don’t know.” — Donald Rumsfeld

## Introduction:

From a defensive perspective, one of the most dangerous things we apply to security is assumptions. Assumptions are blind spots that create uncertainty. By enumerating and eliminating as many assumptions as possible within the detection process, we limit the attack surface and areas where an adversary can evade our detection efforts. There will always be blind spots, but it is better to have ***known*** blind spots than ***unknown*** blind spots. If we are aware of our blind spots we can be more prepared and efficient within our detection efforts.

**Question:** How do we limit the amount of blind spots and assumptions?

**Answer: **Uncover the attack surfaces and understanding the attack vectors that are within an environment. Having this understanding would allow us to uncover how an attack could subvert and evade defensive or detection efforts.

## **Mapping Data Sources:**

A robust detection can only **begin **once the data sources (process monitoring, file monitoring, etc.) within a specified environment are mapped to malicious activity.

What does this mean, specifically?

**Scenario:** As a defender you want to monitor process creation within your environment to determine when an adversary might be trying to spawn a new process.

**Solution:** You start logging Window Event ID:[ 4688](https://docs.microsoft.com/en-us/windows/security/threat-protection/auditing/event-4688) -*A new process has been created, *(if you have Sysmon within your environment) Sysmon Event ID:[ 1](https://docs.microsoft.com/en-us/sysinternals/downloads/sysmon)-*Process Creation.*

As a defender you have made the correlation that by logging these events you will be able to monitor process creation events. By creating these correlations and mappings, a defender will better understand how their data maps to malicious activity and behavior during the detection process.

![Event data to malicious activity correlation](/images/uncovering-the-unknowns/iRZEC9buY24hjpXA53t7Kg.png)

**Note: **To know more about this, I encourage you to look at the [ATT&CK-Data Modeling](https://docs.google.com/spreadsheets/d/1ow7YRDEDJs67kcKMZZ66_5z1ipJry9QrsDQkjQvizJM/edit#gid=0) sheet created by [Roberto Rodriguez](https://medium.com/u/996cb7f12ac1).

So far we have successfully mapped data sources/event data to malicious behavior; however, as defenders there are still blind spots and assumptions that we make about logging efforts. While we have the correct event IDs being properly forwarded, we don’t know how these events are generated to begin with. What Windows APIs, when called, will cause Sysmon to log a particular data source? Again, it is important to understand these events are generated as it brings light how our defensive capabilities can be bypassed.

## Mapping Windows APIs to Sysmon Event IDs:

To help bring more light to this subject, I started utilizing WinDbg and IDA Pro to “reverse engineer” the Sysmon driver and service executable. I say “reverse engineer”, because I couldn’t have done this without the help of [Matt Graeber](https://medium.com/u/e8e64b89121). I cannot thank him enough for his help and work on this. Doing this project also doesn’t make me a pro at reverse engineering; I have much to learn and am still very much a beginner at this skill.

The mapping within this project is as follows:

![Mapping Flow](/images/uncovering-the-unknowns/TS2T9UXeubK62OzB5iom7Q.png)

Above shows the loose event **registration mechanism** mapping. I decided to add this into the research to give better visibility and understanding to how an adversary might tamper with Sysmon logging efforts. I won’t go into too much detail on how this is done, but it can be done by tampering with ETW providers, unloading the Sysmon driver, changing configurations, and tampering with the kernel callbacks directly. If you are interested in how these things can be done, I suggest taking a look at these very well written blogs:

- [Subverting Sysmon](https://specterops.io/assets/resources/Subverting_Sysmon.pdf) by [Matt Graeber](https://medium.com/u/e8e64b89121) and [Lee Christensen](https://medium.com/u/91b45ba406ef)
- [Evading Sysmon DNS Monitoring](https://blog.xpnsec.com/evading-sysmon-dns-monitoring/) by [Adam](https://medium.com/u/d21a8ee7af2f)
- [Shhmon — Silencing Sysmon via Driver Unload](https://posts.specterops.io/shhmon-silencing-sysmon-via-driver-unload-682b5be57650) by [Matt Hand](https://medium.com/u/43fe4a5cc44)

**Goal of this project:** Map Windows APIs to event registration mechanisms, followed by Sysmon events to help understand attack surfaces, attack vectors, and how an adversary might bypass this logging effort. This project can be found on GitHub: [Windows-API-To-Sysmon-Events](https://github.com/jsecurity101/Windows-API-To-Sysmon-Events).

![API Mapping Sheet](/images/uncovering-the-unknowns/XPbpZ5bG2Wexn2JoZvshMw.png)

**Note: **I am not the only researcher creating these correlations and mappings. [Roberto Rodriguez](https://medium.com/u/996cb7f12ac1) has created a project called [API-To-Event](https://github.com/hunters-forge/API-To-Event). Mauricio Velazco is also doing this research and gave a talk at DerbyCon:[ I Simulate, Therefore I Catch: Improving Detection Engineering with Adversary Simulation](https://www.slideshare.net/mvelazco/derbycon-2019).

With these projects, we defenders have a better understanding of our attack surfaces, attack vectors, and behavioral data. Once we understand the behavior of an attack technique, we can correlate APIs to the events we expect to see within our data.

An overview of the steps taken to properly create this mapping is as follows:

- Locate registration mechanisms (callback routines, register callbacks, filter registers, etc.) within the `Imports` section inside of IDA Pro. Locating registration mechanisms were done by researching function calls that correlate with specific data sources. For example, say we are wanting to map out the API calls that correlate with process creation events, I would look through the Sysmon drivers logic to find this function being called:

![Imports view of Event Registration Mechanism — PsSetCreateProcessNotifyRoutine](/images/uncovering-the-unknowns/baMDJ2_Kxjq9yJtEVV2sKA.png)

- Research those mechanisms to better understand them and make a logical conclusion to which events they would correlate to within Sysmon.

![PsSetCreateProcessNotifyRoutine information on Microsoft Docs](/images/uncovering-the-unknowns/p82PIByW8ZV0westqL4LpQ.png)

- Test logic by attaching a kernel debugger with WinDbg to host of choice. Set a break point on the callback function before the mechanism:

![Function before PsSetCreateProcessNotifyRoutine. Inspect this function.](/images/uncovering-the-unknowns/hHOBhcwxmgpONJ0z_OjfwQ.png)

![Break on highlighted function. This function is the one that will to PsSetCreateProcessNotifyRoutine](/images/uncovering-the-unknowns/w-dpk23LbyMo6JFLe01Srw.png)

- Once the debugger broke, obtain process object address for current process:

![Obtaining processes object address](/images/uncovering-the-unknowns/wyLEzK4e0g6VAJcY_UnbCw.png)

**Note:** Take note of the processes `CID` aka (CLIENT_ID) as it will become handy in a couple of steps below.

- Take the address displayed and switch to the processes context. Reload symbols so that the debugger will display user-mode symbols as well as kernel-mode:

![Switch to the process context and reloading user-mode symbols](/images/uncovering-the-unknowns/eRwt5UNOAGqizISlLj724Q.png)

- Review the stack callback for native Win32 API calls:

![Reviewing the stack callback](/images/uncovering-the-unknowns/EcKZ3wOlmEPJkbkVwv2T4g.png)

Above there is a lot of information. How do you filter out the Window API calls? Any call that came from one of the following API libraries:

- `nt`
- `ntdll`
- `KERNELBASE`
- `KERNEL32`

I would research and make sure the API call correlated specifically with the event that was firing.

- Correlate the `CID` from the process context with ParentProcessID of the process creation event within Sysmon:

![Correlating the CID with the ParentProcessID of the process creation event within Sysmon](/images/uncovering-the-unknowns/ibm1cZ3Ksc3r67bMwAM8qw.png)

The `CID` was **0dd0** in Hexadecimal, convert that to Decimal and it equals **3536** — The `ParentProcessID` of the process that created the process.

**Note: **Each registration mechanism had its own challenge, which altered the process above. Some mechanisms were resolved by disassembling the Sysmon service executable instead of driver and some mechanisms were discovered dynamically, ie: ObRegistersCallback.

## Nice Research, How Can I Effectively Use This?

I have already shown the methodology and research of this work in a previous blog I wrote: [You Can Run, But You Can’t Hide — Detecting Process Reimaging Behavior](https://posts.specterops.io/you-can-run-but-you-cant-hide-detecting-process-reimaging-behavior-e6bb9a10c40b). However, let’s put this research to practice once more with a quick detection on Reflective DLL Injection.

## Detection Engineering:

Process Injection is a very common known attack technique used in post-exploitation activities. For this blog I will be using an iteration of process injection known as [Reflective DLL Injection](https://ired.team/offensive-security/code-injection-process-injection/reflective-dll-injection). Keep in mind, this doesn’t account for every version of “process injection” attacks. There are many different variants — process hollowing, DLL injects, and many more. Below I go through the detection engineering process of research, data behavior correlation, and then data analytics with [Apache Spark](https://spark.apache.org/) and [Jupyter Notebooks](https://jupyter.org/) 🕺🏻. One thing to note, this was taken from a Em[pire-Psinject d](https://github.com/EmpireProject/PSInject)a[taset w](https://github.com/hunters-forge/mordor/blob/master/small_datasets/windows/defense_evasion/process_injection_T1055/empire_psinject.md)ithin the Mo[rdor Project.](https://github.com/hunters-forge/mordor)

### Let’s begin the Data Engineering process shall we:

[Reflective DLL Injection](https://ired.team/offensive-security/code-injection-process-injection/reflective-dll-injection) allows an adversary to load a DLL from memory vs. from disk. Adversaries can enumerate running processes on a system, then can execute arbitrary code by injecting a DLL into the address space of a target process. By doing so, the adversary can run their code under the context of any target process they choose. The process flow of this is as follows:

```
1. Adversary targets a process for injection.
2. Adversary calls OpenProcess to get a handle on the target process.
3. Adversary calls VirtualAllocEx to have an address space in the remote process to write the reflective DLL.
4. Adversary calls WriteProcessMemory to write the reflective DLL into the allocated memory from above.
5. Adversary calls CreateRemoteThreadEx, pointing to the region specified by VirtualAllocEx to begin execution of the reflective DLL.
```

Based off of this behavior, there are 2 APIs that correlate with 2 Sysmon events can be used for detection:

- [Sysmon Event ID 8](https://github.com/hunters-forge/OSSEM/blob/master/data_dictionaries/windows/sysmon/event-8.md) — CreateRemoteThread Detected. This event will call the event registration mechanism: `PsSetCreateThreadNotifyRoutine`, which is a kernel callback function inside of Windows. Inside of the Sysmon driver, the `CreateRemoteThreadEx` API is funneled through this event registration mechanism to create an ID of 8.

![Event ID 8 Mapping](/images/uncovering-the-unknowns/ZGyFZWG757Ozal5eGozwOA.png)

- [Sysmon Event ID 10 ](https://github.com/hunters-forge/OSSEM/blob/master/data_dictionaries/windows/sysmon/event-10.md)— Process Access. This event will call the event registration mechanism: `ObRegisterCallbacks`, which is a kernel callback function inside of Windows. Inside of the Sysmon driver, the `nt!NtOpenProcess `API is funneled through this event registration mechanism to create an ID of 10.

![Event ID 10 Mapping](/images/uncovering-the-unknowns/CRZ0Gr11eVTCzG1EyTn9_A.png)

Although there are 2 APIs that correlate with Sysmon event IDs, there are 4 Window API calls being utilized within this techniques behavior. To better understand the behavior of this malicious activity, it would be good to map out the minimal privileges an adversary needs to access a process handle, while using these APIs.

To map out the **minimal** privileges an adversary need to access process handle, I went to each APIs documentation within Microsoft and mapped out which privileges are needed to access the process handle. The following privileges are needed:

**PROCESS_CREATE_THREAD (0x0002)**

**PROCESS_QUERY_INFORMATION (0x0400)**

**PROCESS_QUERY_LIMITED_INFORMATION (0x1000) — **Automatically granted if a** **handle that has the **PROCESS_QUERY_INFORMATION**

**PROCESS_VM_OPERATION (0x0008)**

**PROCESS_VM_WRITE (0x0020)**

**PROCESS_VM_READ 0x0010)**

After adding these privileges up, the minimal rights needed to access a process handle is: **(0x143A)**.

## Data Analytics:

Below I show 2 ways of querying this data through Jupyter Notebooks. The first way is after the data has been transformed within the HELK stack. The query is pulling from Elasticsearch:

```sql
ReflectiveDLL_ProcessInjection = spark.sql(
'''
SELECT 
    b.process_path,
    b.process_target_name,
    b.process_target_id,
    b.thread_new_id,
    a.process_id,
    a.process_granted_access
FROM sysmon_events b
INNER JOIN(
SELECT event_id, process_granted_access, process_guid, process_id
FROM sysmon_events 
WHERE event_id = 10
AND (process_granted_access & 5178) == 5178 -- 5178 is decimal for 0x143A. The minimal privileges you need to access process handle
) a
ON a.process_guid = b.process_guid
WHERE b.event_id = 8
'''
).show(1,False)
```

![Output of above Query](/images/uncovering-the-unknowns/jdu55y2X5BONSY0FeysH2A.png)

**Note: **Above you can see the function: ***(process_granted_access & 5178) == 5178***. **5178 **is the decimal version of **0x143A**. This was done to pull any events that have the minimal privileges needed to access a process handle within the [***process_granted_access***](https://github.com/hunters-forge/OSSEM/blob/master/data_dictionaries/windows/sysmon/event-10.md) data attribute. The data attribute ***process_granted_access*** represents **GrantedAccess** within Sysmon event ID 10 that will have a value of the rights granted to a process.

Two different notebooks will be available at: [Reflective_DLL_Injection(raw data) and Reflective_DLL_Injection(raw data) ](https://github.com/jsecurity101/mordor/blob/master/small_datasets/windows/defense_evasion/process_injection_T1055/Reflective_DLL_Notebooks/Reflective_DLL_Injection_Raw.ipynb)and [Reflective_DLL_Injection(transformed_data)](https://github.com/jsecurity101/mordor/blob/master/small_datasets/windows/defense_evasion/process_injection_T1055/Reflective_DLL_Notebooks/Reflective_DLL_Injection_Transformed.ipynb). One notebook will be pulling from the raw data within the dataset itself. The other will be pulling from the transformed data within Elasticsearch. I wanted to give both options, as it will help whoever wants it to get a better grasp on how to use Apache Spark and Jupyter Notebooks if they so choose.

## Conclusion:

Above it can be seen how useful uncovering our blindspots and mapping out our data sources can be. As attack techniques progress, we must progress with it so that we may fully understand how to detect these malicious measures. Adversary simulation will continue to learn more and use better tradecraft. In order to prepare for this, we must model our data and create data relationships to better understand data behavior. Again this project can be found on [GitHub](https://github.com/jsecurity101/Windows-API-to-Sysmon-Events/blob/master/README.md) and feedback is always welcome!

## Credit:

A big thanks and credit goes out to the following individuals for the help and insight they had on this project:

- **[Matt Graeber](https://twitter.com/mattifestation) **— Guiding me through the reverse engineering, with walking me through multiple function calls, and verifying many of these call back functions.
- [**Brian Reitz**](https://twitter.com/brian_psu) — Helping me understand function calls and interprocess communication.
- **[Jared Atkinson](https://twitter.com/jaredcatkinson) **— Helping me understand function calls and interprocess communication. Along with helping with the decimal conversion in the query above and minimal viable access rights.

## Resources:

- Microsoft Documentation and various function calls and API’s.
- [Subverting Sysmon](https://specterops.io/assets/resources/Subverting_Sysmon.pdf) by [Matt Graeber](https://medium.com/u/e8e64b89121) and [Lee Christensen](https://medium.com/u/91b45ba406ef)
- [Evading Sysmon DNS Monitoring](https://blog.xpnsec.com/evading-sysmon-dns-monitoring/) by [Adam](https://medium.com/u/d21a8ee7af2f)
- [Shhmon — Silencing Sysmon via Driver Unload](https://posts.specterops.io/shhmon-silencing-sysmon-via-driver-unload-682b5be57650) by [Matt Hand](https://medium.com/u/43fe4a5cc44)
- [Psinject dataset within Mordor](https://github.com/hunters-forge/mordor/blob/master/small_datasets/windows/defense_evasion/process_injection_T1055/empire_psinject.md)
- [OSSEM Sysmon](https://github.com/hunters-forge/OSSEM/tree/master/data_dictionaries/windows/sysmon)
- [Reflective DLL Injection](https://ired.team/offensive-security/code-injection-process-injection/reflective-dll-injection)
- [Roberto Rodriguez’s API Research](https://docs.google.com/spreadsheets/d/1Y3MHsgDWj_xH4qrqIMs4kYJq1FSuqv4LqIrcX24L10A/edit#gid=0)
- [Mauricio Velazco’s API Research](https://www.slideshare.net/mvelazco/derbycon-2019)
- [Dwight Hohnstein](https://medium.com/u/3569e97b827d) and [Lee Christensen](https://medium.com/u/91b45ba406ef) for the process injection knowledge bombs 💣.
