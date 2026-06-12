---
title: "You Can Run, But You Can’t Hide - Detecting Process Reimaging Behavior"
description: "Around 3 months ago, a new attack technique was introduced to the InfoSec community known as “Process Reimaging.” This technique was released by the McAfee Security team in a blog titled — “In NTDLL I Trust — Process Reimaging and Endpoint Security Solution Bypass.” A few days after this attack technique was released, a co-worker and friend of mine — Dwight Hohnstein — came out with proof of concept code demonstrating this technique, which can be found on his GitHub."
pubDate: 2019-09-16
readingTime: "9 min read"
tags: ["windows", "detection"]
slug: "detecting-process-reimaging"
order: 47
---

## **Background:**

Around 3 months ago, a new attack technique was introduced to the InfoSec community known as “Process Reimaging.” This technique was released by the McAfee Security team in a blog titled — “[In NTDLL I Trust — Process Reimaging and Endpoint Security Solution Bypass](https://securingtomorrow.mcafee.com/other-blogs/mcafee-labs/in-ntdll-i-trust-process-reimaging-and-endpoint-security-solution-bypass/).” A few days after this attack technique was released, a co-worker and friend of mine — Dwight Hohnstein — came out with proof of concept code demonstrating this technique, which can be found on his [GitHub](https://github.com/djhohnstein/ProcessReimaging). While this technique isn’t yet mapped to MITRE ATT&CK, I believe it would fall under the ***Defense Evasion** *Tactic.

Although the purpose of this blog post is to show the methodology used to build a detection for this attack, it assumes you have read the blog released by the McAfee team and have looked at Dwight’s proof of concept code. A brief high level outline of the attack is as follows:

Process Reimaging is an attack technique that leverages inconsistencies in how the Windows Operating System determines process image FILE_OBJECT locations. This means that an attacker can drop a binary on disk and hide the physical location of that file by replacing its initial execution full file path with a trusted binary. This in turn allows an adversary to bypass Windows operating system process attribute verification, hiding themselves in the context of the process image of their choosing.

There are three stages involved in this attack:

1. A binary dropped to disk — This ***assumes*** breach and that the attacker can drop a binary to disk.
2. Undetected binary loaded. This will be the original image loaded after process creation.
3. The malicious binary is “reimaged” to a known good binary they’d like to appear as. This is achievable because the Virtual Address Descriptors (VADs) don’t update when the image is renamed. Consequently, this allows the wrong process image file information to be returned when queried by applications.

This allows an adversary the opportunity to defensively evade detection efforts by analysts and incident responders. Too often organizations are not collecting the “right” data. Often, the data is unstructured, gratuitous, and lacking the substantive details required to arrive at a conclusion. Without quality data, organizations are potentially blind to techniques being ran across their environment. Moreover, by relying too heavily on the base configurations of EDR products (i.e. Windows Defender, etc.) you yield the fine-grained details of detection to a third party which may or may not use the correct function calls to detect this malicious activity (such as the case of GetMappedFileName properly detecting this reimaging). Based off of these factors, this attack allows the adversary to successfully evade detection. For further context and information on this attack, check out the ***Technical Deep Dive*** portion in the original blog post on this topic.

**Note: **[GetMappedFileName](https://docs.microsoft.com/en-us/windows/win32/api/psapi/nf-psapi-getmappedfilenamea) is an API that is used by applications to query process information. It checks whether the address requested is within a memory-mapped file in the address space of the specified process. If the address is within the memory-mapped file it will return the name of the memory-mapped file. This API requires PROCESS_QUERY_INFORMATION and PROCESS_VM_READ access rights. , any time a handle has the access rights PROCESS_QUERY_INFORMATION, it is also granted PROCESS_QUERY_LIMITED_INFORMATION. Those access rights have bitmask 0x1010. This may look familiar, as that is one of the desired access rights used by Mimikatz. Matt Graeber brought to my attention that this is the source of many false positives when trying to detect suspicious access to LSASS based on granted access.

## **Transparency:**

When this attack was released I spent a Saturday creating a hunt hypothesis, going through the behavioral aspects of the data, and finding its relationships. When reviewing Dwight’s POC I noticed Win32 API calls in the code, and from those I was positive I could correlate those API calls to specific events. because like many defenders I made assumptions regarding EDR products and their logging capabilities.

Without a known API to Event ID mapping, I started to map these calls myself. I began (and continue to work on) the Sysmon side of the mapping. This involves reverse engineering the Sysmon driver to map API calls to Event Registration Mechanisms to Event ID’s. ***Huge shoutout to Matt Graeber, for helping me in this quest and taking the time to teach me the process of reverse engineering.*** Creating this mapping was a key part of the Detection Strategy that I implemented and would not have been possible without it.

## Process Reimaging Detection:

### **Detection Methodology:**

The methodology that was used for this detection is as follows:

1. Read the technical write up of the Process Reimaging attack.
2. Read through Dwight’s POC code.
3. Gain knowledge on how the attack executes, create relationships between data and the behavior of the attack.
4. Execute the attack.
5. Apply the research knowledge with the data relationships to make a robust detection.

### Detection Walk Through

When walking through the ***Technical Deep Dive ***portion of the blog, this stood out to me:

![https://securingtomorrow.mcafee.com/other-blogs/mcafee-labs/in-ntdll-i-trust-process-reimaging-and-endpoint-security-solution-bypass/](/images/detecting-process-reimaging/KLMRKmw0muDdTk3x.png)

The picture above shows a couple of API calls that were used that particularly piqued my interest.

1. LoadLibrary
2. CreateProcess

Based on my research inside of the Sysmon Driver, both of these API calls are funneled through an event registration mechanism. This mechanism is then called upon by the Sysmon Driver using the requisite Input/Output Interface Control (IOCTL) codes to query the data. The queried data will then be pulled back into the Sysmon Binary which then produces the correlating Event ID.

For both of the API calls above their correlating processes are shown below:

![Mapping of Sysmon Event ID 1:Process Creation](/images/detecting-process-reimaging/xqzrrV077EcAOKQ9.png)

![Mapping of Sysmon Event ID 7:Image Loaded](/images/detecting-process-reimaging/TP4_U25koCPKZt0A.png)

Based off of this research and the technical deep dive section in the McAffee article, I know exactly what data will be generated when this attack is performed. Sysmon should have an Event ID 7 for each call to LoadLibrary, and an Event ID 1 for the call to CreateProcess; however, how do I turn **data **into **actionable** **data? **Data that a threat hunter can easily use and manipulate to suit their needs? To do this, we focus on Data Standardization and Data Quality.

Data Quality is derived from Data Standardization. Data Standardization is the process of transforming data into a common readable format that can then be easily analyzed. Data Quality is the process of making sure the environment is collecting the correct data, which can then be rationalized to specific attack techniques. This can be achieved by understanding the behavior of non-malicious data and creating behavioral correlations of the data provided during this attack.

For example, when a process is created the **OriginalFileName** (a relatively new addition to Sysmon) should match the **Image** section within Sysmon Event ID 1. Say you wanted to launch PowerShell, when you launch PowerShell the **OriginalFileName **will be ***Powershell.EXE*** and the **Image** will be ***C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe. ***When these two things don’t match it is possibly an indicator of malicious activity. After process reimaging, and an application calls the GetMappedFileName API to retrieve the process image file, Windows will send back the incorrect file path.

A correlation can be made between the **Image** field in Event ID 1 and the **ImageLoaded** field in Event ID 7.** **Since Event ID 1 and 7 both have the **OriginalFileName** field, an analyst can execute a JOIN on the data for both events**. **On this JOIN the results will show that the same process path of the process being created and the **Image** of the process being loaded should equal. With this correlation, one can determine that these two events are from the same activity subset.

The correlation above follows this portion of the attack:

![Function section we are basing Detection from: https://securingtomorrow.mcafee.com/other-blogs/mcafee-labs/in-ntdll-i-trust-process-reimaging-and-endpoint-security-solution-bypass/](/images/detecting-process-reimaging/Ox4P4HSQFrSQ7ODR.png)

Although a relationship can be made using Sysmon Event ID 1 and Sysmon Event ID 7, another relationship can be made based on the user mode API **NtCreateFile**. This will go through the event registration mechanism **FltRegisterFilter** which creates an Event ID 11 — File Creation in Sysmon.

This relationship can be correlated on Sysmon Event ID 1’s** Image** field, which should match Sysmon Event ID 11’s **TargetFilename**. Sysmon Event ID 1’s **ParentProcessGuid** should also match Sysmon Event ID 11’s **ProcessGuid **to ensure the events are both caused by the same process.

Now that the research is done, the hypotheses have to be tested.

### **Data Analytics:**

Below shows the command of the attack being executed. The process (phase1.exe) was created by loading a binary *(svchost.exe)*, then reimaged as *lsass.exe*.

> .\CSProcessReimagingPOC.exe C:\Windows\System32\svchost.exe C:\Windows\System32\lsass.exe

The following SparkSQL code is the analytics version of what was discussed above:

![Query ran utilizing Jupyter Notebooks and SparkSQL. Gist](/images/detecting-process-reimaging/LTNQPifYDJgm4Wug.png)

I tried to make the JOIN functions as readable to the user as possible. One thing to note is that this query is pulling from the raw data logs within Sysmon. No transformations are being performed within a SIEM pipeline.

Below is a visual representation of the joins and data correlations being done within Jupyter Notebooks utilizing SparkSQL.

This query was also checked if a file created is subsequently moved to a different directory, as well if the **OriginalFileName** of a file didn’t equal the **Image** for Sysmon Event ID 1.(e.g: created process with Image — “ApplyTrustOffline.exe” and OriginalFileName — “ApplyTrustOffline.PROGRAM”) After these checks the query will only bring back the results of the reimaging attack.

![Graphed View of JOINs in Query](/images/detecting-process-reimaging/eoilS9Tc1W7LLJlL.png)

The output of the SQL query above can be seen below. You find in the query output of data after the attack seems to have “duplicates” of the events. This isn’t the case. Each time the attack is run, there will be a Sysmon Event ID 11 — FileCreate that fires after each Sysmon Event ID 1 -Process Creation. This correlates to the behavior of the attack that was discussed above.

![Query Output](/images/detecting-process-reimaging/6YdKc4Ygl4KBrwfV.png)

The dataset and Jupyter Notebook that correlates with the following analysis is available on my [GitHub](https://github.com/jsecurity101/mordor/tree/master/small_datasets/windows/defense_evasion/process_reimaging). I encourage anyone to pull it down to analyze the data for themselves. If you don’t have a lab to test it in, one can be found here: [https://github.com/jsecurity101/mordor/tree/master/environment/shire/aws](https://github.com/jsecurity101/mordor/tree/master/environment/shire/aws).

Below breaks down the stages and the information of the dataset that was ran. This correlates with the query that was ran above:

![Figure 8](/images/detecting-process-reimaging/T3idcX7h8eOqGDD-soiokg.png)

One thing to keep in mind is when the malicious binary is reimaged to the binary of the adversaries choosing (stage 3), you will not see that “phase1.exe” was reimaged to “lsass.exe”. This is the behavior of the attack; Windows will send back the improper file object. This **doesn’t** debunk this detection. The goal is to discover the behavior of the attack, and once that is done you can either follow the **ProcessGuid** of “phase1.exe” or go to its full path to find the **Image** of the binary it was reimaged with. “Phase1.exe” will appear under the context of that reimaged binary.

![Image of the properties of phase1.exe after reimaging is executed](/images/detecting-process-reimaging/kX2RYu74P4tXuKEy.png)

## **Conclusion:**

Process Reimaging really piqued my interest as it seemed to be focused on flying under the radar to avoid detection. Each technique an attacker leverages will have data that follows the behavior of the attack. This can be leveraged, but only once we understand our data and data sources. Moving away from signature based hunts to more of the data driven hunt methodology will help with the robustness of detections.

## **Thank You:**

Huge thank you to Matt Graeber for helping me with the reverse engineering process of the Sysmon Driver. To Dwight Hohnstein, for his POC code. Lastly, to Brian Reitz for helping when SQL wasn’t behaving.

## **References/Resources:**

- [In NTDLL I Trust — Process Reimaging and Endpoint Security Solution Bypass](https://securingtomorrow.mcafee.com/other-blogs/mcafee-labs/in-ntdll-i-trust-process-reimaging-and-endpoint-security-solution-bypass/)
- [Dwight’s Process Reimaging POC](https://github.com/djhohnstein/ProcessReimaging)
- [Microsoft Docs](https://docs.microsoft.com/en-us/windows/win32/api/psapi/nf-psapi-getmappedfilenamea)
