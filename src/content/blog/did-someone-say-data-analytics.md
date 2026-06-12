---
title: "Did Someone Say Data Analytics?"
description: "One thing that the SpecterOps defensive team likes to pride ourselves in, is our ability to manipulate data in a way to best help our client’s needs."
pubDate: 2020-04-28
readingTime: "6 min read"
tags: ["detection"]
slug: "did-someone-say-data-analytics"
order: 44
---

### Integrating Jupyter Notebooks with Splunk Enterprise

## Introduction

One thing that the SpecterOps defensive team likes to pride ourselves in, is our ability to manipulate data in a way to best help our client’s needs. This may be in the pursuit to create a detection for a client or doing a compromise assessment. Either way, we like to take the data that is given to us and find the best way to use it for the specific situation at hand. The majority of our clients use Splunk. Splunk is a great tool and allows for good initial analysis of data. However, some desired data manipulations might not be straight forward, such as JOIN functions or bitwise operations. There are “ways” to accomplish these goals, but they aren’t as easy as they could be through another analytics platform. This is where [Jupyter Notebooks](https://jupyter.org/) come in.

## Integration

One of the most common integrations we have seen is where you have Notebooks pulling straight from a data lake (Elasticsearch, S3, etc), this is how Roberto Rodriguez is doing this within his **[HELK](https://github.com/Cyb3rWard0g/HELK) **project. You can also feed a Notebook a JSON file, parse the data, and perform analytics that way. These aren’t the only ways, however.

With the two examples above, there are three conflicts that could occur in terms of detection:

1. Reading from a JSON blob might be good for studying and understanding a specific dataset or good for post-detection and investigation analytics, not so good for actual alerting.
2. Analysts might prefer Splunk’s query language: [**SPL**](https://docs.splunk.com/Splexicon:SPL) (Search Processing Language).
3. Within your environment you don’t want to have your two analytic platforms (Splunk and Notebooks) work independently, you would like for there to be an option to utilize them simultaneously.

Luckily Splunk has the ability to use their **REST API** and** SDK’s** to perform searches and return their results. Essentially, we can utilize these components to have Jupyter Notebooks to pull data from Splunk Enterprise and perform some advanced analytics!

**[Splunk REST APIs](https://docs.splunk.com/Documentation/Splunk/8.0.3/RESTREF/RESTprolog) **— runs the actual search.

**[Splunk SDKs](https://dev.splunk.com/enterprise/docs/welcome/) **— a layer built on top of the REST API’s that will handle authentication to Splunk Enterprise, provides “result readers” that will parse the REST API results as they come back in a raw format.

![Integration Diagram. Picture from: https://dev.splunk.com/enterprise/docs/welcome/](/images/did-someone-say-data-analytics/yfPHz7b9vBZO-Ka0.png)

Splunk has some great documentation on these various components on their **[developer documentation pages](https://dev.splunk.com/enterprise/docs/welcome/).**

## Notebook Integration Example

The analytics of this Notebook is focused on data pertaining to an attack sub-technique known as [**Dumping LSASS**](https://attack.mitre.org/beta/techniques/T1003/001/).

**An Offensive TL;DR:**

- LSASS — Subsystem service process for LSA (Local Security Authority). This process responsible for enforcing the security policies on the system.
- Stores credentials in memory on behalf of users with interactive/remote interactive logon sessions.
- **Adversaries may attempt to dump the memory information of the LSASS process to acquire plaintext credentials.**

**A Defensive TL;DR:**

- 3 Primary APIs attackers use to dump credentials from LSASS ([**MiniDumpWriteDump**](https://docs.microsoft.com/en-us/windows/win32/api/minidumpapiset/nf-minidumpapiset-minidumpwritedump), [**ReadProcessMemory**](https://docs.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-readprocessmemory), [**PssCaptureSnapshot**](https://docs.microsoft.com/en-us/windows/win32/api/processsnapshot/nf-processsnapshot-psscapturesnapshot))
- OpenProcess is called to obtain a handle to the lsass.exe process. We can use this to narrow in on GrantedAccess rights.
- Some versions of this attack will leave a file on disk.

In this Notebook, I will be focusing on when an attacker uses **[MiniDumpWriteDump](https://docs.microsoft.com/en-us/windows/win32/api/minidumpapiset/nf-minidumpapiset-minidumpwritedump) **(this will leave a file on disk) and pivot on its minimum access right through GrantedAccess (0x1410).

The first thing we will need to do is install the proper libraries to get Jupyter to communicate with Splunk Enterprise:

![List of libraries needed to connect to Splunk Enterprise](/images/did-someone-say-data-analytics/fqW5F_gX9qGdfwCt.png)

Using Splunk’s SDK we will create a service to connect to Splunk Enterprise:

![The function needed to connect to Splunk Enterprise](/images/did-someone-say-data-analytics/fRZGREJbdQJ6SvuR.png)

Next, we will run our Splunk queries, pull back their results and store them within a Pandas Dataframe:

![Running query jobs and returning their results](/images/did-someone-say-data-analytics/AHe8Wqmduz6ERlFG.png)

The Splunk SDK will speak to Splunk’s REST API and have it run the search specified, then the SDK will handle the return of this data. The REST API can bring back data in a CSV, JSON, or XML; however, it is in a raw format. The SDK supplies a result reader that helps Python interpret this data. Lastly, we are converting these results into a [**Pandas Dataframe**](https://pandas.pydata.org/pandas-docs/stable/getting_started/dsintro.html). This allows me to have a two-dimensional data structure of these events, which makes later extraction of these attributes easier.

As you can see I am running two different queries. One to pull data from Sysmon Event ID 11: File Creation, the next Event ID 10: Process Access. As we go through the rest of this Notebook, it would be good to note that I am doing manipulation on each dataset separately before doing the JOIN in the last section.

Next, I will have to take the ***“Message”*** of these events and pull them out. Splunk holds full event data within the ***“Message”*** section. If we don’t pull this out we won’t be able to get proper data context and visibility. Then I am going to remove any ***\n***’s within the data.

![Extracting the Message piece of the data and removing \n’s](/images/did-someone-say-data-analytics/wGKHsCx1ruFVBCzD.png)

After doing this the data will be stored as a “pandas series” which is a one-dimensional array. It will look like the following:

![View of what a Pandas Series looks like](/images/did-someone-say-data-analytics/FBPN0apNUof26P9p.png)

I want to transform this data from one-dimensional pandas series to a two-dimensional multi-indexed dataframe** **while keeping my data with its respective key. This allows me to have column names line up with each row value, without repeating column names. To accomplish this I want to split these characters and split the data to get it to look like this:

![Ideal format of data](/images/did-someone-say-data-analytics/WdzP_WamZdYUr5yt.png)

In order to do this, I need to split on the **“:”** characters and format the data to a list and then back to a DataFrame. If I don’t perform the split on this data, the data will still hold the one-dimensional format of the pandas series. One-dimensional structures won’t allow SQL to read the data properly. I want to be able to align the column labels with their respective values.

![Pulling data from list to an array to stip out “:” between columns and data](/images/did-someone-say-data-analytics/W1wBxVqqft-psS7r.png)

The data is now in a format where I can apply SQL to perform my JOIN functions. However, GrantedAccess within Splunk is stored in hex. To perform a bitwise operation with it, I have to transform it from hex to integer. The following will convert the data that correlates with GrantedAccess from hex to integer:

![Converting GrantedAccess from hex to integer](/images/did-someone-say-data-analytics/l0LBPJm-8FaojeNo.png)

Lastly, I will use SQL to perform a JOIN on Sysmon’s File Creation Event’s (Event ID 11) ProcessGuid and Sysmon’s Process Accessed Event’s (Event ID 10) SourceProcessGuid. After the JOIN is complete, I am going to see if the File Creation event created a file on disk. I am also going to perform a bitwise operation and look for any processes accessing lsass.exe with the minimum rights of 0x1410 (5136 in integer). These are the minimum access rights an attacker needs to utilize [**MiniDumpWriteDump**](https://docs.microsoft.com/en-us/windows/win32/api/minidumpapiset/nf-minidumpapiset-minidumpwritedump) to dump lsass.exe.

![Utilizing SQL to perform a JOIN function and bitwise operations on our data](/images/did-someone-say-data-analytics/aDbQVMJMmpbs0LC2.png)

As you can see, we have an instance where a process ***taskmgr.exe*** accessed ***lsass.exe*** and dumped a file on disk, which contained the minimum rights needed to use [**MiniDumpWriteDump**](https://docs.microsoft.com/en-us/windows/win32/api/minidumpapiset/nf-minidumpapiset-minidumpwritedump) to perform the dump.

## Conclusion

I hope everyone enjoyed this simple walkthrough on how to integrate Jupyter Notebooks and Splunk Enterprise. This research came about because I wanted to perform the exact analytic above while having Splunk within my test environment. Having this flexibility with data allows us as defenders to perform advanced analytics, which in turn means we are not limited in our detections.

For a reference, I uploaded this Notebook to a [Github Gist](https://gist.github.com/jsecurity101/45e4e7caf9207b30626f90b7b539145a). If you are interested in building this integration easily, [Ben Shell](https://twitter.com/UsernameIsBen) and I made a [**Splunk docker script**](https://github.com/jsecurity101/Marvel-Lab/blob/master/Logging/splunk/splunk_logger.sh). Check it out:[ **here**](https://github.com/jsecurity101/Marvel-Lab/tree/master/Logging/splunk). Enjoy! More Notebooks to come!

## Resources

- [Splunk’s Developer Documentation](https://dev.splunk.com/enterprise/docs)
- [MiniDumpWriteDump](https://docs.microsoft.com/en-us/windows/win32/api/minidumpapiset/nf-minidumpapiset-minidumpwritedump)
- [Pandas documentation](https://pandas.pydata.org/pandas-docs/stable/getting_started/comparison/comparison_with_sql.html)
- [Cody Thomas ](https://twitter.com/its_a_feature_)(A Python expert)
- A LOT of Googling
- StackOverflow
