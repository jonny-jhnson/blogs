---
title: "Syncing Into the Shadows"
description: "As an adversary, one of the goals is to capture Domain Admin (DA) credentials, change/modify objects inside of Active Directory, and to be able to evade any detection systems that an environment may have in place."
pubDate: 2019-04-14
readingTime: "12 min read"
tags: ["detection"]
slug: "syncing-into-the-shadows"
order: 49
---

## Introduction:

As an adversary, one of the goals is to capture Domain Admin (DA) credentials, change/modify objects inside of Active Directory, and to be able to evade any detection systems that an environment may have in place.

One way you can capture DA credentials is through an attack technique called “DCSync”. DCSync is an attack technique that many security professionals, like [**Sean Metcalf**](https://adsecurity.org/?p=1729) and [**Will Schroeder**](http://www.harmj0y.net/blog/redteaming/mimikatz-and-dcsync-and-extrasids-oh-my/) have talked about. Once an adversary has DA privileges, they can then perform a defensive evasion technique attack, by injecting objects into the Active Directory Infrastructure. This attack technique is called “DCShadow”. There is a great presentation on DCShadow that was done by [**Benjamin Delpy and Vincent Le Toux**](https://www.dcshadow.com/) which I highly suggest going to, to read and watch.

DCSync and DCShadow sound very similar and could be confusing to understand the differences if not explained. I am going to talk about the differences in DCSync and DCShadow when it comes to their functionality as an attack technique, along with differences when it comes to Indicators of Compromise (IOC) and hunting/detecting these two techniques.

When running these two attacks I wanted to have some fun with it, as I am a big Marvel fan, let me know if you catch any of the references and WHY some of the users were used. I will explain at the end ☺

## Background:

To start taking a look at these two attacks in a Tactics, Technique, and Procedure (TTP) standpoint, can help give a baseline at the differences in these two attack and what they are used for. This is from the [**Mitre Att&ck Framework**](https://attack.mitre.org/):

![TTP’s for DCSync and DCShadow](/images/syncing-into-the-shadows/mOXPnKgaLl0ei_Qb6Z_tgw.png)

**DCSync:**

DCSync has been around for a while and is used quite often. This technique is used to retrieve and dump credentials of a specified account. In order to do this, the user you are using to ‘sync’ to the Domain Controller (DC), must have the following extended rights:

· [**DS-Replication-Get-Changes-All**](https://docs.microsoft.com/en-us/windows/win32/adschema/r-ds-replication-get-changes-all) (GUID — 1131f6ad-9c07–11d1-f79f-00c04fc2dcd2)
· [**DS-Replication-Get-Changes**](https://docs.microsoft.com/en-us/windows/win32/adschema/r-ds-replication-get-changes) (GUID — 1131f6aa-9c07–11d1-f79f-00c04fc2dcd2)

Which by default is given to these high privileged groups: Domain Admins, Enterprise Admins, and Domain Controller computer account. This is done by impersonating the Domain Controller, while doing so it requests user account credentials from the targeted DC. This example is demonstrated in the “On to the Attack” section.

**DCShadow:**

DCShadow is used for Defense Evasion by modifying/pushing object changes inside of the Active Directory (AD) Infrastructure. For example, say you have Domain Admin (DA) credentials and want to avoid being caught in an environment, you can push a user into the Domain Administrators group, then use that user account to move around in the environment/modify other objects and attributes in the AD infrastructure. How is this done?

***Non-Technical Overview:*** This is done by registering the host machine you are on as a (rogue) Domain Controller, creating/modifying objects then pushing them out to the legitimate Domain Controller in the environment.

***Technical Overview:*** Inside of each Domain Controller, there is a built-in process called the knowledge consistency checker [**(KCC)**.](https://docs.microsoft.com/en-us/windows-server/identity/ad-ds/get-started/replication/active-directory-replication-concepts) This handles the replication topology for the Active Directory forest. Also, inside of the Domain Controller is a Directory System Agent (DSA) called Ntdsa.dll, that runs. This is to provide access to the directory database inside of Active Directory (AD). Within the DSA is a forest-wide object [**(nTDSDSA)**](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-srpl/4c62c74a-b55c-47d1-b575-33395a727d97) that represents the DSA on the Domain Controller. DCShadow allows the adversary to create a new nTDSDSA object in the rogue Domain Controller and replicate that change to the legitimate Domain Controller because of the KCC.

**Note** In order to successfully complete this attack you MUST already have Domain Admin or Enterprise Admin privileges.

## Onto the Attack:

**DCSync:**

![For Video: https://jsecurity101.tinytake.com/sf/MzQ1NjQzNV8xMDM1NTA1Mg](/images/syncing-into-the-shadows/Icen2GYXvhyUz7Av.PNG)

Let’s take a closer look and talk about what is going on during the DCSync attack and go over why I demonstrated the DCSync first along with the privileges used to perform this attack:

An adversary has enumerated the user: ironman@windomain.local, which is in the Administrators Group, what does this mean? This user has full control over the Domain Controller(s) in this domain. BUT we want Domain Admin (DA) so the adversary can have control over the whole domain.

A next step might be to check to see who is in the DA group, so we can target said user. To check this, the command ran was:

- **net groups “domain admins” /domain**

See that “vision” is a user in the DA group. This could be a good target. To grap the user’s ntlm hash, this command can be ran inside of [**Mimikatz**](https://github.com/gentilkiwi/mimikatz):

***Open Mimikatz Console***

- **lsadump::dcsync /domain:windomain.local /user:vision**

Users ntlm hash:

- **ac8e786b4305cf56937c8a08b175ed6b**

After cracking this, Vision’s password is **LastStone1!** (hint hint)

Now that DA credentials have been captured and since the adversary knows that DCSync can be detected, why not evade detection and inject another user into the DA Group?

**DCShadow:**

![For Video: https://jsecurity101.tinytake.com/sf/MzQ2NDUzOF8xMDM4MzU3MQ](/images/syncing-into-the-shadows/iGEd0jpujIioIQzO.PNG)

As shown in the video, the user logged in is: vision@windomain.local (member of the Domain Administrator’s Group). The adversary wants to evade any detection or hunting that is currently being done due to logs that have propagated (which I show below). Great way to do so is to inject a user into the DA Group, then use that user. Say there was a user in the domain named: thanos@windomain.local Sounds like a perfect fit, since historically Vision practically gave Thanos the last infinity stone, making him all powerful.

I want to point out, that in this attack we are modifying two things. Firstly, the computers (win10.windomain.local) attribute to classify as a Global Catalog (GC- a role given to one or more Domain Controllers in the environment so that it can store data about every object in the forest). This allows the computer to be a rogue Domain Controller and push out modifications to objects to the legitimate Domain Controller. Secondly, we are modifying Thanos’ privileges to give him DA rights.

How do can this be done? By running these commands inside of [Mimikatz](https://github.com/gentilkiwi/mimikatz):

***Open Mimikatz Console***

- **!+** (Registers and starts a service with SYSTEM level privileges)
- **!processtoken** (Gives the System Token to Mimikatz so it has the appropriate privileges to run the following commands)
- **lsadump::dcshadow /object:thanos /attribute:primaryGroupID /value:512** (This will will use the Security Identifier (512) of the DA Group to inject thanos into the DA Group.

***Open a second Mimikatz Console***

- **lsadump::dcshadow /push** (Pushes the changes we made with the rogue Domain Controller (us) to the actual Domain Controller).

Thanos has now been injected into the DA Group, this can be verified by:

- **net group “domain admins” /domain**

![Figure 4](/images/syncing-into-the-shadows/N-_3UXM-sFnldb6a.gif)

**Note** You could have two separate Mimikatz Consoles opened at the same time to run this attack. Commands are the same, but before the *lsadump::dcshadow /push *you would need to run *privilege::debug *to give the subprocess SYSTEM level privileges.

## Onto the Hunt (the best part):

***DCSync:***

In order to hunt, creating a hypothesis is key. This will help prevent analysis paralysis — Over analyzing an abundance of logs.

During this hunt, I will show how the indicator of compromises (IOC’s) for DCSync, will help us discover and hunt the defense evasion of DCShadow. Keep in mind the IOC’s for DCShadow will stay the same regardless if the adversary did attempt a DCSync beforehand or if they used a different type of technique to collect a DA’s credentials.

To put this into perspective, say we are a Detection/Hunt Team and we got this alert from Microsoft ATA:

![Figure 5](/images/syncing-into-the-shadows/AMsrsZ_ujAmaa_BB.png)

Then upon further analysis we come across this:

![Figure 6](/images/syncing-into-the-shadows/No5g_xSPaEJoh_42.png)

Here we see a Directory Service Replication attempted and succeeded with a user in our environment (Tony Stark: ironman@windomain.local). Let’s discuss WHY this is a red flag. Replication should only be done between registered Domain Controllers through the KCC. After understanding this there shouldn’t be a reason an account (with Administrator privileges or any account) should be doing a replication on directory services from win10.windomain.local, which is not a registered Domain Controller in our forest. Keep in mind this is before we implemented win10 as a rogue Domain Controller. This screams “Credentials Stolen” to me.

After seeing that the replication happened to dc.windomain.local, we go to investigate logs. What are we looking for? There are going to be a lot of logs that will be propagated so we want a hunt hypothesis or a game plan before investigating.

After googling the alert from Microsoft ATA, we get this — “In this detection, an alert is triggered when a replication request is initiated from a computer that is not a Domain Controller.” We know that the replication happened from the win10.windomain.local (not a Domain Controller) and with user account ironman@windomain.local(Administrator privileges).

Inside of dc@windomain.local we see this log:

**Event 4662:** An object was performed on an object.

![Figure 7](/images/syncing-into-the-shadows/yP0aBA-c39iMC367.png)

This looks suspicious, after further investigation we see these properties mean:

**Properties:** Control Access:

{19195a5b-6da0–11d0-afd3–00c04fd930c9} **— Domain-DNS Class**

{1131f6ad-9c07–11d1-f79f-00c04fc2dcd2}- **DS-Replication-Get-Changes-All**

We see the replication happening here, the DS-Replication-Get-Changes-All is giving rights for replication of secret domain data. What is ironman replicating or what is he trying to accomplish. Let’s check the network logs.

***Wireshark:***

One thing to note, we are getting different directory service requests from an IP address that is NOT a Domain Controller in our environment. This shows an adversary is replicating data from their IP from our Domain Controller’s IP address.

![Figure 8](/images/syncing-into-the-shadows/FZh8PO0ljprM2DT3.png)

DCSync is easier to detect once we look at the network. You see these different directory service operations: DsGetDomainControllerInfo, DsCrackNames, DsGetNChanges. As Sean Metcalf explains in his [post](https://adsecurity.org/?p=1729), a way to detect bad activity is to configure the IDS to trigger when you DsGetNCChanges request originates from a non-Domain Controllers IP address.

Here is another an example of what dce_rpc.log in BRO will look like as well:

![Figure 9](/images/syncing-into-the-shadows/HeS3OEddd00JOby9.png)

You can see the directory service operations being done over the network here as well.

### DCSync Analytics:

Below you can find the data relationships I have discussed above in a table format for the DCSync technique.

![Figure 10](/images/syncing-into-the-shadows/fkfdjWgJgnG8JMJq-mQqSg.png)

![Figure 11](/images/syncing-into-the-shadows/QVNDgAqUvOED4RctzkQkjg.png)

***DCShadow:***

So far, we have successfully confirmed that there was a DCSync technique handled above. What did the adversary do with the information it requested from the Domain Controller? How can we successfully hunt the adversary now? We follow the same process. So far we have found tracks from the adversary, not the actual adversary yet.

For DCShadow we are going to work backwards, move from the network logs- Wireshark/Bro, then move into the Window Event ID’s.

Imagine you are still in the network and you see this from Bro:

![Figure 12](/images/syncing-into-the-shadows/7cbPrFHkRW5_ecJ-.png)

Why are we seeing DRSUpdateRefs, DRSReplicaAdd? This isn’t involved with the DCSync. This can be proven this by looking inside of Wireshark:

![Figure 13](/images/syncing-into-the-shadows/IrSj4eFiJbIDzaNJ.png)

What is different then the DCSync network log? DRS_REPLICA_ADD ,DRS_REPLICA_DEL, and DsReplicaUpdateRefs. Take a closer look as to what is going on in this capture:

![Figure 14](/images/syncing-into-the-shadows/jiodaSb8frYzBqAt.png)

This is modifying the nTDSDA object. You can correlate these logs with a Windows Event 4662 that populates inside of the legitimate Domain Controller:

![Figure 15](/images/syncing-into-the-shadows/7zTtZPuuctPHa-Vs.png)

This is activating the replication process:

![Figure 16](/images/syncing-into-the-shadows/-BQcOZ_tYsfp1gbE.png)

We see this replication is happening over the network. How can we tell that this is a DCShadow attack? This can be seen by filtering out LDAP in the packet capture:

![Figure 17](/images/syncing-into-the-shadows/G-29yYJoDwdjHDGg.png)

Inside of the AddRequest you see that Win10 is added into the Servers CN.

![Figure 18](/images/syncing-into-the-shadows/ePw2FjNt6LBoFDSp.png)

Inside of the ModifyRequest we see that Win10 is modified to being a Domain Controller

![Figure 19](/images/syncing-into-the-shadows/Y6nvq3AIsSrd7dLg.png)

Notice the GC part- this proves win10 was registered as a DC. GC stands for global catalog and is a role given to one or more Domain Controllers in the environment. DC’s store data about objects in its own domain where GC stores data about every object in in the forest.

Inside of the Windows Event Security logs you will find another Event ID 4662, showing this change. You can tell by the Object Type, along with the Operation Type/Accesses:

![Figure 20](/images/syncing-into-the-shadows/8dYfuKkkRlK0nBGQ.png)

You will also see a Event ID of 4742, which populates when you make a change to a computers attribute.

![Figure 21](/images/syncing-into-the-shadows/jb17RmwpiogWUEZh.png)

Notice while looking into the details of the 4742 log — underneath ‘Service Principle Names’, anything sticking out? This shows the change done on the win10.windomain.local was changed to classify as a GC.

![Figure 22](/images/syncing-into-the-shadows/zc6YDvQZPgR3o3Pw.png)

Back to the Packet Capture, you will see the request to remove Win10 as a Domain Controller:

![Figure 23](/images/syncing-into-the-shadows/wc_N_xX8-VXHhtpZ.png)

The delReqeust is requesting to remove Win10 from Servers CN:

![Figure 24](/images/syncing-into-the-shadows/KkeiBo51s_13Q0U7.png)

Modify Request is removing WIN10 From GC. Officially removing Win10 as Domain Controller:

![Figure 25](/images/syncing-into-the-shadows/xgxra4dGVLCJdgr9.png)

In between the Addition and removal of win10.windomain.local into the Servers CN, you see that there is a user being searched and modified.

![Figure 26](/images/syncing-into-the-shadows/I3FpBYeNq-1mjkS4.png)

When we look into the packet we see this:

![Figure 27](/images/syncing-into-the-shadows/UlcMksjhp0zkaf_E.png)

Focus on the attribute “Thanos” with the user account control 512? Does 512 sound familiar? That is the Group ID of Domain Admins Group. We set 512 as the primary group ID of Thanos, injecting him into the Domain Admins Group.

Now that there was a user injected in the Domain Admins group and a computer win10.windomain.local was registered as a Domain Controller, we are missing one piece. Who injected this user? Why is this important? We want to know where the adversary has been, who they have compromised, and where they are. We know where they have been, where they are (or could be), but we are missing who all they have compromised. We know they have compromised: ironman@windomain.local and thanos@windomain.local, but who was compromised between those two? How do we know there was a user used between the two? Remember the privileges it takes to implement these two attacks. For DCSync: Administrators, Domain Admins, Enterprise Admins, or a Domain Controller computer accounts. DCShadow: Domain Admin. ironman@windomain.local is in the Administrator Group and thanos@windomain.local was injected into the Domain Administrator Group, but WHO did the injection?

This is actually pretty simple to find, especially over the network. Remember when we had to give system level privileges to Mimikatz in order to run the DCShadow attack? Then we used another Mimikatz window to make the push?

![Figure 28](/images/syncing-into-the-shadows/KSlchbLmBQD50h_3.png)

You notice this before any of the DRS or LDAP logs inside of the packet capture.

## DCShadow Analytics:

Below you can find the data relationships I have discussed above in a table format for the DCShadow technique.

![Figure 29](/images/syncing-into-the-shadows/qvqrQ45ub31LNW4VDw7U9Q.png)

![Figure 30](/images/syncing-into-the-shadows/D9wRerlXc1B2HD_J2Nedqg.png)

## Final Thoughts:

DCSync and DCShadow at first to me sounded very similar. I wanted to give others the clear difference in the two attacks. DCSync is used to capture credentials, where DCShadow is used for Defense Evasion by having the ability to inject objects into the Active Directory Infrastructure. I hope you found this informational and also enjoyed the Marvel references. ☺

## Marvel Explanation:

If you follow Marvel, you know in the movie “Avengers: Age of Ultron”, Tony Stark had a AI (which he created) named “JARVIS”. JARVIS later turned into Vision, who had the Mind Stone attached to his head. In “Avengers: Endgame”, Thanos removed the stone from Vison (killing him), giving Thanos the last infinity stone. Which made him all powerful, which led to him wiping out half of the world.

## Resources:

If any of the following read this blog, I would like to say thank your work, along with your write ups. They are a huge help.

**DCSync:**

- [**Mimikatz DCSync Usage, Exploitation, and Detection**](https://adsecurity.org/?p=1729) by Sean Metcalf
- [**Mimikatz and DCSync and ExtraSids, Oh My**](http://www.harmj0y.net/blog/redteaming/mimikatz-and-dcsync-and-extrasids-oh-my/) by Will Schroeder
- [**Mordor Gates**](https://github.com/Cyb3rWard0g/mordor) by Roberto Rodriguez

**DCShadow:**

- [**DCShadow explained**](https://blog.alsid.eu/dcshadow-explained-4510f52fc19d) by Luc Delsalle
- [**DCShadow**](https://www.dcshadow.com/) by Benjamin Delpy and Vincent Letoux
- [**DCShadow**](https://pentestlab.blog/2018/04/16/dcshadow/) by netboisx

**Other:**

- [**Detection Lab**](https://github.com/clong/DetectionLab) by Chris Long
- [**KCC**](https://docs.microsoft.com/en-us/windows-server/identity/ad-ds/get-started/replication/active-directory-replication-concepts) by Microsoft

*Originally published at [https://jsecurity101.com](https://jsecurity101.com/2019/Syncing-into-the-Shadows/) on April 14, 2019.*
