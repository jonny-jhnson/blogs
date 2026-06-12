---
title: "ThreadSleeper: Suspending Threads via GMER64 Driver"
description: "A walkthrough of how the gmer.sys driver was abused to terminate EDR processes - and a counter-technique that uses the same driver to suspend offensive threads instead."
pubDate: 2023-07-21
readingTime: "8 min read"
tags: ["windows", "reverse engineering"]
slug: "threadsleeper"
order: 20
---

*Originally posted: *[https://www.binarydefense.com/resources/blog/threadsleeper-suspending-threads-via-gmer64-driver/](https://www.binarydefense.com/resources/blog/threadsleeper-suspending-threads-via-gmer64-driver/)

Recently a friend of mine, [Nick Powers](https://twitter.com/zyn3rgy), sent me the [gmer.sys](https://loldrivers.io/drivers/7ce8fb06-46eb-4f4f-90d5-5518a6561f15/) driver that was involved with the [Blackout ](https://github.com/ZeroMemoryEx/Blackout/tree/master/Blackout)activity which exposed functionality to terminate any process you wanted from a medium integrity level context. This was being used against many EDR vendors, including Microsoft Defender for Endpoint, to kill their service process (MsSense.exe in MDE’s case) which was running as an anti-malware-light protected process (PPL). [ZeroMemoryEx](https://twitter.com/ZeroMemoryEx) tweeted about this [here](https://twitter.com/ZeroMemoryEx/status/1661890855966326788?s=20):

![Figure 1](/images/threadsleeper/tlAIR7US85EdqPnP_SbwzA.png)

This was obviously not ideal and vendors like Microsoft worked quickly to prevent this driver from being dropped to disk. However, once loaded there isn’t much that could be done.

While looking at this driver, I found a lot of suspicious capability. One of which was suspending any thread you chose, assuming you have its thread identifier. This blog will cover my process for finding the alternative capability for interfering with the operation of a PPL process associated with an EDR driver that is, in my opinion, a little stealthier.

## Methodology

### Step 1: Check the device object security descriptor

Every device driver must have at least one device object. The purpose of this device object is to handle I/O requests. Device objects are created via IoCreateDevice or IoCreateDeviceSecure. The difference between these 2 APIs is that IoCreateDeviceSecure’s 7th parameter allows the author to specify a DACL for the device object, whereas with IoCreateDevice the developer would have to do so differently.

Note: Some drivers specify the security descriptor in the INF file but that doesn’t apply to us today.

After opening up IDA and finding the DriverEntry, we can see that there is a call to IoCreateDevice:

![Figure 2](/images/threadsleeper/mkG6JduVSA8b_lGA7-Xm2w.png)

One thing we can see here is that the DeviceObject name comes from whatever the service name the driver was installed under. Also, there isn’t a security descriptor set on the device object, so we know if we find this driver installed somewhere we could interact with it from a non-privileged standpoint (e.g., medium integrity level). You can also see this easily with [WinObjEx64](https://github.com/hfiref0x/WinObjEx64):

![Figure 3](/images/threadsleeper/gvfwYRng6f3VYu_iiw3WWA.png)

We can see that “Everyone” has plenty of access for us to get a handle to the device object via CreateFile, which I only use GenericRead/GenericWrite. More on this in the POC below.

Note: If you plan on dropping this driver you will need to be admin on the target host to install the service.

We then see a symbolic link created which allows user-mode applications to get a handle to the device object. This is needed so we can send the IOCTL via DeviceIOControl later.

### Step 2: Find the [DispatchDeviceControl](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nc-wdm-driver_dispatch) routine

Typically when a vulnerability in a driver is discovered, it is because the driver exposes some functionality that can be accessed through its [DispatchDeviceControl ](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nc-wdm-driver_dispatch)routine which can be accessed when a user-mode client uses the DeviceIoControl Win32 API (there are other functions that can be leveraged) to pass in an input/output control code or [IOCTL](https://learn.microsoft.com/en-us/windows/win32/devio/device-input-and-output-control-ioctl-).

When a user-mode application uses [DeviceIoControl](https://learn.microsoft.com/en-us/windows/win32/api/ioapiset/nf-ioapiset-deviceiocontrol) to send an IOCTL to a device driver the information gets packaged into an I/O request packet or IRP. Once the driver has the IRP it will access the [I/O stack location](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/ns-wdm-_io_stack_location) to figure out what type of major function the operation is requesting (in this case, the [IRP_MJ_DEVICE_CONTROL](https://learn.microsoft.com/en-us/windows-hardware/drivers/kernel/irp-mj-device-control) major function), along with its parameters. The IRP is passed to the [DispatchDeviceControl ](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nc-wdm-driver_dispatch)that is registered up within the driver. The [DispatchDeviceControl](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nc-wdm-driver_dispatch) routine will unpackage the IRP to find the IOCTL and the included buffer (typically containing parameters to go with the functionality within the driver). Control codes are defined by the CTL_CODE macro which can be found in the ntfis.h:

![Figure 4](/images/threadsleeper/s-vwI4N43r_6QIkffBvDuA.png)

1. Device Type
2. Access
3. Function
4. Method

When reversing a driver, the IOCTLs are easy to point out after finding the function behind [DispatchDeviceControl](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nc-wdm-driver_dispatch)because they are typically in a switch statement. The switch statement is executed to find the internal function that is set up to handle requests with the matching IOCTL and passes along the parameters which were passed in by the user. I went a bit more in-depth on this in my blogpost [Exploring Impersonation through the Named Pipe Filesystem Driver](https://medium.com/specter-ops-posts/exploring-impersonation-through-the-named-pipe-filesystem-driver-15f324dfbaf2).

To find the driver-specific [DispatchDeviceControl](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nc-wdm-driver_dispatch) routine we need to find if the driver handles the IRP_MJ_DEVICE_CONTROL major function. Most drivers will do something like this if they do:

```rust
DriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = TestDeviceControl;
```

If we look in the gmer64 driver we see:

![Figure 5](/images/threadsleeper/BkeZIeH7EggayotR6cMzew.png)

Within sub_12448, we can see that there is redundant check to see if the major function code is IRP_MJ_DEVICE_CONTROL and to pass it into another internal function, which I renamed to DispatchDeviceControl:

![Figure 6](/images/threadsleeper/l-IhD0w2Xmo7i0ZG0S1VTw.png)

Now that we have found the internal function that handles IRP_MJ_DEVICE_CONTROL requests, we need to see if there are any calls of interest to us.

### Step 3: Map out IOCTLs

If you look closely at the exposed IOCTLs and their functionality, you will quickly see that there are some sketchy things you can do with this driver. However, the one that I found interesting was 0x9876C098:

![Figure 7](/images/threadsleeper/cK0CXnP9X9lkFk9JGSsjYA.png)

0x9876C098 makes a call to an internal function (which I renamed as SuspendThread), which takes in 2 parameters: A pointer to a structure and the 2nd member in that structure. Once in that internal function a call to ZwOpenThread is made and then a function pointer is used to call ZwSuspendThread:

![Figure 8](/images/threadsleeper/Hplbc0FI2MqIR47pQNfhZg.png)

The previous example demonstrated by ZeroMemoryEx used the IOCTL 0x9876C094 which made a call to an internal function that took in a process ID that was passed into ZwTerminateProcess, terminating the process. This had me thinking — what if I could suspend any process I wanted and render a process (say, a PPL process) useless without showing that it was terminated. Let’s create the POC.

### Step 4: Create POC

Note: In order for the us to get the IOCTL to work correctly, initialization has to be done within the driver which is sent via the IOCTL 0x9876C004 which can be seen in the [Blackout](https://github.com/ZeroMemoryEx/Blackout/blob/master/Blackout/Blackout.cpp) POC.

The first thing I needed to do was create a custom structure that could be passed in because the SuspendThread internal function took in 2 parameters: a pointer to some structure and the 1st member in that structure. After looking into that internal function I realized that the structure in question was likely a [CLIENT_ID](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-tsts/a11e7129-685b-4535-8d37-21d4596ac057). as the members of the user-supplied structure were passed into a new CLIENT_ID

Driver Code:

![Figure 9](/images/threadsleeper/gIGCTB2gu9lUCquLbNDRPw.png)

POC code:

```cpp
struct TargetProcess {
    DWORD ProcessId;
    DWORD ThreadId;
};
```

I do want to point out that the ProcessId member isn’t actually used, so from the user-mode side you only need to get the thread ID which can be grabbed as medium IL. I was confused by this at first and was worried I overlooked something so thank you to [Matt Hand](https://twitter.com/matterpreter) for sanity checking this — it was weird to both of us.

Next, we need to get a handle to the device object via the symlink which can be done using CreateFile:

```ini
hDevice = CreateFileW(L"\\\\.\\gmer64", GENERIC_READ | GENERIC_WRITE, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
```

If you are not familiar, CreateFile can be used to not only create files but also obtain handles to existing objects. You will also notice the device object name is gmer64. That is because I created the service as gmer64 on my machine.

After that I created an instance of my structure and passed in the parameters appropriately, where argument 1 is the process ID (again not used) and argument 2 is the thread ID:

```kotlin
TargetProcess data;
data.ProcessId = atoi(argv[1]);
data.ThreadId = atoi(argv[2]);
```

We then need to send the IOCTL via DeviceIoControl. Before we can send the IOCTL to suspend threads, a prerequisite is that we must first do some initialization with the driver. The initialization is simple as we just need to send the IOCTL 0x9876C004. This will set a global variable to 1, if we do not do this and the global variable is not set to 1 the DeviceIoControl call later will fail. Once this is set you can send as many DeviceIoControl requests as you please.

```objectivec
BOOL deviceControl = DeviceIoControl(hDevice, INITIALIZE_IOCTL_CODE, &data, sizeof(data), output, outputSize, &bytes, NULL);
```

After initializing using the previous request, we can call DeviceIoControl for the IOCTL we want along with the thread ID we want to suspend.

```ini
deviceControl = DeviceIoControl(hDevice, SUSPEND_THREAD_IOCTL_CODE, &data, sizeof(data), &output, outputSize, &bytes, NULL);
```

Here is the output showing all threads being suspended in a process:

![Figure 10](/images/threadsleeper/qvg5VDxO1Q-dE_BI9V5_Cg.png)

Code can be found here: [https://github.com/jsecurity101/RandomPOCs/tree/main/SuspendThreadDriver](https://github.com/jsecurity101/RandomPOCs/tree/main/SuspendThreadDriver)

## Impact

For those that aren’t aware, a lot of endpoint protection products will restart their main processes if they have been killed. This is relatively common practice now; however, they aren’t checking if the threads in that main process are suspended. They usually just check to see if the process is alive, which technically still is using this technique. If this driver is already running on a system, you could obtain all the thread IDs associated with a sensor process from medium IL and suspend them with this driver. This is what I was alluding to in this [tweet](https://twitter.com/jsecurity101/status/1664746917174165506?s=20) a while back:

![Figure 11](/images/threadsleeper/zqWW1JWPiWKsMD-_XYmktA.png)

Just to prove that no callbacks happen afterwards here a check I did on a device that had MDE installed 3 days after executing the above:

![Figure 12](/images/threadsleeper/bmXyixbhBU3XbWZTsCeJ1g.png)

## Recommendations

From a defensive perspective, my recommendation is mostly to sensor vendors:

- Collect SuspendThread events from the Threat-Intelligence ETW provider. There are events for calls coming from user-mode and kernel-mode.
- Collect Driver/DeviceLoad events from the Threat-Intelligence ETW provider, you will be able to see when this driver is loaded.
- Add the gmer64 driver to your list of prohibited drivers

## Conclusion

Although this was already tagged as a vulnerable driver, this was an interesting project as it highlights that if a driver is found to be vulnerable, oftentimes there are other vulnerabilities or functionality useful to an adversary embedded if you look at it a bit closer.

Lastly, vulnerable drivers have been really amping up this year and I wanted to point out that there are defensive capabilities outside of WDAC. Microsoft’s team has worked hard to expose events through the Threat-Intelligence ETW provider that can be used in situations like this.

## Resources

Again, thank you to [ZeroMemoryEx](https://twitter.com/ZeroMemoryEx) for their awesome with BlackOut, finding the terminate process vulnerability, and their POC which made my life a bit easier.

General References:

- [https://www.loldrivers.io/drivers/7ce8fb06-46eb-4f4f-90d5-5518a6561f15/](https://www.loldrivers.io/drivers/7ce8fb06-46eb-4f4f-90d5-5518a6561f15/)
- [https://github.com/ZeroMemoryEx/Blackout/blob/master/Blackout/Blackout.cpp](https://github.com/ZeroMemoryEx/Blackout/blob/master/Blackout/Blackout.cpp)
- [https://github.com/gtworek/PSBits/blob/master/Misc/KillWithLolDriver.ps1](https://github.com/gtworek/PSBits/blob/master/Misc/KillWithLolDriver.ps1)
- [https://learn.microsoft.com/en-us/windows-hardware/drivers/kernel/example-i-o-request---an-overview](https://learn.microsoft.com/en-us/windows-hardware/drivers/kernel/example-i-o-request---an-overview)

Other good blogs on reversing drivers/vulnerable drivers:

- [https://www.crowdstrike.com/blog/cve-2021-21551-learning-through-exploitation/](https://www.crowdstrike.com/blog/cve-2021-21551-learning-through-exploitation/)
- [https://posts.specterops.io/methodology-for-static-reverse-engineering-of-windows-kernel-drivers-3115b2efed83](https://posts.specterops.io/methodology-for-static-reverse-engineering-of-windows-kernel-drivers-3115b2efed83)
