//By AlSch092 @ Github - APC Stealth Dispatcher example
#pragma once
#include <Windows.h>
#include <functional>
#include <thread>
#include <iostream>
#include <tuple>

#ifdef _M_X64  //This example features both shellcode execution and ASM stubs as a fallback, these two routines can be found in CallStub.asm

//4C 8B D1 B8 66 01 00 00 CD 2E C3
extern "C" NTSTATUS _MyNtQueueApcThreadEx(HANDLE ThreadHandle, HANDLE ApcContext, PVOID ApcRoutine, PVOID ApcArgument1, PVOID ApcArgument2, PVOID ApcArgument3);

//4C 8B D1 B8 67 01 00 00 CD 2E C3
extern "C" NTSTATUS _MyNtQueueApcThreadEx2(HANDLE ThreadHandle, HANDLE ApcContext, ULONG ApcMode, PVOID ApcRoutine, PVOID ApcArgument1, PVOID ApcArgument2, PVOID ApcArgument3);
#else //currently I haven't finished x86 asm stubs for this since it uses WoW64 transition, and needs to be looked up dynamically
#endif

class ApcExecutor
{
public:

	ApcExecutor()
	{
		_hWorker = CreateThread(nullptr, 0, WorkerRoutine, this, 0, nullptr);

		if (!_hWorker)
			throw std::runtime_error("Failed to create APC worker thread");
#ifdef _M_X64 	
		_NtQueueApcThread = reinterpret_cast<NtQueueApcThreadEx2_t>(GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtQueueApcThreadEx2"));
#else
		_NtQueueApcThread = reinterpret_cast<NtQueueApcThreadEx2_t>(GetProcAddress(GetModuleHandleA("ntdll.dll"), "ZwQueueApcThreadEx2")); //NtQueueApcThreadEx2 does not exist in x86, but ZwQueueApcThreadEx2 does (and works fine)
#endif
	}

	~ApcExecutor()
	{
		if (_hWorker != INVALID_HANDLE_VALUE && !_bShutdownSignalled)
		{
			SignalShutdown(true); //fast exit, you can add signalled shutdown if you want
			WaitForSingleObject(_hWorker, INFINITE); //wait for the thread to finish executing before exiting the program
			CloseHandle(_hWorker);
		}
	}

	template<typename Func, typename... Args>
	bool Queue(Func&& f, Args&&... args)
	{
		TaskThunk<Func, Args...>* pThunk = new TaskThunk<Func, Args...>(std::forward<Func>(f), std::forward<Args>(args)...);
		return NT_SUCCESS(CallQueueApc((PAPCFUNC)TaskThunk<Func, Args...>::Thunk, (ULONG_PTR)pThunk));
	}

	void SignalShutdown(__in const bool bShutdown) { this->_bShutdownSignalled = bShutdown; } //end the APC sleeper thread

private:

	enum CallMethod
	{
		CallMethod_QueueUserAPC,
		CallMethod_NtQueueApcThreadEx2,
		CallMethod_AsmStub,
		CallMethod_Shellcode
	};

	CallMethod CallMethod = CallMethod_Shellcode; //set this to the method you want to use. you can change it at runtime if you want to make things trickier to analyze 

	HANDLE _hWorker = nullptr;
	bool _bShutdownSignalled = false;

	using NtQueueApcThreadEx2_t = NTSTATUS(NTAPI*)(HANDLE, HANDLE, ULONG, PVOID, PVOID, PVOID, PVOID);

	NtQueueApcThreadEx2_t _NtQueueApcThread = nullptr;

	template<typename Func, typename... Args>
	struct TaskThunk
	{
		Func func;
		std::tuple<Args...> args;

		TaskThunk(Func&& f, Args&&... a) : func(std::forward<Func>(f)), args(std::forward<Args>(a)...) {}

		static void CALLBACK Thunk(ULONG_PTR param)
		{
			std::unique_ptr<TaskThunk> self(reinterpret_cast<TaskThunk*>(param));
			CallWithArgs(self->func, self->args, std::index_sequence_for<Args...>{});
			//std::apply(self->func, self->args); //if you're using C++17 or later, you can comment out the above line and uncomment this one
		}

	private:
		template<std::size_t... I>
		static void CallWithArgs(Func& f, const std::tuple<Args...>& args, std::index_sequence<I...>)  //this can be removed if you're using C++17 and use std::apply instead
		{
			f(std::get<I>(args)...);
		}
	};

	static DWORD WINAPI WorkerRoutine(__in LPVOID lpThisPtr)
	{
		ApcExecutor* pThis = reinterpret_cast<ApcExecutor*>(lpThisPtr);
		
		if (!pThis)
			return 1;

		while (true)
		{
			if (pThis->_bShutdownSignalled)
				break;

			SleepEx(1000, TRUE); // alertable wait -> don't use INFINITE here, since signalling for thread shutdown won't reliably work (gets stuck in SleepEx forever)
		}

		return 0;
	}

	NTSTATUS CallQueueApc(PAPCFUNC fn, ULONG_PTR param)
	{
		if (CallMethod == CallMethod_Shellcode)
		{
#ifdef _M_X64
			constexpr uint8_t xor_key = 0x48;

			constexpr uint8_t shellcode_Ex2[] =  //weakly encrypted shellcode, which will be copied to our allocated region and then decrypted & executed
			{
				0x4C ^ xor_key, 0x8B ^ xor_key, 0xD1 ^ xor_key,                                  //mov r10, rcx
				0xB8 ^ xor_key, 0x67 ^ xor_key, 0x01 ^ xor_key, 0x00 ^ xor_key, 0x00 ^ xor_key,  //mov eax, 167h
				0x0F ^ xor_key, 0x05 ^ xor_key,                                                  //syscall
				0xC3 ^ xor_key                                                                   //ret
			};

			DWORD dwOldProt = 0;

			LPVOID shellcodeMemory = VirtualAlloc(NULL, sizeof(shellcode_Ex2), MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);

			if (!shellcodeMemory)
			{
				std::cerr << "VirtualAlloc failed: " << GetLastError() << std::endl;
				return _MyNtQueueApcThreadEx2(_hWorker, NULL, 0, fn, (PVOID)param, NULL, NULL); //fallback to ASM syscall stub if we can't allocate memory
			}

			for (size_t i = 0; i < sizeof(shellcode_Ex2); ++i)
				((uint8_t*)shellcodeMemory)[i] = shellcode_Ex2[i] ^ xor_key; //decrypt shellcode

			typedef NTSTATUS(*MyNtQueueApcThreadEx2_t)(HANDLE, HANDLE, ULONG, PVOID, PVOID, PVOID, PVOID);
			MyNtQueueApcThreadEx2_t _MyNtQueueApcThreadEx2 = (MyNtQueueApcThreadEx2_t)shellcodeMemory;

			NTSTATUS status = _MyNtQueueApcThreadEx2(_hWorker, NULL, 0, fn, (PVOID)param, NULL, NULL);

			VirtualFree(shellcodeMemory, 0, MEM_RELEASE); //free the allocated memory

			return status;
#else
			std::cerr << "Call method not yet supported in 32-bit!" << std::endl;
			return -1;
#endif  //x86 is not yet supported for shellcode, will be added in future code pushes
		}
		else if (CallMethod == CallMethod_AsmStub)
		{
#ifdef _M_X64
			return _MyNtQueueApcThreadEx2(_hWorker, NULL, 0, fn, (PVOID)param, NULL, NULL); //ASM syscall stub
#else
			std::cerr << "Call method not yet supported in 32-bit!" << std::endl;
			return -1;
#endif
		}
		else if (CallMethod == CallMethod_NtQueueApcThreadEx2)
		{
			return _NtQueueApcThread(_hWorker, NULL, 0, fn, (PVOID)param, NULL, NULL); //low-level winapi, suitable in both x86 and x64 across most newer windows builds
		}
		else if(CallMethod == CallMethod_QueueUserAPC)
		{
			return QueueUserAPC(fn, _hWorker, param) ? 0 : -1; 	// fallback to higher-level API, which can be easily blocked by patching over ntdll.Ordinal8
		}
		else
		{
			std::cerr << "Invalid call method" << std::endl;
			return -1;
		}
	}

	static bool NT_SUCCESS(NTSTATUS status)
	{
		return status >= 0;
	}
};

int main(void)
{
	ApcExecutor dispatcher;

	for (int i = 0; i < 100; i++) //example of scheduling routines to run in our APC thread, which sleeps forever when nothing is scheduled
	{
		dispatcher.Queue([]
			{
				std::cout << "APC-scheduled routine" << std::endl;
			});

		dispatcher.Queue([](int a = rand(), int b = rand(), int c = rand(), int d = rand())
			{
				std::cout << "Arguments: " << a << ", " << b << ", " << c << ", " << d << std::endl;
			});

		Sleep(1000);
	}

	return 0;
}