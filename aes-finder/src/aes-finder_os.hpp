#pragma once

#if defined(WIN32) || defined(_WIN32)

#define OS_WINDOWS

#  include <cstdint>

#  define WIN32_LEAN_AND_MEAN
#  ifdef _WIN32_WINNT
#    undef _WIN32_WINNT
#  endif
#  define _WIN32_WINNT 0x0502
#  include <windows.h>
#  include <tlhelp32.h>

static HANDLE os_snapshot;
static bool os_entry_first;
static PROCESSENTRY32 os_entry;

static HANDLE os_process;
static MEMORY_BASIC_INFORMATION os_process_info;

#elif defined(__linux__)

#define OS_LINUX

#include <sys/uio.h>
#include <dirent.h>
#include <unistd.h>

static DIR* os_dir;

static FILE* os_maps;
static pid_t os_process_pid;

#elif defined(__APPLE__)

#define OS_APPLE

#include <cstddef>
#include <cstdint>
#include <cstring>
#include <cstdlib>

#include <sys/sysctl.h>
#include <errno.h>
#include <mach/mach_init.h>
#include <mach/mach_traps.h>
#include <mach/mach_port.h>
#include <mach/vm_map.h>

static kinfo_proc* os_processes;
static size_t os_process_count;
static size_t os_process_idx;

static task_t os_process_task;
static vm_address_t os_process_addr;
static vm_size_t os_process_size;

#else
#error Unknown OS!
#endif

static void os_startup()
	{
#if defined(OS_WINDOWS)
		HANDLE hToken;
		if (OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES, &hToken))
		{
			TOKEN_PRIVILEGES tp;
			if (LookupPrivilegeValue(nullptr, "SeDebugPrivilege", &tp.Privileges[0].Luid))
			{
				tp.PrivilegeCount = 1;
				tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

				AdjustTokenPrivileges(hToken, FALSE, &tp, 0, nullptr, nullptr);
			}

			CloseHandle(hToken);
		}
#elif defined(OS_LINUX)
		sprintf(os_self_name, "%u", getpid());
#elif defined(OS_APPLE)
		// nothing
#endif
	}

	static bool os_enum_start()
	{
#if defined(OS_WINDOWS)
		os_snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
		if (os_snapshot == INVALID_HANDLE_VALUE)
		{
			return false;
		}

		os_entry_first = true;
		os_entry.dwSize = sizeof(os_entry);

		return Process32First(os_snapshot, &os_entry);
#elif defined(OS_LINUX)
		os_dir = opendir("/proc");
		return !!os_dir;
#elif defined(OS_APPLE)
		static const int name[] = {CTL_KERN, KERN_PROC, KERN_PROC_ALL, 0};

		size_t length;

		os_processes = NULL;

		int err;
		bool done = false;
		do
		{
			err = sysctl((int*)name, (sizeof(name) / sizeof(*name)) - 1, NULL, &length, NULL, 0);
			if (err == -1)
			{
				break;
			}

			os_processes = (kinfo_proc*)realloc(os_processes, length);
			if (os_processes == NULL)
			{
				err = -1;
				break;
			}

			err = sysctl((int*)name, (sizeof(name) / sizeof(*name)) - 1, os_processes, &length, NULL, 0);
			if (err == -1 && errno == ENOMEM)
			{
				continue;
			}

			break;
		} while (err == 0 && !done);

		if (err != 0)
		{
			free(os_processes);
			return false;
		}

		os_process_count = length / sizeof(kinfo_proc);
		os_process_idx = 0;

		return true;
#endif
	}

	static uint32_t os_enum_next(const char* name)
	{
#if defined(OS_WINDOWS)
		if (!os_entry_first)
		{
			if (!Process32Next(os_snapshot, &os_entry))
			{
				return 0;
			}
		}
		else
		{
			os_entry_first = false;
		}

		do
		{
			if (_stricmp(os_entry.szExeFile, name) == 0)
			{
				return os_entry.th32ProcessID;
			}
		} while (Process32Next(os_snapshot, &os_entry));

		return 0;
#elif defined(OS_LINUX)
		ssize_t name_len = strlen(name);

		for (;;)
		{
			struct dirent* de = readdir(os_dir);
			if (de == NULL)
			{
				return 0;
			}

			if (strcmp(de->d_name, "self") == 0 || strcmp(de->d_name, os_self_name) == 0)
			{
				continue;
			}

			char path[1024];
			snprintf(path, sizeof(path), "/proc/%s/exe", de->d_name);

			char link[1024];
			ssize_t link_len = readlink(path, link, sizeof(link));
			if (link_len == -1)
			{
				continue;
			}

			if (link_len < name_len || strncmp(link + link_len - name_len, name, name_len) != 0)
			{
				continue;
			}

			return atoi(de->d_name);
		}
#elif defined(OS_APPLE)
		while (os_process_idx < os_process_count)
		{
			kinfo_proc* p = os_processes + os_process_idx++;

			if (strcmp(name, p->kp_proc.p_comm) == 0)
			{
				return p->kp_proc.p_pid;
			}
		}

		return 0;
#endif
	}

	static void os_enum_end()
	{
#if defined(OS_WINDOWS)
		CloseHandle(os_snapshot);
#elif defined(OS_LINUX)
		closedir(os_dir);
#elif defined(OS_APPLE)
		free(os_processes);
#endif
	}

	static bool os_process_begin(uint32_t pid)
	{
#if defined(OS_WINDOWS)
		os_process_info.BaseAddress = nullptr;
		os_process_info.RegionSize = 0;

		os_process = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, pid);
		if (os_process == nullptr)
		{
			return false;
		}

#  if defined(_M_IX86) || defined(__i386__)
		BOOL wow64;
		if (IsWow64Process(GetCurrentProcess(), &wow64) && wow64)
		{
			if (IsWow64Process(os_process, &wow64) && !wow64)
			{
				// 32-bit (wow) process should not touch 64-bit (non-wow) process
				CloseHandle(os_process);
				return false;
			}
		}
#  endif

		return true;
#elif defined(OS_LINUX)
		os_process_pid = pid;

		char path[1024];
		snprintf(path, sizeof(path), "/proc/%u/maps", pid);

		os_maps = fopen(path, "r");
		if (os_maps == NULL)
		{
			return false;
		}

		// check if we are allowed to read process memory
		{
			char buffer;
			struct iovec in = {0, 1};
			struct iovec out = {&buffer, 1};

			process_vm_readv(pid, &out, 1, &in, 1, 0);

			if (errno == EPERM)
			{
				fclose(os_maps);
				return false;
			}
		}

		return true;
#elif defined(OS_APPLE)
		kern_return_t kr = task_for_pid(mach_task_self(), pid, &os_process_task);

		if (kr != KERN_SUCCESS)
		{
			return false;
		}

		os_process_addr = 0;
		os_process_size = 0;

		return true;
#endif
	}

	static size_t os_process_next(size_t& size)
	{
#if defined(OS_WINDOWS)
		for (;;)
		{
			LPCVOID addr = (char*)os_process_info.BaseAddress + os_process_info.RegionSize;

			if (VirtualQueryEx(os_process, addr, &os_process_info, sizeof(os_process_info)) == FALSE)
			{
				return 0;
			}

			if ((os_process_info.Protect & (PAGE_READONLY | PAGE_READWRITE)) == 0)
			{
				continue;
			}

			size = os_process_info.RegionSize;
			return reinterpret_cast<size_t>(os_process_info.BaseAddress);
		}
#elif defined(OS_LINUX)
		for (;;)
		{
			char line[1024];
			if (fgets(line, sizeof(line), os_maps) == NULL)
			{
				return 0;
			}

			size_t start;
			size_t end;
			char flag;
			if (sscanf(line, "%llx-%llx %c", &start, &end, &flag) != 3)
			{
				continue;
			}

			if (flag != 'r')
			{
				continue;
			}

			size = end - start;
			return start;
		}
#elif defined(OS_APPLE)
		for (;;)
		{
			os_process_addr += os_process_size;

			uint32_t depth = 1;
			mach_msg_type_number_t info_count = VM_REGION_BASIC_INFO_COUNT;
			vm_region_submap_info_64 info;
			mach_msg_type_number_t count = VM_REGION_SUBMAP_INFO_COUNT_64;

			kern_return_t kr = vm_region_recurse_64(os_process_task, &os_process_addr, &os_process_size, &depth, (vm_region_info_64_t)&info, &count);
			if (kr != KERN_SUCCESS)
			{
				return 0;
			}

			if ((info.protection & VM_PROT_READ) == 0)
			{
				continue;
			}


			size = os_process_size;
			return os_process_addr;
		}
#endif
	}

	static size_t os_process_read(size_t addr, void* buffer, size_t size)
	{
#if defined(OS_WINDOWS)
		if (!ReadProcessMemory(os_process, (LPCVOID)addr, buffer, size, &size))
		{
			return 0;
		}
		return size;
#elif defined(OS_LINUX)
		struct iovec in = {reinterpret_cast<void*>(addr), size};
		struct iovec out = {buffer, size};

		ssize_t read = process_vm_readv(os_process_pid, &out, 1, &in, 1, 0);

		return read < 0 ? 0 : read;
#elif defined(OS_APPLE)
		if (vm_read_overwrite(os_process_task, addr, size, (vm_address_t)buffer, &size) != KERN_SUCCESS)
		{
			return 0;
		}

		return size;
#endif
	}

	static void os_process_end()
	{
#if defined(OS_WINDOWS)
		CloseHandle(os_process);
#elif defined(OS_LINUX)
		fclose(os_maps);
#elif defined(OS_APPLE)
		mach_port_deallocate(mach_task_self(), os_process_task);
#endif
	}
