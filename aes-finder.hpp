#pragma once

#if defined(WIN32)
#include "os_windows.h"
#elif defined(__linux__)
#include "os_linux.h"
#elif defined(__APPLE__)
#include "os_osx.h"
#else
#error Unknown OS!
#endif

#define BUFFER_SIZE (64 * 1024)
#define CTX_SIZE 60

namespace AESFinder
{
	class KeyFinder
	{
		static std::mutex os_mtx;
		static std::mutex fk_mtx;

		enum KeyOp
		{
			ENCRYPT,
			DECRYPT
		};

		struct FoundKey
		{
			void*   address;
			uint8_t key[32];
			KeyOp   key_op;
			int     key_size;
		};

		uint8_t* buffer;

	public:
		KeyFinder()
		{
			thread_time = 0.0;
			buffer = new uint8_t[BUFFER_SIZE];
		}

		~KeyFinder()
		{
			delete(buffer);
		}

		static std::atomic<size_t> total;
		static std::vector<FoundKey> found_keys;

		double thread_time;

		void operator()();

		static inline void PrintKeys();

		static inline bool CompareKeyAddress(FoundKey k1, FoundKey k2)
		{
			return(k1.address < k2.address);
		}

		static inline size_t safe_process_next(size_t& size)
		{
			std::lock_guard<std::mutex> lock(KeyFinder::os_mtx);
			return os_process_next(size);
		}

		static inline void safe_push_back(const FoundKey& fk)
		{
			std::lock_guard<std::mutex> lock(KeyFinder::fk_mtx);
			found_keys.push_back(fk);
		}

	};

}
