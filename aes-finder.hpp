#pragma once

#include <algorithm>

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

	struct FoundKey
	{
		enum KeyOp
		{
			ENCRYPT,
			DECRYPT
		};

		void*   address;
		uint8_t key[32];
		KeyOp   key_op;
		int     key_size;
	};

	class FoundKeyVector : std::vector<FoundKey>
	{
		static std::mutex mtx;

		static inline bool CompareKeyAddress(const FoundKey& k1, const FoundKey& k2)
		{
			return(k1.address < k2.address);
		}

	public:

		void PrintKeys()
		{
			std::sort(this->begin(), this->end(), CompareKeyAddress);
			for (auto fk : *this)
			{
				
				if (fk.key_op == FoundKey::ENCRYPT)
				{
					printf("[%p] Found AES-%d encryption key: ", fk.address, fk.key_size * 8);
				}
				else
				{
					printf("[%p] Found AES-%d decryption key: ", fk.address, fk.key_size * 8);
				}
				for (int i = 0; i < fk.key_size; i++)
				{
					printf("%02x", fk.key[i]);
				}
				printf("\n");
			}
		}

		void safe_emplace_back(const FoundKey& fk)
		{
			std::lock_guard<std::mutex> lock(FoundKeyVector::mtx);
			this->emplace_back(fk);
		}

	};



	class KeyFinder
	{
		static std::mutex mtx;

		uint8_t* buffer;

	public:
		KeyFinder()
		{
			thread_time = std::chrono::duration<double>(0.0);
			buffer = new uint8_t[BUFFER_SIZE];
		}

		KeyFinder(const KeyFinder&) = delete;
		KeyFinder& operator=(const KeyFinder&) = delete;
		KeyFinder(KeyFinder&&) = delete;
		KeyFinder&& operator=(KeyFinder&&) = delete;

		~KeyFinder()
		{
			delete(buffer);
		}

		std::chrono::duration<double> thread_time;

		void operator()(std::atomic<size_t>* total_size, FoundKeyVector* found_keys);

		static inline size_t safe_process_next(size_t& size)
		{
			std::lock_guard<std::mutex> lock(KeyFinder::mtx);
			return os_process_next(size);
		}

	};



}
