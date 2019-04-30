#pragma once

#include <atomic>
#include <vector>
#include <mutex>
#include <algorithm>

#include "aes-finder_os.hpp"

#define BUFFER_SIZE (64 * 1024)
#define CTX_SIZE 60

namespace AESFinder
{
	
	template <bool>
	static bool aes128_detect_enc(const uint32_t*, uint32_t*);
	
	template <bool>
	static bool aes192_detect_enc(const uint32_t*, uint32_t*);
	
	template <bool>
	static bool aes256_detect_enc(const uint32_t*, uint32_t*);
	
	template <bool>
	static bool aes128_detect_decF(const uint32_t*, uint32_t*);
	
	template <bool>
	static bool aes128_detect_decB(const uint32_t*, uint32_t*);
	
	template <bool>
	static bool aes192_detect_decF(const uint32_t*, uint32_t*);
	
	template <bool>
	static bool aes192_detect_decB(const uint32_t*, uint32_t*);
	
	template <bool>
	static bool aes256_detect_decF(const uint32_t*, uint32_t*);
	
	template <bool>
	static bool aes256_detect_decB(const uint32_t*, uint32_t*);
	
	template <bool>
	static int aes_detect_dec(const uint32_t*, uint32_t*);
	
	static int aes_detect_enc(const uint32_t*, uint32_t*);
	static int aes_detect_dec(const uint32_t*, uint32_t*);
	
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
		KeyFinder() : thread_time(std::chrono::duration<double>(0.0))
		{
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

		static void find_keys(uint32_t pid)
		{
			printf("Searching PID %u ...\n", pid);

			if (!os_process_begin(pid))
			{
				printf("Failed to open process\n");
				return;
			}

			const auto t0 = std::chrono::steady_clock::now();

			std::atomic<size_t> total_size(0);
			FoundKeyVector found_keys;

			const size_t num_threads = std::thread::hardware_concurrency();
			std::list<KeyFinder> key_finders(num_threads);
			std::list<std::thread> threads;

			auto it = key_finders.begin();
			for (size_t i = 0; i < num_threads; i++, ++it)
			{
				threads.emplace_back(std::thread(&KeyFinder::operator(), it, &total_size, &found_keys));
			}

			for (auto p = std::make_pair(key_finders.begin(), threads.begin()); p.first != key_finders.end() && p.second != threads.end(); ++p.first, ++p.second)
			{
				p.second->join();
				//printf("Thread time : %f\n", p.first->thread_time);
			}
			found_keys.PrintKeys();

			const auto t1 = std::chrono::steady_clock::now();
			std::chrono::duration<double> time = t1 - t0;
			const double MB = 1024.0 * 1024.0;
			printf("Processed %.2f MB, total time %.2fs, speed = %.2f MB/s\n", total_size / MB, time.count(), total_size / MB / time.count());

			os_process_end();
		}

		static inline size_t safe_process_next(size_t& size)
		{
			std::lock_guard<std::mutex> lock(KeyFinder::mtx);
			return os_process_next(size);
		}

	};

}
