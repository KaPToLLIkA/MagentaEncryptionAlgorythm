#pragma once
#include <vector>
#include <array>
#include <string>
#include <random>
#include <fstream>

#define MAGENTA_BLOCK_SZ 16 //in bytes
#define BYTE(b64, shift) (uint8_t(b64 >> ((7 - shift) * 8)))

namespace crypto {
	typedef uint8_t byte;
	typedef std::array<uint64_t, 2> block64_t;

	block64_t operator^(const block64_t& a, const block64_t& b);
	std::vector<byte>& operator+(std::vector<byte>& a, const block64_t& b);

	class magenta
	{
		static uint8_t S_box[256];
		
		// round function
		static uint8_t f(uint8_t byte);
		static uint8_t A(uint8_t x, uint8_t y);
		static uint16_t PE(uint8_t x, uint8_t y);
		static block64_t P(block64_t X);
		static block64_t T(block64_t X);
		static block64_t S(block64_t X);
		static block64_t C(uint32_t k, block64_t X);
		static uint64_t F(block64_t X);
		static block64_t round_F(block64_t X, uint64_t key);

		static std::vector<block64_t> split_data(std::vector<byte> data, bool append_service_block = true);

#ifdef _DEBUG
		size_t file_buf_sz = MAGENTA_BLOCK_SZ * 128; //in bytes
#else
		size_t file_buf_sz = MAGENTA_BLOCK_SZ * 65536; //in bytes
#endif // _DEBUG

		std::vector<byte> raw_key;
		std::vector<uint64_t> prepared_key;

		block64_t crypt(block64_t data, std::vector<uint64_t>& keys);

		block64_t generate_random_iv();

	public:
		static std::vector<byte> generate_random_key();

		explicit magenta();
		explicit magenta(std::vector<byte>& key);

		void set_key(std::vector<byte>& key);
		std::vector<byte> get_key();

		void set_file_buf_sz(size_t sz);
		size_t get_file_buf_sz();

		std::vector<byte> encrypt(std::vector<byte>* data);
		std::vector<byte> encrypt(std::vector<byte> data);
		std::vector<byte> decrypt(std::vector<byte>* data);
		std::vector<byte> decrypt(std::vector<byte> data);

		std::string encrypt_file(std::string* fname);
		std::string encrypt_file(std::string fname);
		std::string decrypt_file(std::string* fname);
		std::string decrypt_file(std::string fname);
		
	};

} // end crypto namespace