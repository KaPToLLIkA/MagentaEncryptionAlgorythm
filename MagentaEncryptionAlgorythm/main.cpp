#include <iostream>
#include <fstream>
#include <string>

#include "magenta.h"

//#define ENABLE_TEST

#ifdef ENABLE_TEST
void create_random_filled_file(std::string fname, size_t size);
bool files_are_equal(std::string fname1, std::string fname2);
#endif // ENABLE_TEST

int main(int argc, char* argv[]) {
	using namespace crypto;

#ifdef ENABLE_TEST
	std::string f1_resource = "tests_data/data1.dt";
	std::string f2_resource = "tests_data/data2.dt";
	std::string f3_resource = "tests_data/data3.dt";
	std::string fpdf_resource = "tests_data/book.pdf";

	create_random_filled_file(f1_resource, 0);
	create_random_filled_file(f2_resource, 16 * 1024 * 32 / 3);
	create_random_filled_file(f3_resource, 16 * 1024);

	magenta cypher;
	auto f1 = cypher.decrypt_file(cypher.encrypt_file(f1_resource));
	auto f2 = cypher.decrypt_file(cypher.encrypt_file(f2_resource));
	auto f3 = cypher.decrypt_file(cypher.encrypt_file(f3_resource));

	cypher.set_file_buf_sz(cypher.get_file_buf_sz() * 11 / 3);

	auto key = magenta::generate_random_key();
	cypher.set_key(key);

	auto fpdf = cypher.decrypt_file(cypher.encrypt_file(fpdf_resource));

	if (files_are_equal(f1, f1_resource)) std::cout << "TEST1: OK." << std::endl;
	else std::cout << "TEST1: FAILED." << std::endl;

	if (files_are_equal(f2, f2_resource)) std::cout << "TEST2: OK." << std::endl;
	else std::cout << "TEST2: FAILED." << std::endl;

	if (files_are_equal(f3, f3_resource)) std::cout << "TEST3: OK." << std::endl;
	else std::cout << "TEST3: FAILED." << std::endl;

	if (files_are_equal(fpdf, fpdf_resource)) std::cout << "TESTPDF: OK." << std::endl;
	else std::cout << "TESTPDF: FAILED." << std::endl;
#endif // ENABLE_TEST
	std::string way_to_program(argv[0]);
	size_t pos = way_to_program.find_last_of('\\');

	std::string program_name(
		way_to_program.begin() + (pos == std::string::npos ? 0 : pos + 1),
		way_to_program.end()
	);

	std::string usage = "How to use: " + program_name
		+ " encode|decode target_file_name key_file_name\n" 
		+ "Show this text: " + program_name + " --help";

	if (argc != 4 
		|| (argc == 2 && !strcmp(argv[1], "--help")))
	{
		std::cout << usage << std::endl;
		return -1;
	}

	if (!strcmp(argv[1], "encode"))
	{
		std::cout << "starting encryption..." << std::endl;

		magenta cypher;
		
		try 
		{
			auto fkeyname = cypher.save_key_as_file(argv[3]);
			auto fname = cypher.encrypt_file(argv[2]);

			std::cout << "Finish. File saved as: "
				<< fname << std::endl;
			std::cout << "Key saved as: "
				<< fkeyname << std::endl;
			return 0;
		}
		catch (std::runtime_error & e) 
		{
			std::cout << e.what() << std::endl;
		}
		catch (...)
		{
			std::cout << "Error. Something went wrong..." << std::endl;
		}

	}

	if (!strcmp(argv[1], "decode"))
	{
		std::cout << "starting decryption..." << std::endl;

		magenta cypher;

		try
		{
			cypher.load_key_from_file(argv[3]);
			auto fname = cypher.encrypt_file(argv[2]);

			std::cout << "Finish. File saved as: "
				<< fname << std::endl;
			return 0;
		}
		catch (std::runtime_error & e)
		{
			std::cout << e.what() << std::endl;
		}
		catch (...)
		{
			std::cout << "Error. Something went wrong..." << std::endl;
		}

	}

	std::cout << "Wrong command name!" << std::endl;
	std::cout << usage << std::endl;
	
	return -1;
}

#ifdef ENABLE_TEST
void create_random_filled_file(std::string fname, size_t size)
{
	std::ofstream file(fname, std::ios_base::trunc | std::ios_base::binary);
	std::random_device rd;
	std::mt19937_64 generator(rd());
	std::uniform_int_distribution<int32_t> distribution;

	std::vector<char> data(size);
	std::generate(data.begin(), data.end(),
		[&distribution, &generator]() { return distribution(generator); });

	file.write(const_cast<const char*>(data.data()), data.size());
	file.close();
}

bool files_are_equal(std::string fname1, std::string fname2)
{
	std::ifstream f1(fname1, std::ios_base::binary);
	std::ifstream f2(fname2, std::ios_base::binary);

	f1.seekg(0, std::ios::end);
	f2.seekg(0, std::ios::end);
	std::streampos s1 = f1.tellg(), s2 = f2.tellg();
	f1.seekg(0, std::ios::beg);
	f2.seekg(0, std::ios::beg);

	if (s1 != s2)
	{
		return false;
	}

	size_t buf_sz = 64 * 1024;

	while (!f1.eof())
	{
		std::vector<char> dt1(buf_sz);
		std::vector<char> dt2(buf_sz);

		f1.read(dt1.data(), buf_sz);
		f2.read(dt2.data(), buf_sz);

		if (dt1 != dt2)
		{
			return false;
		}
	}

	return true;
}
#endif // ENABLE_TEST