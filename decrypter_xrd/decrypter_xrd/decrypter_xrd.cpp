// decrypter_xrd.cpp : 定义控制台应用程序的入口点。
//

#include "stdafx.h"
#include <iostream>
#include <fstream>
#include <memory>
#include <string>
#include <algorithm>

void process_crypt_table(unsigned *crypt_table)
{
	for (auto i = 0; i < 227; i++)
	{
		crypt_table[i] =
			crypt_table[i + 397] ^
			((crypt_table[i + 1] & 1) != 0 ? 0x9908B0DF : 0) ^
			((crypt_table[i] ^ (crypt_table[i + 1] ^ crypt_table[i]) & 0x7FFFFFFE) >> 1);
	}
	for (auto i = 0; i < 396; i++)
	{
		crypt_table[i + 227] =
			crypt_table[i] ^
			((crypt_table[i + 228] & 1) != 0 ? 0x9908B0DF : 0) ^
			((crypt_table[i + 227] ^ (crypt_table[i + 228] ^ crypt_table[i + 227]) & 0x7FFFFFFE) >> 1);
	}

	crypt_table[623] =
		crypt_table[396] ^
		((crypt_table[0] & 1) != 0 ? 0x9908B0DF : 0) ^
		((crypt_table[623] ^ (crypt_table[0] ^ crypt_table[623]) & 0x7FFFFFFE) >> 1);
}

void decrypt(const char *name)
{
	std::ifstream in(name, std::ios::binary);
	if (!in)
	{
		std::cerr << "Couldn't open " << name << std::endl;
		return;
	}

	auto cppname = std::string(name);
	std::ofstream out(cppname + ".decrypted", std::ios::binary);

	// Remove path
	const auto slash_it = std::find(cppname.rbegin(), cppname.rend(), '/');
	if (slash_it != cppname.rend())
		cppname.erase(cppname.begin(), slash_it.base());

	const auto bslash_it = std::find(cppname.rbegin(), cppname.rend(), '\\');
	if (bslash_it != cppname.rend())
		cppname.erase(cppname.begin(), bslash_it.base());

	// Uppercase
	std::transform(cppname.begin(), cppname.end(), cppname.begin(), toupper);

	// Use the uppercase filename to seed the crypto algorithm
	auto crypt_seed = 0;
	for (auto &c : cppname)
		crypt_seed = c + 137 * crypt_seed;

	in.seekg(0, std::ios::end);
	const auto size = (int)(in.tellg());
	in.seekg(0);

	auto buf = std::make_unique<unsigned[]>(size / 4);
	in.read((char*)(buf.get()), size);

	unsigned crypt_table[624];
	crypt_table[0] = crypt_seed;
	for (auto i = 1; i < 624; i++)
	{
		const auto last = crypt_table[i - 1];
		crypt_table[i] = i + 0x6C078965 * (last ^ (last >> 30));
	}

	auto last_out = 0x43415046u;
	for (auto i = 0; i < size / 4; i++)
	{
		if (i % 624 == 0)
			process_crypt_table(crypt_table);

		const auto entry = crypt_table[i % 624];
		const auto key =
			(((((((entry >> 11) ^ entry) & 0xFF3A58AD) << 7) ^ (entry >> 11) ^ entry) & 0xFFFFDF8C) << 15) ^
			((((entry >> 11) ^ entry) & 0xFF3A58AD) << 7) ^
			(entry >> 11) ^
			entry;

		last_out ^= buf[i] ^ (key ^ (key >> 18));
		out.write((char*)(&last_out), 4);
	}
}

int main(const int argc, const char *argv[])
{
	if (argc <= 1)
	{
		std::cerr << "decrypter_xrd <filename1> <filename2> etc" << std::endl;
		return EXIT_FAILURE;
	}

	for (auto i = 1; i < argc; i++)
	{
		decrypt(argv[i]);
		if (remove(argv[i]) == 0)
		{
			auto cppname = std::string(argv[i]);
			cppname += ".decrypted";
			rename(cppname.c_str(), argv[i]);
		}
	}

	return 0;
}