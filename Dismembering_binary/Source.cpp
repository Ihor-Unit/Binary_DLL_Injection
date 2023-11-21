//https://web.archive.org/web/20111024201441/http://wasm.ru/article.php?article=green2red02#_Toc100906485

#include <iostream>
#include <fstream>
#include <string>
#include <vector>

#include "import_functions.h"

extern "C" __declspec(dllimport)
int mult(int a, int b);

using namespace std;



void copy_to_str(const vector<char>& buff, string& str) {
	const char* copying = buff.data();
	for (size_t i{}; i < buff.size(); i++) {
		auto a = copying[i];
		if (copying[i] == '\0')
			str.push_back('\0');
		else
			str.push_back(copying[i]);
	}
}

int main() {
	get_names_from_import_table("A:\\[1]IMPORTANT\\Desktop\\REverce\\p7.exe");

	std::ifstream inputFile("A:\\[1]IMPORTANT\\Desktop\\VS\\Project1\\x64\\Debug\\another.exe", std::ios::binary);

	if (!inputFile.is_open()) {
		std::cerr << "Error opening file: " << std::endl;
		return 1;
	}

	inputFile.seekg(0, std::ios::end);
	std::streampos fileSize = inputFile.tellg();
	inputFile.seekg(0, std::ios::beg);

	std::vector<char> buffer(fileSize);
	inputFile.read(buffer.data(), fileSize);

	string str;
	copy_to_str(buffer, str);

	auto a = str.length();

	/*auto pos = str.find("running");
	str.erase(pos, 7);
	str.insert(pos, "fucking with C++");*/

	/* for (size_t i{}; i < fileSize; i++) {
		 std::cout << buffer[i];
	 }*/


	inputFile.close();







	ofstream outFile("A:\\[1]IMPORTANT\\Desktop\\VS\\Project1\\x64\\Debug\\another_copy.exe", std::ios::binary);

	if (!outFile.is_open()) {
		std::cerr << "Error opening the output file: " << std::endl;
		return 1;
	}

	outFile.write(str.c_str(), str.length());
}