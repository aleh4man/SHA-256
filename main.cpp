#include "SHA-256.h"
#include <ctime>

int main(int argc, char* argv[]) {
	//if (argc < 2) {
	//	std::cout << "ERROR: One or two arguments are missing!";
	//	return -1;
	//}
	//std::string option = std::string(argv[1]);
	std::string sourse;
	std::cout << "Enter the string:\n";
	std::getline(std::cin, sourse);
	SHA_256 a;
	
	clock_t beg = clock();
	a.count_hash(sourse);
	clock_t total = clock() - beg;
	std::cout << "\nProgram ended\ntime: " << ((float)total / CLK_TCK) << '\n';


	return 0;
}