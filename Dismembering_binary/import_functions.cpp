#include <iostream>
#include <fstream>
#include <vector>
#include <Windows.h>

#include "import_functions.h"

typedef unsigned long long		QWORD;

int get_names_from_import_table(const std::string const &filename) {
	// Replace "your_program.exe" with the actual filename

	// Open the file for reading in binary mode
	std::ifstream fileStream(filename, std::ios::binary);

	if (!fileStream.is_open()) {
		std::cerr << "Error opening file: " << filename << std::endl;
		return 1;
	}

	fileStream.seekg(0, std::ios::end);
	std::streampos fileSize = fileStream.tellg();
	fileStream.seekg(0, std::ios::beg);
	std::vector<char> fileData(fileSize);
	fileStream.read(fileData.data(), fileSize);

	// Close the file
	fileStream.close();


	// Read DOS header to determine the offset to PE header
	IMAGE_DOS_HEADER* dosHeader;
	dosHeader = reinterpret_cast<IMAGE_DOS_HEADER*>(fileData.data());

	// Read the entire PE header (starting from the PE\0\0 signature)
	IMAGE_NT_HEADERS64* imageNTHeaders;
	auto a = sizeof(IMAGE_NT_HEADERS64);
	//fileStream.read(reinterpret_cast<char*>(&imageNTHeaders), sizeof(imageNTHeaders));



	imageNTHeaders = reinterpret_cast<IMAGE_NT_HEADERS64*>(fileData.data() + dosHeader->e_lfanew);



	QWORD sectionSize = static_cast<QWORD>(sizeof(IMAGE_SECTION_HEADER));

	// Locate the RVA of the Import Data Directory
	//https://learn.microsoft.com/en-us/windows/win32/debug/pe-format#optional-header-windows-specific-fields-image-only
	IMAGE_OPTIONAL_HEADER64* optionalHeader = &imageNTHeaders->OptionalHeader;

	QWORD importDirectoryRVA = optionalHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress;
	//here we have the address of the import table, but we don't know in what section it is located


	IMAGE_SECTION_HEADER* sectionHeader{};
	IMAGE_SECTION_HEADER* importSection{};

	// get modified pointer of the data string to the first section header
	QWORD sectionLocation = reinterpret_cast<QWORD>(imageNTHeaders) + sizeof(DWORD)/*?because all sections are terminated with a NULL DWORD?*/ +
		static_cast<QWORD>(sizeof(IMAGE_FILE_HEADER)) +
		static_cast<QWORD>(imageNTHeaders->FileHeader.SizeOfOptionalHeader);

	//looking fot the section where is the import directory table located
	for (int i = 0; i < imageNTHeaders->FileHeader.NumberOfSections; i++) {
		sectionHeader = reinterpret_cast<IMAGE_SECTION_HEADER*>(sectionLocation);
		// PointerToRawData == offset, if RVA is outside any section then PointerToRawData == offset == RVA

		// save section that contains import directory table
		if (importDirectoryRVA >= sectionHeader->VirtualAddress && importDirectoryRVA < sectionHeader->VirtualAddress + sectionHeader->Misc.VirtualSize) {
			importSection = sectionHeader;
		}
		sectionLocation += sectionSize;
	}

	// get file offset to import table
	QWORD rawOffset = (QWORD)fileData.data() + importSection->PointerToRawData;
	//																																												  (here we get the offset relatively to the beginning of the section)														
	// get pointer to import descriptor's file offset. Note that the formula for calculating file offset is: imageBaseAddress + pointerToRawDataOfTheSectionContainingRVAofInterest + (RVAofInterest - SectionContainingRVAofInterest.VirtualAddress)

	//printf("\t%s\n", rawOffset + ((imageNTHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress - importSection->VirtualAddress)));
	IMAGE_IMPORT_DESCRIPTOR* importDescriptor = reinterpret_cast<IMAGE_IMPORT_DESCRIPTOR*>(rawOffset + (imageNTHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress - importSection->VirtualAddress));

	QWORD thunk;
	IMAGE_THUNK_DATA* thunkData;
	printf("\n******* DLL IMPORTS *******\n");
	for (; importDescriptor->Name != 0; importDescriptor++) {
		/*
		printf("\t%s\n", rawOffset + (importDescriptor->Name - importSection->VirtualAddress));
		
		this is fucking offset which is calculated by the following formula: 
			sectionWhereIsTheRVA->PointerToRawData + (RVA - sectionWhereIsTheRVA->VirtualAddress)

		 ~ importSection->VirtualAddress -> the address of the first byte of the section relative to the image base when the section is loaded into memory
		 ~ importDescriptor->Name -> The address of an ASCII string that contains the name of the DLL. This address is relative to the image base. 
		 ~ (importDescriptor->Name - importSection->VirtualAddress) -> this RVAs is RELATIVE TO the 
		IMPORT TABLE. To get the actual offset in the file you have to add  
		`importSection->PointerToRawData` to the result of the expression
		*/
		printf("\t%s\n", rawOffset + (importDescriptor->Name - importSection->VirtualAddress));
		thunk = importDescriptor->OriginalFirstThunk == 0 ? importDescriptor->FirstThunk : importDescriptor->OriginalFirstThunk;
		thunkData = (IMAGE_THUNK_DATA*)(rawOffset + (thunk - importSection->VirtualAddress));

		// dll exported functions
		for (; thunkData->u1.AddressOfData != 0; thunkData++) {
			//a cheap and probably non-reliable way of checking if the function is imported via its ordinal number ¯\_(ツ)_/¯
			if (thunkData->u1.AddressOfData > 0x80000000) {
				//show lower bits of the value to get the ordinal ¯\_(ツ)_/¯
				printf("\t\tOrdinal: %x\n", (WORD)thunkData->u1.AddressOfData);
			}
			else {
				//name of an imported function                                                                                  
				printf("\t\t%s\n", (rawOffset + (thunkData->u1.AddressOfData - importSection->VirtualAddress + 2)));
			}
		}

	}
}