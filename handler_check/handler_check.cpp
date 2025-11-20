#include "memory.h"
#include "anti_handler.h"
#include <iostream>

int main()
{
	//add some veh installs or set veh with debugger

	auto veh_scan_result = anti_debug::scan_vectored_exception_handlers();
	if (!veh_scan_result)
	{
		printf("Error: scan_vectored_exception_handlers().%s\n", veh_scan_result.error().c_str());
		return 1;
	}

	auto vehs = *veh_scan_result;
	if (vehs.empty())
	{
		printf("VEH was not detected.\n");
		return 0;
	}

	printf("-->Detected VEH List\n");
	for (auto& veh : vehs)
	{
		printf("> 0x%IIx\n", veh);
	}

	return 0;
}