rule VmStub 
{
	strings: 
		$hex_string = { 60 9C 9C 59 ?? ?? 8B 5C 24 24 8B 54 24 28 E8 00 00 00 00 5C 8B A4 24 E1 FE FF FF 55 ?? ?? 83 EC 2C 89 44 24 28 89 0C 24 ?? ?? 8D 7C 24 04 ?? ?? 46 8A 02 32 42 01 ?? ?? ?? 50 56 57 E8 D8 05 00 00 } 
	condition: 
		$hex_string
}