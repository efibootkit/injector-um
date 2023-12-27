#include "map.h"

manualmap::manualmap( INJECTION_TYPE type )
{
	if ( type == INJECTION_TYPE::USERMODE )
	proc = std::make_unique<usermode_proc_handler>( );
}

bool manualmap::attach( const char* process_name )
{
	this->process_name = process_name;

	if ( !proc->attach( process_name ) )
	{
		LOG_ERROR( "Unable to attach to process!" );
		std::cin.get( );
		return false;
	}

	LOG( "Handling %s process context" , process_name );
	return true;
}

bool manualmap::load_dll( const char* file_name )
{
	std::ifstream f( file_name , std::ios::binary | std::ios::ate );

	if ( !f )
	{
		LOG_ERROR( "Unable to open DLL file!" );
		std::cin.get( );
		return false;
	}

	std::ifstream::pos_type pos{ f.tellg( ) };
	data_size = pos;

	raw_data = new uint8_t[ data_size ];

	if ( !raw_data ) return false;

	f.seekg( 0 , std::ios::beg );
	f.read( ( char* ) raw_data , data_size );

	f.close( );
	return true;
}

bool manualmap::inject( )
{
	if ( !proc->is_attached( ) )
	{
		LOG_ERROR( "Not attached to process!" );
		std::cin.get( );
		return false;
	}

	if ( !raw_data )
	{
		LOG_ERROR( "Data buffer is empty!" );
		std::cin.get( );
		return false;
	}

	// Credits to VM for dll_stub
	uint8_t dll_stub [ ] = { "\x51\x52\x55\x56\x53\x57\x41\x50\x41\x51\x41\x52\x41\x53\x41\x54\x41\x55\x41\x56\x41\x57\x48\xB8\xFF\x00\xDE\xAD\xBE\xEF\x00\xFF\x48\xBA\xFF\x00\xDE\xAD\xC0\xDE\x00\xFF\x48\x89\x10\x48\x31\xC0\x48\x31\xD2\x48\x83\xEC\x28\x48\xB9\xDE\xAD\xBE\xEF\xDE\xAD\xBE\xEF\x48\x31\xD2\x48\x83\xC2\x01\x48\xB8\xDE\xAD\xC0\xDE\xDE\xAD\xC0\xDE\xFF\xD0\x48\x83\xC4\x28\x41\x5F\x41\x5E\x41\x5D\x41\x5C\x41\x5B\x41\x5A\x41\x59\x41\x58\x5F\x5B\x5E\x5D\x5A\x59\x48\x31\xC0\xC3" };

	IMAGE_DOS_HEADER* dos_header{ ( IMAGE_DOS_HEADER* ) raw_data };
	if ( dos_header->e_magic != IMAGE_DOS_SIGNATURE )
	{
		LOG_ERROR( "Invalid DOS header signature!" );
		std::cin.get( );
		return false;
	}

	IMAGE_NT_HEADERS* nt_header{ ( IMAGE_NT_HEADERS* ) ( &raw_data[ dos_header->e_lfanew ] ) };
	if ( nt_header->Signature != IMAGE_NT_SIGNATURE )
	{
		LOG_ERROR( "Invalid NT header signature!" );
		std::cin.get( );
		return false;
	}

	uint64_t base{ proc->virtual_alloc( nt_header->OptionalHeader.SizeOfImage, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE ) };
	if ( !base )
	{
		LOG_ERROR( "Unable to allocate memory for the image!" );
		std::cin.get( );
		return false;
	}

	LOG( "Image base: 0x%p" , base );

	uint64_t stub_base{ proc->virtual_alloc( sizeof( dll_stub ), MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE ) };
	if ( !stub_base )
	{
		LOG_ERROR( "Unable to allocate memory for the stub!" );
		std::cin.get( );
		return false;
	}

	LOG( "Stub base: 0x%p" , stub_base );

	PIMAGE_IMPORT_DESCRIPTOR import_descriptor{ ( PIMAGE_IMPORT_DESCRIPTOR ) get_ptr_from_rva( ( uint64_t ) ( nt_header->OptionalHeader.DataDirectory[ IMAGE_DIRECTORY_ENTRY_IMPORT ].VirtualAddress ), nt_header, raw_data ) };
	if ( nt_header->OptionalHeader.DataDirectory[ IMAGE_DIRECTORY_ENTRY_IMPORT ].Size )
	{
		LOG( "Fixing imports" );
		solve_imports( raw_data , nt_header , import_descriptor );
	}

	PIMAGE_BASE_RELOCATION base_relocation{ ( PIMAGE_BASE_RELOCATION ) get_ptr_from_rva( nt_header->OptionalHeader.DataDirectory[ IMAGE_DIRECTORY_ENTRY_BASERELOC ].VirtualAddress, nt_header, raw_data ) };
	if ( nt_header->OptionalHeader.DataDirectory[ IMAGE_DIRECTORY_ENTRY_BASERELOC ].Size )
	{
		LOG( "Fixing relocations..." );
		solve_relocations( ( uint64_t ) raw_data , base , nt_header , base_relocation , nt_header->OptionalHeader.DataDirectory[ IMAGE_DIRECTORY_ENTRY_BASERELOC ].Size );
	}

	if ( !parse_imports( ) )
	{
		LOG_ERROR( "Unable to parse imports!" );
		std::cin.get( );
		return false;
	}

	uint64_t iat_function_ptr{ imports[ "TranslateMessage" ] };
	if ( !iat_function_ptr )
	{
		LOG_ERROR( "Cannot find import" );
		std::cin.get( );
		return false;
	}

	uint64_t orginal_function_addr{ read_memory<uint64_t>( iat_function_ptr ) };
	LOG( "IAT function pointer: 0x%p" , iat_function_ptr );

	*( uint64_t* ) ( dll_stub + 0x18 ) = iat_function_ptr;
	*( uint64_t* ) ( dll_stub + 0x22 ) = orginal_function_addr;

	proc->write_memory( base , ( uintptr_t ) raw_data , nt_header->FileHeader.SizeOfOptionalHeader + sizeof( nt_header->FileHeader ) + sizeof( nt_header->Signature ) );

	LOG( "Mapping PE sections..." );
	map_pe_sections( base , nt_header );

	uint64_t entry_point{ ( uint64_t ) base + nt_header->OptionalHeader.AddressOfEntryPoint };

	*( uint64_t* ) ( dll_stub + 0x39 ) = ( uint64_t ) base;
	*( uint64_t* ) ( dll_stub + 0x4a ) = entry_point;

	LOG( "Module entry point: 0x%p" , entry_point );

	proc->write_memory( stub_base , ( uintptr_t ) dll_stub , sizeof( dll_stub ) );
	proc->virtual_protect( iat_function_ptr , sizeof( uint64_t ) , PAGE_READWRITE );
	proc->write_memory( iat_function_ptr , ( uintptr_t ) &stub_base , sizeof( uint64_t ) );

	LOG( "Injected." );

	std::cin.get( );
	proc->virtual_protect( iat_function_ptr , sizeof( uint64_t ) , PAGE_READONLY );

	delete [ ] raw_data;

	exit( 0 );
	return true;
}

uint64_t* manualmap::get_ptr_from_rva( uint64_t rva , IMAGE_NT_HEADERS* nt_header , uint8_t* image_base )
{
	PIMAGE_SECTION_HEADER section_header{ get_enclosing_section_header( rva, nt_header ) };
	if ( !section_header ) return 0;

	int64_t delta{ ( int64_t ) ( section_header->VirtualAddress - section_header->PointerToRawData ) };
	return ( uint64_t* ) ( image_base + rva - delta );
}

PIMAGE_SECTION_HEADER manualmap::get_enclosing_section_header( uint64_t rva , PIMAGE_NT_HEADERS nt_header )
{
	PIMAGE_SECTION_HEADER section{ IMAGE_FIRST_SECTION( nt_header ) };

	for ( int i = 0; i < nt_header->FileHeader.NumberOfSections; i++ , section++ )
	{
		uint64_t size{ section->Misc.VirtualSize };
		if ( !size )
			size = section->SizeOfRawData;

		if ( ( rva >= section->VirtualAddress ) &&
			( rva < ( section->VirtualAddress + size ) ) )
			return section;
	}

	return 0;
}

void manualmap::solve_imports( uint8_t* base , IMAGE_NT_HEADERS* nt_header , IMAGE_IMPORT_DESCRIPTOR* import_descriptor )
{
	char* module;
	while ( ( module = ( char* ) get_ptr_from_rva( ( DWORD64 ) ( import_descriptor->Name ) , nt_header , ( PBYTE ) base ) ) )
	{
		HMODULE local_module{ LoadLibrary( module ) };
		IMAGE_THUNK_DATA* thunk_data{ ( IMAGE_THUNK_DATA* ) get_ptr_from_rva( ( DWORD64 ) ( import_descriptor->FirstThunk ), nt_header, ( PBYTE ) base ) };

		while ( thunk_data->u1.AddressOfData )
		{
			IMAGE_IMPORT_BY_NAME* iibn{ ( IMAGE_IMPORT_BY_NAME* ) get_ptr_from_rva( ( DWORD64 ) ( ( thunk_data->u1.AddressOfData ) ), nt_header, ( PBYTE ) base ) };
			thunk_data->u1.Function = ( uint64_t ) ( get_proc_address( module , ( char* ) iibn->Name ) );
			thunk_data++;
		}

		import_descriptor++;
	}

	return;
}

void manualmap::solve_relocations( uint64_t base , uint64_t relocation_base , IMAGE_NT_HEADERS* nt_header , IMAGE_BASE_RELOCATION* reloc , size_t size )
{
	uint64_t image_base{ nt_header->OptionalHeader.ImageBase };
	uint64_t delta{ relocation_base - image_base };
	unsigned int bytes{ 0 };

	while ( bytes < size )
	{
		uint64_t* reloc_base{ ( uint64_t* ) get_ptr_from_rva( ( uint64_t ) ( reloc->VirtualAddress ), nt_header, ( PBYTE ) base ) };
		auto num_of_relocations{ ( reloc->SizeOfBlock - sizeof( IMAGE_BASE_RELOCATION ) ) / sizeof( WORD ) };
		auto reloc_data = ( uint16_t* ) ( ( uint64_t ) reloc + sizeof( IMAGE_BASE_RELOCATION ) );

		for ( unsigned int i = 0; i < num_of_relocations; i++ )
		{
			if ( ( ( *reloc_data >> 12 ) & IMAGE_REL_BASED_HIGHLOW ) )
			*( uint64_t* ) ( ( uint64_t ) reloc_base + ( ( uint64_t ) ( *reloc_data & 0x0FFF ) ) ) += delta;
			reloc_data++;
		}

		bytes += reloc->SizeOfBlock;
		reloc = ( IMAGE_BASE_RELOCATION* ) reloc_data;
	}

	return;
}

void manualmap::map_pe_sections( uint64_t base , IMAGE_NT_HEADERS* nt_header )
{
	auto header{ IMAGE_FIRST_SECTION( nt_header ) };
	size_t virtual_size{ 0 };
	size_t bytes{ 0 };

	while ( nt_header->FileHeader.NumberOfSections && ( bytes < nt_header->OptionalHeader.SizeOfImage ) )
	{
		proc->write_memory( base + header->VirtualAddress , ( uintptr_t ) ( raw_data + header->PointerToRawData ) , header->SizeOfRawData );
		virtual_size = header->VirtualAddress;
		virtual_size = ( ++header )->VirtualAddress - virtual_size;
		bytes += virtual_size;

		// Todo: Add page protection
	}

	return;
}

uint64_t manualmap::get_proc_address( const char* module_name , const char* func )
{
	uint64_t remote_module{ proc->get_module_base( module_name ) };
	uint64_t local_module{ ( uint64_t ) GetModuleHandle( module_name ) };
	uint64_t delta{ remote_module - local_module };

	return ( ( uint64_t ) GetProcAddress( ( HMODULE ) local_module , func ) + delta );
}

bool manualmap::parse_imports( )
{
	auto base{ proc->get_module_base( process_name.c_str( ) ) };
	if ( !base )
	{
		LOG_ERROR( "Cannot get module base" );
		std::cin.get( );
		return false;
	}

	auto dos_header{ read_memory< IMAGE_DOS_HEADER >( base ) };
	auto nt_headers{ read_memory< IMAGE_NT_HEADERS >( base + dos_header.e_lfanew ) };
	auto descriptor{ read_memory< IMAGE_IMPORT_DESCRIPTOR >( base + nt_headers.OptionalHeader.DataDirectory[ 1 ].VirtualAddress ) };

	int descriptor_count{ 0 };
	int thunk_count{ 0 };

	while ( descriptor.Name )
	{
		auto first_thunk{ read_memory< IMAGE_THUNK_DATA >( base + descriptor.FirstThunk ) };
		auto original_first_thunk{ read_memory< IMAGE_THUNK_DATA >( base + descriptor.OriginalFirstThunk ) };
		thunk_count = 0;

		while ( original_first_thunk.u1.AddressOfData )
		{
			char name[ 256 ];
			proc->read_memory( base + original_first_thunk.u1.AddressOfData + 0x2 , ( uintptr_t ) name , 256 );
			std::string str_name( name );
			auto thunk_offset{ thunk_count * sizeof( uintptr_t ) };

			if ( str_name.length( ) > 0 ) imports[ str_name ] = base + descriptor.FirstThunk + thunk_offset;

			++thunk_count;
			first_thunk = read_memory< IMAGE_THUNK_DATA >( base + descriptor.FirstThunk + sizeof( IMAGE_THUNK_DATA ) * thunk_count );
			original_first_thunk = read_memory< IMAGE_THUNK_DATA >( base + descriptor.OriginalFirstThunk + sizeof( IMAGE_THUNK_DATA ) * thunk_count );
		}

		++descriptor_count;
		descriptor = read_memory< IMAGE_IMPORT_DESCRIPTOR >( base + nt_headers.OptionalHeader.DataDirectory[ 1 ].VirtualAddress + sizeof( IMAGE_IMPORT_DESCRIPTOR ) * descriptor_count );
	}

	return ( imports.size( ) > 0 );
}