#include "workspace/workspace.h"

auto main( ) -> int
{
	manualmap map( INJECTION_TYPE::USERMODE );

	if ( !map.attach( "notepad.exe" ) )
		return 1;

	if ( !map.load_dll( "module.dll" ) )
		return 1;

	if ( !map.inject( ) )
		return 1;

	return 0;
}