#include <stdlib.h>   // For _MAX_PATH definition
#include <stdio.h>
#include <malloc.h>

int main()
{
	void* pData = NULL;

	// Allocate space for a path name
	pData = _malloca(_MAX_PATH);

	// In a C++ file, explicitly cast malloc's return.  For example,
	// string = (char *)malloc( _MAX_PATH );

	if (pData != NULL)
	{
		free(pData);
	}
}
