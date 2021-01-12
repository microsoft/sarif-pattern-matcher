#include <stdlib.h>   // For _MAX_PATH definition
#include <stdio.h>
#include <malloc.h>

int main()
{
    char* string;

    // Allocate space for a path name
    string = _alloca(_MAX_PATH);

    // In a C++ file, explicitly cast malloc's return.  For example,
    // string = (char *)malloc( _MAX_PATH );

    if (string == NULL)
        printf("Insufficient memory available\n");
    else
    {
        printf("Memory space allocated for path name\n");
        free(string);
        printf("Memory freed\n");
    }
}
