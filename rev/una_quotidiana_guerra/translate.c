#include <stdio.h>
#include <stdlib.h>
#include <string.h>

char dict[] = "abcdefghijklmnopqrstuvwxyz.:_-=/{}ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
char flag[] = "HDVIC8tq8}Es/{-}JOPJAHHJQ.=Y5rAHJWEtRgSc";  

int indexof(char chr)
{
	for (int i = 0; i < strlen(dict); i++)
	{
		if (chr == dict[i])
		{
			return i;
		}
	}
	return 0;
}

void print_flag()
{
	for (int i = 0; i < strlen(flag); i++)
	{
		flag[i] = dict[(indexof(flag[i]) + strlen(dict) - i) % strlen(dict)];
	}
	printf("%s\n", flag);
}

int main()
{
	printf("Kilometri di kilometri di kilometri di kilometri\n");
	print_flag();
	return 0;
}

// HCTF{3nj0y_https://youtu.be/DYeklxeUpFo}
