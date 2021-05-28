#include <stdio.h>

int main(int argc, char** argv)
{
	int a = atoi(argv[1]);
	switch (a)
	{
		case 1:
			puts("1");
			break;
		case 2:
			puts("2");
			break;
		case 3:
		case 4:
		case 5:
		case 1337:
			puts("tri");
			break;
		case 1000:
			printf("%d asdf \n", 1000);
		default:
			puts("idi nahuy");
	}

	return 0;
}
