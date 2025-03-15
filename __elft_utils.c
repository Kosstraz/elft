#include "elft.h"

void*	__elft_ret(t_elf* elft, int code)
{
	elft->err = code;
	return (NULL);
}

int	__elft_iret(t_elf* elft, int code)
{
	elft->err = code;
	return (-1);
}
