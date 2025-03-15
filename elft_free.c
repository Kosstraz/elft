#include "elft.h"

void	elft_free_shfinder(t_elf_shfinder* shf)
{
	if (shf)
	{
		free(shf->f);
		free(shf);
	}
}

void	elft_free_phfinder(t_elf_phfinder* phf)
{
	if (phf)
	{
		free(phf->f);
		free(phf);
	}
}

void	elft_free_symfinder(t_elf_symfinder* symf)
{
	if (symf)
	{
		elft_free_shfinder(symf->shf);
		free(symf->name);
		free(symf);
	}
}
