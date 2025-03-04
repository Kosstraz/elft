#include "elft.h"

void	elft_free_sfinder(t_elf_shfinder* shf)
{
	free(shf->f);
	free(shf);
}

void	elft_free_pfinder(t_elf_phfinder* phf)
{
	free(phf->f);
	free(phf);
}

void	elft_free_finder(t_elf_symfinder* symf)
{
	elft_free_sfinder(symf->shf);
	free(symf);
}
