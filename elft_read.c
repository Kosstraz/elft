#include "elft.h"

int	elft_read_header(t_elf* elft)
{
	elft->header = (t_elf_header*)elft_get_raw(elft)->data;
	elft->bits = elft->header->identification_field.bits_archi;
	return (0);
}

int	elft_read_section_headers(t_elf* elft)
{
	if (elft->header == NULL)
		return (elft->err = ELFT_NEED_TO_READ_HEADER,
				-1);
	elft->sHeaders = malloc(elft->header->section_headers_count * sizeof(t_elf_section_header*));
	if (!elft->sHeaders)
		return (elft->err = ELFT_MALLOC_FAILED,
				-1);
	for (elftUWord i = 0 ; i < elft->header->section_headers_count ; ++i)
		elft->sHeaders[i] = (t_elf_section_header*)(elft_get_raw(elft)->data + elft->header->section_headers_offset + i * sizeof(t_elf_section_header));
	return (0);
}

int	elft_read_program_headers(t_elf* elft)
{
	if (elft->header == NULL)
		return (elft->err = ELFT_NEED_TO_READ_HEADER,
				-1);
	elft->pHeaders = malloc(elft->header->program_headers_count * sizeof(t_elf_program_header*));
	if (!elft->pHeaders)
		return (elft->err = ELFT_MALLOC_FAILED,
				-1);
	for (elftUWord i = 0 ; i < elft->header->program_headers_count ; ++i)
		elft->pHeaders[i] = (t_elf_program_header*)(elft_get_raw(elft)->data + elft->header->program_headers_offset + i * sizeof(t_elf_program_header));
	return (0);
}

int	elft_read_shstrtab(t_elf* elft)
{
	if (elft->sHeaders == NULL)
		return (elft->err = ELFT_NEED_TO_READ_SHEADERS,
				-1);
	t_elf_shfinder* shf = elft_find_shstrtab_header(elft);
	
	elft_get_raw(elft)->shstrtab = shf->f->data;
	elft_get_raw(elft)->shstrtab_size = shf->f->size;
	elft_free_sfinder(shf);
	return (elft->err);
}
