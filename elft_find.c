#include "elft.h"

static int	next_sym_count = 0;

t_elf_shfinder*	elft_find_shstrtab_header(t_elf* elft)
{
	if (elft->sHeaders == NULL)
		return (elft->err = ELFT_NEED_TO_READ_SHEADERS,
				NULL);
	t_elf_shfinder*	shf = malloc(sizeof(t_elf_shfinder));
	if (!shf)
		return (elft->err = ELFT_MALLOC_FAILED,
				NULL);
	shf->f = malloc(sizeof(t_elf_finder));
	if (!shf->f)
		return (elft->err = ELFT_MALLOC_FAILED,
				elft_free_shfinder(shf),
				NULL);
	shf->header = elft->sHeaders[elft->header->sections_names_index];
	shf->f->data = elft_get_raw(elft)->data + shf->header->offset;
	shf->f->size = shf->header->size;
	strncpy(shf->name, ".shstrtab", 16);
	return (shf);
}

t_elf_shfinder*	elft_find_sectionH_by_name(t_elf* elft, const char* sname)
{
	if (elft_get_raw(elft)->shstrtab == NULL)
		return (elft->err = ELFT_NEED_TO_READ_SHSTRTAB,
				NULL);
	t_elf_shfinder*	shf = malloc(sizeof(t_elf_shfinder));
	if (!shf)
		return (elft->err = ELFT_MALLOC_FAILED,
				NULL);
	shf->f = malloc(sizeof(t_elf_finder));
	if (!shf->f)
		return (elft->err = ELFT_MALLOC_FAILED,
				elft_free_shfinder(shf),
				NULL);
	unsigned int	i = 0;
	for ( ; i < elft->header->section_headers_count ; ++i)
	{
		if (!strcmp(elft_get_raw(elft)->shstrtab + elft->sHeaders[i]->name_offset, sname))
			break ;
	}
	if (i == elft->header->section_headers_count)
		return (elft_free_shfinder(shf),
				elft->err = ELFT_SHEADER_NOT_EXIST,
				NULL);
	shf->header = elft->sHeaders[i];
	shf->f->data = elft_get_raw(elft)->data + elft->sHeaders[i]->offset;
	shf->f->size = elft->sHeaders[i]->size;
	strncpy(shf->name, sname, 16);
	elft->err = ELFT_SUCCESS;
	return (shf);
}

t_elf_shfinder*	elft_find_sectionH_by_type(t_elf* elft, elftUDouble ELFTSH_type)
{
	if (elft_get_raw(elft)->shstrtab == NULL)
		return (elft->err = ELFT_NEED_TO_READ_SHSTRTAB,
				NULL);
	t_elf_shfinder*	shf = malloc(sizeof(t_elf_shfinder));
	if (!shf)
		return (elft->err = ELFT_MALLOC_FAILED,
				NULL);
	shf->f = malloc(sizeof(t_elf_finder));
	if (!shf->f)
		return (elft->err = ELFT_MALLOC_FAILED,
				elft_free_shfinder(shf),
				NULL);
	unsigned int	i = 0;
	for ( ; i < elft->header->section_headers_count ; ++i)
	{
		if (elft->sHeaders[i]->type == ELFTSH_type)
			break ;
	}
	if (i == elft->header->section_headers_count)
		return (elft_free_shfinder(shf),
				elft->err = ELFT_SHEADER_NOT_EXIST,
				NULL);
	shf->header = elft->sHeaders[i];
	shf->f->data = elft_get_raw(elft)->data + elft->sHeaders[i]->offset;
	shf->f->size = elft->sHeaders[i]->size;
	strncpy(shf->name, elft_get_raw(elft)->shstrtab + elft->sHeaders[i]->name_offset, 16);
	elft->err = ELFT_SUCCESS;
	return (shf);
}

/*t_elf_phfinder*	elft_find_programH_by_type(t_elf* elft, elftDouble ELFTPH_type)
{
	if (elft_get_raw(elft)->shstrtab == NULL)
		return (elft->err = ELFT_NEED_TO_READ_SHSTRTAB,
				NULL);
	t_elf_phfinder*	phf = malloc(sizeof(t_elf_phfinder));
	if (!phf)
		return (elft->err = ELFT_MALLOC_FAILED,
				NULL);
	phf->f = malloc(sizeof(t_elf_finder));
	if (!phf->f)
		return (elft->err = ELFT_MALLOC_FAILED,
				NULL);
	unsigned int	i = 0;
	for ( ; i < elft->header->program_headers_count ; ++i)
	{
		if (elft->pHeaders[i]->segment_type == ELFTPH_type)
			break ;
	}
	if (i == elft->header->program_headers_count)
		return (elft_free_pfinder(phf),
				elft->err = ELFT_SHEADER_NOT_EXIST,
				NULL);
	phf->header = elft->pHeaders[i];
	phf->f->data = elft_get_raw(elft)->data + elft->pHeaders[i]->segment_offset;
	phf->f->size = elft->pHeaders[i]->segment_size;
	return (phf);
	return (phf);
}*/

// Return first sym found by its name
t_elf_symfinder*	elft_find_sym_by_name(t_elf* elft, const char* symname)
{
	if (elft->sHeaders == NULL)	return (__elft_ret(elft, ELFT_NEED_TO_READ_SHEADERS));

	t_elf_symfinder*	symf = malloc(sizeof(t_elf_symfinder));
	if (symf == NULL)	return (__elft_ret(elft, ELFT_MALLOC_FAILED));

	symf->name = NULL;
	symf->sym = malloc(sizeof(t_elf_symbol));
	if (symf->sym == NULL)	return (__elft_ret(elft, ELFT_MALLOC_FAILED));

	t_elf_shfinder*	strtab = elft_find_sectionH_by_name(elft, ".strtab");
	if (strtab == NULL)	return (__elft_ret(elft, ELFT_SHEADER_NOT_EXIST));

	symf->shf = elft_find_sectionH_by_name(elft, ".symtab");
	if (symf->shf)
	{
		symf->name = strdup(symname);
		symf->sym = (t_elf_symbol*)symf->shf->f->data;
		unsigned long i = 0;
		for ( ; i < symf->shf->f->size / sizeof(t_elf_symbol) ; ++i)
		{
			t_elf_symbol*	tmp = (&((t_elf_symbol*)symf->shf->f->data)[i]);
			if (!strcmp(symname, (char*)(strtab->f->data + tmp->name_offset))) // compare with strtab
				return (elft_free_shfinder(strtab), elft->err = ELFT_SUCCESS, (symf->sym = (t_elf_symbol*)(&symf->shf->f->data[i])), symf);
		}
	}
	elft_free_shfinder(strtab);
	elft_free_symfinder(symf);
	elft->err = ELFT_SYMBOL_NOT_FOUND;
	return (NULL);
}

void	elft_find__reset_next_sym_count(void)
{
	next_sym_count = 0;
}

int	elft_find__get_next_sym_count(void)
{
	return (next_sym_count);
}

t_elf_symfinder*	elft_find_next_sym(t_elf* elft)
{
	t_elf_symfinder*		sf = malloc(sizeof(t_elf_symfinder));
	if (sf == NULL)	return (__elft_ret(elft, ELFT_MALLOC_FAILED));

	sf->name = NULL;
	sf->sym = NULL;
	t_elf_shfinder*	strtab = elft_find_sectionH_by_name(elft, ".strtab");
	sf->shf = elft_find_sectionH_by_name(elft, ".symtab");
	if (sf->shf && sizeof(t_elf_symbol) * next_sym_count < sf->shf->f->size)
	{
		sf->sym = &((t_elf_symbol*)sf->shf->f->data)[next_sym_count++];
		if (strtab)
			sf->name = strdup(strtab->f->data + sf->sym->name_offset);
		elft_free_shfinder(strtab);
		elft->err = ELFT_SUCCESS;
		return (sf);
	}
	elft_free_shfinder(strtab);
	elft_free_symfinder(sf);
	return (NULL);
}

// Return first sym found by its name in a section
//t_elf_symfinder*	elft_find_sym_by_shf(t_elf* elft, const char* symname, t_elf_shfinder* shf)
//{
//	if (elft->sHeaders == NULL)
//		return (elft->err = ELFT_NEED_TO_READ_SHEADERS,
//				NULL);
//	t_elf_symfinder*	f = malloc(sizeof(t_elf_symfinder));
//	if (!shf->f)
//		return (elft->err = ELFT_MALLOC_FAILED,
//				NULL);
//	
//}


