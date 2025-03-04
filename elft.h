/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   elft.h                                             :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: ymanchon <ymanchon@student.42.fr>          +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2025/01/21 14:05:37 by ymanchon          #+#    #+#             */
/*   Updated: 2025/03/04 20:31:04 by ymanchon         ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#ifndef ELFT_H
#define ELFT_H

# define ELFTSH_PROGRAM_DATA	SHT_PROGBITS
# define ELFTSH_SYMBOL			SHT_SYMTAB
# define ELFTSH_STRING			SHT_STRTAB
# define ELFTSH_RELA			SHT_RELA
# define ELFTSH_SYMBOL_HASH		SHT_HASH
# define ELFTSH_DYN_INFO		SHT_DYNAMIC
# define ELFTSH_NOTES			SHT_NOTE
# define ELFTSH_BSS				SHT_NOBITS
# define ELFTSH_REL				SHT_REL
# define ELFTSH_RESERVED		SHT_SHLIB
# define ELFTSH_DYNSYM			SHT_DYNSYM
# define ELFTSH_INIT_ARRAY		SHT_INIT_ARRAY
# define ELFTSH_END_ARRAY		SHT_FINI_ARRAY
# define ELFTSH_PREINIT_ARRAY	SHT_PREINIT_ARRAY
# define ELFTSH_GROUP			SHT_GROUP
# define ELFTSH_SYM_EXT			SHT_SYMTAB_SHNDX

# define ELFT_SUCCESS				0
# define ELFT_INVALID_FD			1
# define ELFT_MALLOC_FAILED			2
# define ELFT_MMAP_FAILED			3
# define ELFT_INVALID_FILE_FORMAT	4
# define ELFT_NEED_TO_READ_HEADER	5
# define ELFT_NEED_TO_READ_SHEADERS	6
# define ELFT_NEED_TO_READ_PHEADERS	7
# define ELFT_NEED_TO_READ_SHSTRTAB	8
# define ELFT_SHEADER_NOT_EXIST		9
# define ELFT_PHEADER_NOT_EXIST		10
# define ELFT_SYMBOL_NOT_FOUND		11

# define _POSIX_C_SOURCE 200809L
# include <stdio.h>
# include <stdlib.h>
# include <unistd.h>
# include <sys/stat.h>
# include <sys/mman.h>
# include <elf.h>
# include <string.h>

typedef char		elftByte;
typedef short		elftWord;
typedef int			elftDouble;
typedef long long	elftQuad;


typedef unsigned char		elftUByte;
typedef unsigned short		elftUWord;
typedef unsigned int		elftUDouble;
typedef unsigned long long	elftUQuad;

typedef struct s_elf_hid
{
	elftUByte	magic_numbers[4];
	elftUByte	bits_archi;
	elftUByte	endianness;
	elftUByte	header_format_version;
	elftUByte	ABI;
	elftUByte	ABI_version;
	elftUByte	__tamping__[6];
	elftUByte	identification_field_size;
}	t_elf_hid;

// Header struct for ELF 64bits binary file
typedef struct s_elf_header
{
	t_elf_hid	identification_field;
	elftUWord	file_type;
	elftUWord	proc_target;
	elftDouble	version;
	elftQuad	entry_point;
	elftUQuad	program_headers_offset;
	elftUQuad	section_headers_offset;
	elftUDouble	proc_flags;
	elftUWord	header_size;
	elftUWord	program_headers_size;	// Size of an entry in the section header table (in bytes)
	elftUWord	program_headers_count;	// Number of entries in the section header table
	elftUWord	section_headers_size;	// Size of an entry in the table containing the programme header (in bytes)
	elftUWord	section_headers_count;	// Number of entries in the table containing the programme header
	elftUWord	sections_names_index;	// Index in the table of section headings of the entry associated with the table containing the names of the sections
}	t_elf_header;

# if defined(__x86_64__) || defined(__ppc64__) || defined(__arm64__)
typedef struct s_elf_program_header
{
	elftDouble	segment_type; //Identifies the type of the segment. 
	elftDouble	segment_dep_flags;	// only 64bits architecture
	elftQuad	segment_offset;	// Offset of the segment in the file image. 
	elftQuad	VAddress_of_segment;	// Virtual address of the segment in memory. 
	elftQuad	PAddress_of_segment;	// On systems where physical address is relevant, reserved for segment's physical address.
	elftQuad	segment_size;	// Size in bytes of the segment in the file image. May be 0.
	elftQuad	segment_mem_size; // Size in bytes of the segment in memory. May be 0.
	elftQuad	segment_alignement;  // 0 and 1 specify no alignment. Otherwise should be a positive, integral power of 2, with p_vaddr equating p_offset modulus p_align.
	//elftByteU	__end_tamping__[8];
}	t_elf_program_header;
# else
typedef struct s_elf_program_header
{
	elftDouble	segment_type; //Identifies the type of the segment. 
	elftQuad	segment_offset;	// Offset of the segment in the file image. 
	elftQuad	VAddress_of_segment;	// Virtual address of the segment in memory. 
	elftQuad	PAddress_of_segment;	// On systems where physical address is relevant, reserved for segment's physical address.
	elftQuad	segment_size;	// Size in bytes of the segment in the file image. May be 0.
	elftQuad	segment_mem_size; // Size in bytes of the segment in memory. May be 0.
	elftDouble	segment_dep_flags;	// only 32bits architecture
	elftQuad	segment_alignement;  // 0 and 1 specify no alignment. Otherwise should be a positive, integral power of 2, with p_vaddr equating p_offset modulus p_align.
	//elftByteU	__end_tamping__[4];
}	t_elf_program_header;
# endif

typedef struct s_elf_section_header
{
	elftUDouble	name_offset;
	elftUDouble	type;
	elftUQuad	flags;
	elftUQuad	VAddress_of_section;
	elftUQuad	offset;
	elftUQuad	size;	// section size (not header size) 
	elftUDouble	link;	// Contains the section index of an associated section. This field is used for several purposes, depending on the type of section. 
	elftUDouble	info;	// Contains extra information about the section. This field is used for several purposes, depending on the type of section.
	elftUQuad	required_alignement; // Contains the required alignment of the section. This field must be a power of two. 
	elftUQuad	entry_size;	// Contains the size, in bytes, of each entry, for sections that contain fixed-size entries. Otherwise, this field contains zero.
	//elftByteU	__end_tamping__[8];
}	t_elf_section_header;

typedef struct s_elf
{
	int						err;
	int						bits;
	t_elf_header*			header;
	t_elf_program_header**	pHeaders;
	t_elf_section_header**	sHeaders;
	void*	__p;
}	t_elf;

typedef struct	s_elf_raw
{
	int		fd;
	int		data_size;
	int		shstrtab_size;
	char*	data;
	char*	shstrtab;
}	t_elf_raw;

# if defined(__x86_64__) || defined(__ppc64__) || defined(__arm64__)
typedef struct	s_elf_symbol
{
	elftUDouble	name_offset;
	elftUByte	info;
	elftUByte	other;
	elftUWord	index;
	elftUQuad	value;
	elftUQuad	size;
}	t_elf_symbol;
# else
typedef struct	s_elf_symbol
{
	elftUDouble	name_offset;
	elftUQuad	value;
	elftUQuad	size;
	elftUByte	info;
	elftUByte	other;
	elftUWord	index;
}	t_elf_symbol;
# endif

typedef struct	s_elf_finder
{
	char*	data;		// c data
	int		size;		// data size
}	t_elf_finder;

typedef struct	s_elf_phfinder
{
	t_elf_finder*			f;
	t_elf_program_header*	header;
}	t_elf_phfinder;

typedef struct	s_elf_shfinder
{
	t_elf_finder*			f;
	t_elf_section_header*	header;
	char					name[16];
}	t_elf_shfinder;

typedef struct	s_elf_symfinder
{
	t_elf_symbol*	sym;
	t_elf_shfinder*	shf;
}	t_elf_symfinder;

	// elft_read.c

// need to elft_init() before
int	elft_read_header(t_elf* elft);
// need to elft_read_header() before
int	elft_read_section_headers(t_elf* elft);
// need to elft_read_header() before
int	elft_read_program_headers(t_elf* elft);
// need to elft_read_section_headers() before
int	elft_read_shstrtab(t_elf* elft);

	// elft_find.c

// NOT need to elft_read_shstrtab() before
t_elf_shfinder*	elft_find_shstrtab_header(t_elf* elft);
// need to elft_read_shstrtab() before
t_elf_shfinder*	elft_find_sectionH_by_name(t_elf* elft, const char* sname);
// need to elft_read_section_headers() before
// Return first section header found
t_elf_shfinder*	elft_find_sectionH_by_type(t_elf* elft, elftUDouble ELFTSH_type);	// faire un systeme de recherche par occurrence (sinon acces au premier trouver)
// need to elft_read_program_headers() before
// Return first program header found
//t_elf_phfinder*	elft_find_programH_by_type(t_elf* elft, elftDouble ELFTPH_type);	// faire un systeme de recherche par occurrence (sinon acces au premier trouver)

// Return first sym found by its name
t_elf_symfinder*	elft_find_sym_by_name(t_elf* elft, const char* symname);
// Return first sym found by its name in a section
//t_elf_symfinder*	elft_find_sym_by_shf(t_elf* elft, const char* symname, t_elf_shfinder* shf);

	// elft_sym.c

void*	elft_sym_get_addr(t_elf_symfinder* sym);
void	elft_sym_set_addr(t_elf_symfinder* sym);

	// elft_free.c

void	elft_free_sfinder(t_elf_shfinder* shf);
void	elft_free_pfinder(t_elf_phfinder* phf);
void	elft_free_finder(t_elf_symfinder* f);

	// elft.c

char*		elft_strerror(t_elf* elft);
t_elf*		elft_init(int fd, int prot_flags);
t_elf_raw*	elft_get_raw(t_elf* elft);
// need to elft_init() before
void		elft_destroy(t_elf* elft);

#endif
