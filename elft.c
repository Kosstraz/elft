#include "elft.h"

static inline
int	_elft_valid_file_format(char header_magic_number[4])
{
	if (header_magic_number[0] == 0x7f && !strncmp(&header_magic_number[1], "ELF", 3))
		return (1);
	return (0);
}

static inline
int	_elft_file_size(int fd)
{
	struct stat	statbuffer;
	fstat(fd, &statbuffer);
	return (statbuffer.st_size);
}

char*	elft_strerror(t_elf* elft)
{
	switch (elft->err)
	{
		case ELFT_INVALID_FD:
			return ("elft: invalid fd (maybe not an ELF file).");
			break ;
		case ELFT_MALLOC_FAILED:
			return ("elft: fatal error (malloc).");
			break ;
		case ELFT_MMAP_FAILED:
			return ("elft: imap file failed.");
			break ;
		case ELFT_INVALID_FILE_FORMAT:
			return ("elft: invalid file format.");
			break ;
		case ELFT_NEED_TO_READ_PHEADERS:
			return ("elft: need to elft_read_program_headers() before.");
			break ;
		case ELFT_NEED_TO_READ_SHEADERS:
			return ("elft: need to elft_read_section_headers() before.");
			break ;
		case ELFT_NEED_TO_READ_SHSTRTAB:
			return ("elft: need to elft_read_shstrtab_headers() before.");
			break ;
		case ELFT_SHEADER_NOT_EXIST:
			return ("elft: section header does not exist.");
			break ;
		case ELFT_PHEADER_NOT_EXIST:
			return ("elft: program header does not exist.");
			break ;
		case ELFT_SYMBOL_NOT_FOUND:
			return ("elft: symbol not found.");
			break ;
		case ELFT_SUCCESS:
		default:
			return ("elft: success.");
			break ;
	}
	return ("elft: ??? unknow error code ???");
}

t_elf_raw*	elft_get_raw(t_elf* elft)
{
	return ((t_elf_raw*)elft->__p);
}

t_elf*	elft_init(int fd, int prot_flags)
{
	char		*data;
	t_elf*		elft;

	elft = calloc(1, sizeof(t_elf));
	if (!elft)
		return (NULL);
	else if (fd <= -1)
		return (elft->err = ELFT_INVALID_FD,
				NULL);
	elft->__p = calloc(1, sizeof(t_elf_raw));
	if (!elft->__p)
		return (elft->err = ELFT_MALLOC_FAILED,
				NULL);
	elft_get_raw(elft)->fd = fd;
	data = mmap(NULL, 4, PROT_READ, MAP_PRIVATE, fd, 0);
	if (data <= (char*)0)
		return (elft->err = ELFT_MMAP_FAILED,
				NULL);
	else if (!_elft_valid_file_format(data))
		return (elft->err = ELFT_INVALID_FILE_FORMAT,
				NULL);
	munmap(data, 4);
	elft_get_raw(elft)->data_size = _elft_file_size(fd);
	data = mmap(NULL, elft_get_raw(elft)->data_size, prot_flags, MAP_SHARED, fd, 0);
	if (data <= (char*)0)
		return (elft->err = ELFT_MMAP_FAILED,
			NULL);
	elft_get_raw(elft)->data = data;
	elft_get_raw(elft)->data = data;
	elft->err = ELFT_SUCCESS;
	return (elft);
}

void	elft_destroy(t_elf* elft)
{
	t_elf_raw*	raw;

	raw = elft_get_raw(elft);
	munmap(raw->data, raw->data_size);
	free(raw);
	free(elft->pHeaders);
	free(elft->sHeaders);
	free(elft);
}
