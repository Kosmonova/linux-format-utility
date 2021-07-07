#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <stdlib.h>
#include <fcntl.h>
#include <elf.h>
#include <arpa/inet.h>
#include "a.out.h"

struct ar_header
{
	char file_id[16];
	char time_steamp[12];
	char owner_id[6];
	char group_id[6];
	char file_mode[8];
	char file_size[10];
	char end[2];
};

#define INIT_SH_NAME_H (struct sh_name_headers) \
	{                                           \
		-1, -1, -1, -1, -1, -1, -1, -1, -1,      \
		-1, -1, -1, -1, -1, -1, -1, -1,          \
		-1, -1, -1, -1, -1, -1, -1, -1           \
	}

#define IF_MODIFY_ADDR_CODE(paddr_code) \
	if(((paddr_code)[-1] == '\xe8' || \
	(paddr_code)[-1] == '\xe9' || \
	((paddr_code)[-1] == '\x84') && (paddr_code)[-2] == '\x0f'))


struct sh_name_headers
{
	int null;
	int text, idx_text, idx_sym_text;
	int data, idx_data, idx_sym_data;
	int bss, idx_bss, idx_sym_bss;
	int rel_text, idx_rel_text, idx_sym_rel_text;
	int rel_data, idx_rel_data, idx_sym_rel_data;
	int shstrtab, idx_shstrtab, idx_sym_shstrtab;
	int symtab, idx_symtab, idx_sym_symtab;
	int strtab, idx_strtab, idx_sym_strtab;
}sh_name_h = INIT_SH_NAME_H;

int cat_symbol(char *start_head, int offset_sym_h, char *name_symbol, 
			   int *sh_name)
{
	int size_name = strlen(name_symbol) + 1;
	memcpy(start_head + offset_sym_h, name_symbol, size_name);
	*sh_name = offset_sym_h;
	return size_name;
}

void sort_aout_sym(struct nlist * const paout_syms, int size, int *reloc)
{
	int idx, idx_first_glob, tmp_idx;
	struct nlist tmp;

	int rev_reloc[size];

	for( idx = 0; idx < size; idx++ )
		rev_reloc[ idx ] = idx;

	for( idx_first_glob = 0; idx_first_glob < size; idx_first_glob++ )
	{
		struct nlist *p_sym_gl = paout_syms + idx_first_glob;
		if(!(p_sym_gl->n_type & N_EXT))
			continue;

		for( idx = idx_first_glob; idx < size; ++idx )
		{
			struct nlist *p_sym = paout_syms + idx;
			if(p_sym->n_type & N_EXT)
				continue;

			tmp = *p_sym;
			*p_sym = paout_syms[idx_first_glob];
			paout_syms[idx_first_glob] = tmp;

			tmp_idx = rev_reloc[idx];
			rev_reloc[idx] = rev_reloc[idx_first_glob];
			rev_reloc[idx_first_glob] = tmp_idx;
			break;
		}
	}

	for( idx = 0; idx < size; idx++ )
		reloc[rev_reloc[ idx ]] = idx;
}

int strip_syms(char *aout_buf, struct exec obj)
{
	int cnt_syms_aout = obj.a_syms/sizeof(struct nlist);
	int idx_sym;

	struct nlist * const paout_syms = (struct nlist *)(aout_buf + N_SYMOFF(obj));

	struct relocation_info * const prel_info_text = 
		(struct relocation_info *)(aout_buf + N_TRELOFF(obj));

	struct relocation_info *const prel_info_data =
		(struct relocation_info *)(aout_buf + N_DRELOFF(obj));

	for( idx_sym = 0; idx_sym < cnt_syms_aout; )
	{
		struct nlist *p_sym = paout_syms + idx_sym;
		char *strx = aout_buf + N_STROFF(obj) + p_sym->n_un.n_strx;

		if(strstr(strx, ".o"))
		{
			p_sym->n_type = N_ABS;
		}
			
		if(!strcmp(strx, "gcc2_compiled.") || 
			!strcmp(strx, "___gnu_compiled_c"))
		{
			int idx_syms_rel = 0;
			int cnt_syms_rel = obj.a_trsize / sizeof(struct relocation_info);
	
			for( idx_syms_rel = 0; idx_syms_rel < cnt_syms_rel; idx_syms_rel++)
			{
				struct relocation_info * const psym_rel = prel_info_text + idx_syms_rel;
				
				if(psym_rel->r_extern && psym_rel->r_symbolnum >= idx_sym)
					--(psym_rel->r_symbolnum);
			}

			cnt_syms_rel = obj.a_drsize / sizeof(struct relocation_info);
	
			for( idx_syms_rel = 0; idx_syms_rel < cnt_syms_rel; idx_syms_rel++)
			{
				struct relocation_info * const psym_rel = prel_info_data + idx_syms_rel;

				if(psym_rel->r_extern && psym_rel->r_symbolnum >= idx_sym)
					--(psym_rel->r_symbolnum);
			}
			
			int idx_sym1;
			for( idx_sym1 = idx_sym; idx_sym1 < cnt_syms_aout; idx_sym1++)
			{
				struct nlist *p_sym1 = paout_syms + idx_sym1;
				*p_sym1 = *(p_sym1 + 1);
			}

			--cnt_syms_aout;

			continue;
		}

		idx_sym++;
	}
	
	return cnt_syms_aout;
}

Elf32_Sym *find_sym_by_addr(unsigned long addr, char *aout_buf, struct exec obj, 
							Elf32_Sym * const psymbols)
{
	int cnt_syms_aout = obj.a_syms/sizeof(struct nlist);
	struct nlist * const paout_syms = (struct nlist *)(aout_buf + N_SYMOFF(obj));
	int idx_sym;
	
	for( idx_sym = 0; idx_sym < cnt_syms_aout; idx_sym++)
	{
		struct nlist *p_sym = paout_syms + idx_sym;

		if((p_sym->n_type & N_TYPE) != N_ABS && (p_sym->n_type & N_TYPE) != N_UNDF &&
			p_sym->n_value == addr)
			return psymbols + idx_sym;
	}

	return NULL;
}

void sort_aout_sym_by_addr(struct nlist * const paout_syms, int size, int *adr_reloc)
{
	int idx, idx1, tmp_idx, tmp_addr;
	long tab_addr[size];

	for( idx = 0; idx < size; idx++ )
	{
		struct nlist *p_syml = paout_syms + idx;
		tab_addr[ idx ] = p_syml->n_value;
		adr_reloc[ idx ] = idx;
	}

	for( idx = 0; idx < size; idx++ )
	{
		for( idx1 = idx; idx1 < size; ++idx1 )
		{
			if(tab_addr[idx] < tab_addr[idx1])
				continue;

			tmp_addr = tab_addr[idx1];
			tab_addr[idx1] = tab_addr[idx];
			tab_addr[idx] = tmp_addr;
			
			tmp_idx = adr_reloc[idx1];
			adr_reloc[idx1] = adr_reloc[idx];
			adr_reloc[idx] = tmp_idx;
		}
	}
}

void usage()
{
	printf("usage: aouttoelf -o elf_file aout_file\n");
	exit(-1);
}

int valid_aout(struct exec *obj)
{
	short int magic = obj->a_info & 0777;

	switch(magic)
	{
		case OMAGIC:break;
		case NMAGIC:break;
		case ZMAGIC:break;
		case QMAGIC:break;
		case CMAGIC:break;
		default: 
			return 0;
	}

	return 1;
}

int check_obj_src(char *aout_buf)
{
	struct exec *obj = (struct exec *)aout_buf;
	struct nlist * const paout_syms = (struct nlist *)(aout_buf + N_SYMOFF(*obj));
	struct nlist *p_sym = paout_syms + 1;
	char *strx = aout_buf + N_STROFF(*obj) + p_sym->n_un.n_strx;
	printf("check_obj_src %s \n", strx);

	if(!strcmp(strx, "gcc2_compiled."))
		return 0;
	
	if(!strcmp(strx, "___gnu_compiled_c"))
		return 0;

		return 1;
}

int convert(char *elf_buf, char *aout_buf, int *len_elf)
{
	int len = 0, off_text = 0, off_data = 0, off_bss = 0, off_strtab = 0;
	sh_name_h = INIT_SH_NAME_H;
	struct exec obj = *((struct exec *)aout_buf);

	Elf32_Ehdr *elfn = (Elf32_Ehdr*)elf_buf;

	*elfn =
	(Elf32_Ehdr){
		.e_ident=
		{
			0x7F, 0x45, 0x4C, 0x46, 
			0x01, 0x01, 0x01, 0x00, 
			0x00, 0x00, 0x00, 0x00,
			0x00, 0x00, 0x00, 0x00
		},
		.e_type = 0x01,
		.e_machine = 0x03,
		.e_version = 0x01,
		.e_entry = 0x00,
		.e_phoff = 0x00,
		.e_shoff = 0xA4,
		.e_flags = 0,
		.e_ehsize = 0x34,
		.e_phentsize = 0x00,
		.e_phnum = 0x00,
		.e_shentsize = 0x28,
		.e_shnum = 0x07,
		.e_shstrndx = 0x04,
	};

	off_text = len = sizeof(Elf32_Ehdr);
	memset(len + elf_buf, 0x00, 0x40 - len);
	len = off_text = 0x40;

	int diff_text = 0, diff_data = 0;

	if(obj.a_text)
	{
		memcpy(elf_buf + len, aout_buf + N_TXTOFF(obj), obj.a_text);
		len += obj.a_text;
		diff_text = len % 0x10;
              
		if(diff_text)
		{
			diff_text = 0x10 - diff_text;
			memset(elf_buf + len, 0x00, diff_text);
			len += diff_text;
		}

	}

	off_data = len;

	if(obj.a_data)
	{
		memcpy(elf_buf + len, aout_buf + N_DATOFF(obj), obj.a_data);
		len += obj.a_data;
		diff_data = len % 0x10;

		if(diff_data)
		{
			diff_data = 0x10 - diff_data;
			memset(elf_buf + len, 0x00, diff_data);
			len += diff_data;
		}

	}

	const struct relocation_info *prel_info_text = 
		(struct relocation_info *)(aout_buf + N_TRELOFF(obj));

	const struct relocation_info *prel_info_data =
		(struct relocation_info *)(aout_buf + N_DRELOFF(obj));

	char *start_head = elf_buf + len;
	off_strtab = len;
	int size_sym_h = 0;

	size_sym_h += cat_symbol(start_head, size_sym_h, "",          &sh_name_h.null);
	size_sym_h += cat_symbol(start_head, size_sym_h, ".symtab",   &sh_name_h.symtab);
	size_sym_h += cat_symbol(start_head, size_sym_h, ".strtab",   &sh_name_h.strtab);
	size_sym_h += cat_symbol(start_head, size_sym_h, ".shstrtab", &sh_name_h.shstrtab);

	if(obj.a_trsize)
	{
		if(!obj.a_text)
		{
			printf("missing text header for relocation header\n");
			return -1;
		}
		size_sym_h += cat_symbol(start_head, size_sym_h, ".rel",
								 &sh_name_h.rel_text) - 1;
	}

	if(obj.a_text)
		size_sym_h += cat_symbol(start_head, size_sym_h, ".text",
								 &sh_name_h.text);

	if(obj.a_drsize)
	{
		if(!obj.a_data)
		{
			printf("missing data header for relocation header\n");
			return -1;
		}
		size_sym_h += cat_symbol(start_head, size_sym_h, ".rel",
								 &sh_name_h.rel_data) - 1;
	}

	if(obj.a_data)
		size_sym_h += cat_symbol(start_head, size_sym_h, ".data",
								 &sh_name_h.data);
	if(obj.a_bss)
		size_sym_h += cat_symbol(start_head, size_sym_h, ".bss",
								 &sh_name_h.bss);

	len += size_sym_h;
	elfn->e_shoff = len;
	Elf32_Shdr * const pshdr = (Elf32_Shdr *)(elf_buf + len), *pshdrx = NULL;

	int idx_shdr = 1;
	if(sh_name_h.text != -1)
	{
		sh_name_h.idx_text = idx_shdr;
		pshdrx = pshdr + idx_shdr++;
		memset(pshdrx, 0 , sizeof(Elf32_Shdr));
		pshdrx->sh_name = sh_name_h.text;
		pshdrx->sh_type = SHT_PROGBITS;
		pshdrx->sh_flags = SHF_ALLOC | SHF_EXECINSTR;
		pshdrx->sh_offset = off_text;
		pshdrx->sh_size = obj.a_text;
		pshdrx->sh_addralign = 4;
		pshdrx->sh_addr = obj.a_entry;
	}

	pshdrx = NULL;
	if(sh_name_h.rel_text != -1)
	{
		sh_name_h.idx_rel_text = idx_shdr++;
		pshdrx = pshdr + sh_name_h.idx_rel_text;
		memset(pshdrx, 0 , sizeof(Elf32_Shdr));
		pshdrx->sh_name = sh_name_h.rel_text;
		pshdrx->sh_type = SHT_REL;
		pshdrx->sh_offset = off_bss;
		pshdrx->sh_entsize = 8;
		pshdrx->sh_size = obj.a_trsize;
		pshdrx->sh_size *= sizeof(Elf32_Rel) / sizeof(struct relocation_info);
		pshdrx->sh_addralign = 4;
	}
	Elf32_Shdr * const pshdr_rel_text = pshdrx;

	if(sh_name_h.data != -1)
	{
		sh_name_h.idx_data = idx_shdr;
		pshdrx = pshdr + idx_shdr++;
		memset(pshdrx, 0 , sizeof(Elf32_Shdr));
		pshdrx->sh_name = sh_name_h.data;
		pshdrx->sh_type = SHT_PROGBITS;
		pshdrx->sh_flags = SHF_ALLOC | SHF_WRITE;
		pshdrx->sh_offset = off_data;
		pshdrx->sh_size = obj.a_data;
		pshdrx->sh_addralign = 1;
		if(obj.a_entry)
			pshdrx->sh_addr = obj.a_entry + obj.a_text;
	}

	pshdrx = NULL;
	if(sh_name_h.rel_data != -1)
	{
		sh_name_h.idx_rel_data = idx_shdr++;
		pshdrx = pshdr + sh_name_h.idx_rel_data;
		memset(pshdrx, 0 , sizeof(Elf32_Shdr));
		pshdrx->sh_name = sh_name_h.rel_data;
		pshdrx->sh_type = SHT_REL;
		pshdrx->sh_offset = off_bss;
		pshdrx->sh_entsize = 8;
		pshdrx->sh_size = obj.a_drsize;
		pshdrx->sh_size *= sizeof(Elf32_Rel) / sizeof(struct relocation_info);
		pshdrx->sh_addralign = 4;
	}
	Elf32_Shdr * const pshdr_rel_data = pshdrx;

	if(sh_name_h.bss != -1)
	{
		sh_name_h.idx_bss = idx_shdr;
		pshdrx = pshdr + idx_shdr++;
		memset(pshdrx, 0 , sizeof(Elf32_Shdr));
		pshdrx->sh_name = sh_name_h.bss;
		pshdrx->sh_type = SHT_NOBITS;
		pshdrx->sh_flags = SHF_ALLOC | SHF_WRITE;
		pshdrx->sh_offset = off_strtab;
		pshdrx->sh_size = obj.a_bss;
		pshdrx->sh_addralign = 8;
		if(obj.a_entry)
			pshdrx->sh_addr = obj.a_entry + obj.a_text + obj.a_data;
	}

	sh_name_h.idx_shstrtab = idx_shdr++;
	sh_name_h.idx_symtab   = idx_shdr++;
	sh_name_h.idx_strtab   = idx_shdr++;

	elfn->e_shstrndx = sh_name_h.idx_shstrtab;
	elfn->e_shnum = idx_shdr;
	len += sizeof(Elf32_Shdr) * idx_shdr;

	pshdrx = pshdr + sh_name_h.idx_shstrtab;
	memset(pshdrx, 0 , sizeof(Elf32_Shdr));
	pshdrx->sh_name = sh_name_h.shstrtab;
	pshdrx->sh_type = SHT_STRTAB;
	pshdrx->sh_offset = off_strtab;
	pshdrx->sh_size = size_sym_h;
	pshdrx->sh_addralign = 1;

	Elf32_Shdr * const pshdr_symtab = pshdrx = pshdr + sh_name_h.idx_symtab;
	memset(pshdr_symtab, 0 , sizeof(Elf32_Shdr));
	*pshdr_symtab = (Elf32_Shdr)
	{
		.sh_name = sh_name_h.symtab,
		.sh_offset = len,
		.sh_type = SHT_SYMTAB,
		.sh_link = sh_name_h.idx_strtab,
		.sh_addralign = 4,
		.sh_entsize = 0x10,
	};

	Elf32_Shdr * const pshdr_strtab = pshdrx = pshdr + sh_name_h.idx_strtab;
	memset(pshdr_strtab, 0 , sizeof(Elf32_Shdr));
	*pshdr_strtab = (Elf32_Shdr)
	{
		.sh_name = sh_name_h.strtab,
		.sh_type = SHT_STRTAB,
	};

	int obj_is_from_asm = check_obj_src(aout_buf);
	int idx = 0;
	int str_len = 0;

	struct nlist * const paout_syms = (struct nlist *)(aout_buf + N_SYMOFF(obj));

	for( idx = 0; idx < obj.a_syms/sizeof(struct nlist); idx++)
	{
		struct nlist *p_sym = paout_syms + idx;
		printf("%08lx ", p_sym->n_value);
		char *strx = aout_buf + N_STROFF(obj) + p_sym->n_un.n_strx;
		str_len += strlen(strx);

		if(obj_is_from_asm && 
			((p_sym->n_type & N_TYPE) != N_UNDF || p_sym->n_value) &&
			(~p_sym->n_type & N_EXT))
		{
			str_len++;
			printf("%s \n", strx);
		}
		else  if(strx[0] != '_')
		{
			printf("missing underscore on %s\n", strx);
			str_len++;
		}
		else
			printf("%s \n", strx);
	}
	
	int reloc[obj.a_syms/sizeof(struct nlist)];
	const int cnt_syms_aout =  strip_syms(aout_buf, obj);

	char string_names[str_len];
	memset(string_names, 0, str_len);
	char *pstr_names = string_names;

	sort_aout_sym(paout_syms, cnt_syms_aout, reloc);

	for( idx = 0; idx < cnt_syms_aout; idx++)
	{
		struct nlist *p_sym = paout_syms + idx;
		char *strx = aout_buf + N_STROFF(obj) + p_sym->n_un.n_strx;

		if(obj_is_from_asm && 
			((p_sym->n_type & N_TYPE) != N_UNDF || p_sym->n_value) &&
			(~p_sym->n_type & N_EXT));
		else if(strx[0] == '_')
			strx++;

		strcpy(pstr_names, strx);
		printf("\t%s \n", pstr_names);
		pstr_names += strlen(strx) + 1;
	}

	Elf32_Sym *psymbols = (Elf32_Sym *)(elf_buf + len);
	
	memset(psymbols, 0, sizeof(Elf32_Sym) * 4);
	int cnt_symbols = 1;

	if(sh_name_h.idx_text != -1)
	{
		sh_name_h.idx_sym_text = cnt_symbols;
		psymbols[cnt_symbols].st_shndx = sh_name_h.idx_text;
		psymbols[cnt_symbols].st_info = ELF32_ST_INFO(STB_LOCAL, STT_SECTION);
		cnt_symbols++;
	}

	if(sh_name_h.idx_data != -1)
	{
		sh_name_h.idx_sym_data = cnt_symbols;
		psymbols[cnt_symbols].st_shndx = sh_name_h.idx_data;
		psymbols[cnt_symbols].st_info = ELF32_ST_INFO(STB_LOCAL, STT_SECTION);
		cnt_symbols++;
	}
	
	if(sh_name_h.idx_bss != -1)
	{
		sh_name_h.idx_sym_bss = cnt_symbols;
		psymbols[cnt_symbols].st_shndx = sh_name_h.idx_bss;
		psymbols[cnt_symbols].st_info = ELF32_ST_INFO(STB_LOCAL, STT_SECTION);
		cnt_symbols++;
	}

	int first_glob_pos = cnt_symbols;
	int last_sect_sym = cnt_symbols;
	int pos_name = 0;
	int adr_reloc[cnt_syms_aout];
	int rev_adr_reloc[cnt_syms_aout];
	sort_aout_sym_by_addr(paout_syms, cnt_syms_aout, adr_reloc);

	for( idx = 0; idx < cnt_syms_aout; idx++)
		rev_adr_reloc[adr_reloc[idx]] = idx;
	
	for( idx = 0; idx < cnt_syms_aout; idx++)
	{
		struct nlist * const paout_sym = paout_syms + idx;
		Elf32_Sym *psymbol = psymbols + cnt_symbols + idx;
		*psymbol = (Elf32_Sym)
		{
			.st_shndx = 1,
			.st_value = paout_sym->n_value,
		};

		int bind = paout_sym->n_type & N_EXT ? STB_GLOBAL : STB_LOCAL;
			
		if(bind == STB_LOCAL)
			first_glob_pos++;
		
		pos_name++;
		psymbol->st_name = pos_name;
		pos_name += strlen(string_names + pos_name) + 1;

		switch(paout_sym->n_type & N_TYPE)
		{
			case N_UNDF:
				if(paout_sym->n_value)
				{
					psymbol->st_size = paout_sym->n_value;
					psymbol->st_shndx = SHN_COMMON;
					psymbol->st_info = ELF32_ST_INFO(bind, STT_OBJECT);
				}
				else
				{
					psymbol->st_info = ELF32_ST_INFO(bind, STT_NOTYPE);
					psymbol->st_shndx = SHN_UNDEF;
				}
			break;
			case N_ABS:
				if(strstr(string_names + psymbol->st_name, ".o"))
					psymbol->st_info = ELF32_ST_INFO(bind, STT_FILE);
				else
					psymbol->st_info = ELF32_ST_INFO(bind, STT_NOTYPE);
			
				psymbol->st_shndx = SHN_ABS;
			break;
			case N_TEXT:
				psymbol->st_info = ELF32_ST_INFO(bind, STT_FUNC);
				if(sh_name_h.idx_text != -1)
					psymbol->st_shndx = sh_name_h.idx_text;
				
				if(rev_adr_reloc[idx] < cnt_syms_aout - 1)
					psymbol->st_size = 
					(paout_syms + adr_reloc[rev_adr_reloc[idx]+1])->n_value - paout_sym->n_value;
				else
					psymbol->st_size = obj.a_text - paout_sym->n_value;

			break;
			case N_DATA:
				psymbol->st_info = ELF32_ST_INFO(bind, STT_OBJECT);
				if(sh_name_h.idx_data != -1)
					psymbol->st_shndx = sh_name_h.idx_data;

				if(rev_adr_reloc[idx] < cnt_syms_aout - 1)
					psymbol->st_size = 
					(paout_syms + adr_reloc[rev_adr_reloc[idx]+1])->n_value - paout_sym->n_value;
				else
					psymbol->st_size = obj.a_data + obj.a_text - paout_sym->n_value;

				psymbol->st_value -= obj.a_text;
			break;
			case N_BSS:
				psymbol->st_info = ELF32_ST_INFO(bind, STT_OBJECT);
				if(sh_name_h.idx_bss != -1)
					psymbol->st_shndx = sh_name_h.idx_bss;

				if(rev_adr_reloc[idx] < cnt_syms_aout - 1)
					psymbol->st_size = 
					(paout_syms + adr_reloc[rev_adr_reloc[idx]+1])->n_value - paout_sym->n_value;
				else
					psymbol->st_size = obj.a_bss + obj.a_data + obj.a_text - paout_sym->n_value;

				psymbol->st_value -= obj.a_text + obj.a_data;
			break;
			default:
				printf("paout_sym->n_type: %x\n", paout_sym->n_type);
				exit(-2);
			break;
		}
	}

	cnt_symbols += cnt_syms_aout;
	pshdr_symtab->sh_info = first_glob_pos;

	pshdr_symtab->sh_size = sizeof(Elf32_Sym) * cnt_symbols;

	len += sizeof(Elf32_Sym) * cnt_symbols;
	str_len++;
	pshdr_strtab->sh_offset = len;
	pshdr_strtab->sh_size = str_len;
	elf_buf[len++] = 0;

	memcpy(elf_buf + len, string_names, str_len);
	len += str_len;

	if(pshdr_rel_text)
	{
		pshdr_rel_text->sh_link = sh_name_h.idx_symtab;
		pshdr_rel_text->sh_info = sh_name_h.idx_text;
		pshdr_rel_text->sh_offset = len;
		Elf32_Rel *prel = (Elf32_Rel *)(elf_buf + pshdr_rel_text->sh_offset);

		memset(prel, 0, pshdr_rel_text->sh_size);
		int cnt_itm_rel = pshdr_rel_text->sh_size / sizeof(Elf32_Rel);
		
		for(idx = 0; idx < cnt_itm_rel; idx++)
		{
			const struct relocation_info * prel_aout = prel_info_text + idx;
			prel->r_offset = prel_aout->r_address;
			
			long *paddr_code = (long*)(elf_buf + off_text + prel->r_offset);
			unsigned long addr_code = *paddr_code;
			
			// call instruction
			IF_MODIFY_ADDR_CODE((char*)paddr_code)
				addr_code += 4 + prel_aout->r_address;

			int idx_sym = reloc[prel_aout->r_symbolnum] + last_sect_sym;

			Elf32_Sym *p_sym = find_sym_by_addr(addr_code, aout_buf, obj,
								psymbols + last_sect_sym);
			if(prel_aout->r_extern)
			{
				IF_MODIFY_ADDR_CODE((char*)paddr_code)
					*paddr_code = 0xfffffffc;
				
				prel->r_info = ELF32_R_INFO(idx_sym, 
					prel_aout->r_pcrel ? R_386_PC32 : R_386_32);
			}
			else
			{
				switch(prel_aout->r_symbolnum & N_TYPE)
				{
					case N_UNDF: idx_sym = 0; break;
					case N_TEXT: 
					{
						if(p_sym)
						{
							idx_sym = p_sym - psymbols;
							IF_MODIFY_ADDR_CODE((char*)paddr_code)
								*paddr_code = 0xfffffffc;
							else
								*paddr_code = 0;
						}
						else
								idx_sym = sh_name_h.idx_sym_text;
						break;
					}
					case N_DATA:
					{
						if(p_sym)
						{
							idx_sym = p_sym - psymbols;
							IF_MODIFY_ADDR_CODE((char*)paddr_code)
								*paddr_code = 0xfffffffc;
							else
								*paddr_code = 0;
						}
						else
						{
							*paddr_code -= obj.a_text;
							idx_sym = sh_name_h.idx_sym_data; 
						}	
						break;
					}
					case N_BSS:
					{
						if(p_sym)
						{
							idx_sym = p_sym - psymbols;
							IF_MODIFY_ADDR_CODE((char*)paddr_code)
								*paddr_code = 0xfffffffc;
							else
								*paddr_code = 0;
						}
						else
						{
							*paddr_code -= obj.a_text + obj.a_data;
							idx_sym = sh_name_h.idx_sym_bss;
						}
						break;
					}
				}
				
				prel->r_info = ELF32_R_INFO(idx_sym, 
					prel_aout->r_pcrel ? R_386_PC32 : R_386_32);
			}

			prel++;
		}

		len += pshdr_rel_text->sh_size;
	}

	if(pshdr_rel_data)
	{
		pshdr_rel_data->sh_link = sh_name_h.idx_symtab;
		pshdr_rel_data->sh_info = sh_name_h.idx_data;
		pshdr_rel_data->sh_offset = len;
		Elf32_Rel *prel = (Elf32_Rel *)(elf_buf + pshdr_rel_data->sh_offset);

		memset(prel, 0, pshdr_rel_data->sh_size);
		int cnt_itm_rel = pshdr_rel_data->sh_size / sizeof(Elf32_Rel);
		
		for(idx = 0; idx < cnt_itm_rel; idx++)
		{
			const struct relocation_info * prel_aout = prel_info_data + idx;
			prel->r_offset = prel_info_data[idx].r_address;

			long *paddr_code = (long*)(elf_buf + off_data + prel->r_offset);
			unsigned long addr_code = *paddr_code;

			int idx_sym = reloc[prel_aout->r_symbolnum] + last_sect_sym;

			if(prel_info_data[idx].r_extern)
			{
				prel->r_info = ELF32_R_INFO(idx_sym, 
					prel_aout->r_pcrel ? R_386_PC32 : R_386_32);
			}
			else
			{
				Elf32_Sym *p_sym = find_sym_by_addr(addr_code, aout_buf, obj,
								psymbols + last_sect_sym);

				switch(prel_aout->r_symbolnum & N_TYPE)
				{
					case N_UNDF: idx_sym = 0; break;
					case N_TEXT: 
					{
						if(p_sym)
						{
							idx_sym = p_sym - psymbols;
							*paddr_code = 0;
						}
						else
							idx_sym = sh_name_h.idx_sym_text;
						break;
					}
					case N_DATA:
					{
						if(p_sym)
						{
							idx_sym = p_sym - psymbols;
							*paddr_code = 0;
						}
						else
						{
							*paddr_code -= obj.a_text;
							idx_sym = sh_name_h.idx_sym_data; 
						}	
						break;
					}
					case N_BSS:
					{
						if(p_sym)
						{
							idx_sym = p_sym - psymbols;
							*paddr_code = 0;
						}
						else
						{
							*paddr_code -= obj.a_text + obj.a_data;
							idx_sym = sh_name_h.idx_sym_bss;
						}
						break;
					}
				}
				
				prel->r_info = ELF32_R_INFO(idx_sym, 
					prel_aout->r_pcrel ? R_386_PC32 : R_386_32);
			}

			prel++;
		}

		len += pshdr_rel_data->sh_size;
	}

	*len_elf = len;
	return 0;
}

int skip_underscore(const char *in_buff, char *str_fnc, const int size_str)
{
	int pos_str = 0;
	int pos_buff = 0;

	while(pos_buff < size_str)
	{
		const char *strx = in_buff + pos_buff;
		int len_str = strlen(strx);
		pos_buff += len_str + 1;
		printf("%s \n", strx);

		if(strx[0] != '_')
		{
			printf("missing underscore on %s\n", strx);
		}
		strcpy(str_fnc + pos_str, ++strx);
		pos_str += len_str;
	}
	
	return pos_str;
}

int fileInOpen(char fname[])
{
	int fd_elf;

	truncate(fname, (off_t) 0);
	fd_elf = open(fname, O_WRONLY | O_CREAT | O_TRUNC);

	if(fd_elf < 0)
	{
		printf("unable open %s\n", fname);
		return -1;
	}

	struct stat st; 
	if(stat(fname, &st) != 0) 
	{
		printf("unable read permision for %s\n", fname);
		close(fd_elf);
		return -2;
	}
	st.st_mode |= S_IRWXU | S_IRWXG | S_IRWXO;

	if(chmod(fname, st.st_mode) != 0)
	{
		printf("unable write permision for %s\n", fname);
		close(fd_elf);
		return -3;
	}

	return fd_elf;
}

int main(int argc, char *argv[])
{
	if(argc < 4)
		usage();

	int fd_elf = 0, fd_aout = 0;
	char *name_elf = NULL, *name_aout = NULL;
	int retval = 0;
	
	if(!strcmp("-o", argv[1]))
	{
		name_elf = argv[2];
		name_aout = argv[3];
	}
	else if(!strcmp("-o", argv[2]))
	{
		name_aout = argv[1];
		name_elf = argv[3];
	}
	else
	{
		usage();
		goto error0;
	}

	fd_aout = open(name_aout, O_RDONLY);
	if(fd_aout < 0)
	{
		printf("unable open %s\n", argv[3]);
		retval = -2;
		goto error1;
	}

	fd_elf = fileInOpen(name_elf);
	if(fd_elf < 0)
	{
		retval = -2;
		goto error1;
	}

	char *elf_buf = NULL, *aout_buf = NULL;

	int aout_len = lseek(fd_aout, 0L, SEEK_END);
	int elf_len_buff = 0x300000;

	if(aout_len < 0)
	{
		printf("unable get size aout file\n");
		retval = -2;
		goto error2;
	}

	aout_buf = (char *)malloc(sizeof(char) * aout_len);
	if(!aout_buf)
	{
		printf("unable allocate memory of %d bytes\n", aout_len);
		retval = -2;
		goto error2;
	}

	elf_buf = (char *)malloc(sizeof(char) * elf_len_buff);
	if(!elf_buf)
	{
		printf("unable allocate memory of %d bytes\n", elf_len_buff);
		retval = -2;
		goto error3;
	}

	lseek(fd_aout, 0, SEEK_SET);
	if(read(fd_aout, aout_buf, aout_len) != aout_len)
	{
		printf("unable read from file %s\n", argv[1]);
		retval = -2;
		goto error4;
	}

	int len_elf = 0;


	if(!memcmp(aout_buf, "!<arch>\n", 8))
	{
		write(fd_elf, "!<arch>\n", 8);
		
		struct ar_header elf_ah;
		
		char file_id[16];
		int off_ar = 8;
		int pos_elf = 8;

		struct ar_header *ah = (struct ar_header*)(aout_buf + off_ar);
		int len_start = atoi(ah->file_size);
		off_ar += sizeof(struct ar_header);
		elf_ah = *ah;
		const int *aout_tab = (int*)(aout_buf + off_ar);
		
		int aout_idx = 2;
		int elf_idx = 0;

		const int number = *((int*)(aout_buf + off_ar))/ 8 + 1;
		int elf_tab[number];
		memset(elf_tab, 0xFF, number * 4);
		elf_tab[elf_idx++] = htonl(number - 1);

		off_ar += atoi(ah->file_size);

		if(off_ar % 2)
			off_ar++;

		ah = (struct ar_header*)(aout_buf + off_ar);

		int size_str = len_start - number * 8;
		char str_fnc[size_str];
		
		int elf_str_size = skip_underscore(aout_buf + number * 8 + 68, str_fnc, size_str);
		
		if(elf_str_size % 2)
			elf_str_size++;
		
		pos_elf = 68 + number * 4 + elf_str_size;
		
		
		memcpy((char *)&elf_ah.file_id, "/               ", 16);

		sprintf((char *)&elf_ah.file_size, "%-10d", pos_elf - 68);
		elf_ah.end[0] = '`';
		write(fd_elf, (char *)&elf_ah, sizeof(struct ar_header));
		write(fd_elf, elf_tab, number * 4);
		write(fd_elf, str_fnc, elf_str_size);

		strncpy(file_id, ah->file_id, 16);
		file_id[15] = '\0';
		
		off_ar += sizeof(struct ar_header);
		elf_ah = *ah;
		

		while(off_ar < aout_len)
		{
			if(!valid_aout((struct exec*)(aout_buf + off_ar)))
			{
				printf("%s: Malformed archive %d\n\n", name_elf, off_ar);
				retval = -2;
				goto error2;
			}

			int len_aout = atoi(ah->file_size);
			printf("File: %s(%s)\n", argv[1], file_id);

			if(convert(elf_buf, aout_buf + off_ar, &len_elf) != 0)
			{
				retval = -2;
				goto error2;
			}

			off_ar += len_aout;

			if(aout_buf[off_ar] == '\n')
				off_ar++;

			if(len_elf%2)
				len_elf++;

			sprintf((char *)&elf_ah.file_size, "%-10d", len_elf);
			elf_ah.end[0] = '`';
			
			int aout_prev_pos;

			do
			{
				elf_tab[elf_idx++] = htonl(pos_elf);
				aout_prev_pos = aout_tab[aout_idx];
				printf("aout_prev_pos: %x\n", pos_elf);
				aout_idx += 2;
			}
			while(aout_prev_pos == aout_tab[aout_idx]);
	
			write(fd_elf, (char *)&elf_ah, sizeof(struct ar_header));
			pos_elf += sizeof(struct ar_header);

			write(fd_elf, elf_buf, len_elf);
			pos_elf += len_elf;

			memset(elf_buf, 0, 0x30000);
			ah = (struct ar_header*)(aout_buf +  off_ar);
			elf_ah = *ah;
			strncpy(file_id, ah->file_id, 16);
			file_id[15] = '\0';

			off_ar += sizeof(struct ar_header);
		}

		lseek(fd_elf, 68, SEEK_SET);
		write(fd_elf, elf_tab, number * 4);
	}
	else if(valid_aout((struct exec *)aout_buf))
	{
		if(convert(elf_buf, aout_buf, &len_elf) != 0)
		{
			retval = -4;
			goto error4;
		}
		
		write(fd_elf, elf_buf, len_elf);
	}
	else
	{
		printf("file isn't aout format\n");
		retval = -4;
		goto error4;
	}

	error4:
		free(elf_buf);
	error3:
		free(aout_buf);
	error2:
		close(fd_elf);
	error1:
		close(fd_aout);
	error0:
		exit(retval);
}
