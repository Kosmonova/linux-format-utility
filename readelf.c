// https://www.wikiwand.com/en/Ar_(Unix)

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <fcntl.h>
#include <elf.h>


#define BLOCK_SIZE 			1024
#define type_print(x) case (x): printf("%-"ALIGENT"s", #x + 4); break;
#define type_print0(x) case (x): printf("%-"ALIGENT"s", #x); break;



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

/*
    ********** begin buff **********
    --------------------------------   Elf32_Ehdr *elfn = buff
    |  e_type,  e_machine,          |
    |    . . .                      |
    |  e_shoff, e_shnum, e_shstrndx |
    --------------------------------   Elf32_Shdr *pshdr = buff + elfn->e_shoff
    |                               |  pshdr[1] / ----------------------------
    --------------------------------- ---------/ | sh_name, sh_type, sh_flags |
    |                               |  pshdr[2]  | sh_addr, sh_offset         |
    --------------------------------- ---------\ | sh_size, sh_link, sh_info  |
    |                               |  pshdr[.] \| sh_addralign, sh_entsize   |
    ---------------------------------              ---------------------------
    |                               |  pshdr[e_shnum]
    ---------------------------------
    |               .               |
    |               .               |  char *shstrtab = buff + \
    |               .               |         pshdr[elfn->e_shstrndx].sh_offset
    --------------------------------- <-----------------------------
    |                               |            ---                |
    |   ".shstrtab" <---------------------------| + | <-------      |
    |   ".symtab"   <-----------------------     ---          |     |
    |   ".strtab"   <--------------------   |     ^           |     |
    |   "..."                       |    |  |     |           |     |
    ---------------------------------    |  |  shstrtab       |     |
    |                               |    |  |                 |     |
    |                           --- |    |  |    ---          |     |
    ---------------------------------    |   ---| + |<-----   |     |
    |          ...                  |    |       ---       |  |     |
    ---------------------------------    |        ^        |  |     |
    ***********  end buff  ********      |        |        |  |     |
                                         |     shstrtab    |  |     |
                                         |                 |  |    ---
                                         |       ---       |  |   | + |<-- buff
                                          ------| + |<--   |  |    ---
                                                 ---    |  |  |     ^
                                                  ^     |  |  |     |
                                                  |     |  |  |     |
    ********** begin pshdr ********           shstrtab  |  |  |     |
     pshdr[x]                                           |  |  |     |
     ------------------------                           |  |  |     |
    | sh_name                |                          |  |  |     |
    | sh_offset              |                          |  |  |     |
    | ....                   |                          |  |  |     |
     ------------------------      ---                  |  |  |     |
                          buff -->|   |                 |  |  |     |
     pshdr[x]                   ->| + | -> char *strtab |  |  |     |
     ------------------------  |  |   |                 |  |  |     |
    | sh_offset >--------------    --                   |  |  |     |
    | sh_name    >--------------------------------------   |  |     |
    | sh_type == SHT_STRTAB  |                             |  |     |
    | ....                   |                             |  |     |
     ------------------------                              |  |     |
                                                           |  |     |
     const Elf32_Shdr *symtab = pshdr[x]                   |  |     |
     ------------------------                              |  |     |
    | sh_name    >-----------------------------------------   |     |
    | sh_type == SHT_SYMTAB  |                                |     |
    | ....                   |                                |     |
     ------------------------                                 |     |
                                                              |     |
     pshdr[e_shstrndx]                                        |     |
     -------------------------                                |     |
    | sh_name    >--------------------------------------------      |
    | sh_offset  >--------------------------------------------------
    | ....                    |
     -------------------------
               .
               .
               .

     pshdr[e_shnum]
     -------------------------
    | sh_name                 |
    | ....                    |
     -------------------------
    *********** end pshdr *********



    ******** begin string symbols *******
     ------------------------------ <------- strtab      ---
    | "nameVal1" <--------------------------------------| + |<----------
    | "nameVal2" <---------------------------------      ---            |
    | "..."                        |               |      ^             |
     ------------------------------                |      |             |
    ********* end string symbols ********          |    strtab          |
                                                   |                    |
                                                   |     ---            |
                                                    ----| + |<-------   |
                                                         ---         |  |
                                                          ^          |  |
                                                          |          |  |
                                                        strtab       |  |
                                                                     |  |
                                                                     |  |
                                                                     |  |
    ******** begin psymbols *******                                  |  |
                                    Elf32_Sym *psymbols = \          |  |
     psymbols[x]                          buff + symtab->sh_offset   |  |
     ------------------------------<--------------------             |  |
    | st_value, st_size, st_info  |                                  |  |
    | st_name >------------------------------------------------------   |
    | ..........                  |                                     |
     ------------------------------                                     |
               .                                                        |
               .                                                        |
               .                                                        |
     psymbols[symtab->sh_size / symtab->sh_entsize]                     |
     ------------------------------<--------------------                |
    | st_value, st_size, st_info  |                                     |
    | st_name >---------------------------------------------------------
    | ..........                  |
     ------------------------------
    ******** end psymbols *********

   */

void dump_elf(char *buff, int len_elf)
{
	Elf32_Ehdr *elfn = (Elf32_Ehdr*)buff;
	

	printf("\tELF format\n");

	printf("\te_type:      0x%x=%d\n", elfn->e_type,      elfn->e_type);
	printf("\te_machine:   0x%x=%d\n", elfn->e_machine,   elfn->e_machine);
	printf("\te_version:   0x%x=%u\n", elfn->e_version,   elfn->e_version);
	printf("\te_entry:     0x%x=%u\n", elfn->e_entry,     elfn->e_entry);
	printf("\te_phoff:     0x%x=%u\n", elfn->e_phoff,     elfn->e_phoff);
	printf("\te_shoff:     0x%x=%u\n", elfn->e_shoff,     elfn->e_shoff);
	printf("\te_flags:     0x%x=%u\n", elfn->e_flags,     elfn->e_flags);
	printf("\te_ehsize:    0x%x=%u\n", elfn->e_ehsize,    elfn->e_ehsize);
	printf("\te_phentsize: 0x%x=%u\n", elfn->e_phentsize, elfn->e_phentsize);
	printf("\te_phnum:     0x%x=%u\n", elfn->e_phnum,     elfn->e_phnum);
	printf("\te_shentsize: 0x%x=%u\n", elfn->e_shentsize, elfn->e_shentsize);
	printf("\te_shnum:     0x%x=%u\n", elfn->e_shnum,     elfn->e_shnum);
	printf("\te_shstrndx:  0x%x=%u\n", elfn->e_shstrndx,  elfn->e_shstrndx);

	int len = sizeof(Elf32_Ehdr);
	len += elfn->e_shoff;
	const Elf32_Shdr *pshdr = (const Elf32_Shdr *)(buff + elfn->e_shoff);
	const int nr_entries_tab = elfn->e_shnum;
	
	int idx_entry = 0;
	
	char *shstrtab = (char *)(buff + pshdr[elfn->e_shstrndx].sh_offset);
	char *strtab = NULL;
	const Elf32_Shdr *symtab = NULL, *reltab_text = NULL, * reltab_data = NULL;

	int no_rel_sect = 0;
	const Elf32_Shdr *pshdr_no_rel[nr_entries_tab];
	memset((char *)pshdr_no_rel, 0, nr_entries_tab * sizeof(Elf32_Shdr *));

	while(idx_entry < nr_entries_tab)
	{
		const Elf32_Shdr *pshdr_act = pshdr + idx_entry++;
		switch(pshdr_act->sh_type)
		{
			case SHT_REL:
			{
				if(pshdr[pshdr_act->sh_info].sh_flags & SHF_EXECINSTR)
					reltab_text = pshdr_act;

				if(pshdr[pshdr_act->sh_info].sh_flags & SHF_WRITE)
					reltab_data = pshdr_act;
				
				break;
			}

			default:
				pshdr_no_rel[no_rel_sect++] = pshdr_act;
				break;
		}
	}


	printf("\nSection Headers:\n");
	printf("  [Nr] Name              Type            Addr     Off    Size   ES Flg Lk Inf Al\n");


	
	for(idx_entry = 0; idx_entry < nr_entries_tab; idx_entry++)
	{
		if(pshdr[idx_entry].sh_type == SHT_SYMTAB)
			symtab= pshdr + idx_entry;

		if(pshdr[idx_entry].sh_type == SHT_STRTAB &&
			elfn->e_shstrndx != idx_entry)
				strtab = (char *)(buff + pshdr[idx_entry].sh_offset);

		printf("  [%-2d] %-18s", idx_entry, shstrtab + pshdr[idx_entry].sh_name);

		switch(pshdr[idx_entry].sh_type)
		{
#define ALIGENT	"16"
			type_print(SHT_NULL);
			type_print(SHT_PROGBITS);
			type_print(SHT_SYMTAB);
			type_print(SHT_STRTAB);
			type_print(SHT_RELA);
			type_print(SHT_HASH);
			type_print(SHT_DYNAMIC);
			type_print(SHT_NOTE);
			type_print(SHT_NOBITS);
			type_print(SHT_REL);
			type_print(SHT_SHLIB);
			type_print(SHT_DYNSYM);
			type_print(SHT_LOPROC);
			type_print(SHT_HIPROC);
			type_print(SHT_LOUSER);
			type_print(SHT_HIUSER);
#undef ALIGENT
		}
		printf("%08x ", pshdr[idx_entry].sh_addr);
		printf("%06x ", pshdr[idx_entry].sh_offset);
		printf("%06x ", pshdr[idx_entry].sh_size);
		printf("%02x ", pshdr[idx_entry].sh_entsize);
		
		char str_flags[5];
		memset(str_flags, 0, 5);
		if(pshdr[idx_entry].sh_flags & SHF_WRITE)
			strcat(str_flags, "W");

		if(pshdr[idx_entry].sh_flags & SHF_ALLOC)
			strcat(str_flags, "A");
		
		if(pshdr[idx_entry].sh_flags & SHF_EXECINSTR)
			strcat(str_flags, "X");
		
		if(pshdr[idx_entry].sh_flags & SHF_MASKPROC)
			strcat(str_flags, "p");

		printf("%3s ", str_flags);
		printf("%2d ", pshdr[idx_entry].sh_link);
		printf("%3d ", pshdr[idx_entry].sh_info);
		printf("%2d" , pshdr[idx_entry].sh_addralign);

		printf("\n");
	}

	Elf32_Sym *psymbols = (Elf32_Sym *)(buff + symtab->sh_offset);

	if(reltab_text)
	{
		int cnt_itm_rel = reltab_text->sh_size / sizeof(Elf32_Rel);
		printf("\nRelocation section '%s' at offset 0x%x contains %d entries:\n",
			shstrtab + reltab_text->sh_name, reltab_text->sh_offset, cnt_itm_rel);
		printf(" Offset     Info    Type            Sym.Value  Sym. Name\n");
		Elf32_Rel *prel = (Elf32_Rel *)(buff + reltab_text->sh_offset);

		for(idx_entry = 0; idx_entry < cnt_itm_rel; idx_entry++)
		{
			printf("%08x  ", prel->r_offset);
			printf("%08x ", prel->r_info);
			
			switch(ELF32_R_TYPE(prel->r_info))
			{
#define ALIGENT	"18"
				type_print0(R_386_NONE);
				type_print0(R_386_32);
				type_print0(R_386_PC32);
				type_print0(R_386_GOT32);
				type_print0(R_386_PLT32);
				type_print0(R_386_COPY);
				type_print0(R_386_GLOB_DAT);
#undef ALIGENT
			}

			printf("%08x   ", (psymbols + ELF32_R_SYM(prel->r_info))->st_value);
			if(ELF32_ST_TYPE((psymbols + ELF32_R_SYM(prel->r_info))->st_info) == STT_SECTION)
				printf("%-8s ", shstrtab + (*(pshdr_no_rel + ELF32_R_SYM(prel->r_info)))->sh_name);
			else
				printf("%-8s ", strtab + (psymbols + ELF32_R_SYM(prel->r_info))->st_name);
			printf("\n");
			prel++;
		}
	}

	if(reltab_data)
	{
		int cnt_itm_rel = reltab_data->sh_size / sizeof(Elf32_Rel);
		printf("\nRelocation section '%s' at offset 0x%x contains %d entries:\n",
			shstrtab + reltab_data->sh_name, reltab_data->sh_offset, cnt_itm_rel);
		printf(" Offset     Info    Type            Sym.Value  Sym. Name\n");
		Elf32_Rel *prel = (Elf32_Rel *)(buff + reltab_data->sh_offset);

		for(idx_entry = 0; idx_entry < cnt_itm_rel; idx_entry++)
		{
			printf("%08x  ", prel->r_offset);
			printf("%08x ", prel->r_info);
			
			switch(ELF32_R_TYPE(prel->r_info))
			{
#define ALIGENT	"18"
				type_print0(R_386_NONE);
				type_print0(R_386_32);
				type_print0(R_386_PC32);
				type_print0(R_386_GOT32);
				type_print0(R_386_PLT32);
				type_print0(R_386_COPY);
				type_print0(R_386_GLOB_DAT);
#undef ALIGENT
			}

			printf("%08x   ", (psymbols + ELF32_R_SYM(prel->r_info))->st_value);
			if(ELF32_ST_TYPE((psymbols + ELF32_R_SYM(prel->r_info))->st_info) == STT_SECTION)
				printf("%-8s ", shstrtab + (*(pshdr_no_rel + ELF32_R_SYM(prel->r_info)))->sh_name);
			else
				printf("%-8s ", strtab + (psymbols + ELF32_R_SYM(prel->r_info))->st_name);
			printf("\n");
			prel++;
		}
	}

	const int nr_sym_entries = symtab->sh_size / symtab->sh_entsize;
	printf("\nSymbol table '%s' contains %d entries:\n", 
		   shstrtab + symtab->sh_name, nr_sym_entries);
	printf("\n   Num:    Value  Size Type    Bind   Vis      Ndx Name\n");

	for(idx_entry = 0; idx_entry < nr_sym_entries; idx_entry++)
	{
		Elf32_Sym *psymbol = psymbols + idx_entry;
		printf("%6d: %08x  %4d ", idx_entry, psymbol->st_value, 
			   psymbol->st_size);

		switch(ELF32_ST_TYPE(psymbol->st_info))
		{
#define ALIGENT	"8"
			type_print(STT_NOTYPE);
			type_print(STT_OBJECT);
			type_print(STT_FUNC);
			type_print(STT_SECTION);
			type_print(STT_FILE);
			type_print(STT_LOOS);
			type_print(STT_HIOS);
			type_print(STT_LOPROC);
			type_print(STT_HIPROC);
#undef ALIGENT
		}

		switch(ELF32_ST_BIND(psymbol->st_info))
		{
#define ALIGENT	"7"
			type_print(STB_LOCAL);
			type_print(STB_GLOBAL);
			type_print(STB_WEAK);
			type_print(STB_LOOS);
			type_print(STB_HIOS);
			type_print(STB_LOPROC);
			type_print(STB_HIPROC);
#undef ALIGENT
		}

		switch(psymbol->st_other)
		{
#define ALIGENT	"9"
			type_print(STV_DEFAULT);
			type_print(STV_INTERNAL);
			type_print(STV_HIDDEN);
			type_print(STV_PROTECTED);
#undef ALIGENT
		}

		if(psymbol->st_shndx == SHN_UNDEF)
			printf("UND ");
		else if(psymbol->st_shndx == SHN_ABS)
			printf("ABS ");
		else if(psymbol->st_shndx == SHN_COMMON)
			printf("COM ");
		else
			printf("%3d ", psymbol->st_shndx);

		if(psymbol->st_name)
			printf("%s", strtab + psymbol->st_name);

		printf("\n");
	}
	
	printf("\n");
}

int main(int argc, char *argv[])
{
	if(argc < 2)
	{
		printf("usage: readelf exec_file\n");
		return -1;
	}

	int rd = open(argv[1],O_RDONLY);
	if(rd < 0)
	{
		printf("unable open file: %s", argv[1]);
		return -2;
	}

	int file_len = lseek(rd, 0L, SEEK_END);

	if(file_len < 0)
	{
		printf("unable get size file %s\n", argv[1]);
		close(rd);
		return -2;
	}

	char *buff = NULL;
	buff = (char *)malloc(sizeof(char) * file_len);
	if(!buff)
	{
		printf("unable allocate memory of %d bytes\n", file_len);
		close(rd);
		return -2;
	}

	lseek(rd, 0, SEEK_SET);
	if(read(rd, buff, file_len) != file_len)
	{
		printf("unable read from file %s\n", argv[1]);
		free(buff);
		close(rd);
		return -2;
	}

	printf("\nheader table:\n");

	if(!memcmp(buff, "!<arch>\n", 8))
	{
		int off_arr = 8;
		struct ar_header *ah = (struct ar_header*)(buff +  off_arr);
		off_arr += atoi(ah->file_size) + sizeof(struct ar_header);
		ah = (struct ar_header*)(buff +  off_arr);
		
		char file_id[16];
		strncpy(file_id, ah->file_id, 16);
		file_id[15] = '\0';
		
		off_arr += sizeof(struct ar_header);

		while(off_arr < file_len)
		{
			int len_elf = atoi(ah->file_size);
			printf("File: %s(%s)\n", argv[1], file_id);
			dump_elf(buff + off_arr, len_elf);
			off_arr += len_elf;
			
			ah = (struct ar_header*)(buff +  off_arr);
			strncpy(file_id, ah->file_id, 16);
			file_id[15] = '\0';

			off_arr += sizeof(struct ar_header);
		}
	}
	else if(!memcmp(buff, "\x7f" "ELF", 4))
	{
		dump_elf(buff, file_len);
	}
	else
	{
		free(buff);
		close (rd);
		printf("file isn't ELF format\n");
		return -1;
	}

	free(buff);
	close (rd);
	return 0;
}

