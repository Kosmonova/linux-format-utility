
// http://man.cat-v.org/unix-6th/5/a.out
// http://www.retro11.de/ouxr/211bsd/usr/man/cat5/a.out.0.html
// https://www.freebsd.org/cgi/man.cgi?query=a.out&sektion=5


#include <stdio.h>
#include <fcntl.h>
#include <stdlib.h>
#include <string.h>

#define NS32K
#include "a.out.h"


#define BLOCK_SIZE 			1024
#define type_print(x) case (x): printf("%-"ALIGENT"s", #x + 2); break;

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

int valid_magic(struct exec *obj)
{
	short int magic = obj->a_info & 0777;

	if(magic == OMAGIC)
		printf("OMAGIC\n");
	else if(magic == NMAGIC)
		printf("NMAGIC\n");
	else if(magic == ZMAGIC)
		printf("ZMAGIC\n");
	else if(magic == QMAGIC)
		printf("QMAGIC\n");
	else if(magic == CMAGIC)
		printf("CMAGIC\n");
	else
	{
// 		printf("magic %o is no valid a.out format\n", magic);
		return 0;
	}

	return 1;
}

void dump_aout(char *buff, int len_aout)
{
	struct exec obj = *((struct exec *)buff); /* object header */
	
	printf("\nheader table:\n");

	printf("\ta_midmag: 0x%lx=%ld\n", obj.a_info, obj.a_info);
	printf("\ta_text:   0x%x=%d\n", obj.a_text,   obj.a_text);
	printf("\ta_data:   0x%x=%d\n", obj.a_data,   obj.a_data);
	printf("\ta_bss:    0x%x=%d\n", obj.a_bss,    obj.a_bss);
	printf("\ta_syms:   0x%x=%d\n", obj.a_syms,   obj.a_syms);
	printf("\ta_entry:  0x%x=%d\n", obj.a_entry,  obj.a_entry);
	printf("\ta_trsize: 0x%x=%d\n", obj.a_trsize, obj.a_trsize);
	printf("\ta_drsize: 0x%x=%d\n", obj.a_drsize, obj.a_drsize);
	
	int off = N_TXTOFF(obj);
	
	printf("\ntext offset: %d\n", N_TXTOFF(obj));

	off += obj.a_text;
	off += obj.a_data;

	struct relocation_info *prel_info_text = (struct relocation_info *)(buff + off);

	off += obj.a_trsize;
	
	struct relocation_info *prel_info_data = (struct relocation_info *)(buff + off);

	off += obj.a_drsize;

	printf("\nsym offset: %d\n", off);
	
	struct nlist *tab_syms_reloc = (struct nlist *)(buff + off);

	off += obj.a_syms;

	char* pstart_strings = (char*)(buff + off);

	printf("start address 0x%08x\n\n", obj.a_entry);
	
	printf("Sections:\n");
	printf("Idx Name          Size      VMA               " \
		"LMA               File off  Algn\n");
	printf("  0 .text         %08x  %08x  %08x  %08x  2**2\n\n", 
		obj.a_text, 		0, 			0,
		N_TXTOFF(obj));
	printf("  1 .data         %08x  %08x  %08x  %08x  2**2\n\n", 
		obj.a_data, N_DATOFF(obj) - N_TXTOFF(obj),
		N_DATOFF(obj) - N_TXTOFF(obj), N_DATOFF(obj));
	printf("  2 .bss          %08x  %08x  %08x  %08x  2**2\n\n", 
		obj.a_bss, N_TRELOFF(obj) - N_TXTOFF(obj), 
		N_TRELOFF(obj) - N_TXTOFF(obj), 0);


	printf("SYMBOL TABLE:\n");

	int idx = 0;
	char *arr_str[obj.a_syms/sizeof(struct nlist)];
	for( idx = 0; idx < obj.a_syms/sizeof(struct nlist); idx++)
	{
		struct nlist *p_sym = tab_syms_reloc + idx;
		char *sym_string = pstart_strings + p_sym->n_un.n_strx;
		arr_str[ idx ] = sym_string;
		printf("%08lx ", p_sym->n_value);
		
		if((p_sym->n_type & N_TYPE) == N_UNDF && !p_sym->n_value)
			printf("        ");
		else if(p_sym->n_type & N_EXT)
			printf("g       ");
		else
			printf("l       ");

		switch(p_sym->n_type & N_TYPE)
		{
			case N_UNDF: 
				if(p_sym->n_value)
					printf("*COM* "); 
				else
					printf("*UND* ");
			break;
			case N_ABS:  printf("*ABS* "); break;
			case N_TEXT: printf(".text "); break;
			case N_DATA: printf(".data "); break;
			case N_BSS:  printf(".bss  "); break;
// 			case N_REG:  printf(".bss  "); break;
// 			type_print(N_FN);
		}

		printf("%04d ", p_sym->n_other);
		printf("%02d ", p_sym->n_desc);
		printf("%02d ", p_sym->n_type);
		printf("%s ", sym_string);

		printf("\n");
	}

	if(obj.a_trsize)
	{
		printf("\n\nRELOCATION RECORDS FOR [.text]:\n");
		printf("OFFSET   TYPE              VALUE\n");

		for( idx = 0; idx < obj.a_trsize/sizeof(struct relocation_info); idx++)
		{
			printf("%08x ", prel_info_text[idx].r_address);
			
			if(prel_info_text[idx].r_pcrel)
				printf("DISP%02d            ", 8 << prel_info_text[idx].r_length);
			else
				printf("%02d                ", 8 << prel_info_text[idx].r_length);
			
			if(prel_info_text[idx].r_extern)
				printf("%s", arr_str[prel_info_text[idx].r_symbolnum]);
			else
				switch(prel_info_text[idx].r_symbolnum & N_TYPE)
				{
					case N_UNDF: printf("*UND* "); break;
					case N_COMM: printf("*COM* "); break;
					case N_ABS:  printf("*ABS* "); break;
					case N_TEXT: printf(".text "); break;
					case N_DATA: printf(".data-0x%08x", N_DATOFF(obj) - N_TXTOFF(obj)); break;
					case N_BSS:  printf(".bss-0x%08x", N_TRELOFF(obj) - N_TXTOFF(obj));break;
		// 			case N_REG:  printf(".bss  "); break;
		// 			type_print(N_FN);
				}
			printf("\n");
		}
	}

	if(obj.a_drsize)
	{
		printf("\n\nRELOCATION RECORDS FOR [.data]:\n");
		printf("OFFSET   TYPE              VALUE\n");

		for( idx = 0; idx < obj.a_drsize/sizeof(struct relocation_info); idx++)
		{
			printf("%08x ", prel_info_data[idx].r_address);
			
			if(prel_info_data[idx].r_pcrel)
				printf("DISP%02d            ", 8 << prel_info_data[idx].r_length);
			else
				printf("%02d                ", 8 << prel_info_data[idx].r_length);
			
			if(prel_info_data[idx].r_extern)
				printf("%s", arr_str[prel_info_data[idx].r_symbolnum]);
			else
				switch(prel_info_data[idx].r_symbolnum & N_TYPE)
				{
					case N_UNDF: printf("*UND* "); break;
					case N_COMM: printf("*COM* "); break;
					case N_ABS:  printf("*ABS* "); break;
					case N_TEXT: printf(".text "); break;
					case N_DATA: printf(".data "); break;
					case N_BSS:  printf(".bss-0x%08x", N_TRELOFF(obj) - N_TXTOFF(obj));break;
		// 			case N_REG:  printf(".bss  "); break;
		// 			type_print(N_FN);
				}
			printf("\n");
		}
	}

	printf("\n\n");	
}

int main(int argc, char *argv[])
{
	if(argc < 2)
	{
		printf("usage: readout exec_file\n");
		return -1;
	}
	
	int rd = open(argv[1],O_RDONLY);
	if(rd < 0)
	{
		printf("unable open file: %s\n", argv[1]);
		return -2;
	}
	
	int file_len = lseek(rd, 0L, SEEK_END);
	
	printf("size file: %d\n", file_len);
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

	if(!memcmp(buff, "!<arch>\n", 8))
	{
		char file_id[16];
		int off_ar = 8;
		struct ar_header *ah = (struct ar_header*)(buff +  off_ar);

		off_ar += atoi(ah->file_size) + sizeof(struct ar_header);

		if(off_ar % 2)
			off_ar++;

		ah = (struct ar_header*)(buff +  off_ar);
		
		
		strncpy(file_id, ah->file_id, 16);
		file_id[15] = '\0';
		
		off_ar += sizeof(struct ar_header);

		while(off_ar < file_len)
		{
			if(!valid_magic((struct exec*)(buff + off_ar)))
			{
				printf("%s: Malformed archive %d\n\n", argv[1], off_ar);
				free(buff);
				close (rd);
				return -1;
			}

			int len_aout = atoi(ah->file_size);
			printf("File: %s(%s)\n", argv[1], file_id);

			dump_aout(buff + off_ar, len_aout);
			off_ar += len_aout;
			
			if(buff[off_ar] == '\n')
				off_ar++;
	
			ah = (struct ar_header*)(buff +  off_ar);
			strncpy(file_id, ah->file_id, 16);
			file_id[15] = '\0';

			off_ar += sizeof(struct ar_header);
			
		}
	}
	else if(valid_magic((struct exec*)buff))
	{
		dump_aout(buff, file_len);
	}
	else
	{
		free(buff);
		close (rd);
		printf("file isn't aout format\n");
		return -1;
	}


	free(buff);
	close (rd);
	exit(0);
}

