#include <stdio.h>
#include <fcntl.h>
#include <stdlib.h>
#include <string.h>

#include "out.h"

int valid_magic(struct outhead *head)
{
	return head->oh_magic == O_MAGIC;
}

void dump_ack(char *buff, int len)
{
	struct outhead head =*((struct outhead *)buff);
	int position_ack = 0;
	int ntext = 0;
	int ndata = 0;
	int nbss = 0;
	
	int text_offset = 0;
	int data_offset = 0;
	int bss_offset = 0;
	int string_offset = 0;
	
	printf("\nheader table:\n");

	printf("\toh_magic: 0x%lx=%d\n", head.oh_magic, head.oh_magic);
	printf("\toh_stamp: 0x%x=%d\n", head.oh_stamp,   head.oh_stamp);
	printf("\toh_flags: 0x%x=%d\n", head.oh_flags,   head.oh_flags);
	printf("\toh_nsect: 0x%lx=%d\n", head.oh_nsect, head.oh_nsect);
	printf("\toh_nrelo: 0x%lx=%d\n", head.oh_nrelo, head.oh_nrelo);
	printf("\toh_nname: 0x%lx=%d\n", head.oh_nname, head.oh_nname);
	printf("\toh_nemit: 0x%lx=%d\n", head.oh_nemit, head.oh_nemit);

	position_ack = OFF_SECT(head);

	struct outsect *osects = position_ack + buff;

	int idx = 0;
	for(idx = 0; idx < head.oh_nsect; idx++)
	{
		struct outsect *osectc = osects + idx;
		printf("idx %d, os_size=%d\n", idx, osectc->os_size);
		switch(idx)
		{
			case 0:
				ntext = osectc->os_size;
				text_offset = osectc->os_foff;
				break;
			case 1:
				// ntext = os_size;
				break;
			case 2:
				ndata = osectc->os_size;
				data_offset = osectc->os_foff;
				break;
			case 3:
				nbss = osectc->os_size;
				bss_offset = osectc->os_foff;
				break;
			default:
				printf("index %d not valid\n", idx);
				break;
		}
	}

	position_ack += head.oh_nsect * sizeof(struct outsect);

	printf("\ncode:\n");
	for(idx = 0; idx < ntext; idx++)
	{
		if(idx % 16 == 0 && idx > 0)
			printf("\n");
		printf("%0.2x ", (unsigned char)*(buff + text_offset + idx));
	}
	printf("\n");
	position_ack += ntext;

	printf("\ndata:\n");
	for(idx = 0; idx < ndata; idx++)
	{
		if(idx % 16 == 0 && idx > 0)
			printf("\n");
		printf("%c", (unsigned char)*(buff + data_offset + idx));
	}
	
	printf("\n");

	struct outrelo *p_outrelos =buff + OFF_RELO(head);

	printf("outrelo:\n");
	for(idx = 0; idx < head.oh_nrelo; idx++)
	{
		struct outrelo *p_outrelo = p_outrelos + idx;
		printf("%d: or_addr=%d type=0x%0.2x\n", idx, p_outrelo->or_addr,
			p_outrelo->or_type);
	}

	struct outname *p_outnames = buff + OFF_NAME(head);

	char *chars[head.oh_nname];
	printf("outname:\n");
	for(idx = 0; idx < head.oh_nname; idx++)
	{
		struct outname *p_outname = p_outnames + idx;
		printf("%d: on_type=%d on_off=0x%0.2x\n", idx, p_outname->on_type,
			p_outname->on_foff);
		chars[idx] = buff + p_outname->on_foff;
	}

	position_ack += head.oh_nname * sizeof(struct outname);
	printf("chars:\n");
	for(idx = 0; idx < head.oh_nname; idx++)
	{
		printf("%d: %s\n", idx, chars[idx]);
	}
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

	if(valid_magic(buff))
	{
		dump_ack(buff, file_len);
	}
	else
	{
		free(buff);
		close (rd);
		printf("file isn't ack format\n");
		return -1;
	}

	free(buff);
	close (rd);
	exit(0);
}
