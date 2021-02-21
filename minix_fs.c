#include <stdio.h>
#include <unistd.h>
#include <fcntl.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <stdarg.h> 
#include <string.h>

#define NAME_LEN 			14
#define BUFF_SIZE 			(0x20 * 120)
#define BLOCK_SIZE 			1024
#define COUNT_BLOCKS		20
#define NR_SUPER			1
#define I_MAP_SLOTS 8
#define Z_MAP_SLOTS 8
#define SUPER_MAGIC 0x137F
#define NUM_DISK	1

/* Root device at bootup. */
#define ROOT_DEV 0x300
#define NR_INODE 32




void panic(char *s)
{
		printf ("%s\n", s);
		exit(-1);
}

static char buf[1024];

int printk(const char *fmt, ...)
{
	va_list args;
	int i;

	va_start(args, fmt);
	i=vsprintf(buf,fmt,args);
	va_end(args);
	printf ("%s\n", buf);
	
	return i;
}

long start_sect = 0;
int rd;

struct partition {
	unsigned char boot_ind;		/* 0x80 - active (unused) */
	unsigned char head;		/* ? */
	unsigned char sector;		/* ? */
	unsigned char cyl;		/* ? */
	unsigned char sys_ind;		/* ? */
	unsigned char end_head;		/* ? */
	unsigned char end_sector;	/* ? */
	unsigned char end_cyl;		/* ? */
	unsigned int start_sect;	/* starting sector counting from 0 */
	unsigned int nr_sects;		/* nr of sectors in partition */
};

struct dir_entry {
	unsigned short inode;
	char name[NAME_LEN];
};

struct d_inode {
	unsigned short i_mode;
	unsigned short i_uid;
	unsigned long i_size;
	unsigned long i_time;
	unsigned char i_gid;
	unsigned char i_nlinks;
	unsigned short i_zone[9];
};

int used_nodes = 0;
int used_zones = 0;

struct inode_itm
{
	int index;
	struct d_inode inode;
}*p_inodes = NULL;

struct m_inode {
	unsigned short i_mode;
	unsigned short i_uid;
	unsigned long i_size;
	unsigned long i_mtime;
	unsigned char i_gid;
	unsigned char i_nlinks;
	unsigned short i_zone[9];
/* these are in memory also */
	struct task_struct * i_wait;
	unsigned long i_atime;
	unsigned long i_ctime;
	unsigned short i_dev;
	unsigned short i_num;
	unsigned short i_count;
	unsigned char i_lock;
	unsigned char i_dirt;
	unsigned char i_pipe;
	unsigned char i_mount;
	unsigned char i_seek;
	unsigned char i_update;
};

struct super_block {
	unsigned short s_ninodes;
	unsigned short s_nzones;
	unsigned short s_imap_blocks;
	unsigned short s_zmap_blocks;
	unsigned short s_firstdatazone;
	unsigned short s_log_zone_size;
	unsigned long s_max_size;
	unsigned short s_magic;
/* These are only in memory */
	struct buffer_head * s_imap[8];
	struct buffer_head * s_zmap[8];
	unsigned short s_dev;
	struct m_inode * s_isup;
	struct m_inode * s_imount;
	unsigned long s_time;
	unsigned char s_rd_only;
	unsigned char s_dirt;
};

struct buffer_head {
	char b_data[BLOCK_SIZE];			/* pointer to data block (1024 bytes) */
	unsigned short b_blocknr;	/* block number */
	unsigned char b_dirt;		/* 0-clean,1-dirty */
	unsigned char b_count;		/* users using this block */
} blocks[COUNT_BLOCKS];

const char mask_patern[] = "drwxrwxrwx";
// const char path[] = "/opt/barebones/pokus/Linux-0.11/pokus.img";
// const char path[] = "/opt/barebones/pokus/Linux-0.11/hdc-0.11.img";
// const char path[] = "/opt/barebones/pokus/linux-0.01/hd_oldlinux.img";
// const char path[] = "/opt/barebones/pokus/Linux-0.11/my1.img";
const char path[] = "/opt/barebones/pokus/Linux-0.11/my2.img";
// const char path[] = "/opt/barebones/pokus/Linux-0.11/minix.img";

struct m_inode inode_table[NR_INODE]={{0,},};
struct super_block super_block[NR_SUPER];

struct buffer_head * bread(int dev,int block)
{
	int idx;
	int idx_free = -1;
	for(idx = 0; idx < COUNT_BLOCKS; idx++)
	{
		if(blocks[idx].b_blocknr == block)
		{
			blocks[idx].b_count++;
			return &blocks[idx];
		}	
		if(idx_free == -1 && blocks[idx].b_count == 0)
			idx_free = idx;
	}

	if(idx_free == -1)
		panic("no free buffer!\n");

	if(idx_free == -1)
	{
		idx_free = COUNT_BLOCKS - 1;
		blocks[idx_free].b_blocknr = 0;
	}
		
	struct buffer_head *p = blocks + idx_free;
	p->b_blocknr = block;
	block *= 2;
	block += start_sect;
	lseek(rd, block * 512, SEEK_SET);
	read(rd, p, BLOCK_SIZE);
	p->b_count++;

	return p;
}

void brelse(struct buffer_head * buf)
{
	if (!buf)
		return;
	if (!(buf->b_count--))
		panic("Trying to free free buffer");
}

void info_node(struct d_inode *pnode, int num_node)
{
		unsigned short mode = pnode->i_mode;
		char mask[] = "----------";

		int pos = 10;
		while (--pos >= 0)
			if( (1 << (9-pos))& mode )
				mask[pos] = mask_patern[pos];
		
		if(mode & S_IFDIR)	
			mask[0] = mask_patern[0];
		
		int block = super_block[0].s_imap_blocks;
		block += super_block[0].s_zmap_blocks;
		block += 2;
	
		int addr = 	block *= 2;
		addr += start_sect;
		addr *= 512;
		addr += (num_node - 1) * 32;
		
		printf ("num inode: %d, addr: 0x%X\n", num_node, addr);
		printf ("mask: %s\n", mask);
		printf ("mode: 0x%X\n", mode);
		
		printf ("type: ");
		if(S_ISSOCK(mode))
			printf ("socket ");
		if(S_ISLNK(mode))
			printf ("symbolic link ");
		if(S_ISREG(mode))
			printf ("regular file ");
		if(S_ISBLK(mode))
			printf ("block device ");
		if(S_ISDIR(mode))
			printf ("directory ");
		if(S_ISCHR(mode))
			printf ("character device ");
		if(S_ISFIFO(mode))
			printf ("FIFO");
		printf ("\n");
		
		printf ("uid: %x\n", pnode->i_uid);
		printf ("size: %lu\n", pnode->i_size);
		printf ("link: %d\n", pnode->i_nlinks);
		
		int zone;
		for(zone = 0; zone < 9; zone++)
		{
			if(!pnode->i_zone[zone])
				break;
			
			printf ("zone%d: %u\n", zone, pnode->i_zone[zone]);
		}
		
		unsigned long num = pnode->i_time;
		unsigned int seconds = num % 60;
		num /= 60;
		unsigned int minutes = num % 60;
		num /= 60;
		unsigned int hourse = num % 24;
		num /= 24;
		unsigned int days = num % 365;
		num /= 365;
		unsigned int years = num;

		printf ("time: %d %d days %d:%d:%d\n\n",
			1970 + years, days, hourse, minutes, seconds );	
}

struct d_inode *get_inode( int idx_search )
{
	int idx;
	
	for ( idx = 0; idx < used_nodes; idx++ )
		if(idx_search == p_inodes[idx].index)
			return &p_inodes[idx].inode;
	
	p_inodes[0].index = idx_search;
	idx_search--;
	int block = super_block[0].s_imap_blocks;
	block += super_block[0].s_zmap_blocks;
	block += idx_search / 32;
	struct buffer_head *p = bread(0, block);
	memcpy(&p_inodes[0].inode , p->b_data + idx_search * 0x20 % BLOCK_SIZE, 0x20 );
	brelse(p);
		
	return &p_inodes[0].inode;
}

void fold_dir(int idx_inode, int depth)
{
	struct d_inode *p_inode = get_inode( idx_inode );
	
	if( !p_inode )
	{
		printf ("node %d not exist\n", idx_inode);
		return;
	}
	
	if(!S_ISDIR(p_inode->i_mode))
		return;
	
	char anchor[depth + 1];
	memset (anchor, '\t', depth);
	anchor[depth] = '\0';
	
	unsigned long size = p_inode->i_size;
	int idx_zone = 0;
	struct dir_entry *dirs = NULL;
	struct buffer_head *bhead = NULL;
	
	while( size )
	{
		int zone = p_inode->i_zone[idx_zone++];
		if (!zone || !size)
			return;
		
		int size_buff = size > BLOCK_SIZE ? BLOCK_SIZE : size;
		int cnt_itm = size_buff / 16;
		
		if( bhead )
			brelse(bhead);
		
		bhead = bread(0,zone);
		dirs = (struct dir_entry*)bhead->b_data;
		
		size -= size_buff;
		
		int idx = 0;
		
		for (idx = 0; idx < cnt_itm; idx++)
		{
			printf ("\t%s%s\t\tinode: %d\n", anchor, dirs[idx].name, dirs[idx].inode);
			
			if(strcmp(dirs[idx].name, ".") == 0)
				continue;
			
			if(strcmp(dirs[idx].name, "..") == 0)
				continue;
			
			if(dirs[idx].inode < 2)
				continue;
			
			if(dirs[idx].inode == idx_inode)
				continue;
				
			fold_dir( dirs[idx].inode, depth + 1 );	
		}

	}
	
	if( bhead )
		brelse(bhead);
}

void root_dir()
{
	unsigned long size = p_inodes[0].inode.i_size;
	int cnt_itm = size / 16;
	
	int idx = 0;
	int idx_zone = 0;
	struct buffer_head *bhead = NULL;
	
	printf("root:\n");
	for (idx = 0; idx < cnt_itm; idx++)
	{
		struct dir_entry *dirs;
		
		if(idx % 64 == 0)
		{
			if(bhead)
				brelse(bhead);
			
			bhead = bread(0,p_inodes[0].inode.i_zone[idx_zone++]);
			dirs = (struct dir_entry*)bhead->b_data;	
		}

		int idx_int_block = idx % 64;
		printf ("\t%s\t\tinode: %d\n", dirs[idx_int_block].name, dirs[idx_int_block].inode);
		
		if(dirs[idx].inode > 1)
			fold_dir( dirs[idx].inode, 1 );
	}
	
	if( bhead )
		brelse(bhead);
}

#define set_bit(nr,addr) ({\
char tmp = addr[(nr) / 8];\
register int res;/* __asm__("ax");*/ \
__asm__("btsl %2,%3\n\tsetb %%al":"=a" (res):"0" (0),"r" (nr),"m" (*(addr))); \
addr[(nr) / 8] = tmp;\
res;})

int check_interval(int inodes)
{
	struct super_block * p = super_block;
	int size =p->s_imap_blocks;
	size *= BLOCK_SIZE;
	size *= 8;
	
	int total_nodes = 0;
	int last_set = 0;
	int i = 0;
	
	for ( i = 0; i < size; i++ )
		if (!set_bit(i&8191,p->s_imap[i>>13]->b_data))
		{
			if(last_set + 1 != i)
			{
				printf("<%d, ", last_set + 1 );
				printf("%d>,", i + 1);	
			}

			
			last_set = i;
		}
		else
			total_nodes++;

	printf  ("\ntotal_nodes: %d\n", total_nodes);

	return total_nodes;
}

void cash_nodes(struct inode_itm *pnodes)
{
	struct super_block * p = super_block;
	struct buffer_head * pbhead = NULL;
	int idx_node = 0;
	int i;
	int block = super_block[0].s_imap_blocks;
	block += super_block[0].s_zmap_blocks;
	block += 2;
	int size =p->s_imap_blocks;
	size *= BLOCK_SIZE;
	size *= 8;
	int idx_map;
	
	for( i = 0, idx_map = 0; i < size; i++ )
	{
		if( i * 0x20 % BLOCK_SIZE == 0)
		{
			if(pbhead)
				brelse(pbhead);
			
			pbhead = bread(0, block++);
		}	
		
		if (set_bit(i&8191,p->s_imap[i>>13]->b_data))
		{
			memcpy(&pnodes[idx_node].inode , pbhead->b_data + i * 0x20 % BLOCK_SIZE, 0x20 );
			pnodes[idx_node].index = 1 + i;
			idx_node++;
		}
	}
	
	if(pbhead)
		brelse(pbhead);
}

struct super_block * do_mount(int dev)
{
	struct super_block * p;
	struct buffer_head * bh;
	int i,block;

	for(p = &super_block[0] ; p < &super_block[NR_SUPER] ; p++ )
		if (!(p->s_dev))
			break;
	p->s_dev = -1;		/* mark it in use */
	if (p >= &super_block[NR_SUPER])
		return NULL;
	printk("bod 0\n");
	if (!(bh = bread(dev,1)))
		return NULL;
	printk("bod 1\n");
	*p = *((struct super_block *) bh->b_data);
	brelse(bh);
	printf("p->s_magic: %x\n", p->s_magic);
	if (p->s_magic != SUPER_MAGIC) {
		p->s_dev = 0;
		return NULL;
	}

	printk("bod 2\n");
	for (i=0;i<I_MAP_SLOTS;i++)
		p->s_imap[i] = NULL;
	for (i=0;i<Z_MAP_SLOTS;i++)
		p->s_zmap[i] = NULL;
	block=2;
	for (i=0 ; i < p->s_imap_blocks ; i++)
		if ((p->s_imap[i]=bread(dev,block)))
			block++;
		else
			break;
	for (i=0 ; i < p->s_zmap_blocks ; i++)
		if ((p->s_zmap[i]=bread(dev,block)))
			block++;
		else
			break;
	if (block != 2+p->s_imap_blocks+p->s_zmap_blocks) {
		for(i=0;i<I_MAP_SLOTS;i++)
			brelse(p->s_imap[i]);
		for(i=0;i<Z_MAP_SLOTS;i++)
			brelse(p->s_zmap[i]);
		p->s_dev=0;
		return NULL;
	}
	p->s_imap[0]->b_data[0] |= 1;
	p->s_zmap[0]->b_data[0] |= 1;
	p->s_dev = dev;
	p->s_isup = NULL;
	p->s_imount = NULL;
	p->s_time = 0;
	p->s_rd_only = 0;
	p->s_dirt = 0;
	return p;
}

static volatile int last_allocated_inode = 0;

void mount_root(void)
{
	int i,free;
	struct super_block * p;
	struct m_inode * mi;

	if (32 != sizeof (struct d_inode))
		panic("bad i-node size");

	for(p = &super_block[0] ; p < &super_block[NR_SUPER] ; p++)
		p->s_dev = 0;
	if (!(p=do_mount(ROOT_DEV)))
		panic("Unable to mount root");
}

int main(int argc, char *argv[])
{
	if(argc < 2)
	{
		printf("usage: minix_fs minix_image.img\n");
		return -1;
	}

	rd = open(argv[1],O_RDONLY);
	if(rd < 0)
	{
		printf("unable open file: %s", argv[1]);
		return -2;
	}

	struct d_inode node;
	struct partition *p;
	memset(blocks, 0,  sizeof(struct buffer_head) * COUNT_BLOCKS);
	int i;
	char block[BLOCK_SIZE];
	
	lseek(rd, 0, SEEK_SET);
	read(rd, block, BLOCK_SIZE);
	p = (struct partition *)(0x1BE + block);
	start_sect = p->start_sect;
	int idx_part;
	
	for( idx_part = 0; idx_part < 5; idx_part++, p++)
	{
		start_sect = p->start_sect;
		int h1 = p->head;
		int s1 = p->sector;
		int c1 = p->cyl;
		int h2 = p->end_head;
		int s2 = p->end_sector;
		int c2 = p->end_cyl;
		int cnt_sector = p->nr_sects;
	
		int sector_n = c2 * (start_sect + 1 - s1);
		sector_n -= c1 * (start_sect + cnt_sector - s2 + 1);
		int denominator = c2 * h1 - c1 * h2;
		if(!denominator)
			break;
		sector_n /= denominator;
		int head_n = h2 * (s1 - 1 - start_sect);
		head_n += h1 * (start_sect + cnt_sector - s2 + 1);
		denominator = (c2 * (start_sect + 1 - s1) - c1 * (start_sect + cnt_sector - s2 + 1));
		if(!denominator)
			break;
		head_n /= denominator;
		
		printf("Geometry:\n");
		printf("\theads: %d, sectors per track: %d\n", head_n, sector_n);
	}
	
	p = (struct partition *)(0x1BE + NUM_DISK * 16 + block);
	start_sect = p->start_sect;
	printf("Starting sector: %ld\n\n", start_sect);
	
	mount_root();
	
	printf("Super block:\n");
	printf("ninodes: %u\n", super_block->s_ninodes);
	printf("nzones: %u\n", super_block->s_nzones);
	printf("imap blocks: %u\n", super_block->s_imap_blocks);
	printf("zmap blocks: %u\n", super_block->s_zmap_blocks);
	printf("first datazone: %u\n", super_block->s_firstdatazone);
	printf("log zone size: %u\n", super_block->s_log_zone_size);
	printf("max size: %lu\n", super_block->s_max_size);
	printf("magic: %x\n", super_block->s_magic);
	printf("\n");
	
	int total;
	printf ("reserved inodes:\n");	
	total = check_interval(1);
	used_nodes = total;
	printf("\ntotal nodes: %d", total);
	printf("\n\n");
	
	p_inodes = (struct inode_itm*)malloc(total * sizeof(struct inode_itm));
	cash_nodes(p_inodes);
	
	if(!p_inodes)
	{
		printf("error allocate p_inodes\n");
		close (rd);
		return -1;
	}

	printf ("used zones:\n");
	total = check_interval(0);
	printf("\ntotal zones: %d", total);
	printf("\n\n");
	
	for( i=0; i < used_nodes; i++)
		info_node( &p_inodes[i].inode, p_inodes[i].index );

	root_dir();
	
	if(p_inodes)
		free(p_inodes);
	
	close (rd);
	return 0;
}

