#include <stdio.h>
#include <stdlib.h>

/**
 *  AUTHOR:	Ivan Stanev
 *  LIBNUM: 33123063
 *  DATE:	13 Mar 2014
 *
 *  "Buddy system" implementation 
 *  for memory management.
 *
 */

/* 
 * DEFINITIONS
 */
// size of buffer for reading input
#define BUFFER_SIZE (16)
// safe range for reading (should be BUFFER_SIZE - 1)
#define SAFE_READ_SIZE (15)
// main memory size (4K)
#define MEMORY_SIZE (4096)
// minimum memory block size 
#define	BLOCK_SIZE_MIN (128)
// actually, 63 bits are used but value must be 62
// to accommodate bit shifts and to avoid the sign bit
#define USED_BITS_MAX (62)
// the middle of the used bits in the 64-bit integer
#define INT_MIDDLE_BITS (32)
// bit state for marking a free bit
#define STATE_BLOCK_FREE (0)
// the character that symbolises a free block when memory is printed
#define CHAR_BLOCK_FREE ('F')
// bit state for marking an allocated bit
#define STATE_BLOCK_ALLOCATED (1)
// the character that symbolises an allocated block when memory is printed
#define CHAR_BLOCK_ALLOCATED ('A')

/*
 * GLOBAL VARIABLES
 */
// our main memory, with each bit corresponding to a block address
static long long int memory;

/* 
 * FUNCTION PROTOTYPES
 */
int mem_free(int address);
int mem_alloc(int size);
int mem_print(void);
int get_parent(int address);
int get_buddy(int address);
int get_child(int address);
int get_address_size(int address);

int bit_set(long long int *num, int bit);
int bit_clear(long long int *num, int bit);
int is_bit_free(long long int num, int bit);
int mem_free_helper(int address);
int mem_alloc_helper(long long int mem_copy, int size, int address);
int mem_print_helper(int address);
int round_up(int size);
int addr2loc(int address);
int loc2addr(int loc);

int
main(int argc, char *argv[])
{
	// buffer for holding input
	char buff[BUFFER_SIZE];
	int value;
	
	buff[SAFE_READ_SIZE] = '\0';
	// start obtaining input
	while (fgets(buff, SAFE_READ_SIZE, stdin)) {
		// get the number from the input
		value = atoi(buff + 2);
		if (value < 0) {
			fprintf(stdout, "Bad numeric format\n");
			continue;
		}
		
		// decide what to do based on the input
		if (buff[0] == CHAR_BLOCK_ALLOCATED) {
			fprintf(stdout, "[%d]", mem_alloc(value));
		}
		else if (buff[0] == CHAR_BLOCK_FREE) {
			fprintf(stdout, "[%d]", mem_free(loc2addr(value)));
		}
		else {
			break;
		}
		// print memory alayout
		(void)mem_print();
		
		buff[SAFE_READ_SIZE] = '\0';
	} 
	
	return 0;
}

/*
 * A recursive function that attempts to free a block and then
 * merge it with its (presumably) free buddy.
 * 
 */
int
mem_free_helper(int address) 
{
	int buddy;
	int parent;
	
	buddy = get_buddy(address);
	parent = get_parent(address);
	
	// if the current block has no buddy then we've reached
	// the topmost and largest block
	if (buddy == -1) {
		memory = 0;
		return 0;
	}
	
	// mark the current block as free
	bit_clear(&memory, address);
	// if this block's buddy is also free, then merge them
	if (is_bit_free(memory, buddy)) {
		bit_clear(&memory, parent);
		// continue with the merged block
		return mem_free_helper(parent);
	}
	
	return 0;
}

/*
 * Frees an address and recursively attempts to
 * merge buddies that are marked as free.
 * Returns 0 if successful, -1 otherwise.
 */
int 
mem_free(int address)
{
	int child;
	
	// first perform some data validation checks
	if (address > USED_BITS_MAX || address < 0) {
		return -1;
	}
	// handling the case of an attempt to free the max size block
	if (address == USED_BITS_MAX) {
		// if the whole max size block is used, then we can allow freeing
		if (memory == (1LL << USED_BITS_MAX)) {
			memory = 0;
			return 0;
		}
		else {
			return -1;
		}
	}
	
	child = get_child(address);
	if (is_bit_free(memory, address)) {
		return -1;
	}
	
	if (child != -1) {
		if (!is_bit_free(memory, child) || !is_bit_free(memory, get_buddy(child))) {
			return -1;
		}
	}

	return mem_free_helper(address);
}

/*
 * Gets the first child of the address (i.e. the left branch of a binary tree).
 * Its buddy can be found by calling get_buddy on the return value.
 */
int 
get_child(int address)
{
	// 128 bytes blocks do not have children, as well as blocks over MEMORY_SIZE
	
	if (address <= USED_BITS_MAX && address >= INT_MIDDLE_BITS) {
		// determine where this block's child is based on its address
		if ((address % 2) == 0) {
			return address - ((USED_BITS_MAX - address) + 1);
		}
		else {
			return address - (USED_BITS_MAX - address) - 1;
		}
	}
	
	return -1;
}

/*
 * Finds the parent of a block specified by its address.
 */
int 
get_parent(int address)
{
	// only blocks with size less than MEMORY_SIZE have parents
	if (address < USED_BITS_MAX) {
		return INT_MIDDLE_BITS + address / 2;
	}
	
	return -1;
}

/*
 * Finds the block's buddy by using the block's address.
 */
int 
get_buddy(int address)
{
	// bounds check (make sure the address is valid within the program)
	if (address < USED_BITS_MAX && address >= 0) {
		if ((address % 2) == 0) {
			return address + 1;
		}

		return address - 1;
	}
	
	return -1;
}

/*
 * Converts a specified size to a block size that is 
 * more easily used within the program.
 * Since the blocks used internally are powers of 2 (i.e. 128, 256) 
 * it makes sense to have this conversion.
 * Returns -1 if size cannot be converted.
 *
 * CREDITS TO:
 * Pete Hart and William Lewis (February, 1997), http://graphics.stanford.edu/~seander/bithacks.html#RoundUpPowerOf2
 * Sean Anderson (Sepember 14, 2001), https://groups.google.com/forum/#!topic/comp.lang.python/xNOq4N-RffU
 */
int 
round_up(int size)
{
	if (size <= 0 || size > MEMORY_SIZE) {
		return -1;
	}
	
	// enforce minimum block size
	if (size < BLOCK_SIZE_MIN) {
		return BLOCK_SIZE_MIN;
	}
	
	size--;
	size |= size >> 1;
	size |= size >> 2;
	size |= size >> 4;
	size |= size >> 8;
	size |= size >> 16;
	size++;
	
	return size;
}

/*
 * A helper recursive function that attempts to scan the memory in search for a free block.
 * Holds a copy of the memory ("mem_copy") on which it writes potential changes.
 * The "address" parameter is the block's address that is browsed in each recursive context.
 * If a free block is found, all changes done on "mem_copy" are applied to memory.
 * The block's address is returned, or -1 if no free block is found.
 */
int
mem_alloc_helper(long long int mem_copy, int size, int address)
{
	// stores the current address' occupied memory size in bytes
	int address_size;
	// the left child of the conceptual binary tree search
	int child_left;
	// ... and the right child
	int child_right;
	// temporary holder for return values from functions
	int retval;
	
	address_size = get_address_size(address);
	if (size > address_size) {
		// can't allocate blocks THAT big
		return -1;
	}
	
	child_right = get_child(address);
	child_left = get_buddy(child_right);

	// is the location we are currently viewing free?
	if (is_bit_free(mem_copy, address)) {
		// it was free, so now we can mark it as allocated
		bit_set(&mem_copy, address);

		// is this the block size we were looking for?
		if (size == address_size) {
			// apply all accumulated changes to memory
			memory = mem_copy;
			return address;
		}
		else {
			// this block size is too big, continue searching lower blocks
			return mem_alloc_helper(mem_copy, size, child_left);
		}
	}
	else {
		// the location is not free
		
		// if this block has children, then we can continue searching
		if (child_left != -1 && child_right != -1) {
			// if both children are NOT allocated, then their parent occupies the block completely
			if (is_bit_free(mem_copy, child_left) && is_bit_free(mem_copy, child_right)) {
				// we can't search more at this point
				return -1;
			}
			
			// try searching one of the children; if it does not give us a free address,
			// then go in the other child's direction in the hopes of finding a free one
			retval = mem_alloc_helper(mem_copy, size, child_left);
			if (retval == -1) {
				return mem_alloc_helper(mem_copy, size, child_right);
			}
			else {
				return retval;
			}
			// ^ in either case we return the found address or -1
		}
		
		// we can do nothing if we have reached an allocated 128 bytes block - no free space!
	}
	
	// default -1 (usually returned when we've reached an allocated 128 bytes block)
	return -1;
}

/*
 * Attempts to allocate a block of a specified size.
 * Performs validity checks on the requested size and converts it to an internally usable value.
 * Uses a helper recursive function with a copy of main memory that accumulates changes.
 * Returns the allocated block's address or -1 if nothing is found.
 */
int 
mem_alloc(int size)
{
	int retval;
	
	// first convert the size to an appropriate value
	size = round_up(size);

	if (size == MEMORY_SIZE) {
		// is memory occupied if its full size is requested?
		if (memory) {
			return -1;
		}
		
		bit_set(&memory, USED_BITS_MAX);
		return USED_BITS_MAX;
	}
	if (size <= 0) {
		return -1;
	}
	
	retval = mem_alloc_helper(memory, size, USED_BITS_MAX);
	if (retval != -1) {
		return addr2loc(retval);
	}
	
	return -1;
}

/*
 * Given a memory address (bit), its corresponding size is returned.
 */
int 
get_address_size(int address)
{
	int i;
	int step;
	
	i = INT_MIDDLE_BITS;
	step = 1;
	while (i <= USED_BITS_MAX) {
		if (address < i) {
			return BLOCK_SIZE_MIN * step;
		}
		
		step *= 2;
		i += (INT_MIDDLE_BITS / step);
	}
	if (address == USED_BITS_MAX) {
		return MEMORY_SIZE;
	}
	
	return -1;
}

/*
 * A recursive function that scans the branches of the binary tree memory layout.
 */
int 
mem_print_helper(int address)
{
	// temporary holder for the "left" child (conceptual binary tree)
	int child_left;
	// the other child of "address"
	int child_right;
	
	if (address < 0) {
		// stop here if a faulty adress is passed
		return -1;
	}
	
	child_right = get_child(address);
	child_left = get_buddy(child_right);

	// is the current address bit free?
	if (is_bit_free(memory, address)) {
		// does the address have children?
		if (child_left != -1 && child_right != -1) {
			// if both children are free, then the current address can be considered free
			if (is_bit_free(memory, child_left) && is_bit_free(memory, child_right)) {
				fprintf(stdout, "(%d%c)", get_address_size(address), CHAR_BLOCK_FREE);
			}
		}
		// if the address has no children, we've reached a free block with the smallest possible size
		else {
			fprintf(stdout, "(%d%c)", get_address_size(address), CHAR_BLOCK_FREE);
		}
	}
	// the current address is occupied...
	else {
		// does the block have children? (it can be traversed)
		if (child_left != -1 && child_right != -1) {
			// are both children free? this means we should not search downwards - this block is fully taken
			if (is_bit_free(memory, child_left) && is_bit_free(memory, child_right)) {
				fprintf(stdout, "(%d%c)", get_address_size(address), CHAR_BLOCK_ALLOCATED);
			}
			// one or both of the children are marked as allocated - continue downwards
			else {
				mem_print_helper(child_left);
				mem_print_helper(child_right);
			}
		}
		// the address has no more children; just print that it is allocated
		else {
			fprintf(stdout, "(%d%c)", get_address_size(address), CHAR_BLOCK_ALLOCATED);
		}
	}
	
	return 0;
}


/*
 * Prints the memory layout and the state of the memory blocks.
 * Uses a recursive helper function to scan the memory.
 */
int 
mem_print(void)
{
	(void)mem_print_helper(USED_BITS_MAX);
	fprintf(stdout, "\n");
	return 0;
}

/*
 * Sets the requested bit to 1.
 */
int 
bit_set(long long int *num, int bit)
{
	if (bit < 0 || bit > USED_BITS_MAX) {
		return -1;
	}	
	
	*num |= (1LL << bit);
	return 0;
}

/*
 * Checks whether a bit is free.
 * Returns 1 if the bit is free, 0 otherwise.
 */
int
is_bit_free(long long int num, int bit) 
{
	return !(num & (1LL << bit));
}

/*
 * Sets the specified bit to 0.
 */
int
bit_clear(long long int *num, int bit)
{
	if (bit < 0 || bit > USED_BITS_MAX) {
		return -1;
	}	
	
	*num &= ~(1LL << bit);
	return 0;
}


/*
 * Converts an internal address representation (a bit) to a memory location.
 * Used to translate the return value from mem_alloc() to a printable memory location.
 */
int
addr2loc(int address)
{
	int i;
	int step;
	int prev;
	
	// the same mechanism for looping is used as in get_address_size()
	
	i = INT_MIDDLE_BITS;
	step = 1;
	// however, we have a variable that would store the previous value of "i"; must default to 0
	prev = 0;
	
	while (i <= USED_BITS_MAX) {
		if (address < i) {
			return BLOCK_SIZE_MIN * step * (address - prev);
		}
		
		prev = i;
		step *= 2;
		i += (INT_MIDDLE_BITS / step);
	}
	// if the whole memory is to be occupied, the block starts at address 0
	if (address == USED_BITS_MAX) {
		return 0;
	}
	
	return -1;
}

/*
 * Converts a memory address/location to an internal representation (a bit).
 * Used to revert back a previously displayed memory location to an internal bit position.
 * This passes an argument 
 */
int 
loc2addr(int loc)
{
	int i;
	int parent;
	int temp;
	
	// mem_alloc() will always return addresses that are multiple of BLOCK_SIZE_MIN
	if (loc % BLOCK_SIZE_MIN != 0) {
		return -1;
	}
	
	// loop until we reach the bit that holds the block which presumably corresponds to "loc"
	for (i = 0; i < INT_MIDDLE_BITS; ++i) {
		if (i * BLOCK_SIZE_MIN == loc) {
			// if this block is free, then "loc" must correspond to a block of bigger size
			if (is_bit_free(memory, i)) {
				temp = i;
				// start looping upwards until we find the block which we want to convert
				while (1) {
					parent = get_parent(temp);
					if (!is_bit_free(memory, parent)) {
						// we found the bit corresponding to "loc", so return it
						return parent;
					}
					
					temp = parent;
				}
			}
			
			// if it isn't free, then this is the block we are looking to free
			return i;
		}
	}
	/* NOTREACHED */
	
	return 0;
}

/*
MAPPING TABLE FOR 32-BIT MEMORY WITH LOWEST BLOCK SIZE 256 BYTES

30 -> 29 28, where 28 is obtained through get_child(30), and 29 with get_buddy(get_child(30))
29 -> 27 26
28 -> 25 24
27 -> 23 22
26 -> 21 20
25 -> 19 18
24 -> 17 16
23 -> 15 14
22 -> 13 12
21 -> 11 10
20 -> 9 8
19 -> 7 6
18 -> 5 4
17 -> 3 2
16 -> 1 0
0-15 = 256 byte blocks
Total used bits: 31

0   1   2   3   4   5   6   7   8   9   10  11  12  13  14  15
256 256 256 256 256 256 256 256 256 256 256 256 256 256 256 256 

512 512 512 512 512 512 512 512 1024 1024 1024 1024 2048 2048 4096
16  17  18  19  20  21  22  23  24   25   26   27   28   29   30

TREE WITH BIT RELATIONSHIPS:
          30
		/    \
	   29    28
	  /  \  /  \
     27  26 25  24
	 /\ /\  /\ /\
	      etc.
		  
The same concept applies for 64-bit memory with lowest block size 128 bytes.
There will be 32 blocks of 128 bytes, 16 blocks of 256, 8 of 512, 4 of 1024, 2 of 2048, 1 of 4096.
Total of used bits: 63
*/
