* GOT: writtable
* No PIE: address fixed
* Have libc.so
* UAF: 
	* fastbin attack
	* unlink: global pointer array.

## How to attack:
### Method 1: Fastbin attack
fastbin attack or unlink 
	1. allocate to global pointer array: modify an entry make it points to another entry in the global pointer array.
	2. modify the second entry, make it points to a atoi's got entry.
	3. through this atoi's got pointer to rewrite the got, make it points to system.
