* no-pie binary：
	* The offset of ptr2canary to libc base is different when aslr is on or off.
	* The offset of ptr2canary to libc base is constant, no matter ASLR is on or off.

* pie binary:
	* The offset of ptr2canary to libc base is diffent when aslr is on or off.
	* The offset of ptr2canary to libc base is constant, no matter ASLR is on or off.

* The offset of ptr2canary is a constant that is relative to ASLR, the libc its loaded and is irrelevant to PIE.
