#include <cstdio>
// Upstream's tests report failure only through assert() (several fall off the end of main without a
// return), so reaching this puts() is the pass signal; the return value is deliberately ignored.
int mayhem_orig_main ();
int main ()
{
	mayhem_orig_main ();
	puts ("MAYHEM_TEST_OK");
	return 0;
}
