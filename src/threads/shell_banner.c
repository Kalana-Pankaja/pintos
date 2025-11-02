/* shell_banner.c */
#include "threads/shell_banner.h"
#include <stdio.h>
#include "devices/timer.h"

void
print_shell_banner(void)
{
    printf("\n");
    printf("************************************\n");
    printf("*        Welcome to Kalana Shell  *\n");
    printf("************************************\n");

    printf("\nLoading ");

    int i;
    for (i = 0; i < 10; i++)
    {
        timer_msleep(150);
        printf(".");
    }

    printf(" Done!\n\n");
    printf("Type a command or 'help' to begin.\n\n");
}
