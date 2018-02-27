/* ========================================================================
   $SOURCE FILE
   $File: user_interface.cpp $
   $Program: $
   $Developer: Jordan Marling $
   $Created On: 2015/10/27 $
   $Functions: $
void RenderProgressbar(const char *text, float percent)

   $Description: This file contains all commandline user interface functions $
   $Revisions: $
   ======================================================================== */

#include <stdio.h>
#include <string.h>
#include <sys/ioctl.h>
#include <unistd.h>

/* ========================================================================
   $ FUNCTION
   $ Name: RenderProgressbar $
   $ Prototype: void RenderProgressbar(const char *text, float percent) $
   $ Params: 
   $    text: The text associated with the progressbar $
   $    percent: The percent the progress bar is at $
   $ Description:  $
   ======================================================================== */
void RenderProgressbar(const char *text, float percent)
{
    struct winsize win;
    int textlen = (text == 0 ? 0 : strlen(text));

    ioctl(STDOUT_FILENO, TIOCGWINSZ, &win);

    int progressbar = win.ws_col - 13 - textlen;
    int progressbar_filled = progressbar * percent;

    if (text != 0)
    {
        printf("%s ", text);
    }
    printf("[");
    for(int j = 0; j < progressbar_filled - 1; j++)
    {
        printf("=");
    }
    if (percent == 1.0f)
    {
        printf("=");
    }
    else
    {
        printf(">");
    }
    for(int j = 0; j < (progressbar - progressbar_filled); j++)
    {
        printf(" ");
    }

    printf("] %.2f%%\r", percent * 100);
    fflush(stdout);

}
