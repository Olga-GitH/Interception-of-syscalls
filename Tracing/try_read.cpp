#include <iostream>
#include <sys/stat.h>
#include <sys/types.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>

int main() {
 int fd;
 char buf[80];
 // open file in read-only mode, return file descriptor 
 fd = open("file2.txt", O_RDONLY);
 // read the contents into the buf array
 read(fd, buf, sizeof(buf));
 // print contents of buf to the console
 printf("%s", buf);
 close(fd);
 exit (0); 
}
