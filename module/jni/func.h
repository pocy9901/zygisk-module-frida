#pragma once
#include <sys/types.h>

char * read_content(const char *filename, int *size);
char * eat_white(char * data, char * end);
char * read_line(char *data, char *end, char ** line_end);
char * next_token(char * data, char * end, char ** token_end);
int match(char * token, char * token_end, const char * data, const char * end);

int get_module_base(const char* module_name, uint32_t pid, void** start_address, void** end_address);
int get_module_devinfo(const char* module_name, uint32_t pid, dev_t * dev, ino_t * inode);