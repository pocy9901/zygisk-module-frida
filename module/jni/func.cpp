#include <cstdlib>
#include <string.h>
#include <sys/sysmacros.h>

char * read_content(const char *filename, int *size) {
    FILE* regex = fopen(filename,"rb");
    if(regex != NULL) {
        fseek(regex, 0, SEEK_END);
        int len = ftell(regex);
        fseek(regex, 0, SEEK_SET);
        char * buf = (char *)malloc(len+1);
        if(buf == NULL) {
            fclose(regex);
            return NULL;
        }
        int readsize = fread(buf, 1, len, regex);
        if(readsize != len) {
            free(buf);
            fclose(regex);
            return NULL;
        }
        buf[len] = 0;
        *size = len;
        fclose(regex);
        return buf;
    }
    return NULL;
}

char * eat_white(char * data, char * end) {
    char * d = data;
    while(d < end) {
        if(*d == ' ' || *d == '\t' || *d == '\n' || *d == '\r') {
            d++;
        } else {
            return d;
        }
    }
    return NULL;
}

char * read_line(char * data, char * end, char ** line_end) {
    char * d = eat_white(data, end);
    *line_end = end;
    if(d == NULL) {
        return NULL;
    }
    char * start = d;
    while(d < end) {
        if(*d == '\n' || *d == '\r' || *d == 0) {
            if(d + 1 < end && *(d + 1) == '\n') {
                *line_end = d + 1;
            } else {
                *line_end = d;
            }
            break;
        }
        d++;
    }
    return start;
}

char * next_token(char * data, char * end, char ** token_end) {
    char * d = data;
    char * first = NULL;
    while(d < end) {
        if(*d == ' ' || *d == '\t' || *d == '\n' || *d == '\r' || *d == 0) {
            if(first) {
                *token_end = d;
                return first;
            }
        } else {
            if(!first) {
                first = d;
            }
            d++;
        }
    }
    if(first) {
        *token_end = end;
        return first;
    }
    return NULL;
}

int match(char * token, char * token_end, const char * data, const char * end) {
    int mb = *token == '^';
    int me = *(token_end-1) == '$';
    if(mb) token ++;
    if(me) token_end--;
    if(token + 1 == token_end) {
        return 1;
    }
    int mc = 0;
    char * find_token = token;
    const char * find_data = data;
    while(find_token < token_end && find_data < end) {
        if(*find_token != *find_data) {
            if(mb) {
                return 0;
            }
            find_token = token;
            if(*find_data != *find_token) {
                find_data++;
            }
            continue;
        }
        find_token++;
        find_data++;
    }
    if(find_token == token_end) {
        mc = 1;
        if(mb) {
            if(find_data - data != token_end - token) {
                return 0;
            }
        }
        if(me) {
            if(!(find_data == end && find_token == token_end)) {
                return 0;
            }
        }
        if(!mb && !me) {
            return find_token == token_end ? 1 : 0;
        }
    }
    return mc;
}

int get_module_base(const char* module_name, uint32_t pid, void** start_address, void** end_address) {
    char maps[2048], buffer[1024];
    snprintf(maps, sizeof(maps), "/proc/%d/maps", pid);
    FILE *maps_file = NULL;
    if((maps_file = fopen(maps, "r")) == NULL)
    {
        return -1;
    }
    *start_address = NULL;
    *end_address = NULL;
    unsigned long temp = 0, addr = 0;
    while (fgets(buffer, sizeof(buffer), maps_file)) {
            if (strstr(buffer, module_name)) {
                sscanf(buffer, "%lx-%lx %*s",&temp, &addr);
                if(*start_address == NULL) {
                    *start_address = (void *)temp;
                }
                *end_address = (void *)addr;
            }
    }
	fclose(maps_file);
    return addr > 0 ? 1 : 0;
}

int get_module_devinfo(const char* module_name, uint32_t pid, dev_t * dev, ino_t * inode) {
    char maps[2048], buffer[1024];
    snprintf(maps, sizeof(maps), "/proc/%d/maps", pid);
    FILE *maps_file = NULL;
    if((maps_file = fopen(maps, "r")) == NULL)
    {
        return -1;
    }
    *dev = 0;
    *inode = 0;
    unsigned int dev1 = 0, dev2 = 0, nd = 0;
    while (fgets(buffer, sizeof(buffer), maps_file)) {
        if (strstr(buffer, module_name)) {
            sscanf(buffer, "%*lx-%*lx %*s %*lx %x:%x %u",&dev1, &dev2, &nd);
            break;
        }
    }
    fclose(maps_file);
    *dev = makedev(dev1, dev2);
    *inode = nd;
    return dev1 != 0 ? 1 : 0;
}