/* MOCK functions to provide filesystem OCALLs functionality */

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

uint8_t file[1024];
uint32_t maxfile = 1024;
uint32_t filelen = 0;

#define MAX_FNAME 48

int untrusted_fs_store(char *name, size_t namelen, uint8_t *data,
                       size_t datalen) {
    FILE *fo;
    if ((fo=fopen(name, "wb")) == NULL)
        goto err;
    if (fwrite(data, 1, datalen, fo) != datalen)
        goto closerr;
    if (fclose(fo))
        goto err;
    return 0;
closerr:
    fclose(fo);
err:
    return 1;
}

int untrusted_fs_load(char *name, size_t namelen, uint8_t **data,
                      size_t *datalen) {
    FILE *fo;
    long outlen;
    size_t readlen;
    uint8_t *out = NULL;
    if ((fo=fopen(name, "rb")) == NULL)
        goto err;
    // get total size
    if (fseek(fo, 0, SEEK_END))
        goto closerr;
    // get position
    outlen=ftell(fo);
    // and come back to begin
    if (fseek(fo, 0, SEEK_SET))
        goto closerr;
    // allocate output buffer
    out = (uint8_t *)malloc((uint32_t) outlen);
    if (out == NULL)
        goto closerr;
    // read data
    if(readlen = fread(out, 1, outlen, fo) != outlen)
        goto closerr;
    // done
    if (fclose(fo))
        goto err;
    // output data
    *data = out;
    *datalen = readlen;
    return 0;
closerr:
    fclose(fo);
err:
    free(out);
    return 1;
}

void untrusted_fs_free(uint8_t *data) { free(data); }
