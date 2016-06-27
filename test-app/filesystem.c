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
    if (fopen_s(&fo, name, "wb"))
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
    fpos_t outlen = 0;
    uint8_t *out = NULL;
    if (fopen_s(&fo, name, "rb"))
        goto err;
    // get total size
    if (fseek(fo, 0, SEEK_END))
        goto closerr;
    if (fgetpos(fo, &outlen))
        goto closerr;
    if (fseek(fo, 0, SEEK_SET))
        goto closerr;
    // allocate output buffer
    out = (uint8_t *)malloc(outlen);
    if (out == NULL)
        goto closerr;
    // read data (NOTE: not checking error on read)
    fread_s(out, outlen, 1, outlen, fo);
    // done
    if (fclose(fo))
        goto err;
    // output data
    *data = out;
    *datalen = outlen;
    return 0;
closerr:
    fclose(fo);
err:
    free(out);
    return 1;
}

void untrusted_fs_free(uint8_t *data) { free(data); }