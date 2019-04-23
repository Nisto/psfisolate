#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <limits.h>
#include "zlib/zlib.h"

//
// TODOs:
//
// - miniPSF support?
// - automatic detection of sample data?
//

#define min(a,b) (((a)<(b))?(a):(b))

#ifdef _WIN32
#define issep(x) (((x) == '\\') || ((x) == '/'))
#else
#define issep(x) ((x) == '/')
#endif

#define ADPCM_LOOP_START   (1 << 2)
#define ADPCM_LOOP_EXISTS  (1 << 1)
#define ADPCM_LOOP_END     (1 << 0)

#define ADPCM_BLOCK_SIZE   (16)

// SPU RAM can only hold 508 KiB sample data (4 KiB reserved for decompressed data)
#define MAX_SAMPLE_SIZE    (508 * 1024)

// Every sample should have at least one block
#define MAX_NUM_SAMPLES    (MAX_SAMPLE_SIZE / ADPCM_BLOCK_SIZE)

#define EXE_MAX_SIZE       (2 * 1024 * 1024)

typedef struct {
  long offset;
  long size;
} sample_t;

const uint8_t spu_irq_clear_block[ADPCM_BLOCK_SIZE] = {
  0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00
};

const uint8_t oneshot_end_block_1[ADPCM_BLOCK_SIZE] = {
  0x00,0x07,0x77,0x77,0x77,0x77,0x77,0x77,0x77,0x77,0x77,0x77,0x77,0x77,0x77,0x77
};

const uint8_t oneshot_end_block_2[ADPCM_BLOCK_SIZE] = {
  0x00,0x07,0x07,0x07,0x07,0x07,0x07,0x07,0x07,0x07,0x07,0x07,0x07,0x07,0x07,0x07
};

const uint8_t oneshot_end_block_3[ADPCM_BLOCK_SIZE] = {
  0x00,0x07,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00
};

uint8_t is_sample_end(uint8_t *block)
{
  uint8_t flags = block[0x01];

  if (flags == 0x07) {
    // it's important that we check for one-shot end blocks first,
    // since they contain both the LOOP/EXISTS and LOOP/END bits

    // if (memcmp(oneshot_end_block_1, block, sizeof oneshot_end_block_1) == 0)
    //   return 1;
    // if (memcmp(oneshot_end_block_2, block, sizeof oneshot_end_block_2) == 0)
    //   return 1;
    // if (memcmp(oneshot_end_block_3, block, sizeof oneshot_end_block_3) == 0)
    //   return 1;

    // Crash Team Racing has end blocks which do NOT start with 0x00, so for now...
    return 1;
  } else if (flags & ADPCM_LOOP_EXISTS && flags & ADPCM_LOOP_END) {
    // if there's a loop, it always ends at the end of the sample
    return 1;
  }

  return 0;
}

uint8_t is_adpcm_block(uint8_t *block, uint8_t zero_block_valid)
{
  uint32_t sum = 0;

  if (!zero_block_valid) {
    // check if last three 32-bit words are zero
    sum |= *(uint32_t*)(block+0x04);
    sum |= *(uint32_t*)(block+0x08);
    sum |= *(uint32_t*)(block+0x0C);

    // check if first 32-bit word is zero
    if ( ( sum | *(uint32_t*)(block+0x00) ) == 0 ) {
      return 0;
    }

    // check if first two sample bytes are zero
    if ( ( sum | *(uint16_t*)(block+0x02) ) == 0 ) {
      // if all samples are zero, the first byte should be 0x0C, so:
      // check if not a one-shot end block and if first byte is 0x0C
      if (block[0x00] != 0x0C && block[0x01] != 0x07) {
        return 0;
      }
    }
  }

  if ( ( block[0x00] & 0xF0 ) > 0x40 ) return 0;
  if ( ( block[0x00] & 0x0F ) > 0x0C ) return 0;
  if ( ( block[0x01] & 0xF0 ) > 0x00 ) return 0;
  if ( ( block[0x01] & 0x0F ) > 0x07 ) return 0;

  return 1;
}

long get_sample_meta(sample_t *samples, uint8_t *exebuf, long offset, long size)
{
  long sample_start = offset;
  long sample_size = 0;
  long num_samples = 0;

  for (; offset + ADPCM_BLOCK_SIZE <= size; offset += ADPCM_BLOCK_SIZE) {
    if ( is_adpcm_block(&exebuf[offset], sample_size == 0) ) {
      sample_size += ADPCM_BLOCK_SIZE;
      if ( is_sample_end(&exebuf[offset]) ) {
        samples[num_samples].offset = sample_start;
        samples[num_samples].size = sample_size;

        sample_start = offset + ADPCM_BLOCK_SIZE;
        sample_size = 0;

        num_samples++;
      }
    } else {
      break;
    }
  }

  return num_samples;
}

void smpcpy(uint8_t *dst, uint8_t *src, sample_t *sample)
{
  memcpy(&dst[sample->offset], &src[sample->offset], sample->size);
}

void smpclr(uint8_t *buf, sample_t *sample)
{
  int start = 0;

  if (memcmp(&buf[sample->offset], spu_irq_clear_block, ADPCM_BLOCK_SIZE) == 0) {
    start = 16;
  }

  for (int off = start; off < sample->size; off += ADPCM_BLOCK_SIZE) {
    *(uint32_t*)(buf+sample->offset+off+0x00) = 0;
    *(uint32_t*)(buf+sample->offset+off+0x04) = 0;
    *(uint32_t*)(buf+sample->offset+off+0x08) = 0;
    *(uint32_t*)(buf+sample->offset+off+0x0C) = 0;

    buf[sample->offset+off+0x00] = 0x0C;
    buf[sample->offset+off+0x01] = ADPCM_LOOP_EXISTS;
  }

  buf[sample->offset + sample->size - ADPCM_BLOCK_SIZE + 0x01]
    = ADPCM_LOOP_EXISTS | ADPCM_LOOP_END;
}

char *fncat(char *path, char *suffix)
{
  int i = 0, s = 0;
  char *out = NULL;

  out = malloc(strlen(path) + strlen(suffix) + 1);

  if (out != NULL) {
    // scan from start up to basename (this ensures we're not grabbing something
    // that looks like an extension at the end of a folder name or something)
    for (i = 0; path[i]; i++) {
      if (issep(path[i])) {
        s = i + 1;
      }
    }

    // scan from basename up to extension
    for (i = s; path[i]; i++) {
      if (path[i] == '.') {
        s = i;
      }
    }

    // no extension; get full path
    if (path[s] != '.') {
      s = i;
    }

    // copy everything except extension
    memcpy(out, path, s);

    // append suffix
    strcpy(out + s, suffix);

    // append extension
    strcpy(out + s + strlen(suffix), path + s);

    return out;
  }

  return NULL;
}

uint32_t get_u32_le(uint8_t *mem)
{
  return (mem[3] << 24) | (mem[2] << 16) | (mem[1] << 8) | mem[0];
}

void put_u32_le(uint8_t *mem, uint32_t x)
{
  mem[3] = (x >> 24) & 0xFF;
  mem[2] = (x >> 16) & 0xFF;
  mem[1] = (x >>  8) & 0xFF;
  mem[0] = (x >>  0) & 0xFF;
}

/* returns EXE size or 0 on error */
long psf2exe(uint8_t *psfbuf, long psfsize, uint8_t *exebuf, long exesize)
{
  uLong usize = (uLong) exesize;                      /* max size of uncompressed data */
  uLong csize = (uLong) get_u32_le(psfbuf + 0x08);    /* actual size of compressed data */

  if (
    uncompress(
      (Bytef *)(exebuf+0x00), &usize,                 /* usize = actual size of uncompressed data upon return */
      (Bytef *)(psfbuf+0x10), csize
    ) != Z_OK
  ) return 0;

  return usize;
}

/* returns PSF size or 0 on error */
long exe2psf(uint8_t *exebuf, long exesize, uint8_t *psfbuf, long psfsize, uint8_t *tag, long tagsize)
{
  unsigned long crc = 0;

  uLong csize = (uLong) (psfsize - 0x10 - tagsize);   /* max size of compressed data */
  uLong usize = (uLong) exesize;                      /* actual size of uncompressed data */

  if (
    compress2(
      (Bytef *)(psfbuf+0x10), &csize,                 /* csize = actual size of compressed data upon return */
      (Bytef *)(exebuf+0x00), usize,
      Z_BEST_COMPRESSION
    ) != Z_OK
  ) return 0;

  crc = crc32(crc, psfbuf+0x10, csize);

  memcpy(psfbuf+0x00, "PSF\x01", 4);
  put_u32_le(psfbuf+0x04, 0);
  put_u32_le(psfbuf+0x08, csize);
  put_u32_le(psfbuf+0x0C, crc);

  if (tag != NULL && tagsize > 0) {
    memcpy(psfbuf+0x10+csize, tag, tagsize);
  }

  return 0x10+csize+tagsize;
}

uint8_t readfile(char *path, uint8_t **buffer, long *size)
{
  FILE *file = NULL;
  long offset = 0;
  long read_size = 0;

  file = fopen(path, "rb");

  if (file == NULL) {
    printf("Could not open %s!\n", path);
    return 1;
  }

  fseek(file, 0, SEEK_END);
  *size = ftell(file);
  fseek(file, 0, SEEK_SET);

  *buffer = malloc(*size);

  if (*buffer == NULL) {
    printf("Could not allocate memory for %s!\n", path);
    return 1;
  }

  while (offset < *size) {
    read_size = min(4096, *size - offset);

    if (fread(*buffer + offset, 1, read_size, file) != read_size) {
      printf("Could not read %s!\n", path);
      return 1;
    }

    offset += read_size;
  }

  fclose(file);

  return 0;
}

uint8_t writefile(char *path, uint8_t *buffer, long size)
{
  FILE *file = NULL;
  long offset = 0;
  long write_size = 0;

  file = fopen(path, "wb");

  if (file == NULL) {
    printf("Could not open %s!\n", path);
    return 1;
  }

  while (offset < size) {
    write_size = min(4096, size - offset);

    if (fwrite(buffer + offset, 1, write_size, file) != write_size) {
      printf("Could not write %s!", path);
      return 1;
    }

    offset += write_size;
  }

  fclose(file);

  return 0;
}

int main(int argc, char *argv[])
{
  sample_t
    *samples = NULL
  ;

  char
    *psf_path = NULL,
    *out_path = NULL
  ;

  uint8_t
    *psf_buf = NULL,
    *psf_tag = NULL,
    *exe_buf = NULL,
    *out_buf = NULL
  ;

  long
    offset       = 0,
    exe_size     = 0,
    out_size     = 0,
    psf_size     = 0,
    psf_tag_off  = 0,
    psf_tag_size = 0,
    num_samples  = 0
  ;


  /* get arguments */

  if (argc != 3) {
    printf("Usage: %s <psf> <offset>\n", argv[0]);
    return 1;
  }

  psf_path = argv[1];

  offset = strtol(argv[2], NULL, 0);


  /* read PSF file */

  if (readfile(psf_path, &psf_buf, &psf_size) != 0) {
    return 1;
  }

  if (psf_size < 0x10 || psf_size > EXE_MAX_SIZE) {
    printf("Invalid PSF file?\n");
    return 1;
  }


  /* get tag data */

  psf_tag_off = 0x10 + get_u32_le(psf_buf + 0x08);

  psf_tag_size = psf_size - psf_tag_off;

  if (psf_tag_size > 0) {
    psf_tag = malloc(psf_tag_size);

    if (psf_tag == NULL) {
      printf("Could not allocate memory for PSF tags!\n");
      return 1;
    }

    memcpy(psf_tag, psf_buf + psf_tag_off, psf_tag_size);
  }


  /* convert PSF to EXE */

  exe_buf = malloc(EXE_MAX_SIZE);

  if (exe_buf == NULL) {
    printf("Could not allocate memory for EXE buffer!\n");
    return 1;
  }

  exe_size = psf2exe(psf_buf, psf_size, exe_buf, EXE_MAX_SIZE);

  if (exe_size == 0) {
    printf("Could not convert PSF to EXE!\n");
    return 1;
  }


  /* get sample info */

  if (offset < 0 || offset > exe_size) {
    printf("Specified offset is out of range!\n");
    return 1;
  }

  samples = malloc(sizeof(sample_t) * MAX_NUM_SAMPLES);

  if (samples == NULL) {
    printf("Could not allocate memory for sample info!\n");
    return 1;
  }

  num_samples = get_sample_meta(samples, exe_buf, offset, exe_size);


  /* make a copy of the EXE buffer for modification */

  out_buf = malloc(exe_size);

  if (out_buf == NULL) {
    printf("Could not allocate memory for output!\n");
    return 1;
  }

  memcpy(out_buf, exe_buf, exe_size);


  /* silence all samples */

  for (int i = 0; i < num_samples; i++) {
    smpclr(out_buf, &samples[i]);
  }


  /* write a separate PSF for every sample (isolated) */

  for (int i = 0; i < num_samples; i++) {
    char suffix[16] = { 0 };

    smpcpy(out_buf, exe_buf, &samples[i]);

    sprintf(suffix, " - %02d", i);

    out_path = fncat(psf_path, suffix);

    if (out_path == NULL) {
      printf("Could not build output path!\n");
      return 1;
    }

    out_size = exe2psf(out_buf, exe_size, psf_buf, psf_size, psf_tag, psf_tag_size);

    if (writefile(out_path, psf_buf, out_size) != 0) {
      return 1;
    }

    free(out_path);

    smpclr(out_buf, &samples[i]);
  }


  /* clean up */

  free(psf_tag);
  free(psf_buf);
  free(out_buf);
  free(exe_buf);
  free(samples);

  return 0;
}
