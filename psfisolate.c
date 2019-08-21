#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>

#ifdef _WIN32
#include <Windows.h>
#define strdup _strdup
#define strcasecmp _stricmp
#define strncasecmp _strnicmp
#else
#include <strings.h>
#endif

#include "zlib/zlib.h"

///////////////////////////////////////////////////////////////////////////////

#ifndef min
#define min(a,b) (((a)<(b))?(a):(b))
#endif

#ifndef max
#define max(a,b) (((a)>(b))?(a):(b))
#endif

///////////////////////////////////////////////////////////////////////////////

#define is_valid_block(block)     \
(                                 \
  ((block)[0x00] & 0xF0) <= 0x40  \
  &&                              \
  ((block)[0x00] & 0x0F) <= 0x0C  \
  &&                              \
  ((block)[0x01]) <= 0x07         \
)

#define is_zero_block(block)      \
(                                 \
  ! (                             \
    (*(uint32_t*)((block)+0x00))  \
    ||                            \
    (*(uint32_t*)((block)+0x04))  \
    ||                            \
    (*(uint32_t*)((block)+0x08))  \
    ||                            \
    (*(uint32_t*)((block)+0x0C))  \
  )                               \
)

///////////////////////////////////////////////////////////////////////////////

#define PSF_MAX_RECURSION_DEPTH  10
#define ADPCM_BLOCK_SIZE         0x10
#define MIN_SAMPLE_SIZE          0x20
#define MAX_NUM_SAMPLES          0x10000
#define EXE_HEADER_SIZE          0x800
#define PS1_RAM_SIZE             0x200000

///////////////////////////////////////////////////////////////////////////////

typedef struct {
  long    min_region_size;
  uint8_t aligned;
  uint8_t check_flag_consistency;
  uint8_t minipsf;
  int     compression_level;
} opts_t;

typedef struct {
  long offset;
  long size;
} sample_t;

typedef struct {
  char  * name;
  char  * value;
  void  * prev;
  void  * next;
} psf_tag_t;

typedef struct {
  unsigned int    depth;
  char          * dirpath;
  uint32_t        text_start;
  uint32_t        text_end;
  uint32_t        pc;
  uint32_t        sp;
  uint8_t       * exe_header;
  uint8_t       * ps1_ram;
  psf_tag_t     * tags;
} psf_load_state_t;

///////////////////////////////////////////////////////////////////////////////

void put_u32_le(uint8_t *mem, uint32_t x)
{
  mem[3] = (x >> 24) & 0xFF;
  mem[2] = (x >> 16) & 0xFF;
  mem[1] = (x >>  8) & 0xFF;
  mem[0] = (x >>  0) & 0xFF;
}

void put_u32_be(uint8_t *mem, uint32_t x)
{
  mem[0] = (x >> 24) & 0xFF;
  mem[1] = (x >> 16) & 0xFF;
  mem[2] = (x >>  8) & 0xFF;
  mem[3] = (x >>  0) & 0xFF;
}

void put_u16_le(uint8_t *mem, uint16_t x)
{
  mem[1] = (x >> 8) & 0xFF;
  mem[0] = (x >> 0) & 0xFF;
}

void put_u16_be(uint8_t *mem, uint16_t x)
{
  mem[0] = (x >> 8) & 0xFF;
  mem[1] = (x >> 0) & 0xFF;
}

uint32_t get_u32_le(uint8_t *mem)
{
  return (mem[3] << 24) | (mem[2] << 16) | (mem[1] << 8) | mem[0];
}

uint32_t get_u32_be(uint8_t *mem)
{
  return (mem[0] << 24) | (mem[1] << 16) | (mem[2] << 8) | mem[3];
}

uint16_t get_u16_le(uint8_t *mem)
{
  return (mem[1] << 8) | mem[0];
}

uint16_t get_u16_be(uint8_t *mem)
{
  return (mem[0] << 8) | mem[1];
}

///////////////////////////////////////////////////////////////////////////////

char *strrpbrk(char *str, char *breakset)
{
  if (str && *str && breakset && *breakset) {
    for (char *p = str + strlen(str) - 1; p >= str; p--) {
      for (char *b = breakset; *b; b++) {
        if (*p == *b) {
          return p;
        }
      }
    }
  }
  return NULL;
}

char *trim(char *str)
{
  char *end = NULL;

  while (*str > 0 && *str <= ' ') ++str;

  if (!*str) return str;

  end = str + strlen(str) - 1;

  while (end > str && *end > 0 && *end <= ' ') --end;

  end[1] = '\0';

  return str;
}

char *basename(char *path)
{
#ifdef _WIN32
  char *sep = strrpbrk(path, "\\/");
#else
  char *sep = strrchr(path, '/');
#endif
  return sep ? sep + 1 : path;
}

char *subext(char *path, char *repl)
{
  const char *name, *ext, *c;
  size_t prefix_len;
  char *buffer;

  name = basename(path);

  ext = name + strlen(name);

  for (c = ext - 1; c >= name; c--) {
    if (*c == '.') {
      ext = c;
      break;
    }
  }

  prefix_len = ext - path;

  buffer = malloc(prefix_len + strlen(repl) + 1);

  if (buffer) {
    memcpy(buffer, path, prefix_len);
    strcpy(buffer + prefix_len, repl);
  }

  return buffer;
}

int isfile(char *path)
{
#if _WIN32
    DWORD dwAttrib = GetFileAttributes(path);
    if (dwAttrib != INVALID_FILE_ATTRIBUTES) {
        if (!(dwAttrib & FILE_ATTRIBUTE_DIRECTORY)) {
            return 1;
        }
    }
    return 0;
#else
    struct stat s;
    if (stat(path, &s) == 0) {
        if(s.st_mode & S_IFREG) {
            return 1;
        }
    }
    return 0;
#endif
}

///////////////////////////////////////////////////////////////////////////////

uint8_t *find_adpcm_region(uint8_t *ptr, uint8_t *end, uint8_t alignment)
{
  /* 1. first block is null */
  /* 2. second block looks like a valid ADPCM block */
  /* 3. second block is NOT null */

  for (; ptr + MIN_SAMPLE_SIZE <= end; ptr += alignment) {
    if (is_zero_block(ptr)) {
      if (is_valid_block(ptr + ADPCM_BLOCK_SIZE)) {
        if (!is_zero_block(ptr + ADPCM_BLOCK_SIZE)) {
          return ptr;
        }
      }
    }
  }

  return NULL;
}

const uint8_t oneshot_end_flags[] = { 0x01, 0x05, 0x07 };

long find_adpcm_samples(uint8_t *buf, long size, long offset, sample_t *samples, opts_t *opts)
{
  uint8_t  * ptr               = buf + offset;
  uint8_t  * end               = buf + size;

  uint8_t  * region_start      = NULL;
  uint8_t  * region_end        = NULL;

  long       sample_index      = 0;
  long       samples_in_region = 0;

  uint8_t    flags             = 0;
  uint8_t    loop_sample       = 0;
  uint8_t    loop_block        = 0;
  uint8_t    alignment         = opts->aligned ? ADPCM_BLOCK_SIZE : 1;

  while ( ( ptr = find_adpcm_region(ptr, end, alignment) ) != NULL ) {
    region_start = region_end = ptr;

    samples_in_region = 0;

    while (ptr + ADPCM_BLOCK_SIZE <= end && is_valid_block(ptr)) {
      if (is_zero_block(ptr)) {
        if (ptr == region_end) {
          samples[sample_index].offset = (long)(ptr - buf);
          ptr += ADPCM_BLOCK_SIZE;
          continue; /* found zero at first block */
        } else {
          break; /* found zero after first block */
        }
      } else if (ptr == region_end) {
        break; /* found non-zero at first block */
      }

      flags = ptr[0x01];

      if (opts->check_flag_consistency) {
        loop_block = (flags & 2) && (flags != 0x07);

        /* update sample type on second block */
        if (ptr == region_end + ADPCM_BLOCK_SIZE) {
          loop_sample = loop_block;
        }

        /* expect block type to match sample type */
        if (loop_sample != loop_block) break;
      }

      /* end of sample? */
      if (flags & 1) {
        /*

          One-shot end blocks are a iittle special..

          * The most common (standard) case is a 0x01 (end) block possibly
            followed by a 0x07 (SPU IRQ Clear) block

          * Samples that are only 3 blocks (48 bytes) in length may consist of a
            null block, followed by a 0x05 (start + end) block, and finally a
            0x07 (SPU IRQ Clear) block (e.g. Metal Gear Solid, Resident Evil 2)

          * Blood Omen: Legacy of Kain has samples that end with a 0x05 block,
            but are not always preceded by a 0x01 block

          So I guess we might as well check for [..0x01][..0x05][..0x07]

        */

        if (flags == 0x03) {
          ptr += ADPCM_BLOCK_SIZE;
        } else {
          for (uint8_t i = 0; i < sizeof(oneshot_end_flags); i++) {
            if (ptr + ADPCM_BLOCK_SIZE <= end) {
              if (is_valid_block(ptr)) {
                if (ptr[0x01] == oneshot_end_flags[i]) {
                  ptr += ADPCM_BLOCK_SIZE;
                }
              }
            }
          }
        }

        samples[sample_index].size = (long)(ptr - region_end);

        region_end = ptr;

        ++sample_index, ++samples_in_region;
      } else {
        ptr += ADPCM_BLOCK_SIZE;
      }
    }

    long region_size = (long)(region_end - region_start);

    /* region no good? revert sample index/count and go to (region_start + alignment) */
    if (region_size < opts->min_region_size) {
      sample_index -= samples_in_region;
      ptr = region_start + alignment;
    }
  }

  /* return sample count */
  return sample_index;
}

void smpcpy(uint8_t *dst, uint8_t *src, sample_t *sample)
{
  memcpy(&dst[sample->offset], &src[sample->offset], sample->size);
}

void smpclr(uint8_t *buf, sample_t *sample)
{
  uint8_t *ptr = buf + sample->offset;
  uint8_t *end = ptr + sample->size;

  ptr += ADPCM_BLOCK_SIZE;
  end -= ADPCM_BLOCK_SIZE;

  /*
   * for all blocks except the first and last:
   *
   * 0C 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
   *
   * coef index   = 0x0 (0.0)
   * shift factor = 0xC (shift out all bits)
   * flags        = 0x0 (one-shot, non-start/end block)
   *
   */

  for ( ; ptr < end; ptr += ADPCM_BLOCK_SIZE) {
    *(uint32_t*)(ptr+0x00) = 0;
    *(uint32_t*)(ptr+0x04) = 0;
    *(uint32_t*)(ptr+0x08) = 0;
    *(uint32_t*)(ptr+0x0C) = 0;
    ptr[0x00] = 0x0C;
  }

  /*
   * last block: end / SPU IRQ Clear block:
   *
   * 00 07 00 00 00 00 00 00 00 00 00 00 00 00 00 00
   *
   */

  *(uint32_t*)(end+0x00) = 0;
  *(uint32_t*)(end+0x04) = 0;
  *(uint32_t*)(end+0x08) = 0;
  *(uint32_t*)(end+0x0C) = 0;
  end[0x01] = 0x07;
}

///////////////////////////////////////////////////////////////////////////////

void free_tags(psf_tag_t *tags)
{
  for (psf_tag_t *next = NULL; tags; tags = next) {
    next = tags->next;
    if (tags->name) free(tags->name);
    if (tags->value) free(tags->value);
    free(tags);
  }
}

psf_tag_t *find_tag(psf_tag_t *tags, const char *name)
{
  if (tags && name && *name) {
    for ( ; tags; tags = tags->next) {
      if (strcasecmp(tags->name, name) == 0) {
        return tags;
      }
    }
  }
  return NULL;
}

psf_tag_t *find_lib_tag(psf_tag_t *tags, int n)
{
  char lib[32];
  sprintf(lib, "_lib%d", n);
  return find_tag(tags, lib);
}

uint8_t is_lib_tag(char *name)
{
  if (strncasecmp(name, "_lib", 4) != 0) {
    return 0;
  }

  for (name += 4; *name; name++) {
    if (!isdigit(*name)) {
      return 0;
    }
  }

  return 1;
}

psf_tag_t *add_tag(psf_tag_t *tags, const char *name, const char *value)
{
  if (name && *name && value && *value) {
    psf_tag_t *tag = find_tag(tags, name);

    /* if the tag name already exists, overwrite the value */

    if (tag) {
      char *new_value = strdup(value);
      if (new_value) {
        free(tag->value);
        tag->value = new_value;
      }
    } else {
      tag = calloc(1, sizeof(psf_tag_t));
      if (!tag) {
        return tags;
      }

      tag->name = strdup(name);
      if (!tag->name) {
        free(tag);
        return tags;
      }

      tag->value = strdup(value);
      if (!tag->value) {
        free(tag->name);
        free(tag);
        return tags;
      }

      if (tags) {
        tags->prev = tag;
        tag->next = tags;
      }

      tags = tag;
    }
  }

  return tags;
}

psf_tag_t *process_tag_line(psf_tag_t *tags, char *line)
{
  char *sep, *name, *value;

  sep = strchr(line, '=');
  if (!sep) return tags;
  *sep = '\0';

  name = trim(line);
  if (!*name) return tags;

  value = trim(sep+1);
  if (!*value) return tags;

  /* if a _name tag appears more than once in a file, keep the first value */

  if (*name == '_') {
    if (find_tag(tags, name) != NULL) {
      return tags;
    }
  }

  return add_tag(tags, name, value);
}

psf_tag_t *process_tags(char *ptr)
{
  psf_tag_t *tags = NULL;

  for (char *line_end; ptr && *ptr; ptr = line_end) {
    line_end = strpbrk(ptr, "\r\n");

    if (line_end) {
      *line_end++ = '\0';
      line_end += strspn(line_end, "\r\n");
    }

    tags = process_tag_line(tags, ptr);
  }

  return tags;
}

uint8_t psf_load(psf_load_state_t *state, const char *filename)
{
  uint8_t      psf_header[16];

  char       * tag_buffer              = NULL;
  psf_tag_t  * tags                    = NULL;
  psf_tag_t  * tag                     = NULL;
  long         tag_size                = 0;

  char       * start_dirpath           = NULL;
  char       * filepath                = NULL;
  FILE       * file                    = NULL;
  long         filesize                = 0;

  uint32_t     reserved_size           = 0;

  uint8_t    * exe_compressed_buffer   = NULL;
  uLong        exe_compressed_size     = 0;

  uint8_t    * exe_decompressed_buffer = NULL;
  uLong        exe_decompressed_size   = 0;

  uint32_t     exe_crc32               = 0;


  /* check recursion depth */

  if (++state->depth > PSF_MAX_RECURSION_DEPTH) {
    printf("Exceeded maximum file nesting depth.\n");
    goto error;
  }


  /* set paths and open file */

  filepath = malloc(strlen(state->dirpath) + strlen(filename) + 1);

  if (!filepath) {
    printf("Unable to allocate memory for filepath\n");
    goto error;
  }

  strcpy(filepath, state->dirpath);
  strcat(filepath, filename);

  file = fopen(filepath, "rb");

  if (file) {
    printf("Opened file: %s\n", filepath);
  } else {
    printf("Unable to open file: %s\n", filepath);
    goto error;
  }

  start_dirpath = state->dirpath;
  *basename(filepath) = '\0';
  state->dirpath = filepath;


  /* handle PSF header */

  if (fread(psf_header, 1, sizeof(psf_header), file) != sizeof(psf_header)) {
    printf("Unable to read PSF header.\n");
    goto error;
  }

  if (memcmp(psf_header, "PSF\x01", 4) != 0) {
    printf("Not a valid PSF1 file.\n");
    goto error;
  }

  reserved_size       = get_u32_le(psf_header+0x04);
  exe_compressed_size = get_u32_le(psf_header+0x08);
  exe_crc32           = get_u32_le(psf_header+0x0C);


  /* determine file size */

  if (fseek(file, 0, SEEK_END) != 0) {
    printf("Unable to seek to end of file to determine file size.\n");
    goto error;
  }

  filesize = ftell(file);

  if (filesize < 0) {
    printf("Unable to determine file size.\n");
    goto error;
  }


  /* load tags */

  tag_size = filesize - (sizeof(psf_header) + reserved_size + exe_compressed_size);

  if (tag_size > 5) {
    if (fseek(file, -tag_size, SEEK_CUR) != 0) {
      printf("Unable to seek to tag data.\n");
      goto error;
    }

    tag_buffer = malloc(tag_size + 1);

    if (!tag_buffer) {
      printf("Unable to allocate memory for tag buffer.\n");
      goto error;
    }

    if (fread(tag_buffer, 1, tag_size, file) != tag_size) {
      printf("Unable to read tag data.\n");
      goto error;
    }

    tag_buffer[tag_size] = '\0';

    if (memcmp(tag_buffer, "[TAG]", 5) == 0) {
      tags = process_tags(tag_buffer + 5);
    }

    free(tag_buffer);
    tag_buffer = NULL;

    if (tags) {
      tag = tags;

      /* tags are added stack-wise, so start from the bottom */

      while (tag->next) tag = tag->next;

      for ( ; tag; tag = tag->prev) {
        // the Crash Team Racing set on JoshW has a "_vrefresh" tag, which
        // foo_psf doesn't like (won't play at all when tags are combined),
        // so I guess we'll have to explicitly check _name tags
        if (*tag->name != '_' || is_lib_tag(tag->name) || strcasecmp(tag->name, "_refresh") == 0) {
          if (find_tag(state->tags, tag->name) == NULL) {
            state->tags = add_tag(state->tags, tag->name, tag->value);
          }
        }
      }

      /* load _lib PSF first, if one exists */

      tag = find_tag(tags, "_lib");

      if (tag) {
        if (psf_load(state, tag->value) != 0) {
          goto error;
        }
      }
    }
  }


  /* read in compressed EXE data */

  if (exe_compressed_size) {
    exe_compressed_buffer = malloc(exe_compressed_size);

    if (!exe_compressed_buffer) {
      printf("Unable to allocate buffer for compressed EXE section.\n");
      goto error;
    }

    if (fseek(file, sizeof(psf_header) + reserved_size, SEEK_SET) != 0) {
      printf("Unable to seek to compressed EXE section.\n");
      goto error;
    }

    if (fread(exe_compressed_buffer, 1, exe_compressed_size, file) != exe_compressed_size) {
      printf("Unable to read compressed EXE section.\n");
      goto error;
    }

    if (crc32(0, exe_compressed_buffer, exe_compressed_size) != exe_crc32) {
      printf("CRC mismatch on compressed EXE section.\n");
      goto error;
    }
  }


  /* close file */

  fclose(file);
  file = NULL;


  /* load EXE data */

  if (exe_compressed_size) {
    uint32_t t_addr, t_size;

    /* "Uncompressed size of the executable must not exceed 2,033,664 bytes." */

    exe_decompressed_size = 0x1F0800;

    exe_decompressed_buffer = malloc(exe_decompressed_size);

    if (!exe_decompressed_buffer) {
      printf("Unable to allocate buffer for decompressed EXE section.\n");
      goto error;
    }

    if (uncompress(exe_decompressed_buffer, &exe_decompressed_size, exe_compressed_buffer, exe_compressed_size) != Z_OK) {
      printf("Unable to decompress EXE section.\n");
      goto error;
    }

    free(exe_compressed_buffer);
    exe_compressed_buffer = NULL;

    if (exe_decompressed_size < EXE_HEADER_SIZE) {
      printf("EXE size is too small.\n");
      goto error;
    }

    if (memcmp(exe_decompressed_buffer, "PS-X EXE", 8) != 0) {
      printf("EXE does not contain a valid header.\n");
      goto error;
    }

    t_addr = get_u32_le(exe_decompressed_buffer + 0x18);
    t_size = get_u32_le(exe_decompressed_buffer + 0x1C);

    if (EXE_HEADER_SIZE + t_size > exe_decompressed_size) {
      printf("Decompressed EXE missing data.\n");
      goto error;
    }

    if (t_addr < 0x80010000) {
      printf("Text start address too low.\n");
      goto error;
    }

    if (t_addr + t_size > 0x80200000) {
      printf("Text region overflows PS1 RAM.\n");
      goto error;
    }

    if (!state->text_start) {
      /* get PC and SP from the first EXE that comes in */

      state->pc = get_u32_le(exe_decompressed_buffer + 0x10);
      state->sp = get_u32_le(exe_decompressed_buffer + 0x38);

      state->text_start = t_addr;
      state->text_end   = t_addr + t_size;
    } else {
      state->text_start = min(state->text_start, t_addr);
      state->text_end   = max(state->text_end, t_addr + t_size);
    }

    /* get region (header) from the outermost EXE (for default refresh rate) */

    if (state->depth == 1) {
      memcpy(state->exe_header, exe_decompressed_buffer, EXE_HEADER_SIZE);
      put_u32_le(state->exe_header + 0x10, state->pc);
      put_u32_le(state->exe_header + 0x38, state->sp);
    }

    memcpy(state->ps1_ram + (t_addr & 0x1FFFFF), exe_decompressed_buffer + EXE_HEADER_SIZE, t_size);

    free(exe_decompressed_buffer);
    exe_decompressed_buffer = NULL;
  }


  /* lastly, superimpose any additional libraries.. */

  for (int n = 2; ( tag = find_lib_tag(tags, n) ) != NULL; n++) {
    if (psf_load(state, tag->value) != 0) {
      goto error;
    }
  }


  /* clean up and return */

  free_tags(tags);

  free(state->dirpath);

  state->dirpath = start_dirpath;

  --state->depth;

  return 0;

error:

  if (tags) free_tags(tags);
  if (exe_compressed_buffer) free(exe_compressed_buffer);
  if (exe_decompressed_buffer) free(exe_decompressed_buffer);
  if (tag_buffer) free(tag_buffer);
  if (filepath) free(filepath);
  if (file) fclose(file);

  return 1;
}

uint8_t psf_write(char *path, uint8_t *uncompressed_exe_buffer, uint32_t uncompressed_exe_size, uint8_t *tag_buffer, long tag_size, int compression_level)
{
  uint8_t     psf_header[16];
  uint32_t    compressed_exe_crc    = 0;
  uLong       compressed_exe_size   = 0;
  uint8_t   * compressed_exe_buffer = NULL;
  FILE      * f                     = NULL;


  /* compress EXE data */

  compressed_exe_size = compressBound(uncompressed_exe_size);

  compressed_exe_buffer = malloc(compressed_exe_size);

  if (!compressed_exe_buffer) {
    printf("Unable to allocate memory for compressed EXE buffer\n");
    goto error;
  }

  if (compress2(compressed_exe_buffer, &compressed_exe_size, uncompressed_exe_buffer, uncompressed_exe_size, compression_level) != Z_OK) {
    printf("Unable to compress EXE data\n");
    goto error;
  }

  compressed_exe_crc = crc32(0, compressed_exe_buffer, compressed_exe_size);


  /* build PSF header */

  memcpy(psf_header, "PSF\x01", 4);
  put_u32_le(psf_header+0x04, 0);
  put_u32_le(psf_header+0x08, compressed_exe_size);
  put_u32_le(psf_header+0x0C, compressed_exe_crc);


  /* open PSF file for writing */

  f = fopen(path, "wb");

  if (!f) {
    printf("Unable to open output file for writing\n");
    goto error;
  }


  /* write PSF header */

  if (fwrite(psf_header, 1, sizeof(psf_header), f) != sizeof(psf_header)) {
    printf("Unable to write PSF header\n");
    goto error;
  }


  /* write compressed EXE */

  if (fwrite(compressed_exe_buffer, 1, compressed_exe_size, f) != compressed_exe_size) {
    printf("Unable to write compressed EXE data\n");
    goto error;
  }

  free(compressed_exe_buffer);
  compressed_exe_buffer = NULL;


  /* write PSF tags */

  if (tag_buffer && tag_size) {
    if (fwrite(tag_buffer, 1, tag_size, f) != tag_size) {
      printf("Unable to write tags\n");
      goto error;
    }
  }


  /* clean up and return */

  fclose(f);
  f = NULL;

  return 0;

error:

  if (compressed_exe_buffer) free(compressed_exe_buffer);
  if (f) fclose(f);

  return 1;
}

uint8_t isolate(char *psf_path, uint8_t *exe_in_buf, uint32_t exe_in_size, psf_tag_t *tags, sample_t *samples, long num_samples, opts_t *opts)
{
  char         suffix[32];
  char       * out_path     = NULL;

  uint8_t    * exe_out_buf  = NULL;
  long         exe_out_size = 0;

  uint8_t    * tag_buffer   = NULL;
  long         tag_size     = 0;

  psf_tag_t  * tag          = NULL;
  psf_tag_t  * out_tags     = NULL;

  uint32_t     t_addr_old   = 0;
  uint32_t     t_addr_new   = 0;
  uint32_t     t_size_new   = 0;


  /* allocate output EXE buffer */

  exe_out_size = exe_in_size;

  exe_out_buf = malloc(exe_out_size);

  if (!exe_out_buf) {
    printf("Unable to allocate memory for output EXE buffer\n");
    goto error;
  }


  /* copy data to output EXE buffer and silence all samples */

  memcpy(exe_out_buf, exe_in_buf, exe_in_size);

  for (long i = 0; i < num_samples; i++) {
    smpclr(exe_out_buf, &samples[i]);
  }


  /* initialize output tags */

  if (tags) {
    tag = tags;

    while (tag->next) tag = tag->next;

    for ( ; tag; tag = tag->prev) {
      if (!is_lib_tag(tag->name)) {
        out_tags = add_tag(out_tags, tag->name, tag->value);
      }
    }
  }


  /* minipsf: write a psflib with all samples silenced */

  if (opts->minipsf) {
    out_path = subext(psf_path, " - silenced.psflib");

    if (!out_path) {
      printf("Unable to allocate memory for psflib path\n");
      goto error;
    }

    if (psf_write(out_path, exe_out_buf, exe_out_size, tag_buffer, tag_size, opts->compression_level) != 0) {
      goto error;
    }

    out_tags = add_tag(out_tags, "_lib", basename(out_path));

    free(out_path);
    out_path = NULL;

    t_addr_old = get_u32_le(exe_in_buf + 0x18);
  }


  /* build output tag buffer */

  if (out_tags) {
    for (tag_size=5, tag=out_tags; tag; tag = tag->next) {
      tag_size += strlen(tag->name) + strlen(tag->value) + 2;
    }

    tag_buffer = malloc(tag_size);

    if (!tag_buffer) {
      printf("Unable to build tag buffer\n");
      goto error;
    }

    memcpy(tag_buffer, "[TAG]", 5);

    tag = out_tags;

    while (tag->next) tag = tag->next;

    for (uint8_t *ptr = tag_buffer + 5; tag; tag = tag->prev) {
      for (uint8_t *c = (uint8_t*)tag->name; *c; *ptr++ = *c++) ;
      *ptr++ = '=';
      for (uint8_t *c = (uint8_t*)tag->value; *c; *ptr++ = *c++) ;
      *ptr++ = '\n';
    }

    free_tags(out_tags);
    out_tags = NULL;
  }


  /* write a file for every sample */

  for (long i = 0; i < num_samples; i++) {
    if (opts->minipsf) {
      sprintf(suffix, " - sample %02d.minipsf", i);
    } else {
      sprintf(suffix, " - sample %02d.psf", i);
    }

    out_path = subext(psf_path, suffix);

    if (!out_path) {
      printf("Unable to allocate memory for sample PSF path\n");
      goto error;
    }

    printf("Writing file: %s\n", out_path);

    if (opts->minipsf) {
      t_addr_new = t_addr_old + (samples[i].offset - EXE_HEADER_SIZE);
      t_size_new = samples[i].size;

      put_u32_le(exe_out_buf + 0x18, t_addr_new);
      put_u32_le(exe_out_buf + 0x1C, t_size_new);

      memcpy(exe_out_buf + EXE_HEADER_SIZE, exe_in_buf + samples[i].offset, samples[i].size);

      exe_out_size = EXE_HEADER_SIZE + t_size_new;
    } else {
      smpcpy(exe_out_buf, exe_in_buf, &samples[i]);
    }

    if (psf_write(out_path, exe_out_buf, exe_out_size, tag_buffer, tag_size, opts->compression_level) != 0) {
      goto error;
    }

    if (!opts->minipsf) {
      smpclr(exe_out_buf, &samples[i]);
    }

    free(out_path);
    out_path = NULL;
  }


  /* clean up and return */

  if (tag_buffer) free(tag_buffer);
  tag_buffer = NULL;

  free(exe_out_buf);
  exe_out_buf = NULL;

  return 0;

error:

  if (tag_buffer) free(tag_buffer);
  if (out_tags) free_tags(out_tags);
  if (exe_out_buf) free(exe_out_buf);
  if (out_path) free(out_path);

  return 1;
}

///////////////////////////////////////////////////////////////////////////////

int main(int argc, char *argv[])
{
  opts_t              opts;

  psf_load_state_t    state;

  char              * psf_path    = NULL;

  uint32_t            text_start  = 0;
  uint32_t            text_size   = 0;

  uint8_t           * exe_buffer  = NULL;
  uLong               exe_size    = 0;

  sample_t          * samples     = NULL;
  long                num_samples = 0;


  /* set default options */

  opts.min_region_size        = 0x1000;
  opts.aligned                = 0;
  opts.check_flag_consistency = 1;
  opts.minipsf                = 1;
  opts.compression_level      = 1;


  /* initialize load state */

  state.dirpath    = "";
  state.depth      = 0;
  state.text_start = 0;
  state.text_end   = 0;
  state.pc         = 0;
  state.sp         = 0;
  state.tags       = NULL;
  state.ps1_ram    = NULL;
  state.exe_header = NULL;


  /* check arguments */

  if (argc < 2) {
    printf(
      "Usage: %s [options] <file>\n"
      "\n"
      "Options:\n"
      "\n"
      "  --min-region-size=N\n"
      "\n"
      "    Default: %ld\n"
      "\n"
      "    Minimum size of a sample region, specified in bytes.\n"
      "    For example, the minimum size of the body (VB) in a VAB bank.\n"
      "\n"
      "    Must be a multiple of 16 and at least 32 bytes.\n"
      "\n"
      "\n"
      "  --aligned=0|1\n"
      "\n"
      "    Default: %u\n"
      "\n"
      "    If enabled, only search for sample regions on 16-byte boundaries.\n"
      "\n"
      "\n"
      "  --check-flag-consistency=0|1\n"
      "\n"
      "    Default: %u\n"
      "\n"
      "    If enabled, ensure that no flags appear \"out of context\". I.e., if the first\n"
      "    block in a sample indicates that a loop exists, check that the rest of the\n"
      "    blocks in the sample reflects that.\n"
      "\n"
      "\n"
      "  --minipsf=0|1\n"
      "\n"
      "    Default: %u\n"
      "\n"
      "    If enabled, output to MINIPSF; otherwise, write standard, fully independent,\n"
      "    self-contained PSF files. MINIPSF tends to be less compatible with software,\n"
      "    but will save a LOT of space if, for example, all songs in the game share a\n"
      "    single universal sound bank or two (e.g. Final Fantasy VII).\n"
      "\n"
      "\n"
      "  --compression-level=1-9\n"
      "\n"
      "    Default: %d\n"
      "\n"
      "    Set zlib compression level for compressed EXE data (1 for fastest speed;\n"
      "    9 for smallest size). Level 1 is recommended for standard PSF output.\n",

      argv[0],
      opts.min_region_size,
      opts.aligned,
      opts.check_flag_consistency,
      opts.minipsf,
      opts.compression_level
    );

    goto error;
  }


  /* get parameters */

  psf_path = argv[argc-1];

  if (!isfile(psf_path)) {
    printf("Specify a valid PSF path\n");
    goto error;
  }

  for (int argn = 1; argn < argc-1; argn++) {
    if (strncasecmp(argv[argn], "--aligned=", 10) == 0) {
      opts.aligned = strtol(&argv[argn][10], NULL, 0) ? 1 : 0;
    } else if (strncasecmp(argv[argn], "--check-flag-consistency=", 25) == 0) {
      opts.check_flag_consistency = strtol(&argv[argn][25], NULL, 0) ? 1 : 0;
    } else if (strncasecmp(argv[argn], "--min-region-size=", 18) == 0) {
      opts.min_region_size = strtol(&argv[argn][18], NULL, 0);
    } else if (strncasecmp(argv[argn], "--minipsf=", 10) == 0) {
      opts.minipsf = strtol(&argv[argn][10], NULL, 0);
    } else if (strncasecmp(argv[argn], "--compression-level=", 20) == 0) {
      opts.compression_level = strtol(&argv[argn][20], NULL, 0);
    } else {
      printf("Invalid argument: %s\n", argv[argn]);
      goto error;
    }
  }


  /* check option values */

  if (opts.min_region_size % 16) {
    printf("--min-region-size must be a multiple of 16\n");
    goto error;
  }

  if (opts.min_region_size < MIN_SAMPLE_SIZE) {
    printf("--min-region-size must be at least 32 bytes\n");
    goto error;
  }

  if (opts.compression_level < 1 || opts.compression_level > 9) {
    printf("--compression-level must be between 1 and 9\n");
    goto error;
  }


  /* allocate memory for EXE header and PS1 RAM */

  state.exe_header = malloc(EXE_HEADER_SIZE);

  if (!state.exe_header) {
    printf("Unable to allocate memory for output EXE header\n");
    goto error;
  }

  state.ps1_ram = malloc(PS1_RAM_SIZE);

  if (!state.ps1_ram) {
    printf("Unable to allocate memory for PS1 RAM\n");
    goto error;
  }


  /* load PSF */

  if (psf_load(&state, psf_path) != 0) {
    goto error;
  }


  /* build merged EXE */

  text_start = state.text_start;
  text_size  = state.text_end - state.text_start;

  put_u32_le(state.exe_header+0x18, text_start);
  put_u32_le(state.exe_header+0x1C, text_size);

  exe_size = EXE_HEADER_SIZE + text_size;
  exe_buffer = malloc(exe_size);

  if (!exe_buffer) {
    printf("Unable to allocate memory for merged EXE buffer\n");
    goto error;
  }

  memcpy(exe_buffer, state.exe_header, EXE_HEADER_SIZE);
  free(state.exe_header);
  state.exe_header = NULL;

  memcpy(exe_buffer + EXE_HEADER_SIZE, state.ps1_ram + (text_start & 0x1FFFFF), text_size);
  free(state.ps1_ram);
  state.ps1_ram = NULL;


  /* find samples */

  samples = malloc(sizeof(sample_t) * MAX_NUM_SAMPLES);

  if (!samples) {
    printf("Unable to allocate memory for sample info\n");
    goto error;
  }

  num_samples = find_adpcm_samples(exe_buffer, exe_size, EXE_HEADER_SIZE, samples, &opts);


  /* isolate samples */

  if (num_samples > 0) {
    if (isolate(psf_path, exe_buffer, exe_size, state.tags, samples, num_samples, &opts) != 0) {
      goto error;
    }
  } else {
    printf("Could not find any sample data?\n");
  }


  /* clean up and return */

  free(samples);
  samples = NULL;

  free(exe_buffer);
  exe_buffer = NULL;

  free_tags(state.tags);
  state.tags = NULL;

  return 0;

error:

  if (state.tags) free_tags(state.tags);
  if (state.ps1_ram) free(state.ps1_ram);
  if (state.exe_header) free(state.exe_header);
  if (exe_buffer) free(exe_buffer);
  if (samples) free(samples);

  return 1;
}
