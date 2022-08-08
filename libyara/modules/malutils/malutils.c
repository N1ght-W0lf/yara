#include <yara/mem.h>
#include <yara/modules.h>

#define MODULE_NAME malutils

unsigned char* module_alloc_data(void* mem, size_t size)
{
  if (mem != NULL)
    yr_free(mem);

  return mem = yr_malloc(size);
}

/**
* converts wide to ascii by removing null bytes
* @param wide string 
* @return ascii string
*/
define_function(wtoa)
{
  YR_OBJECT* module = module();

  SIZED_STRING* buf = sized_string_argument(1);
  unsigned char* out = module_alloc_data(module->data, buf->length / 2 + 1);

  for (size_t i = 0; i < buf->length / 2; i++) out[i] = buf->c_string[i * 2];

  out[buf->length / 2] = 0;
  return_string(out);
}

/**
 * xors a buffer with a key
 * @param buffer string
 * @param key string
 * @return xored string
 */
define_function(xord)
{
  YR_OBJECT* module = module();

  SIZED_STRING* buf = sized_string_argument(1);
  SIZED_STRING* key = sized_string_argument(2);
  unsigned char* out = module_alloc_data(module->data, buf->length + 1);

  for (size_t i = 0; i < buf->length; i++)
    out[i] = buf->c_string[i] ^ key->c_string[i % key->length];

  out[buf->length] = 0;
  return_string(out);
}

/**
 * base64 decodes a string
 * @param buffer string
 * @return decoded string
 */
define_function(base64d)
{
  YR_OBJECT* module = module();

  SIZED_STRING* buf = sized_string_argument(1);

  const unsigned char base64_table[65] =
      "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

  unsigned char dtable[256], *out, *pos, block[4], tmp;
  size_t i, count, olen;
  int pad = 0;

  memset(dtable, 0x80, 256);
  for (i = 0; i < sizeof(base64_table) - 1; i++)
    dtable[base64_table[i]] = (unsigned char) i;
  dtable['='] = 0;

  count = 0;
  for (i = 0; i < buf->length; i++)
  {
    if (dtable[(uint8_t) buf->c_string[i]] != 0x80)
      count++;
  }

  if (count == 0 || count % 4)
    return_string(YR_UNDEFINED);

  olen = count / 4 * 3;
  pos = out = module_alloc_data(module->data, olen + 1);
  if (out == NULL)
    return_string(YR_UNDEFINED);

  count = 0;
  for (i = 0; i < buf->length; i++)
  {
    tmp = dtable[(uint8_t) buf->c_string[i]];
    if (tmp == 0x80)
      continue;

    if (buf->c_string[i] == '=')
      pad++;
    block[count] = tmp;
    count++;
    if (count == 4)
    {
      *pos++ = (block[0] << 2) | (block[1] >> 4);
      *pos++ = (block[1] << 4) | (block[2] >> 2);
      *pos++ = (block[2] << 6) | block[3];
      count = 0;
      if (pad)
      {
        if (pad == 1)
          pos--;
        else if (pad == 2)
          pos -= 2;
        else
        {
          /* Invalid padding */
          yr_free(out);
          return_string(YR_UNDEFINED);
        }
        break;
      }
    }
  }

  olen = pos - out;
  out[olen] = 0;
  return_sized_string(out, olen);
}

begin_declarations
  declare_function("xord", "ss", "s", xord);
  declare_function("base64d", "s", "s", base64d);
  declare_function("wtoa", "s", "s", wtoa);
end_declarations

int module_initialize(YR_MODULE* module)
{
  return ERROR_SUCCESS;
}

int module_finalize(YR_MODULE* module)
{
  return ERROR_SUCCESS;
}

int module_load(
    YR_SCAN_CONTEXT* context,
    YR_OBJECT* module_object,
    void* module_data,
    size_t module_data_size)
{
  return ERROR_SUCCESS;
}

int module_unload(YR_OBJECT* module_object)
{
  if (module_object->data)
    yr_free(module_object->data);

  return ERROR_SUCCESS;
}
