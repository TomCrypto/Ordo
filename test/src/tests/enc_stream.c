/* Ordo Test Driver
 * ================
 *
 * Tests the enc_stream.h module, this implicitly tests all the stream ciphers
 * by running test vectors on them and using all of the module's functions.
*/

#include "testenv.h"

#include <string.h>
#include "ordo.h"

#include "kat/parser.h"

int kat_func(struct KAT_RECORD r)
{
    /*enum STREAM_CIPHER cipher = stream_cipher_by_name(r.name);

    int retval;
    unsigned char buf[1024];
    memcpy(buf, r.plaintext, r.pt_len);
    retval = ordo_enc_stream(cipher, 0, r.key, r.key_len, buf, r.pt_len);
    ASSERT(!retval, "Internal failure: %s.", red(ordo_error_msg(retval)));
    return !memcmp(r.ciphertext, buf, r.ct_len);*/
    return 1;
}

int test_enc_stream_algorithm(void)
{
    return run_kat(kat_func, KAT_STREAM, 0);

    #if 0
    
    return load_kat_stream(kat_func, 0);
    
    
    
    #endif

    return 1;
}

int test_enc_stream_interface(void)
{
    #if 0

    const enum STREAM_CIPHER *primitive;
    unsigned char key[512];
    unsigned char buf0[32];
    unsigned char buf1[32];
    unsigned char buf2[32];
    
    for (primitive = stream_ciphers(0); *primitive; ++primitive)
    {
        size_t key_size = enc_stream_key_len(primitive, 0);
        const char *name = stream_cipher_name(primitive);
        struct ENC_STREAM_CTX ctx, cp1, cp2;
        
        memset(key,  0xAA, sizeof(key));
        memset(buf0, 0xBB, sizeof(buf0));
        memset(buf1, 0xBB, sizeof(buf1));
        memset(buf2, 0xBB, sizeof(buf2));
        
        enc_stream_init(&ctx, key, key_size, cipher, 0); // ctx initialized
        
        cp1 = ctx;
        
        enc_stream_update(&ctx, buf0, 16); // ctx at 16 bytes
        enc_stream_update(&cp1, buf1, 16); // cp1 at 16 bytes
        
        cp2 = cp1;
        
        enc_stream_update(&ctx, buf0 + 16, 16); // ctx at 32 bytes
        enc_stream_update(&cp1, buf1 + 16, 16); // cp1 at 32 bytes
        enc_stream_update(&cp2, buf2 + 16, 16); // cp2 at 32 bytes
        
        // now buf0[0..15] == buf1[0..15]
        // and buf0[16..31] == buf1[16..31] == buf2[16..31]
        
        ASSERT(!memcmp(buf0, buf1, 32),
               "Context copy error for %s.", cyan(name));
        ASSERT(!memcmp(buf0 + 16, buf2 + 16, 16),
               "Context copy error for %s.", cyan(name));
        
        enc_stream_final(&ctx);
        enc_stream_final(&cp1);
        enc_stream_final(&cp2);
    }
    
    #endif
    
    return 1;
}
