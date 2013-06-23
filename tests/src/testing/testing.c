#include <testing/testing.h>

#include <string.h>
#include <stdlib.h>

/* Returns the hexadecimal representation of a buffer. */
char* bufferToHex(void* input, size_t len)
{
    size_t t;
    char* result = malloc(len * 2 + 1);
    if (input == 0) len = 0;
    for (t = 0; t < len; t++) sprintf(result + t * 2, "%.2x", *((unsigned char*)input + t));
    *(result + len * 2) = 0x00;
    return result;
}

/* Clears a buffer with a pseudorandom integer pattern. */
void randomizeBuffer(unsigned char* buffer, size_t len)
{
    /* Get a 256-bit pseudorandom bitstring. */
    unsigned char* data = malloc(32);
    ordo_random(data, 32);

    /* Fill the buffer with this pattern. Assume the buffer length is a multiple of 32 bytes. */
    while (len != 0)
    {
        memcpy(buffer + len - 32, data, 32);
        len -= 32;
    }

    /* Free the bitstring buffer. */
    free(data);
}

/* Opens the test vector file. */
FILE* loadTestVectors(char* path)
{
    /* Just open the file in binary mode. */
    return fopen(path, "rb");
}

/* Reads the next line of a file in a buffer. */
char* readLine(FILE* file)
{
    #define MAX_LINE_LENGTH 2048
    char* line = malloc(MAX_LINE_LENGTH);
    if (fgets(line, MAX_LINE_LENGTH, file) == 0) return 0;

    /* Replace the last char in the line by a null, since fgets includes a \n. */
    if (strlen(line) > 0) line[strlen(line) - 1] = 0x00;

    /* Return the read line. */
    return line;
}

/* Closes the test vector file. */
void unloadTestVectors(FILE* file)
{
    /* Close the file. */
    fclose(file);
}

/* Reads the nth token in a line. */
char* readToken(char* line, size_t n)
{
    /* Set the start and end positions. */
    size_t start = 0;
    size_t end = 0;
    char* out;

    /* Find the (n-1)th colon. */
    while (n != 0) if (*(line + start++) == ':') n--;

    /* Find the next colon, or the zero/comment or end of line character. */
    end = start;
    while ((*(line + end) != ':') && (*(line + end) != 0x00) && (*(line + end) != '#')  && (*(line + end) != '~')) end++;

    /* If the token is empty, just return zero. */
    if (end == start) return 0;

    /* Allocate a large enough output string. */
    out = malloc(end - start + 1);

    /* Copy the string between start and end. */
    strncpy(out, line + start, end - start);

    /* Append a zero and return the token. */
    *(out + end - start) = 0x00;
    return out;
}

/* Converts a null-terminated hexadecimal string to a memory buffer. */
unsigned char* hexToBuffer(char* str, size_t* outlen)
{
    /* Temporary variable since sscanf is incapable of reading a single hex byte. */
    unsigned char* buf;
    unsigned int tmp = 0;
    size_t len;
    size_t t;

    /* If we got an empty string, return null. */
    if ((str == 0) || (strlen(str) == 0))
    {
        *outlen = 0;
        return 0;
    }

    /* Allocate the memory needed. */
    buf = malloc(strlen(str) / 2);
    *outlen = strlen(str) / 2;
    len = strlen(str);

    /* Read each two characters. */
    for (t = 0; t < len / 2; t++)
    {
        sscanf(str + 2 * t, "%2x", &tmp);
        *(buf + t) = (unsigned char)tmp;
    }

    /* Free the string buffer. */
    free(str);

    /* Return the full buffer. */
    return buf;
}

/* Runs a block cipher test vector. */
int runBlockCipherTest(char* line, int n)
{
    /* Parse the test vector and initialize variables. */
    char* primitive_name = readToken(line, 1);
    char* modeName = readToken(line, 2);
    size_t keylen, ivlen, plaintextlen, ciphertextlen;
    unsigned char* key = hexToBuffer(readToken(line, 3), &keylen);
    unsigned char* iv = hexToBuffer(readToken(line, 4), &ivlen);
    unsigned char* plaintext = hexToBuffer(readToken(line, 5), &plaintextlen);
    unsigned char* ciphertext = hexToBuffer(readToken(line, 6), &ciphertextlen);

    /* Create a temporary buffer to store the computed ciphertext and plaintext. */
    unsigned char* computedPlaintext = malloc(plaintextlen);
    unsigned char* computedCiphertext = malloc(ciphertextlen);
    size_t computedPlaintextLen;
    size_t computedCiphertextLen;
    int error, result;

    /* Get the proper primitive and mode. */
    const struct BLOCK_CIPHER* primitive = block_cipher_by_name(primitive_name);
    const struct BLOCK_MODE* mode = block_mode_by_name(modeName);

    /* If the mode or primitive is not recognized, skip (don't error, it might be a test vector added for later). */
    if ((primitive == 0) || (mode == 0))
    {
        printf("[!] Test vector #%.3d skipped", n);
        if (primitive == 0) printf(", primitive (%s) not recognized", primitive_name);
        if (mode == 0) printf(", mode (%s) not recognized", modeName);
        printf(".\n");
        return 1;
    }

    /* Initialize the test result. */
    result = 0;

    /* Perform the encryption test. */
    error = ordoEncrypt(plaintext, plaintextlen, computedCiphertext, &computedCiphertextLen, primitive, mode, key, keylen, iv, ivlen, 0, 0);
    if (error == ORDO_SUCCESS)
    {
        /* Check the computed ciphertext against the expected ciphertext. */
        if ((computedCiphertextLen != ciphertextlen) || (memcmp(computedCiphertext, ciphertext, ciphertextlen) == 0))
        {
            /* Perform the decryption test. */
            error = ordoDecrypt(computedCiphertext, computedCiphertextLen, computedPlaintext, &computedPlaintextLen, primitive, mode, key, keylen, iv, ivlen, 0, 0);
            if (error == ORDO_SUCCESS)
            {
                /* Check the computed plaintext against the expected plaintext. */
                if ((computedPlaintextLen != plaintextlen) || (memcmp(computedPlaintext, plaintext, plaintextlen) == ORDO_SUCCESS))
                {
                    /* Report success. */
                    result = 1;
                    printf("[+] Test vector #%.3d (enc/%s/%s) passed!\n", n, primitive_name, modeName);
                } else printf("[!] Test vector #%.3d (enc/%s/%s) failed: did not get expected plaintext.\n", n, primitive_name, modeName);
            } else printf("[!] Test vector #%.3d (enc/%s/%s) failed: @ordoDecrypt, %s.\n", n, primitive_name, modeName, error_msg(error));
        } else printf("[!] Test vector #%.3d (enc/%s/%s) failed: did not get expected ciphertext.\n", n, primitive_name, modeName);
    } else printf("[!] Test vector #%.3d (enc/%s/%s) failed: @ordoEncrypt, %s.\n", n, primitive_name, modeName, error_msg(error));

    /* Clean up. */
    free(computedPlaintext);
    free(computedCiphertext);
    free(plaintext);
    free(ciphertext);
    free(key);
    free(iv);
    free(primitive_name);
    free(modeName);
    return result;
}

/* Runs a stream cipher test vector. */
int runStreamCipherTest(char* line, int n)
{
    /* Parse the test vector and initialize variables. */
    char* primitive_name = readToken(line, 1);
    size_t keylen, plaintextlen, ciphertextlen;
    unsigned char* key = hexToBuffer(readToken(line, 2), &keylen);
    unsigned char* plaintext = hexToBuffer(readToken(line, 3), &plaintextlen);
    unsigned char* ciphertext = hexToBuffer(readToken(line, 4), &ciphertextlen);

    /* Create a temporary buffer to store the computed ciphertext and plaintext. */
    unsigned char* computedPlaintext = malloc(plaintextlen);
    unsigned char* computedCiphertext = malloc(ciphertextlen);
    int error, result;

    /* Get the proper primitive and mode. */
    const struct STREAM_CIPHER* primitive = stream_cipher_by_name(primitive_name);

    /* If the mode or primitive is not recognized, skip (don't error, it might be a test vector added for later). */
    if (primitive == 0)
    {
        printf("[!] Test vector #%.3d skipped, primitive (%s) not recognized.\n", n, primitive_name);
        return 1;
    }

    /* Initialize the test result. */
    result = 0;

    /* Perform the encryption test. */
    memcpy(computedCiphertext, plaintext, ciphertextlen);
    error = ordoEncryptStream(computedCiphertext, plaintextlen, primitive, key, keylen, 0);
    if (error == ORDO_SUCCESS)
    {
        /* Check the computed ciphertext against the expected ciphertext. */
        if (memcmp(computedCiphertext, ciphertext, ciphertextlen) == 0)
        {
            /* Perform the decryption test. */
            memcpy(computedPlaintext, computedCiphertext, ciphertextlen);
            error = ordoEncryptStream(computedPlaintext, ciphertextlen, primitive, key, keylen, 0);
            if (error == ORDO_SUCCESS)
            {
                /* Check the computed plaintext against the expected plaintext. */
                if (memcmp(computedPlaintext, plaintext, plaintextlen) == ORDO_SUCCESS)
                {
                    /* Report success. */
                    result = 1;
                    printf("[+] Test vector #%.3d (enc/%s) passed!\n", n, primitive_name);
                } else printf("[!] Test vector #%.3d (enc/%s) failed: did not get expected plaintext.\n", n, primitive_name);
            } else printf("[!] Test vector #%.3d (enc/%s) failed: @ordoDecrypt, %s.\n", n, primitive_name, error_msg(error));
        } else printf("[!] Test vector #%.3d (enc/%s) failed: did not get expected ciphertext.\n", n, primitive_name);
    } else printf("[!] Test vector #%.3d (enc/%s) failed: @ordoEncrypt, %s.\n", n, primitive_name, error_msg(error));

    /* Clean up. */
    free(computedPlaintext);
    free(computedCiphertext);
    free(plaintext);
    free(ciphertext);
    free(key);
    free(primitive_name);
    return result;
}

/* Runs a hash function test vector. */
int runDigestTest(char* line, int n)
{
    /* Parse the test vector and initialize variables. */
    char* primitive_name = readToken(line, 1);
    size_t messagelen, digestlen;
    unsigned char* message = hexToBuffer(readToken(line, 2), &messagelen);
    unsigned char* digest = hexToBuffer(readToken(line, 3), &digestlen);

    /* Create a temporary buffer to store the computed digest. */
    unsigned char* computedDigest = malloc(digestlen);
    int error, result;

    /* Get the proper primitive and mode. */
    const struct HASH_FUNCTION* primitive = hash_function_by_name(primitive_name);

    /* If the mode or primitive is not recognized, skip (don't error, it might be a test vector added for later). */
    if (primitive == 0)
    {
        printf("[!] Test vector #%.3d skipped, primitive (%s) not recognized.\n", n, primitive_name);
        return 1;
    }

    /* Initialize the test result. */
    result = 0;

    /* Perform the hash test. */
    error = ordoHash(message, messagelen, computedDigest, primitive, 0);
    if (error == ORDO_SUCCESS)
    {
        /* Check the computed digest against the expected digest. */
        if (memcmp(computedDigest, digest, digestlen) == 0)
        {
            /* Report success. */
            result = 1;
            printf("[+] Test vector #%.3d (digest/%s) passed!\n", n, primitive_name);
        } else printf("[!] Test vector #%.3d (digest/%s) failed: did not get expected digest.\n", n, primitive_name);
    } else printf("[!] Test vector #%.3d (digest/%s) failed: @ordoHash, %s.\n", n, primitive_name, error_msg(error));

    /* Clean up. */
    free(computedDigest);
    free(digest);
    free(message);
    free(primitive_name);
    return result;
}

/* Runs a HMAC test vector. */
int runHMACTest(char* line, int n)
{
    /* Parse the test vector and initialize variables. */
    char* primitive_name = readToken(line, 1);
    size_t messagelen, keylen, digestlen;
    unsigned char* key = hexToBuffer(readToken(line, 2), &keylen);
    unsigned char* message = hexToBuffer(readToken(line, 3), &messagelen);
    unsigned char* digest = hexToBuffer(readToken(line, 4), &digestlen);

    /* Create a temporary buffer to store the computed digest. */
    unsigned char* computedDigest = malloc(digestlen);
    int error, result;

    /* Get the proper primitive and mode. */
    const struct HASH_FUNCTION* primitive = hash_function_by_name(primitive_name);

    /* If the mode or primitive is not recognized, skip (don't error, it might be a test vector added for later). */
    if (primitive == 0)
    {
        printf("[!] Test vector #%.3d skipped, primitive (%s) not recognized.\n", n, primitive_name);
        return 1;
    }

    /* Initialize the test result. */
    result = 0;

    /* Perform the hash test. */
    error = ordoHMAC(message, messagelen, key, keylen, computedDigest, primitive, 0);
    if (error == ORDO_SUCCESS)
    {
        /* Check the computed digest against the expected digest. */
        if (memcmp(computedDigest, digest, digestlen) == 0)
        {
            /* Report success. */
            result = 1;
            printf("[+] Test vector #%.3d (hmac/%s) passed!\n", n, primitive_name);
        } else printf("[!] Test vector #%.3d (hmac/%s) failed: did not get expected digest.\n", n, primitive_name);
    } else printf("[!] Test vector #%.3d (hmac/%s) failed: @ordoHMAC, %s.\n", n, primitive_name, error_msg(error));

    /* Clean up. */
    free(key);
    free(computedDigest);
    free(digest);
    free(message);
    free(primitive_name);
    return result;
}

/* Runs a PBKDF2 test vector. */
int runPBKDF2Test(char* line, int n)
{
    /* Parse the test vector and initialize variables. */
    char* primitive_name = readToken(line, 1);
    size_t saltLen, passwordLen, digestlen;
    unsigned char* password = hexToBuffer(readToken(line, 2), &passwordLen);
    unsigned char* salt = hexToBuffer(readToken(line, 3), &saltLen);
    char* tmp1 = readToken(line, 4); size_t iterations = atoi(tmp1);
    char* tmp2 = readToken(line, 5); size_t outputLen = atoi(tmp2);
    unsigned char* digest = hexToBuffer(readToken(line, 6), &digestlen);

    /* Create a temporary buffer to store the computed digest. */
    unsigned char* computedDigest = malloc(digestlen);
    int error, result;

    /* Get the proper primitive and mode. */
    const struct HASH_FUNCTION* primitive = hash_function_by_name(primitive_name);

    /* If the mode or primitive is not recognized, skip (don't error, it might be a test vector added for later). */
    if (primitive == 0)
    {
        printf("[!] Test vector #%.3d skipped, primitive (%s) not recognized.\n", n, primitive_name);
        return 1;
    }

    /* Initialize the test result. */
    result = 0;

    /* Perform the hash test. */
    error = pbkdf2(primitive, password, passwordLen, salt, saltLen, computedDigest, outputLen, iterations, 0);
    if (error == ORDO_SUCCESS)
    {
        /* Check the computed digest against the expected digest. */
        if (memcmp(computedDigest, digest, digestlen) == 0)
        {
            /* Report success. */
            result = 1;
            printf("[+] Test vector #%.3d (pbkdf2/%s) passed!\n", n, primitive_name);
        } else printf("[!] Test vector #%.3d (pbkdf2/%s) failed: did not get expected digest.\n", n, primitive_name);
    } else printf("[!] Test vector #%.3d (pbkdf2/%s) failed: @pbkdf2, %s.\n", n, primitive_name, error_msg(error));

    /* Clean up. */
    free(password);
    free(computedDigest);
    free(digest);
    free(salt);
    free(tmp1);
    free(tmp2);
    free(primitive_name);
    return result;
}

/* Runs all test vectors. */
void runTestVectors(FILE* file)
{
    /* Different possible actions. */
    #define TOKEN_ENC_BLOCK "enc_block"
    #define TOKEN_ENC_STREAM "enc_stream"
    #define TOKEN_DIGEST "digest"
    #define TOKEN_HMAC "hmac"
    #define TOKEN_PBKDF2 "pbkdf2"

    /* We keep track of how many lines we read. */
    char* line = readLine(file);
    char* token;
    int success = 0;
    int n = 1;

    /* Go over each line in the test vector file, the last test vector always starts with a tilde. */
    while (line[0] != '~')
    {
        /* Read the first character of the line. If it is a zero or a comment, do not process. */
        if ((*line != 0x00) && (*line != '#'))
        {
            /* Read the first token in the line (tokens are separated by a colon). */
            token = readToken(line, 0);

            /* Depending on the token, perform the appropriate test. */
            if (strcmp(token, TOKEN_ENC_BLOCK) == 0) success += runBlockCipherTest(line, n++);
            if (strcmp(token, TOKEN_ENC_STREAM) == 0) success += runStreamCipherTest(line, n++);
            if (strcmp(token, TOKEN_DIGEST) == 0) success += runDigestTest(line, n++);
            if (strcmp(token, TOKEN_HMAC) == 0) success += runHMACTest(line, n++);
            if (strcmp(token, TOKEN_PBKDF2) == 0) success += runPBKDF2Test(line, n++);

            /* Free the token buffer. */
            free(token);
        }

        /* Free the line buffer. */
        free(line);

        /* Read the next line. */
        line = readLine(file);
    }

    /* Free the line buffer. */
    free(line);

    /* Print statistics. */
    if (success == n - 1) printf("\n[+] "); else printf("\n[!] ");
    printf("Results: %d test vectors passed out of %d.\n\n", success, n - 1);
}

/* Performs a test of the random module. */
void randomTest()
{
    /* Allocate a 64-byte buffer. */
    void* buffer = malloc(64);

    /* Fill it with pseudorandom data. */
    int error = ordo_random(buffer, 64);

    /* Convert it to readable hexadecimal. */
    char* hex = bufferToHex(buffer, 64);

    /* Print any error */
    if (error == 0) printf("[+] Generation reported successful, please confirm: %s\n\n", hex);
    else printf("[!] An error occurred during generation [%s].\n\n", error_msg(error));

    /* Free the memory used. */
    free(hex);
    free(buffer);
}

/* Rates the performance of a cipher primitive/encryption mode combination. Uses an existing buffer. */
void blockCipherPerformance(const struct BLOCK_CIPHER* primitive, const struct BLOCK_MODE* mode, size_t keySize, unsigned char* buffer, size_t bufferSize)
{
    /* Declare variables. */
    struct ECB_PARAMS modeParams;
    int error;
    void* iv;
    void* key;
    size_t outlen;
    clock_t start;
    float time;

    /* Randomize the plaintext buffer first, to defeat caching. */
    randomizeBuffer(buffer, bufferSize);

    /* Allocate a buffer of the right size (= cipher block size) for the IV. */
    iv = malloc(cipher_block_size(primitive));
    memset(iv, 0, cipher_block_size(primitive));

    /* Allocate a buffer of the right size for the key. */
    key = malloc(keySize);
    memset(key, 0, keySize);

    /* Print primitive/mode information. */
    printf("[+] Testing %s/%s with a %d-bit key...\n", block_cipher_name(primitive), block_mode_name(mode), (int)keySize * 8);

    /* Save starting time. */
    start = clock();

    /* We want to disable padding (note this works because the only block cipher modes to use parameters happen to have
     * the same parameter structure, a single integer describing whether padding should be enabled or not). */
    modeParams.padding = 0;

    /* Encryption test. */
    error = ordoEncrypt(buffer, bufferSize, buffer, &outlen, primitive, mode, key, keySize, iv, cipher_block_size(primitive), 0, &modeParams);
    if (error < 0) printf("[!] An error occurred during encryption [%s].\n", error_msg(error));
    else
    {
        /* Get total time and display speed. */
        time = (float)(clock() - start) / (float)CLOCKS_PER_SEC;
        printf("[+] Encryption: %.1fMB/s.\n", (float)(bufferSize >> 20) / time);

        /* Save starting time. */
        start = clock();

        /* Decryption test. */
        error = ordoDecrypt(buffer, bufferSize, buffer, &outlen, primitive, mode, key, keySize, iv, cipher_block_size(primitive), 0, &modeParams);
        if (error < 0) printf("[!] An error occurred during decryption [%s].\n", error_msg(error));
        else
        {
            /* Get total time and display speed. */
            time = (float)(clock() - start) / (float)CLOCKS_PER_SEC;
            printf("[+] Decryption: %.1fMB/s.\n", (float)(bufferSize >> 20) / time);
        }
    }

    printf("\n");

    /* Clean up. */
    free(key);
    free(iv);
}

void streamCipherPerformance(const struct STREAM_CIPHER* primitive, size_t keySize, unsigned char* buffer, size_t bufferSize)
{
    /* Declare variables. */
    int error;
    void* key;
    clock_t start;
    float time;

    /* Randomize the plaintext buffer first, to defeat caching. */
    randomizeBuffer(buffer, bufferSize);

    /* Allocate a buffer of the right size for the key. */
    key = malloc(keySize);
    memset(key, 0, keySize);

    /* Print primitive information. */
    printf("[+] Testing %s with a %d-bit key...\n", stream_cipher_name(primitive), (int)keySize * 8);

    /* Save starting time. */
    start = clock();

    /* Encryption test. */
    error = ordoEncryptStream(buffer, bufferSize, primitive, key, keySize, 0);
    if (error < 0) printf("[!] An error occurred during encryption [%s].\n", error_msg(error));
    else
    {
        /* Get total time and display speed. */
        time = (float)(clock() - start) / (float)CLOCKS_PER_SEC;
        printf("[+] Encryption: %.1fMB/s.\n", (float)(bufferSize >> 20) / time);
    }

    printf("\n");

    /* Clean up. */
    free(key);
}

void hashFunctionPerformance(const struct HASH_FUNCTION* primitive, unsigned char* buffer, size_t bufferSize)
{
    /* Declare variables. */
    int error;
    void* digest;
    clock_t start;
    float time;

    /* Allocate a buffer of the right size for the digest. */
    digest = malloc(digest_length(primitive));

    /* Print primitive information. */
    printf("[+] Testing %s...\n", hash_function_name(primitive));

    /* Save starting time. */
    start = clock();

    /* Hashing test. */
    error = ordoHash(buffer, bufferSize, digest, primitive, 0);
    if (error < 0) printf("[!] An error occurred during hashing [%s].\n", error_msg(error));
    else
    {
        /* Get total time and display speed. */
        time = (float)(clock() - start) / (float)CLOCKS_PER_SEC;
        printf("[+] Hashing: %.1fMB/s.\n", (float)(bufferSize >> 20) / time);
    }

    printf("\n");

    /* Clean up. */
    free(digest);
}

void pbkdf2Performance(const struct HASH_FUNCTION* primitive, size_t iterations)
{
    char *password = "my password";
    char *salt = "a salt";
    size_t outputLen = digest_length(primitive); /* testing speed for a single iteration loop */
    void *output = malloc(outputLen);
    clock_t start;
    float time;
    int error;

    start = clock();

    error = pbkdf2(primitive, password, strlen(password), salt, strlen(salt), output, outputLen, iterations, 0);
    if (error < 0) printf("[!] An error occurred during pbkdf2 [%s].\n", error_msg(error));
    else
    {
        /* Get total time and display speed. */
        time = (float)(clock() - start) / (float)CLOCKS_PER_SEC;
        printf("[+] PBKDF2/%s: %.1f seconds for %d iterations.\n", hash_function_name(primitive), time, (int)iterations);
    }

    free(output);
}
