#include <testing/testing.h>

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
    ordoRandom(data, 32);

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
    #define MAX_LINE_LENGTH 512
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
    /* An encrypt test vector takes this form: enc_block:primitive:mode:key:iv:plaintext:ciphertext~
     * Mode may be the strings "ECB", "CBC", etc... and key, iv, plaintext & ciphertext are in
     * hexadecimal notation. If a key or iv is not required, it may be omitted between two colons.
     * The primitive field should be the name of the primitive e.g. "NullCipher" or "RC4". */

    /* Parse the test vector and initialize variables. */
    char* primitiveName = readToken(line, 1);
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
    BLOCK_CIPHER* primitive = getBlockCipherByName(primitiveName);
    BLOCK_CIPHER_MODE* mode = getBlockCipherModeByName(modeName);

    /* If the mode or primitive is not recognized, skip (don't error, it might be a test vector added for later). */
    if ((primitive == 0) || (mode == 0))
    {
        printf("[!] Test vector #%.3d skipped", n);
        if (primitive == 0) printf(", primitive (%s) not recognized", primitiveName);
        if (mode == 0) printf(", mode (%s) not recognized", modeName);
        printf(".\n");
        return 1;
    }

    /* Initialize the test result. */
    result = 0;

    /* Perform the encryption test. */
    error = ordoEncrypt(plaintext, plaintextlen, computedCiphertext, &computedCiphertextLen, primitive, mode, key, keylen, iv, 0, 0);
    if (error == ORDO_ESUCCESS)
    {
        /* Check the computed ciphertext against the expected ciphertext. */
        if ((computedCiphertextLen != ciphertextlen) || (memcmp(computedCiphertext, ciphertext, ciphertextlen) == 0))
        {
            /* Perform the decryption test. */
            error = ordoDecrypt(computedCiphertext, computedCiphertextLen, computedPlaintext, &computedPlaintextLen, primitive, mode, key, keylen, iv, 0, 0);
            if (error == ORDO_ESUCCESS)
            {
                /* Check the computed plaintext against the expected plaintext. */
                if ((computedPlaintextLen != plaintextlen) || (memcmp(computedPlaintext, plaintext, plaintextlen) == ORDO_ESUCCESS))
                {
                    /* Report success. */
                    result = 1;
                    printf("[+] Test vector #%.3d (%s/%s) passed!\n", n, primitiveName, modeName);
                } else printf("[!] Test vector #%.3d (%s/%s) failed: did not get expected plaintext.\n", n, primitiveName, modeName);
            } else printf("[!] Test vector #%.3d (%s/%s) failed: @ordoDecrypt, %s.\n", n, primitiveName, modeName, errorMsg(error));
        } else printf("[!] Test vector #%.3d (%s/%s) failed: did not get expected ciphertext.\n", n, primitiveName, modeName);
    } else printf("[!] Test vector #%.3d (%s/%s) failed: @ordoEncrypt, %s.\n", n, primitiveName, modeName, errorMsg(error));

    /* Clean up. */
    free(computedPlaintext);
    free(computedCiphertext);
    free(plaintext);
    free(ciphertext);
    free(key);
    free(iv);
    free(primitiveName);
    free(modeName);
    return result;
}

/* Runs a stream cipher test vector. */
int runStreamCipherTest(char* line, int n)
{
    /* An encrypt test vector takes this form: enc_stream:cipher:key:plaintext:ciphertext~
     * Mode may be the strings "ECB", "CBC", etc... and key, iv, plaintext & ciphertext are in
     * hexadecimal notation. If a key or iv is not required, it may be omitted between two colons.
     * The primitive field should be the name of the primitive e.g. "NullCipher" or "RC4". */

    /* Parse the test vector and initialize variables. */
    char* primitiveName = readToken(line, 1);
    size_t keylen, plaintextlen, ciphertextlen;
    unsigned char* key = hexToBuffer(readToken(line, 2), &keylen);
    unsigned char* plaintext = hexToBuffer(readToken(line, 3), &plaintextlen);
    unsigned char* ciphertext = hexToBuffer(readToken(line, 4), &ciphertextlen);

    /* Create a temporary buffer to store the computed ciphertext and plaintext. */
    unsigned char* computedPlaintext = malloc(plaintextlen);
    unsigned char* computedCiphertext = malloc(ciphertextlen);
    int error, result;

    /* Get the proper primitive and mode. */
    STREAM_CIPHER* primitive = getStreamCipherByName(primitiveName);

    /* If the mode or primitive is not recognized, skip (don't error, it might be a test vector added for later). */
    if (primitive == 0)
    {
        printf("[!] Test vector #%.3d skipped, primitive (%s) not recognized.\n", n, primitiveName);
        return 1;
    }

    /* Initialize the test result. */
    result = 0;

    /* Perform the encryption test. */
    error = ordoEncryptStream(plaintext, plaintextlen, computedCiphertext, primitive, key, keylen, 0);
    if (error == ORDO_ESUCCESS)
    {
        /* Check the computed ciphertext against the expected ciphertext. */
        if (memcmp(computedCiphertext, ciphertext, ciphertextlen) == 0)
        {
            /* Perform the decryption test. */
            error = ordoDecryptStream(computedCiphertext, ciphertextlen, computedPlaintext, primitive, key, keylen, 0);
            if (error == ORDO_ESUCCESS)
            {
                /* Check the computed plaintext against the expected plaintext. */
                if (memcmp(computedPlaintext, plaintext, plaintextlen) == ORDO_ESUCCESS)
                {
                    /* Report success. */
                    result = 1;
                    printf("[+] Test vector #%.3d (%s) passed!\n", n, primitiveName);
                } else printf("[!] Test vector #%.3d (%s) failed: did not get expected plaintext.\n", n, primitiveName);
            } else printf("[!] Test vector #%.3d (%s) failed: @ordoDecrypt, %s.\n", n, primitiveName, errorMsg(error));
        } else printf("[!] Test vector #%.3d (%s) failed: did not get expected ciphertext.\n", n, primitiveName);
    } else printf("[!] Test vector #%.3d (%s) failed: @ordoEncrypt, %s.\n", n, primitiveName, errorMsg(error));

    /* Clean up. */
    free(computedPlaintext);
    free(computedCiphertext);
    free(plaintext);
    free(ciphertext);
    free(key);
    free(primitiveName);
    return result;
}

/* Runs all test vectors. */
void runTestVectors(FILE* file)
{
    /* Different possible actions. */
    #define TOKEN_ENC_BLOCK "enc_block"
    #define TOKEN_ENC_STREAM "enc_stream"

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
    int error = ordoRandom(buffer, 64);

    /* Convert it to readable hexadecimal. */
    char* hex = bufferToHex(buffer, 64);

    /* Print any error */
    if (error == 0) printf("[+] Generation reported successful, please confirm: %s\n\n", hex);
    else printf("[!] An error occurred during generation [%s].\n\n", errorMsg(error));

    /* Free the memory used. */
    free(hex);
    free(buffer);
}

/* Rates the performance of a cipher primitive/encryption mode combination. Uses an existing buffer. */
void blockCipherPerformance(BLOCK_CIPHER* primitive, BLOCK_CIPHER_MODE* mode, size_t keySize, unsigned char* buffer, size_t bufferSize)
{
    /* Declare variables. */
    int error;
    void* iv;
    void* key;
    size_t outlen;
    clock_t start;
    float time;

    /* Randomize the plaintext buffer first, to defeat caching. */
    randomizeBuffer(buffer, bufferSize);

    /* Allocate a buffer of the right size (= cipher block size) for the IV. This can be zero for stream ciphers. */
    iv = malloc(blockCipherBlockSize(primitive));
    memset(iv, 0, blockCipherBlockSize(primitive));

    /* Allocate a buffer of the right size for the key. */
    key = malloc(keySize);
    memset(key, 0, keySize);

    /* Print primitive/mode information. */
    printf("[+] Testing %s/%s with a %d-bit key...\n", primitiveName(primitive), modeName(mode), (int)keySize * 8);

    /* Save starting time. */
    start = clock();

    /* Encryption test. */                   // this is to make sure we have enough space for padding (yeah, bad design)
    error = ordoEncrypt(buffer, bufferSize - blockCipherBlockSize(primitive), buffer, &outlen, primitive, mode, key, keySize, iv, 0, 0);
    if (error < 0) printf("[!] An error occurred during encryption [%s].\n", errorMsg(error));
    else
    {
        /* Get total time and display speed. */
        time = (float)(clock() - start) / (float)CLOCKS_PER_SEC;
        printf("[+] Encryption: %.1fMB/s.\n", (float)(bufferSize >> 20) / time);

        /* Save starting time. */
        start = clock();

        /* Decryption test. */
        error = ordoDecrypt(buffer, bufferSize, buffer, &outlen, primitive, mode, key, keySize, iv, 0, 0);
        if (error < 0) printf("[!] An error occurred during decryption [%s].\n", errorMsg(error));
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

void streamCipherPerformance(STREAM_CIPHER* primitive, size_t keySize, unsigned char* buffer, size_t bufferSize)
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

    /* Print primitive/mode information. */
    printf("[+] Testing %s with a %d-bit key...\n", primitiveName(primitive), (int)keySize * 8);

    /* Save starting time. */
    start = clock();

    /* Encryption test. */
    error = ordoEncryptStream(buffer, bufferSize, buffer, primitive, key, keySize, 0);
    if (error < 0) printf("[!] An error occurred during encryption [%s].\n", errorMsg(error));
    else
    {
        /* Get total time and display speed. */
        time = (float)(clock() - start) / (float)CLOCKS_PER_SEC;
        printf("[+] Encryption: %.1fMB/s.\n", (float)(bufferSize >> 20) / time);

        /* Save starting time. */
        start = clock();

        /* Decryption test. */
        error = ordoDecryptStream(buffer, bufferSize, buffer, primitive, key, keySize, 0);
        if (error < 0) printf("[!] An error occurred during decryption [%s].\n", errorMsg(error));
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
}
