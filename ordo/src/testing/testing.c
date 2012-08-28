#include <testing/testing.h>

/* Prints out environment information. */
void displayEnvironmentInfo()
{
    /* Print out whether we are in debug or release mode. */
	#if ORDO_DEBUG
	printf("[+] Debug build.\n");
	#else
    printf("[+] Release build.\n");
	#endif

    /* First, find the platform. */
    #if PLATFORM_WINDOWS
    char* platform = "Windows";
    #elif PLATFORM_LINUX
    char* platform = "Linux";
    #endif

    /* Then, the environment. */
    #if ENVIRONMENT_64
    char* environment = "64-bit";
    #else
    char* environment = "32-bit";
    #endif

    /* Finally, the ABI. */
    #if ABI_LINUX_64
    char* ABI = "Linux x64";
    #elif ABI_WINDOWS_64
    char* ABI = "Windows x64";
    #elif ABI_CDECL
    char* ABI = "cdecl x86";
    #endif

    /* Print out this information. */
    printf("[+] Environment: %s, %s, %s.\n", platform, environment, ABI);

    /* Obtain the feature flags. */
    printf("[+] CPU features detected listed");
    #if FEATURE_MMX
    printf(", MMX");
    #endif
    #if FEATURE_SSE
    printf(", SSE");
    #endif
    #if FEATURE_SSE2
    printf(", SSE2");
    #endif
    #if FEATURE_SSE3
    printf(", SSE3");
    #endif
    #if FEATURE_SSE4_1
    printf(", SSE4.1");
    #endif
    #if FEATURE_SSE4_2
    printf(", SSE4.2");
    #endif
    #if FEATURE_AVX
    printf(", AVX");
    #endif
    #if FEATURE_AES
    printf(", AES");
    #endif

    /* All finished. */
    printf(".\n\n");
}

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
    return fgets(line, MAX_LINE_LENGTH, file);
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
    int tmp = 0;

    /* If we got an empty string, return null. */
    if (strlen(str) == 0)
    {
        *outlen = 0;
        return 0;
    }

    /* Allocate the memory needed. */
    unsigned char* buf = malloc(strlen(str) / 2);
    *outlen = strlen(str) / 2;
    size_t len = strlen(str);
    size_t t;

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

/* Gets a cipher primitive object from a name. */
CIPHER_PRIMITIVE* getCipherPrimitive(char* name)
{
    /* Simply compare against the existing list. */
    if (strcmp(name, NullCipher->name) == 0) return NullCipher;
    if (strcmp(name, Threefish256->name) == 0) return Threefish256;
    if (strcmp(name, RC4->name) == 0) return RC4;
    return 0;
}

/* Gets an encryption mode object from a name. */
ENCRYPT_MODE* getEncryptMode(char* name)
{
    /* Simply compare against the existing list. */
    if (strcmp(name, ECB->name) == 0) return ECB;
    if (strcmp(name, CBC->name) == 0) return CBC;
    if (strcmp(name, CTR->name) == 0) return CTR;
    if (strcmp(name, CFB->name) == 0) return CFB;
    if (strcmp(name, OFB->name) == 0) return OFB;
    if (strcmp(name, STREAM->name) == 0) return STREAM;
    return 0;
}

/* Runs an encryption test vector. */
int runEncryptTest(char* line, int n)
{
    /* An encrypt test vector takes this form: encrypt:primitive:mode:key:iv:plaintext:ciphertext.
     * Mode may be the strings "ECB", "CBC", etc... and key, iv, plaintext & ciphertext are in
     * hexadecimal notation. If an iv is not required, it may be omitted between two colons. */

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

    /* Get the proper primitive and mode. */
    CIPHER_PRIMITIVE* primitive = getCipherPrimitive(primitiveName);
    ENCRYPT_MODE* mode = getEncryptMode(modeName);

    /* If the mode or primitive is not recognized, skip (don't error, it might be a test vector added for later). */
    if ((primitive == 0) || (mode == 0))
    {
        printf("[!] Test vector #%d skipped", n);
        if (primitive == 0) printf(", primitive (%s) not recognized", primitiveName);
        if (mode == 0) printf(", mode (%s) not recognized", modeName);
        printf(".\n");
        return 1;
    }

    /* Perform the encryption test. */
    int error = ordoEncrypt(plaintext, plaintextlen, computedCiphertext, &computedCiphertextLen, primitive, mode, key, keylen, iv);
    if (error < 0)
    {
        printf("[!] Test vector #%d (%s/%s) failed: @ordoEncrypt, %s.\n", n, primitiveName, modeName, errorMsg(error));
        return 0;
    }

    /* Check the computed ciphertext against the expected ciphertext. */
    if ((computedCiphertextLen != ciphertextlen) || (memcmp(computedCiphertext, ciphertext, ciphertextlen) != 0))
    {
        printf("[!] Test vector #%d (%s/%s) failed: did not get expected ciphertext.\n", n, primitiveName, modeName);
        return 0;
    }

    /* Perform the decryption test. */
    error = ordoDecrypt(computedCiphertext, computedCiphertextLen, computedPlaintext, &computedPlaintextLen, primitive, mode, key, keylen, iv);
    if (error < 0)
    {
        printf("[!] Test vector #%d (%s/%s) failed: @ordoDecrypt, %s.\n", n, primitiveName, modeName, errorMsg(error));
        return 0;
    }

    /* Check the computed plaintext against the expected plaintext. */
    if ((computedPlaintextLen != plaintextlen) || (memcmp(computedPlaintext, plaintext, plaintextlen) != 0))
    {
        printf("[!] Test vector #%d (%s/%s) failed: did not get expected plaintext.\n", n, primitiveName, modeName);
        return 0;
    }

    /* Clean up. */
    free(computedPlaintext);
    free(computedCiphertext);
    free(plaintext);
    free(ciphertext);
    free(key);
    free(iv);

    /* Report success. */
    printf("[+] Test vector #%d (%s/%s) passed!\n", n, primitiveName, modeName);
    free(primitiveName);
    free(modeName);
    return 1;
}

/* Runs all test vectors. */
void runTestVectors(FILE* file)
{
    /* Different possible actions. */
    #define TOKEN_ENCRYPT "encrypt"

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
            if (strcmp(token, TOKEN_ENCRYPT) == 0) success += runEncryptTest(line, n++);

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
void encryptPerformance(CIPHER_PRIMITIVE* primitive, ENCRYPT_MODE* mode, size_t keySize, unsigned char* buffer, size_t bufferSize)
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
    iv = malloc(primitiveBlockSize(primitive));
    memset(iv, 0, primitiveBlockSize(primitive));

    /* Allocate a buffer of the right size for the key. */
    key = malloc(keySize);
    memset(key, 0, keySize);

    /* Print primitive/mode information. */
    printf("[+] Testing %s/%s with a %zu-bit key...\n", primitiveName(primitive), modeName(mode), keySize * 8);

    /* Save starting time. */
    start = clock();

    /* Encryption test. */
    error = ordoEncrypt(buffer, bufferSize - primitiveBlockSize(primitive), buffer, &outlen, primitive, mode, key, keySize, iv);
    if (error < 0) printf("[!] An error occurred during encryption [%s].", errorMsg(error));
    else
    {
        /* Get total time and display speed. */
        time = (float)(clock() - start) / (float)CLOCKS_PER_SEC;
        printf("[+] Encryption: %.1fMB/s.\n", (float)(bufferSize >> 20) / time);

        /* Save starting time. */
        start = clock();

        /* Decryption test. */
        error = ordoDecrypt(buffer, bufferSize, buffer, &outlen, primitive, mode, key, keySize, iv);
        if (error < 0) printf("[!] An error occurred during decryption [%s].", errorMsg(error));
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
