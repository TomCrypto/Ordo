#include <testing/testing.h>

/* Opens the test vector file. */
FILE* loadTestVectors()
{
    /* Just open the file in binary mode. */
    return fopen("vectors", "rb");
}

/* Reads the next line of a file in a buffer. */
char* readLine(FILE* file)
{
    #define MAX_LINE_LENGTH 512
    char* line = malloc(MAX_LINE_LENGTH);
    char current;
    size_t t = 0;

    /* Read the first character. */
    if (fread(&current, 1, 1, file) == 0) return 0;

    /* Read each character sequentially until encountering a newline. */
    while (current != '\n')
    {
        /* Append the character to the line. */
        *(line + t++) = current;

        /* Read the next character. */
        if (fread(&current , 1, 1, file) == 0) return 0;
    }

    /* Append a zero and resize the line buffer. */
    *(line + t++) = 0x00;
    line = realloc(line, t);

    /* Seek forward in the file to get rid of any extra CR and LF's. */
    while ((current == '\n') && (current == '\r')) current = fread(line, 1, 1, file);

    /* Return the completed line. */
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
    /* Allocate the memory needed. */
    unsigned char* buf = malloc(strlen(str) / 2);
    *outlen = strlen(str) / 2;
    size_t len = strlen(str);
    size_t t;

    /* Read each two characters. */
    for (t = 0; t < len / 2; t++) sscanf(str + 2 * t, "%2hhx", buf + t);

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
     * Mode may be the strings "ECB", "CBC", etc... and key, iv, plaintext & ciphertext
     * are in hexadecimal notation. If an iv is not required, it may be omitted between
     * two colons. Note tweaks are ignored in test vectors (if tweaks don't work then it's
     * the primitive's key schedule's fault which is easily localized and fixed). */

    /* Parse the test vector. */
    char* primitiveName = readToken(line, 1);
    char* modeName = readToken(line, 2);
    size_t keylen, ivlen, plaintextlen, ciphertextlen;
    unsigned char* key = hexToBuffer(readToken(line, 3), &keylen);
    unsigned char* iv = hexToBuffer(readToken(line, 4), &ivlen);
    unsigned char* plaintext = hexToBuffer(readToken(line, 5), &plaintextlen);
    unsigned char* ciphertext = hexToBuffer(readToken(line, 6), &ciphertextlen);
    int padding = atoi(readToken(line, 7));

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
    int error = ordoEncrypt(plaintext, plaintextlen, computedCiphertext, &computedCiphertextLen, primitive, mode, key, keylen, 0, iv, padding);
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
    error = ordoDecrypt(computedCiphertext, computedCiphertextLen, computedPlaintext, &computedPlaintextLen, primitive, mode, key, keylen, 0, iv, padding);
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

    /* Report success. */
    printf("[+] Test vector #%d (%s/%s) successful!\n", n, primitiveName, modeName);
    return 1;
}

/* Runs all test vectors. */
void runTestVectors(FILE* file)
{
    /* Different possible actions. */
    #define TOKEN_ENCRYPT "encrypt"

    /* We keep track of how many lines we read. */
    char* line = readLine(file);
    int success = 0;
    char* token;
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
        }

        /* Read the next line. */
        line = readLine(file);
    }

    /* Print statistics. */
    if (success == n - 1) printf("\n[+] "); else printf("\n[!] ");
    printf("Results: %d test vectors passed out of %d.\n\n", success, n - 1);
}
