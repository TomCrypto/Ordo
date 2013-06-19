/* Sample: md5sum - calculates the MD5 digest of argv[1].
 * Basically a clone of the md5sum utility. */

#include <stdio.h>

#include <common/ordo_utils.h> /* error_msg() */
#include <hash/hash.h> /* Ordo hash. */
#include <ordo.h> /* init */

#define BUF_SIZE 4096

/* Usage: md5sum FILENAME */
int main(int argc, char *argv[])
{
	int err;
	FILE *f;
	size_t t;
	unsigned char *buffer, *digest;

    if (argc != 2) return -1;
	f = fopen(argv[1], "rb");

	/* init Ordo */
	load_ordo();

	struct HASH_CTX *ctx = hash_alloc(MD5());
	if (!ctx)
	{
		printf("Failed to allocate memory.\n");
		return EXIT_FAILURE;
	}

	if (err = hash_init(ctx, 0)) /* no params */
	{
		printf("An error occurred: %s.\n", error_msg(err));
		hash_free(ctx);
		return -1;
	}

	buffer = malloc(BUF_SIZE);

	while (!feof(f))
	{
		size_t len = fread(buffer, 1, BUF_SIZE, f);
		hash_update(ctx, buffer, len);
	}

	free(buffer);
	fclose(f);

	digest = malloc(hash_digest_length(MD5()));
	hash_final(ctx, digest);
	hash_free(ctx);

	for (t = 0; t < hash_digest_length(MD5()); ++t)
		printf("%.2x", digest[t]);
	printf("  %s\n", argv[1]);

	free(digest);

	return 0;
}
