/* Sample: external - shows the library is C++ compatible. Obviously a C++
 *                    wrapper would be somewhat helpful but doesn't exist
 *                    yet.
*/

#include <iostream>
#include <iomanip>
#include <vector>

#include "ordo.h"

int main()
{
    if (ordo_init())
    {
        std::cout << "Failed to initialize Ordo." << std::endl;
        return EXIT_FAILURE;
    }

    std::cout << "Ordo version: " << ordo_version_major() << "."
                                  << ordo_version_minor() << "."
                                  << ordo_version_rev() << "." << std::endl;

    std::cout << "Testing digest module..." << std::endl;

    const struct HASH_FUNCTION *primitive = md5();

    std::string input = "hello world";
    std::vector<unsigned char> digest(digest_length(primitive));
    int err = ordo_digest(primitive, 0, input.c_str(), input.length(),
                          &digest[0]);

    if (err != ORDO_SUCCESS)
    {
        std::cout << "An error occurred: " << err << "." << std::endl;
        std::cout << "Corresponds to: " << error_msg(err) << std::endl;
    }
    else
    {
        std::cout << hash_function_name(primitive)
                  << "(\"" << input << "\") = ";

        for (size_t t = 0; t < digest.size(); ++t)
            std::cout << std::setw(2) << std::setfill('0')
                      << std::hex << +digest[t];

        std::cout << std::endl;
    }

    return EXIT_SUCCESS;
}
