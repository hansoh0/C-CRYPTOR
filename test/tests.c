#include <CUnit/Basic.h>
#include <CUnit/CUnit.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <openssl/rand.h>

#include "../src/crypt.h"

/*
 * Tests that the padding length matches its allocated length
 */
void test_pad_length(void) {
	CU_ASSERT(pad_length(0) == 0);
	CU_ASSERT(pad_length(16) == 16);
	CU_ASSERT(pad_length(32) == 32);
}

/*
 * Tests if a file with data is completely removed after zero_file()
 */
void test_zero_file_removes(void) {
	// Create temporary file in wb mode
	const char *tmpf = "/tmp/test_zero_file_removes.txt";
	FILE *fp = fopen(tmpf, "wb");
	CU_ASSERT_PTR_NOT_NULL_FATAL(fp);

	// Write data to file
	const char data[] = "This file is a test for file removal.";
	fwrite(data, 1, sizeof(data), fp);
	fclose(fp);

	CU_ASSERT(zero_file(tmpf, (long)sizeof(data)) == 0);

	// Check if pointer to file exists 
	FILE *exist = fopen(tmpf, "rb");
	CU_ASSERT_PTR_NULL(exist);
	if (exist) fclose(exist);
}

/*
 * Tests if a file with no data is completely removed after zero_file()
 */
void test_zero_file_empty(void) {
        // Create temporary file in wb mode
        const char *tmpf = "/tmp/test_zero_file_empty.txt";
        FILE *fp = fopen(tmpf, "wb");
        CU_ASSERT_PTR_NOT_NULL_FATAL(fp);
	fclose(fp);

	CU_ASSERT(zero_file(tmpf, 0) == 0);

	FILE *exist = fopen(tmpf, "rb");
	CU_ASSERT_PTR_NULL(exist);
	if (exist) fclose(exist);
}

/*
 * Ensures zero_file() cannot operate on a nonexistent file
 */
void test_zero_file_nopath(void) {
	CU_ASSERT(zero_file("/this/path/doesnt/exist.txt", 16) == -1);
}


int main()
{
	CU_initialize_registry();

	CU_pSuite pad_suite = CU_add_suite("pad_length", NULL, NULL);
	CU_add_test(pad_suite, "sizes", test_pad_length);
	
	CU_pSuite zero_suite = CU_add_suite("zero_file", NULL, NULL);
	CU_add_test(zero_suite, "removes file", test_zero_file_removes);
	CU_add_test(zero_suite, "empty file", test_zero_file_empty);
	CU_add_test(zero_suite, "no path", test_zero_file_nopath);

	CU_basic_set_mode(CU_BRM_VERBOSE);
	CU_basic_run_tests();
	CU_cleanup_registry();

	return CU_get_number_of_failures() != 0;
}
