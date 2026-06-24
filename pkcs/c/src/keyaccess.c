/*
 * Minimal test case to illustrate issue with slow key access times when partition has many keys
 */
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <sys/random.h>

#include "pkcs11.h"
#include "primus_common.h"

#define ID_LENGTH 20


char* buffer_to_hex_string(const unsigned char *buffer, size_t len) {
    if (buffer == NULL || len == 0) {
        return NULL;
    }

    // Each byte requires 2 hex characters + 1 extra byte for the null terminator '\0'
    size_t hex_len = (len * 2) + 1;
    char *hex_string = (char *)malloc(hex_len);
    
    if (hex_string == NULL) {
        perror("Failed to allocate memory for hex string");
        return NULL;
    }

    // Fill the string byte by byte
    for (size_t i = 0; i < len; i++) {
        // %02x prints a lowercase hex string (e.g., "0a" instead of "A"). 
        // Use %02X for uppercase.
        sprintf(&hex_string[i * 2], "%02x", buffer[i]);
    }

    // Explicitly add the null terminator at the very end
    hex_string[len * 2] = '\0';

    return hex_string;
}


CK_RV count_private_keys(CK_SESSION_HANDLE session)
{
    CK_RV rv = CKR_OK;
    printf("\nCounting existing private keys...\n");

    CK_OBJECT_HANDLE objects[1000];
    CK_ULONG objectCount, total = 0;
    time_t t0 = time(NULL);
    

    // Search template
    CK_OBJECT_CLASS class = CKO_PRIVATE_KEY; // CKO_SKA_PRIVATE_KEY
    CK_ATTRIBUTE template[] = {
       {CKA_CLASS, &class, sizeof(class)},
	};

    rv = C_FindObjectsInit(session, template, 1);
    if (rv != CKR_OK)
        return rv;

    while (1)
    {
        rv = C_FindObjects(session, objects, 1000, &objectCount);
        if (rv != CKR_OK)
            return rv;

        if (objectCount == 0)
            break;

	total += objectCount;
    }
    printf("%d private keys found in %d seconds\n", total, time(NULL) - t0);
    rv = C_FindObjectsFinal(session);

    return rv;
}

CK_RV create_key(CK_SESSION_HANDLE session, CK_BYTE *id, CK_UTF8CHAR *label)
{
    CK_RV rv = CKR_OK;
    CK_OBJECT_HANDLE privateKey, publicKey;
    CK_MECHANISM genMechanism = {
        CKM_EC_KEY_PAIR_GEN, NULL_PTR, 0};
    CK_BBOOL bTrue = CK_TRUE;
    CK_BBOOL bFalse = CK_FALSE;
    
    CK_OBJECT_CLASS pub_class = CKO_PUBLIC_KEY;
    CK_KEY_TYPE key_type = CKK_EC;

    CK_BYTE ansix962_namedCurve_prime256v1[] = { 0x06, 0x08, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x03, 0x01, 0x07 };

    CK_ATTRIBUTE publicTemplate[] = {
	{CKA_CLASS, &pub_class},
        {CKA_TOKEN, &bTrue, sizeof(bTrue)},
        {CKA_VERIFY, &bFalse, sizeof(bFalse)},
	{CKA_KEY_TYPE, &key_type, sizeof(key_type)},
        {CKA_ID, id, ID_LENGTH},
        {CKA_LABEL, label, strlen(label)},
	{CKA_EC_PARAMS, &ansix962_namedCurve_prime256v1, sizeof(ansix962_namedCurve_prime256v1)},
    };

    CK_OBJECT_CLASS priv_class = CKO_PRIVATE_KEY;
    CK_ATTRIBUTE privateTemplate[] = {
	{CKA_CLASS, &priv_class},
        {CKA_SIGN, &bTrue, sizeof(bFalse)},
        {CKA_TOKEN, &bTrue, sizeof(bTrue)},
	{CKA_KEY_TYPE, &key_type, sizeof(key_type)},
        {CKA_ID, id, ID_LENGTH},
        {CKA_LABEL, label, strlen(label)},
	{CKA_SENSITIVE, &bTrue, sizeof(bTrue)},
        {CKA_EXTRACTABLE, &bFalse, sizeof(bTrue)},

    };

    time_t t0 = time(NULL);
    printf("\nCreating one new key with id %s and label %s...\n", buffer_to_hex_string(id, ID_LENGTH), label);
    rv = C_GenerateKeyPair(
        session, &genMechanism,
        publicTemplate, NUM_ATTR(publicTemplate),
        privateTemplate, NUM_ATTR(privateTemplate),
        &publicKey, &privateKey);
    if (rv == CKR_OK) {
	    printf("Key created in %d seconds\n", time(NULL) - t0);
    }
    return rv;

}

static void print_object_attributes(CK_SESSION_HANDLE session, CK_OBJECT_HANDLE *objects, CK_ULONG objectCount) {
    for (int i = 0; i < objectCount && i < 10; i++)
    {
        char id[64] = {0};  // if too small, will return CKR_BUFFER_TOO_SMALL
	char label[64] = {0};  // if too small, will return CKR_BUFFER_TOO_SMALL
	CK_KEY_TYPE type = -1; // CKK_RSA == 0
	CK_BBOOL extractable = -1;

	CK_ATTRIBUTE attr[] = {
  	    {CKA_ID, id, sizeof(id)},
	    {CKA_LABEL, label, sizeof(label)},
	    {CKA_KEY_TYPE, &type, sizeof(CK_KEY_TYPE)},
	    {CKA_EXTRACTABLE, &extractable, sizeof(CK_BBOOL)},
	};

	// Ignore the return value and just continue with the next attribute
	C_GetAttributeValue(session, objects[i], attr, NUM_ATTR(attr));

	printf("ID: '%s-40t'\t", buffer_to_hex_string(id, attr[0].ulValueLen));
	printf("Label: '%-40s'\t", label);
	printf("Key type: %lu\t", type);
	printf("Extractable: %u (%s)\n", extractable, extractable ? "true" : "false");
    }
}

CK_RV list_private_keys_by_label(CK_SESSION_HANDLE session, CK_UTF8CHAR *label)
{
    CK_RV rv = CKR_OK;
    printf("\nListing private keys by CK_LABEL %s...\n", label);

    CK_OBJECT_HANDLE objects[10];
    CK_ULONG objectCount, total = 0;
    time_t t0 = time(NULL);

    // Search template
    CK_OBJECT_CLASS class = CKO_PRIVATE_KEY; // CKO_SKA_PRIVATE_KEY
    CK_ATTRIBUTE template[] = {
       {CKA_CLASS, &class, sizeof(class)},
       {CKA_LABEL, label, strlen(label)},
	};

    rv = C_FindObjectsInit(session, template, 2);
    if (rv != CKR_OK)
        return rv;

    while (1)
    {
        rv = C_FindObjects(session, objects, 10, &objectCount);
        if (rv != CKR_OK)
            return rv;

        if (objectCount == 0)
            break;

	total += objectCount;

	print_object_attributes(session, objects, objectCount);
    }

    rv = C_FindObjectsFinal(session);

    printf("%d private keys found in %d seconds\n", total, time(NULL) - t0);

    return rv;
}

CK_RV list_private_keys_by_id(CK_SESSION_HANDLE session, CK_BYTE *id)
{
    CK_RV rv = CKR_OK;
    printf("\nListing private keys by CK_ID %s...\n", buffer_to_hex_string(id, ID_LENGTH));

    CK_OBJECT_HANDLE objects[10];
    CK_ULONG objectCount, total = 0;
    time_t t0 = time(NULL);

    // Search template
    CK_OBJECT_CLASS class = CKO_PRIVATE_KEY; // CKO_SKA_PRIVATE_KEY
    CK_ATTRIBUTE template[] = {
       {CKA_CLASS, &class, sizeof(class)},
       {CKA_ID, id, ID_LENGTH},
	};

    rv = C_FindObjectsInit(session, template, 2);
    if (rv != CKR_OK)
        return rv;

    while (1)
    {
        rv = C_FindObjects(session, objects, 10, &objectCount);
        if (rv != CKR_OK)
            return rv;

        if (objectCount == 0)
            break;

	total += objectCount;

	print_object_attributes(session, objects, objectCount);
    }

    rv = C_FindObjectsFinal(session);

    printf("%d private keys found in %d seconds\n", total, time(NULL) - t0);

    return rv;
}


int main(int argc, char **argv)
{
    CK_RV rv = CKR_OK;
    CK_SESSION_HANDLE session;

    rv = SetupSession(&session);
    if (rv != CKR_OK)
        return rv;

    // Step 1 - Determine how many keys are already present in the partition
    rv = count_private_keys(session);
    if (rv != CKR_OK)
    {
        printf("Got return value 0x%lx\n", rv);
        CloseSession(session);
        return rv;
    }

    // Step 2 - Create one new key to test access times on
    unsigned char key_id[ID_LENGTH];

    getrandom(key_id, sizeof(key_id), 0);
    CK_UTF8CHAR *key_label = buffer_to_hex_string(key_id, sizeof(key_id));

    rv = create_key(session, key_id, key_label);
    if (rv != CKR_OK)
    {
        printf("Got return value 0x%lx\n", rv);
        CloseSession(session);
        return rv;
    }
    // Step 3 - Test how long it takes to access the key by CK_ID
    rv = list_private_keys_by_id(session, key_id);
    if (rv != CKR_OK)
    {
        printf("Got return value 0x%lx\n", rv);
        CloseSession(session);
        return rv;
    }
    // Step 4 - Test how long it takes to access the key by CK_LABEL
    rv = list_private_keys_by_label(session, key_label);
    if (rv != CKR_OK)
    {
        printf("Got return value 0x%lx\n", rv);
        CloseSession(session);
        return rv;
    }

    CloseSession(session);
    return rv;
}
