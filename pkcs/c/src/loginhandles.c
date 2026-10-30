/*
 * Minimal test case: a redundant C_Login (returning CKR_USER_ALREADY_LOGGED_IN) invalidates
 * object handles previously found in other sessions.
 *
 * 1. Session A: C_Login, find private key by label, sign (works)
 * 2. Session B: C_Login, expected to return CKR_USER_ALREADY_LOGGED_IN (0x100) without side effects
 * 3. Session A: use the same key handle again, fails with CKR_OBJECT_HANDLE_INVALID (0x82)
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "pkcs11.h"
#include "primus_common.h"

static CK_OBJECT_HANDLE find_key(CK_SESSION_HANDLE session, char *label)
{
    CK_OBJECT_HANDLE key = CK_INVALID_HANDLE;
    CK_ULONG count = 0;
    CK_OBJECT_CLASS class = CKO_PRIVATE_KEY;
    CK_ATTRIBUTE template[] = {
       {CKA_LABEL, label, strlen(label)},
       {CKA_CLASS, &class, sizeof(class)},
    };

    if (C_FindObjectsInit(session, template, 2) != CKR_OK ||
        C_FindObjects(session, &key, 1, &count) != CKR_OK ||
        C_FindObjectsFinal(session) != CKR_OK || count == 0) {
        fprintf(stderr, "no private key found with label %s\n", label);
        exit(1);
    }
    return key;
}

static CK_RV sign(CK_SESSION_HANDLE session, CK_OBJECT_HANDLE key)
{
    CK_MECHANISM mech = {CKM_ECDSA_SHA256, NULL, 0};
    CK_BYTE message[] = "Foo Bar";
    CK_BYTE signature[512];
    CK_ULONG signatureLen = sizeof(signature);

    CK_RV rv = C_SignInit(session, &mech, key);
    if (rv != CKR_OK) {
        return rv;
    }
    return C_Sign(session, message, sizeof(message), signature, &signatureLen);
}

int main(int argc, char **argv)
{
    CK_SESSION_HANDLE session_a, session_b;
    CK_KEY_TYPE key_type;
    CK_ATTRIBUTE type_attr[] = {{CKA_KEY_TYPE, &key_type, sizeof(key_type)}};
    CK_RV rv;

    if (argc != 2) {
        fprintf(stderr, "usage: %s <existing_key_label>\n", argv[0]);
        exit(1);
    }
    char *label = argv[1];
    CK_UTF8CHAR_PTR pin = (CK_UTF8CHAR_PTR)getenv("P11_PIN");

    // Session A: C_Initialize, C_OpenSession, C_Login
    rv = SetupSession(&session_a);
    if (rv != CKR_OK) {
        fprintf(stderr, "SetupSession failed: 0x%lx\n", (unsigned long)rv);
        return 1;
    }

    CK_OBJECT_HANDLE key = find_key(session_a, label);
    printf("session A: key handle 0x%lx, sign rv 0x%lx\n", (unsigned long)key,
           (unsigned long)sign(session_a, key));

    rv = C_OpenSession(0, CKF_SERIAL_SESSION | CKF_RW_SESSION, NULL_PTR, NULL_PTR, &session_b);
    if (rv != CKR_OK) {
        fprintf(stderr, "C_OpenSession failed: 0x%lx\n", (unsigned long)rv);
        return 1;
    }
    rv = C_Login(session_b, CKU_USER, pin, strlen((char *)pin));
    printf("session B: C_Login rv 0x%lx (expected 0x100 CKR_USER_ALREADY_LOGGED_IN)\n", (unsigned long)rv);

    rv = C_GetAttributeValue(session_a, key, type_attr, 1);
    printf("session A: C_GetAttributeValue on old handle rv 0x%lx\n", (unsigned long)rv);
    CK_RV sign_rv = sign(session_a, key);
    printf("session A: sign with old handle rv 0x%lx\n", (unsigned long)sign_rv);

    CK_OBJECT_HANDLE new_key = find_key(session_a, label);
    printf("session A: new key handle 0x%lx, sign rv 0x%lx\n", (unsigned long)new_key,
           (unsigned long)sign(session_a, new_key));

    C_CloseSession(session_b);
    CloseSession(session_a);

    if (sign_rv != CKR_OK) {
        printf("FAIL: redundant C_Login invalidated existing object handle\n");
        return 1;
    }
    printf("OK: object handle survived redundant C_Login\n");
    return 0;
}
