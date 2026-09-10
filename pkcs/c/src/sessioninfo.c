/*
 * Minimal test case to illustrate behavior change in version 3.8.1 when it comes to login status
 * on newly created sessions.
 */
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <sys/random.h>

#include "pkcs11.h"
#include "primus_common.h"


static CK_RV MySetupSession(CK_SESSION_HANDLE_PTR phSession)
{
    CK_RV rv = CKR_OK;

    CK_CHAR_PTR userPin = (CK_CHAR_PTR)getenv("P11_PIN");
    if (userPin == NULL_PTR)
    {
        printf("P11_PIN envvar not set\n");
        return CKR_GENERAL_ERROR;
    }

    CK_ULONG userPinLen = strlen((char *)userPin);

    CK_ULONG flags = CKF_SERIAL_SESSION | CKF_RW_SESSION;
    CK_SLOT_ID slotId = 0;
    fprintf(stderr, "Opening session...\n");
    rv = C_OpenSession(slotId, flags, NULL_PTR, NULL_PTR, phSession);
    if (rv != CKR_OK)
    {
	fprintf(stderr, "C_OpenSession failed: %d\n", rv);
        return rv;
    }

    CK_SESSION_INFO session_info;

    fprintf(stderr, "Checking login status...\n");
    rv = C_GetSessionInfo(*phSession, &session_info);
    if (rv != CKR_OK)
    {
	fprintf(stderr, "C_GetSessionInfo failed: %d\n", rv);
        return rv;
    }
    // This seems to be true on subsequent sessions in driver 3.8.1 and not in earlier versions
    if (session_info.state == CKS_RO_USER_FUNCTIONS || session_info.state == CKS_RW_USER_FUNCTIONS) {
	fprintf(stderr, "Already logged in according to C_GetSesionInfo! No need to login!?!\n");
	return rv;
    }

    fprintf(stderr, "Logging in...\n");
    rv = C_Login(*phSession, CKU_USER, userPin, userPinLen);
    if (rv != CKR_OK)
    {
	fprintf(stderr, "C_Initialize failed: %d\n", rv);
        return rv;
    }

    return rv;
}

CK_RV find_privkey_by_label(CK_SESSION_HANDLE session, CK_UTF8CHAR *label)
{
    CK_RV rv = CKR_OK;
    fprintf(stderr, "\nListing private keys by CK_LABEL %s...\n", label);

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

    rv = C_FindObjects(session, objects, 10, &objectCount);
    if (rv != CKR_OK)
        return rv;

    if (objectCount == 0) {
	fprintf(stderr, "Key with label %s not found :(\n", label);
    }
    else {
	fprintf(stderr, "Key found!\n");
    }
    rv = C_FindObjectsFinal(session);
    return rv;
}



int main(int argc, char **argv)
{
    CK_RV rv = CKR_OK;
    CK_SESSION_HANDLE session;

    if (argc != 2) {
	printf("Usage: %s <privatekeylabel>\n", argv[0]);
	return 1;
    }

    rv = C_Initialize(NULL);
    if (rv != CKR_OK) {
	fprintf(stderr, "C_Initialize failed: %d\n", rv);
        return rv;
    }

    for(int i=1; i <= 2; i++) {

	rv = MySetupSession(&session);
	if (rv != CKR_OK) {
	    fprintf(stderr, "MySetupSession failed: %d\n", rv);
	    return rv;
	}

	rv = find_privkey_by_label(session, argv[1]);
	if (rv != CKR_OK) {
	    fprintf(stderr, "Key lookup attempt %d failed: %d\n", i, rv);
	    return rv;
	}

        fprintf(stderr, "Closing session...\n\n");
	rv = C_CloseSession(session);
	if (rv != CKR_OK) {
	    fprintf(stderr, "C_CloseSession failed: %d\n", rv);
	    return rv;
	}
    }
}
