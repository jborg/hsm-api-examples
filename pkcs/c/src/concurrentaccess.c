/*
 * Minimal test case to illustrate issue with slow key access times when partition has many keys
 *
 * Set unique_label=true and wait_delay=2000 in primus.cfg
 *
 * The issue is still there if wait_delay is the default 250 but then the freeze detection code in this
 * program needs to be modified to be able to detect sub-second freezes.
 */
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <sys/random.h>
#include <pthread.h>

#include "pkcs11.h"
#include "primus_common.h"

char *key_label;

CK_RV lookup_private_key(CK_SESSION_HANDLE session, CK_UTF8CHAR *label)
{
    CK_RV rv = CKR_OK;
    CK_OBJECT_HANDLE objects[1];
    CK_ULONG objectCount;

    // Search template
    CK_OBJECT_CLASS class = CKO_PRIVATE_KEY; // CKO_SKA_PRIVATE_KEY
    CK_ATTRIBUTE template[] = {
       {CKA_LABEL, label, strlen(label)},
       {CKA_CLASS, &class, sizeof(class)},
    };

    time_t t0 = time(NULL);
    rv = C_FindObjectsInit(session, template, 2);
    if (rv != CKR_OK)
    	return rv;

    rv = C_FindObjects(session, objects, 1, &objectCount);
    if (rv != CKR_OK)
    	return rv;
    if (objectCount == 0) {
	fprintf(stderr, "EEEK no private key found with label %s\n", label);
    	exit(1);
    }
    rv = C_FindObjectsFinal(session);
    if (rv != CKR_OK)
    	return rv;

    if (time(NULL) - t0 > 1) {
    	fprintf(stderr, "EEEK C_FindObjects by label took more than 2 seconds, wait_delay probably triggered: took %d seconds\n", time(NULL) - t0);
        exit(1);
    }
    return rv;
}

void *thread_func(void *arg) {
    CK_RV rv;
    CK_SESSION_HANDLE session;

    long id = (long)arg;
    printf("thread %ld starting\n", id);

    // Step 1: Create new session
    CK_ULONG flags = CKF_SERIAL_SESSION | CKF_RW_SESSION;
    CK_SLOT_ID slotId = 0;
    rv = C_OpenSession(slotId, flags, NULL_PTR, NULL_PTR, &session);
    if (rv != CKR_OK)
    {
	fprintf(stderr, "C_OpenSession failed: %d\n", rv);
	C_Finalize(NULL_PTR);
        return NULL;
    }

    // Step 2: Perform some operations using session
    rv = lookup_private_key(session, key_label);
    if (rv != CKR_OK)
    {
	fprintf(stderr, "list_private_keys_by_label failed: %d\n", rv);	
        C_Finalize(NULL_PTR);
        return NULL;
    }

    // Step 3: Close session
    rv = C_CloseSession(session);
    if (rv != CKR_OK)
    {
	fprintf(stderr, "C_ClosseSession failed: %d\n", rv);	
        C_Finalize(NULL_PTR);
        return NULL;
    }

    printf("thread %ld exiting\n", id);
    return NULL;
}

static int start_threads(int num_threads) {
    pthread_t *threads = malloc(sizeof(pthread_t) * num_threads);

    for (long i = 0; i < num_threads; i++) {
        if (pthread_create(&threads[i], NULL, thread_func, (void *)i) != 0) {
            perror("pthread_create");
            return 1;
        }
    }

    for (int i = 0; i < num_threads; i++) {
        pthread_join(threads[i], NULL);
    }

    printf("all threads finished, looking good so far...\n");
    free(threads);
    return 0;
}

int main(int argc, char **argv)
{
    CK_RV rv = CKR_OK;
    CK_SESSION_HANDLE session;

    if (argc != 3) {
	fprintf(stderr, "usage: %s <num_theads> <existing_key_label>\n", argv[0]);
	exit(1);
    }

    int num_threads = atoi(argv[1]);
    key_label = argv[2];

    rv = SetupSession(&session);
    if (rv != CKR_OK) {
        return rv;
    }
    for(;;) {
	start_threads(num_threads);
    }
    CloseSession(session);
    return rv;
}
