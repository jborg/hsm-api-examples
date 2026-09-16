/*
 * Minimal test case to illustrate the performance regression and variance we're seing with PrimusAPI 2.8.2
 */
#include <assert.h>
#include <stdio.h>
#include <stdint.h>
#include <stdatomic.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <sys/random.h>
#include <pthread.h>

#include "pkcs11.h"
#include "primus_common.h"

char *key_label;

static atomic_uint_fast64_t signature_count = 0;

void record_signature(void) {
    atomic_fetch_add_explicit(&signature_count, 1, memory_order_relaxed);
}

static void *progress_thread(void *arg) {
    (void)arg;
    struct timespec ts = { .tv_sec = 1, .tv_nsec = 0 };

    for (;;) {
        nanosleep(&ts, NULL);
        uint_fast64_t n = atomic_exchange_explicit(&signature_count, 0,
                                                    memory_order_relaxed);
        printf("%llu sigs/s\n", n);
        fflush(stdout);
    }
    return NULL;
}

CK_RV lookup_private_key(CK_SESSION_HANDLE session, CK_UTF8CHAR *label, CK_OBJECT_HANDLE *keyout)
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

    rv = C_FindObjectsInit(session, template, 2);
    if (rv != CKR_OK) {
        return rv;
    }
    rv = C_FindObjects(session, objects, 1, &objectCount);
    if (rv != CKR_OK) {
        return rv;
    }
    if (objectCount == 0) {
        fprintf(stderr, "EEEK no private key found with label %s\n", label);
        exit(1);
    }
    *keyout = objects[0];
    rv = C_FindObjectsFinal(session);
    if (rv != CKR_OK) {
        return rv;
    }
    return rv;
}

// This function tries to emulate the kind of workload and pattern used by Knot when doing DNSSEC signing of a zone
void fake_sign_zone() {
    CK_RV rv;
    CK_SESSION_HANDLE session;
    CK_OBJECT_HANDLE key = 0;
    CK_MECHANISM mech = {CKM_ECDSA_SHA256, NULL, 0};
    CK_ULONG signatureLen;
    char signature[64];
    char message[] = "Foo Bar";

    // Step 1: Create new session
    CK_ULONG flags = CKF_SERIAL_SESSION | CKF_RW_SESSION;
    CK_SLOT_ID slotId = 0;
    rv = C_OpenSession(slotId, flags, NULL_PTR, NULL_PTR, &session);
    if (rv != CKR_OK)
    {
        fprintf(stderr, "C_OpenSession failed: %d\n", rv);
        exit(1);
    }

    // Step 2: Lookup key
    rv = lookup_private_key(session, key_label, &key);
    if (rv != CKR_OK)
    {
        fprintf(stderr, "list_private_keys_by_label failed: %d\n", rv);
        exit(1);
    }

    // Step 3: Perform N signatures
    int num_sigs = random() % 100;
    for(int i=0; i < num_sigs; i++) {
        rv = C_SignInit(session, &mech, key);
        if (rv != CKR_OK)
        {
            fprintf(stderr, "C_SignInit failed: %d\n", rv);
            exit(1);
        }
        signatureLen = sizeof(signature);
        rv = C_Sign(session, message, sizeof(message), signature, &signatureLen);
        if (rv != CKR_OK)
        {
            fprintf(stderr, "C_Sign failed: %d\n", rv);
            exit(1);
        }
        record_signature();
    }
    // Step 4: Close session
    rv = C_CloseSession(session);
    if (rv != CKR_OK)
    {
        fprintf(stderr, "C_ClosseSession failed: %d\n", rv);
        exit(1);
    }
}

void *fake_knot_background_worker(void *arg) {
    long id = (long)arg;
    printf("thread %ld starting\n", id);

    for(;;) {
        fake_sign_zone();
    }
    return NULL;
}

static int start_threads(int num_threads) {
    pthread_t progress_tid;

    // Start progress thread that outputs signature rate every second;
    if (pthread_create(&progress_tid, NULL, progress_thread, NULL) != 0) {
        perror("pthread_create of progress_thread");
        return 1;
    }

    pthread_t *threads = malloc(sizeof(pthread_t) * num_threads);

    for (long i = 0; i < num_threads; i++) {
        if (pthread_create(&threads[i], NULL, fake_knot_background_worker, (void *)i) != 0) {
            perror("pthread_create");
            return 1;
        }
    }

    for (int i = 0; i < num_threads; i++) {
        pthread_join(threads[i], NULL);
    }
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
    start_threads(num_threads);
    CloseSession(session);
    return rv;
}
