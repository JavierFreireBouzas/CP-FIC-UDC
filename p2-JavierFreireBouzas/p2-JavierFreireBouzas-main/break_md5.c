#include <sys/types.h>
#include <openssl/md5.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>
#include <stdbool.h>
#include <unistd.h>

#define PASS_LEN 6
#define NUM_THREADS 4
#define PSWD_THREAD 1000

struct progress {
    struct psswd *psswds;            //array of passwords
    int numHash;
    char bar[27];                   //progress bar
    int bar_iterations;             //counter each time the bar grows
    long tried;                      //number of tries
    pthread_mutex_t *tried_mutex;
    pthread_mutex_t *bar_mutex;
    pthread_mutex_t *found_mutex;
    bool pswrd_found;               //true if the password is found
    long pswrd_sec;                 //passwords per second
};

struct args {
    int thread_num;
    struct progress *progress;
};

struct thread_info {
    pthread_t id;
    struct args *args;
};

struct psswd {
    char *input_hash;
    int index;
    unsigned char md5_num[MD5_DIGEST_LENGTH];
    bool found;
    char solution[6];
};

struct thread_info *start_thread(struct progress *progress, void *function)
{
    struct thread_info *thread;
    thread = malloc(sizeof(struct thread_info));

    if(thread == NULL){
        printf("Not enough memory\n");
        exit(1);
    }

    thread[0].args = malloc(sizeof(struct args));
    thread[0].args->progress = progress;
    thread[0].args->thread_num = 0;

    if (0 != pthread_create(&thread[0].id, NULL, function, thread[0].args)) {
        printf("Could not create thread");
        exit(1);
    }

    return thread;
}

struct thread_info *start_multiple_threads(struct progress *progress, void *function)
{
    int i;
    struct thread_info *threads;
    threads = malloc(sizeof(struct thread_info) * NUM_THREADS);

    if(threads == NULL){
        printf("Not enough memory\n");
        exit(1);
    }

    for(i = 0; i < NUM_THREADS; i++){
        threads[i].args = malloc(sizeof(struct args));
        threads[i].args->progress = progress;
        threads[i].args->thread_num = i;

        if (0 != pthread_create(&threads[i].id, NULL, function, threads[i].args)) {
            printf("Could not create thread %d", i);
            exit(1);
        }
    }

    return threads;
}

void init_progress(struct progress *progress, char *argv[], struct psswd *psswds, int numElements)
{
    progress->bar[0] = '[';
    for(int i = 1; i < 26; i++){
        progress->bar[i] = '_';
    }
    progress->bar[26] = ']';
    progress->pswrd_found = false;
    progress->tried = 0;
    progress->psswds = malloc(sizeof (struct psswd) * numElements);
    progress->psswds = psswds;
    progress->numHash = numElements;
    progress->bar_iterations = 1;
    progress->pswrd_sec = 0;
    progress->tried_mutex = malloc(sizeof(pthread_mutex_t) * NUM_THREADS);
    progress->bar_mutex = malloc(sizeof(pthread_mutex_t) * NUM_THREADS);
    progress->found_mutex = malloc(sizeof(pthread_mutex_t) * NUM_THREADS);

    for(int i=0; i < NUM_THREADS; i++){
        pthread_mutex_init(&progress->tried_mutex[i],NULL);
        pthread_mutex_init(&progress->bar_mutex[i],NULL);
        pthread_mutex_init(&progress->found_mutex[i],NULL);
    }
}

long ipow(long base, int exp)
{
    long res = 1;
    for (;;)
    {
        if (exp & 1)
            res *= base;
        exp >>= 1;
        if (!exp)
            break;
        base *= base;
    }

    return res;
}

long pass_to_long(char *str) {
    long res = 0;

    for(int i=0; i < PASS_LEN; i++)
        res = res * 26 + str[i]-'a';

    return res;
};

void long_to_pass(long n, unsigned char *str) {  // str should have size PASS_SIZE+1
    for(int i=PASS_LEN-1; i >= 0; i--) {
        str[i] = n % 26 + 'a';
        n /= 26;
    }
    str[PASS_LEN] = '\0';
}

int hex_value(char c) {
    if (c>='0' && c <='9')
        return c - '0';
    else if (c>= 'A' && c <='F')
        return c-'A'+10;
    else if (c>= 'a' && c <='f')
        return c-'a'+10;
    else return 0;
}

void hex_to_num(char *str, unsigned char *hex) {
    for(int i=0; i < MD5_DIGEST_LENGTH; i++)
        hex[i] = (hex_value(str[i*2]) << 4) + hex_value(str[i*2 + 1]);
}

void *print_bar(void *ptr)
{
    struct args *args = ptr;
    int last_tried, ctrlr;
    long percentage;
    ctrlr = 0;

    while(1){
        pthread_mutex_lock(&args->progress->bar_mutex[args->thread_num]);
        if(args->progress->pswrd_found){
            pthread_mutex_unlock(&args->progress->bar_mutex[args->thread_num]);
            break;
        }
        last_tried = args->progress->tried;
        if(ctrlr >= (ipow(26,6)/26)){
            args->progress->bar[args->progress->bar_iterations] = '#';
            args->progress->bar_iterations++;
            ctrlr = 0;
        }
        pthread_mutex_unlock(&args->progress->bar_mutex[args->thread_num]);
        usleep(100000);
        pthread_mutex_lock(&args->progress->bar_mutex[args->thread_num]);
        percentage = args->progress->tried * 100 / ipow(26,6);
        args->progress->pswrd_sec = args->progress->tried - last_tried;
        ctrlr += args->progress->pswrd_sec;
        printf("\r");
        printf("%-26s\t(%3ld%%)\tpasswords/s = %ld", args->progress->bar, percentage ,args->progress->pswrd_sec * 10);
        pthread_mutex_unlock(&args->progress->bar_mutex[args->thread_num]);
        fflush(stdout);
    }

    printf("\n");

    return NULL;
}

bool allFound(struct progress * progress){
    for(int i = 0; i < progress->numHash; i++){
        if(!progress->psswds[i].found)
            return false;
    }
    return true;
}

void *break_pass(void *ptr) {
    struct args *args = ptr;
    unsigned char res[MD5_DIGEST_LENGTH];
    unsigned char *pass = malloc((PASS_LEN + 1) * sizeof(char));
    long bound = ipow(26, PASS_LEN);    // we have passwords of PASS_LEN
                                                // lowercase chars =>
                                                //     26 ^ PASS_LEN  different cases

    while(1) {

        pthread_mutex_lock(&args->progress->tried_mutex[args->thread_num]);
        if (args->progress->pswrd_found == true || args->progress->tried >= bound) {
            pthread_mutex_unlock(&args->progress->tried_mutex[args->thread_num]);
            break;
        }

        for (long i = 0; i < PSWD_THREAD; i++) {

            if (args->progress->pswrd_found == true || args->progress->tried >= bound) {
                pthread_mutex_unlock(&args->progress->tried_mutex[args->thread_num]);
                break;
            }

            long_to_pass(args->progress->tried, pass);

            MD5(pass, PASS_LEN, res);

            for(int i = 0; i < args->progress->numHash; i++) {


                if ((!args->progress->psswds[i].found) && (0 == memcmp(res, args->progress->psswds[i].md5_num, MD5_DIGEST_LENGTH))) {
                    pthread_mutex_lock(&args->progress->found_mutex[args->thread_num]);
                    args->progress->psswds[i].found = true;
                    args->progress->pswrd_found = allFound(args->progress);
                    pthread_mutex_unlock(&args->progress->found_mutex[args->thread_num]);
                    for(int j = 0; j < 6; j++){
                        args->progress->psswds[i].solution[j] = pass[j];
                    }
                    pthread_mutex_unlock(&args->progress->tried_mutex[args->thread_num]);
                    break;
                }// Found it!
            }

            args->progress->tried++;
        }
        pthread_mutex_unlock(&args->progress->tried_mutex[args->thread_num]);
    }

    return NULL;
}

void wait(struct thread_info *thread){
    for(int i = 0; i < NUM_THREADS; i++)
        pthread_join(thread[i].id, NULL);
}

void freeProgress(struct progress *progress){
    for(int i=0; i < NUM_THREADS; i++){
        pthread_mutex_destroy(&progress->tried_mutex[i]);
        pthread_mutex_destroy(&progress->bar_mutex[i]);
        pthread_mutex_destroy(&progress->found_mutex[i]);
    }
}


int main(int argc, char *argv[]) {
    if(argc < 2) {
        printf("Use: %s string\n", argv[0]);
        exit(0);
    }

    struct progress progress;
    struct thread_info *thr_break;
    struct psswd *psswds;
    int numElements = 0;

    while(argv[numElements + 1] != NULL)
        numElements++;

    psswds = malloc(sizeof (struct psswd) * numElements);

    for(int i = 1; i <= numElements; i++){
        psswds[i-1].input_hash = malloc(sizeof(char*));
        psswds[i-1].input_hash = argv[i];
        psswds[i-1].index = (i-1);
        hex_to_num(argv[i], psswds[i-1].md5_num);
        psswds[i-1].found = false;
    }

    init_progress(&progress, argv, psswds, numElements);


    thr_break = start_multiple_threads(&progress, break_pass);
    start_thread(&progress, print_bar);
    wait(thr_break);

    for(int i = 0; i < numElements; i++){
        printf("\n%s: %s\n", progress.psswds[i].input_hash, progress.psswds[i].solution);
    }

    freeProgress(&progress);

    return 0;
}