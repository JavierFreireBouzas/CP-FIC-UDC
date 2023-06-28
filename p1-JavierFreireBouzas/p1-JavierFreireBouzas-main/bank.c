#include <errno.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/time.h>
#include <stdbool.h>
#include "options.h"


#define MAX_AMOUNT 20

struct bank {
    int num_accounts;        // number of accounts
    int *accounts;           // balance array
    pthread_mutex_t *mutex;
    struct str_iterations *str_iter;
};

struct args {
    int          thread_num;  // application defined thread #
    int          delay;       // delay between operations
    int	         iterations;  // number of operations
    int          net_total;   // total amount deposited by this thread
    struct bank *bank;        // pointer to the bank (shared with other threads)
    bool         ctrl_total;
    pthread_mutex_t ctrl_mutex;
};

struct thread_info {
    pthread_t    id;    // id returned by pthread_create()
    struct args *args;  // pointer to the arguments
};

struct str_iterations {
    int             n_iterations;
    pthread_mutex_t it_mutex;
};

// Threads run on this function
void *deposit(void *ptr)
{
    struct args *args =  ptr;
    int amount, account, balance;

    pthread_mutex_lock(&args->bank->str_iter->it_mutex);

    while(args->bank->str_iter->n_iterations) {
        pthread_mutex_unlock(&args->bank->str_iter->it_mutex);
        args->bank->str_iter->n_iterations--;
        amount  = rand() % MAX_AMOUNT;
        account = rand() % args->bank->num_accounts;

        printf("Thread %d depositing %d on account %d\n",
               args->thread_num, amount, account);

        pthread_mutex_lock(&args->bank->mutex[account]);

        balance = args->bank->accounts[account];
        if(args->delay) usleep(args->delay); // Force a context switch

        balance += amount;
        if(args->delay) usleep(args->delay);

        args->bank->accounts[account] = balance;
        if(args->delay) usleep(args->delay);

        args->net_total += amount;

        pthread_mutex_unlock(&args->bank->mutex[account]);
        pthread_mutex_lock(&args->bank->str_iter->it_mutex);
    }

    pthread_mutex_unlock(&args->bank->str_iter->it_mutex);

    return NULL;
}

void *transfers(void *ptr)
{
    struct args *args =  ptr;
    int amount, account1, account2;

    pthread_mutex_lock(&args->bank->str_iter->it_mutex);

    while(args->bank->str_iter->n_iterations) {
        pthread_mutex_unlock(&args->bank->str_iter->it_mutex);
        args->bank->str_iter->n_iterations--;

        account1 = rand() % args->bank->num_accounts;

        account2 = rand() % args->bank->num_accounts;
        while(account1 == account2)
            account2 = rand() % args->bank->num_accounts;


        pthread_mutex_lock(&args->bank->mutex[account1]);
        if(pthread_mutex_trylock(&args->bank->mutex[account2])){
            pthread_mutex_unlock(&args->bank->mutex[account1]);
            continue;
        }

        if(args->bank->accounts[account1] != 0){
            amount = rand() % args->bank->accounts[account1];
        }else
            amount = 0;


        args->bank->accounts[account1] -= amount;
        args->bank->accounts[account2] += amount;

        pthread_mutex_unlock(&args->bank->mutex[account1]);
        pthread_mutex_unlock(&args->bank->mutex[account2]);

        printf("Transfer: %d from account %d to account %d\n", amount, account1, account2);
        pthread_mutex_lock(&args->bank->str_iter->it_mutex);
    }

    pthread_mutex_unlock(&args->bank->str_iter->it_mutex);

    return NULL;
}

// start opt.num_threads threads running on deposit.
struct thread_info *start_threads(struct options opt, struct bank *bank, void *function)
{
    int i;
    struct thread_info *threads;

    printf("creating %d threads\n", opt.num_threads);
    threads = malloc(sizeof(struct thread_info) * opt.num_threads);

    if (threads == NULL) {
        printf("Not enough memory\n");
        exit(1);
    }

    // Create num_thread threads running swap()
    for (i = 0; i < opt.num_threads; i++) {
        threads[i].args = malloc(sizeof(struct args));

        threads[i].args -> thread_num = i;
        threads[i].args -> net_total  = 0;
        threads[i].args -> bank       = bank;
        threads[i].args -> delay      = opt.delay;
        threads[i].args -> iterations = opt.iterations;
        threads[i].args -> ctrl_total = false;

        if (0 != pthread_create(&threads[i].id, NULL, function, threads[i].args)) {
            printf("Could not create thread #%d", i);
            exit(1);
        }
    }

    return threads;
}

struct thread_info *start_total_thread(struct options opt, struct bank *bank, void *function)
{
    struct thread_info *thread;
    thread = malloc(sizeof(struct thread_info));

    if (thread == NULL) {
        printf("Not enough memory\n");
        exit(1);
    }

    thread[0].args = malloc(sizeof(struct args));

    thread[0].args -> thread_num = 0;
    thread[0].args -> net_total  = 0;
    thread[0].args -> bank       = bank;
    thread[0].args -> delay      = opt.delay;
    thread[0].args -> iterations = opt.iterations;
    thread[0].args -> ctrl_total = false;

    if (0 != pthread_create(&thread[0].id, NULL, function, thread[0].args)) {
        printf("Could not create thread");
        exit(1);
    }

    return thread;
}


void *print_total(void *ptr){
    struct args *args =  ptr;
    int total = 0;

    while(!args->ctrl_total){

        total = 0;

        for(int i=0; i < args->bank->num_accounts; i++) {

            pthread_mutex_lock(&args->bank->mutex[i]);
            total += args->bank->accounts[i];
            pthread_mutex_unlock(&args->bank->mutex[i]);
        }
        printf("Total: %d\n", total);
        usleep(args->delay);
    }
    return NULL;
}

// Print the final balances of accounts and threads
void print_balances(struct bank *bank, struct thread_info *thrs, int num_threads) {
    int total_deposits=0, bank_total=0;
    printf("\nNet deposits by thread\n");

    for(int i=0; i < num_threads; i++) {
        printf("%d: %d\n", i, thrs[i].args->net_total);
        total_deposits += thrs[i].args->net_total;
    }
    printf("Total: %d\n", total_deposits);

    printf("\nAccount balance\n");
    for(int i=0; i < bank->num_accounts; i++) {
        printf("%d: %d\n", i, bank->accounts[i]);
        bank_total += bank->accounts[i];
    }
    printf("Total: %d\n", bank_total);
}

// wait for all threads to finish, print totals, and free memory
void wait(struct options opt, struct bank *bank, struct thread_info *threads) {
    // Wait for the threads to finish
    for (int i = 0; i < opt.num_threads; i++)
        pthread_join(threads[i].id, NULL);
}

void freeThreads(struct options opt, struct bank *bank, struct thread_info *threads){
    for (int i = 0; i < opt.num_threads; i++){
        free(threads[i].args);
        pthread_mutex_destroy(&bank->mutex[i]);
    }
    free(threads);
}

// allocate memory, and set all accounts to 0
void init_accounts(struct bank *bank, int num_accounts, int num_iterations) {
    bank->num_accounts = num_accounts;
    bank->accounts     = malloc(bank->num_accounts * sizeof(int));
    bank->mutex        = malloc(sizeof(pthread_mutex_t) * bank->num_accounts);
    bank->str_iter     = malloc(sizeof(struct str_iterations));

    bank->str_iter->n_iterations = num_iterations;

    for(int i=0; i < bank->num_accounts; i++){
        bank->accounts[i] = 0;
        pthread_mutex_init(&bank->mutex[i], NULL);
    }
    pthread_mutex_init(&bank->str_iter->it_mutex, NULL);
}

int main (int argc, char **argv)
{
    struct options      opt;
    struct bank         bank;
    struct thread_info *thrs_deposit;
    struct thread_info *thrs_transfer;
    struct thread_info *thr_total;

    srand(time(NULL));

    // Default values for the options
    opt.num_threads  = 5;
    opt.num_accounts = 10;
    opt.iterations   = 100;
    opt.delay        = 10;

    read_options(argc, argv, &opt);

    init_accounts(&bank, opt.num_accounts, opt.iterations);

    thrs_deposit = start_threads(opt, &bank, deposit);
    wait(opt, &bank, thrs_deposit);

    pthread_mutex_lock(&bank.str_iter->it_mutex);
    bank.str_iter->n_iterations = opt.iterations;
    pthread_mutex_unlock(&bank.str_iter->it_mutex);

    thr_total = start_total_thread(opt, &bank, print_total);

    pthread_mutex_init(&thr_total->args->ctrl_mutex, NULL);

    thrs_transfer = start_threads(opt, &bank, transfers);
    wait(opt, &bank, thrs_transfer);

    pthread_mutex_lock(&thr_total->args->ctrl_mutex);
    thr_total->args->ctrl_total = true;
    pthread_mutex_unlock(&thr_total->args->ctrl_mutex);

    pthread_join(thr_total->id, NULL);

    print_balances(&bank, thrs_deposit, opt.num_threads);

    freeThreads(opt, &bank, thrs_deposit);
    freeThreads(opt, &bank, thrs_transfer);

    pthread_mutex_destroy(&thr_total->args->ctrl_mutex);
    pthread_mutex_destroy(&bank.str_iter->it_mutex);

    free(bank.accounts);
}