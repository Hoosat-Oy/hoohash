#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <pthread.h>
#include <arpa/inet.h>
#include <cjson/cJSON.h>
#include <inttypes.h>
#include <sys/select.h>
#include "hoohash.h"
#include <math.h>
#include <stdint.h>
#include <signal.h>
#include <gmp.h> // Added GMP header

#ifdef _WIN32
#include <windows.h>

int get_cpu_threads()
{
    SYSTEM_INFO sysInfo;
    GetSystemInfo(&sysInfo);
    return sysInfo.dwNumberOfProcessors;
}
#elif __APPLE__
#include <sys/types.h>
#include <sys/sysctl.h>

int get_cpu_threads()
{
    int ncpu;
    size_t len = sizeof(ncpu);
    sysctlbyname("hw.logicalcpu", &ncpu, &len, NULL, 0);
    return ncpu;
}
#else
#include <stdio.h>

int endianness = 0;

int get_cpu_threads()
{
    FILE *fp;
    char buffer[128];
    int threads = 0;

    fp = popen("lscpu | grep ^CPU\\(s\\):", "r");
    if (fp == NULL)
    {
        perror("popen");
        return -1;
    }

    if (fgets(buffer, sizeof(buffer), fp) != NULL)
    {
        sscanf(buffer, "CPU(s): %d", &threads);
    }

    fclose(fp);
    return threads;
}
#endif

#define BUFFER_SIZE 8192
#define HASH_SIZE 32
#ifndef DOMAIN_HASH_SIZE
#define DOMAIN_HASH_SIZE 32
#endif

typedef struct
{
    int sockfd;
    char *job;
    uint8_t header[DOMAIN_HASH_SIZE];
    double timestamp;
    volatile int running;
    int indice;
} MiningJob;

typedef struct
{
    int sockfd;
    volatile int running;
} StratumContext;

MiningJob current_job;
pthread_t *mining_threads = NULL;
int threads = 12;

volatile uint64_t nonces_processed = 0;
volatile uint64_t cpu_accepted = 0;
volatile uint64_t cpu_rejected = 0;
volatile uint64_t cpu_blocks = 0;
pthread_mutex_t hashrate_mutex = PTHREAD_MUTEX_INITIALIZER;

double difficulty_from_target(uint8_t *target)
{
    mpz_t target_val, max_val;
    mpf_t diff, max_mpf, target_mpf;

    // Initialize GMP variables with sufficient precision (at least 256 bits)
    mpz_init(target_val);
    mpz_init(max_val);
    mpf_init2(diff, 256); // Set precision to 256 bits
    mpf_init2(max_mpf, 256);
    mpf_init2(target_mpf, 256);

    // Import target as a big integer (big-endian byte array)
    mpz_import(target_val, DOMAIN_HASH_SIZE, 1, sizeof(uint8_t), 0, 0, target);

    // Maximum target
    mpz_set_str(max_val, "00000000FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF", 16);

    // Convert both integers to floating-point for division
    mpf_set_z(max_mpf, max_val);
    mpf_set_z(target_mpf, target_val);

    // Compute difficulty = max_target / target
    mpf_div(diff, max_mpf, target_mpf);

    double difficulty = mpf_get_d(diff);

    // Clean up
    mpz_clear(target_val);
    mpz_clear(max_val);
    mpf_clear(diff);
    mpf_clear(max_mpf);
    mpf_clear(target_mpf);

    return difficulty;
}

uint8_t *target_from_pool_difficulty(double difficulty)
{
    mpz_t max_target, target;
    mpf_t diff, temp;

    // Initialize GMP variables with sufficient precision (at least 256 bits)
    mpz_init(max_target);
    mpz_init(target);
    mpf_init2(diff, 256); // Set precision to 256 bits
    mpf_init2(temp, 256);

    // Set max_target to the full 256-bit value
    mpz_set_str(max_target, "0000FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF", 16);

    // Set difficulty as a floating-point value
    mpf_set_d(diff, difficulty);
    if (mpf_cmp_d(diff, 0.0) <= 0) // Check for invalid difficulty
    {
        mpz_clear(max_target);
        mpz_clear(target);
        mpf_clear(diff);
        mpf_clear(temp);
        return NULL;
    }

    // Compute target = max_target / difficulty
    mpf_set_z(temp, max_target);
    mpf_div(temp, temp, diff);
    mpz_set_f(target, temp);

    // Allocate target as 32-byte array
    uint8_t *target_bytes = calloc(DOMAIN_HASH_SIZE, sizeof(uint8_t));
    if (!target_bytes)
    {
        mpz_clear(max_target);
        mpz_clear(target);
        mpf_clear(diff);
        mpf_clear(temp);
        return NULL;
    }

    // Export target to exactly 32 bytes, big-endian
    size_t count;
    mpz_export(target_bytes, &count, 1, sizeof(uint8_t), 0, 0, target);
    if (count < DOMAIN_HASH_SIZE)
    {
        // Shift bytes to the right and pad with leading zeros
        memmove(target_bytes + (DOMAIN_HASH_SIZE - count), target_bytes, count);
        memset(target_bytes, 0, DOMAIN_HASH_SIZE - count);
    }

    // Print target in hex (big-endian)
    printf("Target from Pool: 0x");
    for (int i = 0; i < DOMAIN_HASH_SIZE; i++)
    {
        printf("%02x", target_bytes[i]);
    }
    printf("\n");
    printf("Difficulty: %f\n", difficulty_from_target(target_bytes));

    // Cleanup
    mpz_clear(max_target);
    mpz_clear(target);
    mpf_clear(diff);
    mpf_clear(temp);

    return target_bytes;
}

uint8_t *target;

void smallJobHeader(const uint64_t *ids, uint8_t *headerData)
{
    for (int i = 0; i < 4; i++)
    {
        uint64_t value = ids[i];
        for (int j = 0; j < 8; j++)
        {
            headerData[i * 8 + j] = (uint8_t)((value >> (j * 8)) & 0xFF);
        }
    }
}

void init_mining_job()
{
    current_job.running = 0;
}

void cleanup_mining_job()
{
    current_job.job = NULL;
    current_job.running = 0;
}

int submit_mining_solution(int sockfd, const char *worker, const char *job_id, uint64_t nonce, uint8_t *hash)
{
    // Create the JSON object
    cJSON *submit_request = cJSON_CreateObject();
    cJSON_AddNumberToObject(submit_request, "id", 1);
    cJSON_AddStringToObject(submit_request, "method", "mining.submit");

    // Add params
    cJSON *params = cJSON_CreateArray();
    cJSON_AddItemToArray(params, cJSON_CreateString(worker));
    cJSON_AddItemToArray(params, cJSON_CreateString(job_id));

    // Add nonce as a hexadecimal string
    char nonce_hex[20];
    snprintf(nonce_hex, sizeof(nonce_hex), "0x%" PRIx64, nonce);
    cJSON_AddItemToArray(params, cJSON_CreateString(nonce_hex));

    // Add the hash as a hexadecimal string
    char hash_hex[2 * DOMAIN_HASH_SIZE + 1];
    for (int i = 0; i < DOMAIN_HASH_SIZE; i++)
    {
        snprintf(&hash_hex[i * 2], 3, "%02x", hash[i]);
    }
    cJSON_AddItemToArray(params, cJSON_CreateString(hash_hex));

    // Attach params to the request
    cJSON_AddItemToObject(submit_request, "params", params);

    // Convert the JSON object to a string
    char *submit_msg = cJSON_PrintUnformatted(submit_request);
    if (!submit_msg)
    {
        fprintf(stderr, "Failed to create mining.submit request\n");
        cJSON_Delete(submit_request);
        return -1;
    }

    // Append newline to the JSON message
    strcat(submit_msg, "\n");

    // Send the message
    int send_result = send(sockfd, submit_msg, strlen(submit_msg), 0);
    if (send_result < 0)
    {
        perror("Failed to send mining.submit request");
        return -1;
    }

    // Clean up
    if (submit_msg != NULL)
    {
        // printf("free submit msg\n");
        free(submit_msg);
        submit_msg = NULL;
    }
    cJSON_Delete(submit_request);
}

void *hashrate_display_thread(void *arg)
{
    while (1)
    {
        sleep(1);

        // Simulated performance metrics
        double hashrate = (double)nonces_processed / 1000.0; // in KH/s

        // Get current time
        time_t t = time(NULL);
        struct tm tm_info;
        localtime_r(&t, &tm_info);

        // Format time string
        char time_str[9];
        strftime(time_str, sizeof(time_str), "%H:%M:%S", &tm_info);

        // Print output in the specified format
        printf("[%-6s] =======================================================\n", time_str);
        printf("[%-6s] [hoohash]\t\t|\t accepted|       rejected| \n", time_str);
        printf("[%-6s] CPU0 : %.2f KH/s\t|\t\t%d|\t\t%d|\n",
               time_str, hashrate, cpu_blocks, cpu_rejected);
        printf("[%-6s] Total: %.2f KH/s\t|\t\t%d|\t\t%d|\n", time_str, hashrate, cpu_accepted, cpu_rejected, cpu_blocks);
        printf("[%-6s] =======================================================\n", time_str);

        // Reset nonces processed counter for the next iteration
        nonces_processed = 0;
    }

    return NULL;
}

void *mining_thread_function(void *arg)
{
    // Create a local copy of the job to avoid racing conditions
    MiningJob job_copy;
    memcpy(&job_copy, (MiningJob *)arg, sizeof(MiningJob));

    State state = {0};
    memcpy(state.PrevHeader, job_copy.header, DOMAIN_HASH_SIZE);
    state.Timestamp = (uint64_t)job_copy.timestamp;

    uint64_t nonce = job_copy.indice; // Start nonce unique to the thread
    uint64_t step = threads;          // Increment step equal to the total number of threads

    generateHoohashMatrix(state.PrevHeader, state.mat);

    while (job_copy.running)
    {
        state.Nonce = nonce;
        uint8_t result[DOMAIN_HASH_SIZE];
        miningAlgorithm(&state, result);

        if (compare_target(result, target) <= 0)
        {
            // Use the sockfd from the copy, not directly from arg which might be changed by another thread
            submit_mining_solution(job_copy.sockfd, "worker", job_copy.job, nonce, result);
        }

        nonce += step;
        job_copy.running = current_job.running;
        nonces_processed++;
    }

    return NULL;
}

void start_mining_loop(int sockfd, char *job, uint8_t *header, double timestamp)
{
    int i;

    if (!job || !header)
    {
        fprintf(stderr, "Invalid job or header received\n");
        return;
    }

    // Stop any existing mining threads
    // printf("Stopping existing mining jobs\n");
    if (current_job.running)
    {
        current_job.running = 0;
        // Join all threads
        for (i = 0; i < threads; i++)
        {
            pthread_cancel(mining_threads[i]);
        }
        // printf("free mining threads\n");
        free(mining_threads);
        mining_threads = NULL;
    }

    // Update the job details
    // printf("Update job details\n");
    current_job.job = NULL;
    current_job.sockfd = sockfd;
    current_job.job = strdup(job);
    if (!current_job.job)
    {
        return;
    }
    memcpy(current_job.header, header, DOMAIN_HASH_SIZE);
    current_job.timestamp = timestamp;
    current_job.running = 1;

    // Allocate memory for thread handles
    // printf("Allocate memory for thread handles\n");
    mining_threads = malloc(threads * sizeof(pthread_t));
    if (!mining_threads)
    {
        perror("Failed to allocate memory for threads\n");
        current_job.running = 0;
        return;
    }

    // Create mining threads
    // printf("Create mining threads\n");
    for (i = 0; i < threads; i++)
    {
        current_job.indice = i;
        if (pthread_create(&mining_threads[i], NULL, mining_thread_function, &current_job) != 0)
        {
            perror("Thread creation failed\n");
            current_job.running = 0;
            break;
        }
    }

    // If thread creation failed partway, clean up
    // printf("If thread creation failed partway, clean up\n");
    if (i < threads && mining_threads != NULL)
    {
        for (int j = 0; j < i; j++)
        {
            pthread_cancel(mining_threads[j]);
        }
        // printf("free mining threads\n");
        free(mining_threads);
        mining_threads = NULL;
    }
}

void process_stratum_message(int sockfd, cJSON *message)
{
    if (!message)
    {
        fprintf(stderr, "Null message received in process_stratum_message\n");
        return;
    }

    char *message_str = cJSON_Print(message);
    if (message_str)
    {
        printf("%s\n", message_str);
        // printf("free message str\n");
        if (message_str != NULL)
        {
            free(message_str);
        }
    }

    cJSON *method = cJSON_GetObjectItemCaseSensitive(message, "method");
    if (cJSON_IsString(method))
    {
        if (strcmp(method->valuestring, "mining.set_difficulty") == 0)
        {
            cJSON *params = cJSON_GetObjectItemCaseSensitive(message, "params");
            if (cJSON_IsArray(params) && cJSON_GetArraySize(params) > 0)
            {
                cJSON *difficulty = cJSON_GetArrayItem(params, 0);
                if (cJSON_IsNumber(difficulty))
                {
                    double diff = (difficulty->valuedouble);
                    target = target_from_pool_difficulty(diff);
                }
            }
        }
        else if (strcmp(method->valuestring, "mining.notify") == 0)
        {
            cJSON *params = cJSON_GetObjectItemCaseSensitive(message, "params");
            if (cJSON_IsArray(params) && cJSON_GetArraySize(params) >= 3)
            {
                cJSON *job_id = cJSON_GetArrayItem(params, 0);
                cJSON *prev_hash_array = cJSON_GetArrayItem(params, 1);
                cJSON *time = cJSON_GetArrayItem(params, 2);

                if (cJSON_IsString(job_id) && cJSON_IsArray(prev_hash_array) && cJSON_IsNumber(time))
                {
                    uint64_t hash_elements[4] = {0};
                    for (int i = 0; i < cJSON_GetArraySize(prev_hash_array) && i < 4; i++)
                    {
                        cJSON *item = cJSON_GetArrayItem(prev_hash_array, i);
                        if (cJSON_IsNumber(item))
                        {
                            hash_elements[i] = (uint64_t)item->valuedouble;
                        }
                    }

                    uint8_t headerData[32];
                    smallJobHeader(hash_elements, headerData);
                    // printf("Start mining loop\n");
                    start_mining_loop(sockfd, job_id->valuestring, headerData, time->valuedouble);
                }
            }
        }
        else if (strcmp(method->valuestring, "set_extranonce") == 0)
        {
            // TODO: Handle setting extranonce.
            // {
            //         "jsonrpc":      "2.0",
            //         "method":       "set_extranonce",
            //         "params":       ["f013", 6],
            //         "id":   null
            // }
        }
    }
    else
    {
        cJSON *result = cJSON_GetObjectItemCaseSensitive(message, "result");
        if (cJSON_IsNull(result))
        {
            cJSON *error = cJSON_GetObjectItemCaseSensitive(message, "error");
            if (cJSON_IsArray(error) && cJSON_GetArraySize(error) >= 3)
            {
                cJSON *error_code = cJSON_GetArrayItem(error, 0);
                cJSON *error_message = cJSON_GetArrayItem(error, 1);
                cJSON *thirdvalue = cJSON_GetArrayItem(error, 2);
                switch (error_code->valueint)
                {
                case 20:
                    cpu_rejected++;
                    printf("%s\n", error_message->valuestring);
                    break;
                case 21:
                    cpu_rejected++;
                    printf("%s\n", error_message->valuestring);
                    break;
                case 22:
                    cpu_rejected++;
                    printf("%s\n", error_message->valuestring);
                    break;
                case 24:
                    printf("%s\n", error_message->valuestring);
                    break;
                }
            }
        }
        else
        {
            if (cJSON_IsTrue(result))
            {
                printf("Mining solution accepted\n");
                cpu_blocks++;
            }
        }
    }
}

void *stratum_receive_thread(void *arg)
{
    StratumContext *context = (StratumContext *)arg;
    char buffer[BUFFER_SIZE];
    char json_buffer[BUFFER_SIZE * 2] = {0};
    size_t json_buffer_len = 0;

    while (context->running)
    {
        fd_set read_fds;
        struct timeval timeout;

        FD_ZERO(&read_fds);
        FD_SET(context->sockfd, &read_fds);

        timeout.tv_sec = 1;
        timeout.tv_usec = 0;

        int ready = select(context->sockfd + 1, &read_fds, NULL, NULL, &timeout);
        if (ready <= 0)
            continue;

        int bytes_read = recv(context->sockfd, buffer, sizeof(buffer) - 1, 0);
        if (bytes_read <= 0)
        {
            printf("Failed reading bytes\n");
            break;
        }

        buffer[bytes_read] = '\0';

        // Append new data to the buffer, check for overflow
        if (json_buffer_len + bytes_read >= sizeof(json_buffer))
        {
            fprintf(stderr, "Buffer overflow detected\n");
            break;
        }
        memcpy(json_buffer + json_buffer_len, buffer, bytes_read);
        json_buffer_len += bytes_read;

        // Process complete JSON messages
        char *message_start = json_buffer;
        char *message_end;
        while ((message_end = strchr(message_start, '\n')) != NULL ||
               (json_buffer_len > 0 && json_buffer_len >= sizeof(json_buffer) - 1))
        {
            if (message_end)
            {
                *message_end = '\0';
                size_t message_len = message_end - message_start;

                cJSON *message = cJSON_Parse(message_start);
                if (message)
                {
                    process_stratum_message(context->sockfd, message);
                    cJSON_Delete(message);
                }
                else
                {
                    fprintf(stderr, "JSON parsing error: %s\n", cJSON_GetErrorPtr());
                }

                message_start = message_end + 1;
                json_buffer_len -= (message_len + 1);

                if (json_buffer_len > 0)
                {
                    memmove(json_buffer, message_start, json_buffer_len);
                    message_start = json_buffer;
                }
            }
            else
            {
                // No newline found but buffer is full, clear it to avoid overflow
                if (json_buffer_len >= sizeof(json_buffer) - 1)
                {
                    // fprintf(stderr, "Warning: Discarding oversized message without newline\n");
                    json_buffer_len = 0;
                }
                break;
            }
        }
    }

    return NULL;
}

int start_stratum_receive_thread(int sockfd, pthread_t *thread, StratumContext **out_context)
{
    StratumContext *context = malloc(sizeof(StratumContext));
    if (!context)
    {
        perror("Memory allocation failed");
        return -1;
    }

    context->sockfd = sockfd;
    context->running = 1;

    if (pthread_create(thread, NULL, stratum_receive_thread, context) != 0)
    {
        perror("Thread creation failed");
        if (context != NULL)
        {
            // printf("free context\n");
            free(context);
            context = NULL;
        }
        return -1;
    }

    // Return the context to the caller
    *out_context = context;
    return 0;
}

int stratum_subscribe(int sockfd, const char *pool_ip, int pool_port)
{
    cJSON *subscribe_request = cJSON_CreateObject();
    cJSON_AddNumberToObject(subscribe_request, "id", 1);
    cJSON_AddStringToObject(subscribe_request, "method", "mining.subscribe");
    cJSON *params = cJSON_CreateArray();
    cJSON_AddItemToArray(params, cJSON_CreateString("Hoominer/0.0.0"));
    cJSON_AddItemToObject(subscribe_request, "params", params);

    char *subscribe_msg = cJSON_PrintUnformatted(subscribe_request);
    if (!subscribe_msg)
    {
        fprintf(stderr, "Failed to create subscription request\n");
        cJSON_Delete(subscribe_request);
        return -1;
    }

    snprintf(subscribe_msg + strlen(subscribe_msg), 2, "\n");

    int send_result = send(sockfd, subscribe_msg, strlen(subscribe_msg), 0);
    if (subscribe_msg != NULL)
    {
        // printf("free subscribe msg\n");
        free(subscribe_msg);
        subscribe_msg = NULL;
    }
    cJSON_Delete(subscribe_request);

    if (send_result < 0)
    {
        perror("Failed to send subscription request");
        return -1;
    }

    // printf("Subscription request sent successfully\n");
    return 0;
}

int stratum_authenticate(int sock_fd, const char *username, const char *password)
{
    cJSON *auth_request = cJSON_CreateObject();
    cJSON_AddNumberToObject(auth_request, "id", 1);
    cJSON_AddStringToObject(auth_request, "method", "mining.authorize");
    cJSON *params = cJSON_CreateArray();
    cJSON_AddItemToArray(params, cJSON_CreateString(username));
    cJSON_AddItemToArray(params, cJSON_CreateString(password));
    cJSON_AddItemToObject(auth_request, "params", params);

    char *auth_msg = cJSON_PrintUnformatted(auth_request);
    // printf("Sending authentication message: %s\n", auth_msg);
    strcat(auth_msg, "\n");
    int send_result = send(sock_fd, auth_msg, strlen(auth_msg), 0);
    if (auth_msg != NULL)
    {
        // printf("free auth msg\n");
        free(auth_msg);
        auth_msg = NULL;
    }
    cJSON_Delete(auth_request);

    if (send_result < 0)
    {
        perror("Failed to send subscription request");
        return -1;
    }
    return 0;
}

int connect_to_stratum_server(const char *server_ip, int port)
{
    int sock_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (sock_fd == -1)
    {
        perror("Socket creation failed");
        return -1;
    }

    struct sockaddr_in server_addr = {
        .sin_family = AF_INET,
        .sin_port = htons(port)};

    if (inet_pton(AF_INET, server_ip, &server_addr.sin_addr) <= 0)
    {
        perror("Invalid IP address");
        close(sock_fd);
        return -1;
    }

    if (connect(sock_fd, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0)
    {
        perror("Connection failed");
        close(sock_fd);
        return -1;
    }

    return sock_fd;
}

void parse_args(int argc, char **argv, const char **pool_ip, int *pool_port, const char **username, const char **password, int *threads)
{
    int i;
    for (i = 1; i < argc; i++)
    {
        if (strcmp(argv[i], "--help") == 0 || strcmp(argv[i], "-h") == 0)
        {
            printf("Usage: %s [OPTIONS]\n", argv[0]);
            printf("Options:\n");
            printf("  --ip   <IP address>         Set the pool IP address\n");
            printf("  --port <port number>        Set the pool port number\n");
            printf("  --user <username>           Set the username for authentication\n");
            printf("  --pass <password>           Set the password for authentication\n");
            printf("  --algorithm <algorithm>     Set the password for authentication\n");
            printf("  --cpu-threads <number>      Set the amount of cpu threads.\n");
            printf("  --help, -h                  Show this help message\n");
            exit(0);
        }
        else if (strcmp(argv[i], "--ip") == 0 && i + 1 < argc)
        {
            *pool_ip = argv[++i];
        }
        else if (strcmp(argv[i], "--port") == 0 && i + 1 < argc)
        {
            *pool_port = atoi(argv[++i]);
        }
        else if (strcmp(argv[i], "--user") == 0 && i + 1 < argc)
        {
            *username = argv[++i];
        }
        else if (strcmp(argv[i], "--pass") == 0 && i + 1 < argc)
        {
            *password = argv[++i];
        }
        else if (strcmp(argv[i], "--cpu-threads") == 0 && i + 1 < argc) // Fixed argument name
        {
            *threads = atoi(argv[++i]); // Assign the integer value directly
        }
        else
        {
            fprintf(stderr, "Unrecognized argument: %s\n", argv[i]);
            exit(1);
        }
    }
}

int main(int argc, char **argv)
{
    signal(SIGPIPE, SIG_IGN);
    const char *pool_ip = "127.0.0.1";
    int pool_port = 5555;
    const char *username = "    ";
    const char *password = "x";

    target = NULL;
    threads = get_cpu_threads();
    mining_threads = NULL;

    parse_args(argc, argv, &pool_ip, &pool_port, &username, &password, &threads);

    int sockfd = connect_to_stratum_server(pool_ip, pool_port);
    if (sockfd < 0)
    {
        fprintf(stderr, "Failed to connect to stratum server\n");
        return -1;
    }

    if (stratum_subscribe(sockfd, pool_ip, pool_port) == 0)
    {
        printf("Stratum subscribe sent\n");
    }

    if (stratum_authenticate(sockfd, username, password) == 0)
    {
        printf("Stratum authenticate sent\n");
    }

    init_mining_job();

    StratumContext context;
    context.sockfd = sockfd;
    context.running = 1;

    pthread_t receive_thread, display_thread;

    int error = 0;
    if (pthread_create(&receive_thread, NULL, stratum_receive_thread, &context) != 0)
    {
        perror("Failed to create receive thread");
        error = -1;
    }

    if (pthread_create(&display_thread, NULL, hashrate_display_thread, NULL) != 0)
    {
        perror("Failed to create hashrate display thread");
        error = -1;
    }

    pthread_join(receive_thread, NULL);
    pthread_join(display_thread, NULL);
    close(sockfd);
    cleanup_mining_job();
    if (target != NULL)
    {
        free(target);
    }
    return error;
}