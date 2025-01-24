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

#ifdef _WIN32
#include <windows.h>

int get_cpu_threads()
{
    SYSTEM_INFO sysInfo;
    GetSystemInfo(&sysInfo);
    return sysInfo.dwNumberOfProcessors; // Number of logical processors
}
#elif __APPLE__
#include <sys/types.h>
#include <sys/sysctl.h>

int get_cpu_threads()
{
    int ncpu;
    size_t len = sizeof(ncpu);
    sysctlbyname("hw.logicalcpu", &ncpu, &len, NULL, 0); // Get the number of logical CPUs
    return ncpu;
}
#else
#include <stdio.h>

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

#define BUFFER_SIZE 4096
#define HASH_SIZE 32 // SHA256 produces a 32-byte hash

#ifndef DOMAIN_HASH_SIZE
#define DOMAIN_HASH_SIZE 32
#endif

typedef struct
{
    int sockfd;
    char *job;
    uint8_t header[DOMAIN_HASH_SIZE];
    double timestamp;
    volatile int running; // Flag to stop mining
    pthread_mutex_t mutex;
    pthread_cond_t cond;
    int indice;
} MiningJob;

typedef struct
{
    int sockfd;
    volatile int running;
} StratumContext;

MiningJob current_job;
pthread_t *mining_threads = NULL;
int threads = 10;

// Add this to track the number of nonces per second
volatile uint64_t nonces_processed = 0;
volatile uint64_t cpu_accepted = 0;
volatile uint64_t cpu_rejected = 0;
volatile uint64_t cpu_blocks = 0;
pthread_mutex_t hashrate_mutex = PTHREAD_MUTEX_INITIALIZER;

// Utility functions for difficulty and target conversion
uint64_t div_ceil_128(uint64_t high, uint64_t low, uint64_t divisor)
{
    if (high == 0)
        return low / divisor;

    long double dividend = (long double)high * UINT64_MAX + low;
    return (uint64_t)(dividend / divisor);
}

uint64_t target_from_difficulty(uint64_t difficulty)
{
    uint64_t max_target_high = 0xFFFF000000000000ULL;
    uint64_t max_target_low = 0x0000000000000000ULL;
    return div_ceil_128(max_target_high, max_target_low, difficulty);
}

uint64_t difficulty_from_target(uint64_t target)
{
    uint64_t max_target_high = 0xFFFF000000000000ULL;
    uint64_t max_target_low = 0x0000000000000000ULL;
    return div_ceil_128(max_target_high, max_target_low, target);
}

uint64_t diff = 0;
uint64_t target = 0;

void smallJobHeader(const uint64_t *ids, uint8_t *headerData)
{
    for (int i = 0; i < 4; i++)
    {
        // Convert the uint64 back to little endian byte order
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
    pthread_mutex_init(&current_job.mutex, NULL);
    pthread_cond_init(&current_job.cond, NULL);
}

void cleanup_mining_job()
{
    pthread_mutex_destroy(&current_job.mutex);
    pthread_cond_destroy(&current_job.cond);
    if (current_job.job)
        free(current_job.job);
}

void submit_mining_solution(int sockfd, const char *worker, const char *job_id, uint64_t nonce, uint8_t *hash)
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
        return;
    }

    // Append newline to the JSON message
    strcat(submit_msg, "\n");

    // Send the message
    int send_result = send(sockfd, submit_msg, strlen(submit_msg), 0);
    if (send_result < 0)
    {
        perror("Failed to send mining.submit request");
    }
    else
    {
        cpu_blocks += 1;
        printf("Mining.submit message sent successfully\n");
    }

    // Clean up
    free(submit_msg);
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
        printf("[%-6s] =======================================================================\n", time_str);
        printf("[%-6s] [hoohash]             |       accepted|       rejected|         blocks| \n", time_str);
        printf("[%-6s] CPU0 : %.2f KH/s      |\t\t%d|\t\t%d|\t\t%d|\n",
               time_str, hashrate, cpu_accepted, cpu_rejected, cpu_blocks);
        printf("[%-6s] Total: %.2f KH/s      |\t\t%d|\t\t%d|\t\t%d|\n", time_str, hashrate, cpu_accepted, cpu_rejected, cpu_blocks);
        printf("[%-6s] =======================================================================\n", time_str);

        // Reset nonces processed counter for the next iteration
        nonces_processed = 0;
    }

    return NULL;
}

void *mining_thread_function(void *arg)
{
    MiningJob *job = (MiningJob *)arg;
    if (!job)
    {
        perror("Received null job argument");
        return NULL;
    }
    memcpy(job, (MiningJob *)arg, sizeof(MiningJob));

    State state = {0};
    memcpy(state.prePowHash, job->header, DOMAIN_HASH_SIZE);
    state.Timestamp = (uint64_t)job->timestamp;

    uint64_t nonce = job->indice; // Start nonce unique to the thread
    uint64_t step = threads;      // Increment step equal to the total number of threads

    generateHoohashMatrix(state.prePowHash, state.mat);

    while (job->running)
    {
        state.Nonce = nonce;
        uint8_t result[DOMAIN_HASH_SIZE];
        miningAlgorithm(&state, result);

        uint64_t hash_value;
        memcpy(&hash_value, result, sizeof(hash_value));

        if (hash_value <= target)
        {
            cpu_accepted += 1;
            printf("Solution found!\n");
            printf("Job ID: %s\n", job->job);
            printf("Nonce: %" PRIu64 "\n", nonce);
            printf("Hash: ");
            for (int i = 0; i < DOMAIN_HASH_SIZE; i++)
            {
                printf("%02x", result[i]);
            }
            printf("\n");

            submit_mining_solution(job->sockfd, "worker", job->job, nonce, result);
            break;
        }

        nonce += step; // Increment nonce by the step size

        // pthread_mutex_lock(&hashrate_mutex);
        nonces_processed++;
        // pthread_mutex_unlock(&hashrate_mutex);
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
    if (current_job.running)
    {
        current_job.running = 0;

        // Join all threads
        if (mining_threads != NULL)
        {
            for (i = 0; i < threads; i++)
            {
                pthread_join(mining_threads[i], NULL);
            }
            free(mining_threads);
            mining_threads = NULL;
        }
    }

    // Update the job details
    if (current_job.job)
        free(current_job.job);
    current_job.sockfd = sockfd;
    current_job.job = strdup(job);
    if (!current_job.job)
    {
        perror("Failed to allocate memory for job");
        return;
    }
    memcpy(current_job.header, header, DOMAIN_HASH_SIZE);
    current_job.timestamp = timestamp;
    current_job.running = 1;

    // Allocate memory for thread handles and indices
    mining_threads = malloc(threads * sizeof(pthread_t));
    if (!mining_threads)
    {
        perror("Failed to allocate memory for threads or indices");
        current_job.running = 0;
        return;
    }

    // Create mining threads
    for (i = 0; i < threads; i++)
    {
        current_job.indice = i;
        if (pthread_create(&mining_threads[i], NULL, mining_thread_function, &current_job) != 0)
        {
            perror("Thread creation failed");
            current_job.running = 0;
            break;
        }
    }

    // If thread creation failed partway, clean up
    if (i < threads)
    {
        current_job.running = 0;
        for (int j = 0; j < i; j++)
        {
            pthread_join(mining_threads[j], NULL);
        }
        free(mining_threads);
        mining_threads = NULL;
    }
}

void process_stratum_message(int sockfd, cJSON *message)
{
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
                    diff = (uint64_t)(difficulty->valuedouble * 100000000); // Convert to fixed point
                    target = target_from_difficulty(diff);

                    printf("New difficulty set: %f\n", difficulty->valuedouble);
                    printf("Corresponding target: 0x%016" PRIX64 "\n", target);
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
                    // printf("Job ID: %s\n", job_id->valuestring);
                    // printf("Previous header: ");

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

                    // Print the hash in hex format
                    // for (int i = 0; i < 32; i++)
                    // {
                    //     printf("%02x", headerData[i]);
                    // }
                    // printf("\n");

                    // printf("Timestamp: %" PRIu64 "\n", (uint64_t)time->valuedouble);
                    start_mining_loop(sockfd, job_id->valuestring, headerData, time->valuedouble);
                }
            }
        }
    }
    // Handle other methods or no method case as needed
}

// Thread function to handle incoming Stratum messages
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
            printf("Connection closed or error\n");
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
        while ((message_end = strchr(message_start, '\n')) || json_buffer_len >= sizeof(json_buffer) - 1)
        {
            if (message_end)
            {
                *message_end = '\0';
                size_t message_len = message_end - message_start;

                cJSON *message = cJSON_Parse(message_start);
                if (message)
                {
                    // Print the JSON message
                    // char *string = cJSON_Print(message);
                    // if (string)
                    // {
                    //     printf("Received message: %s\n", string);
                    //     free(string); // Free the string allocated by cJSON_Print
                    // }
                    process_stratum_message(context->sockfd, message);
                    cJSON_Delete(message);
                }
                else
                {
                    fprintf(stderr, "JSON parsing error: %s\n", cJSON_GetErrorPtr());
                }

                message_start = message_end + 1;
                json_buffer_len -= (message_len + 1);
                memmove(json_buffer, message_start, json_buffer_len + 1);
            }
            else
            {
                // If we've reached the end of the buffer without finding '\n', we might have an incomplete message
                break;
            }
        }
    }

    // Clean up
    context->running = 0;
    free(context);
    return NULL;
}

int start_stratum_receive_thread(int sockfd, pthread_t *thread)
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
        free(context);
        return -1;
    }

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
    free(subscribe_msg);
    cJSON_Delete(subscribe_request);

    if (send_result < 0)
    {
        perror("Failed to send subscription request");
        return -1;
    }

    printf("Subscription request sent successfully\n");
    return 0;
}

// Stratum communication functions
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
    printf("Sending authentication message: %s\n", auth_msg);
    strcat(auth_msg, "\n");
    send(sock_fd, auth_msg, strlen(auth_msg), 0);

    free(auth_msg);
    cJSON_Delete(auth_request);

    char buffer[BUFFER_SIZE];
    int bytes_read = recv(sock_fd, buffer, sizeof(buffer) - 1, 0);
    if (bytes_read <= 0)
    {
        perror("Authentication response failed");
        return -1;
    }
    buffer[bytes_read] = '\0';

    printf("Received response: %s\n", buffer);

    cJSON *response = cJSON_Parse(buffer);
    if (!response)
    {
        fprintf(stderr, "JSON parsing error: %s\n", cJSON_GetErrorPtr());
        return -1;
    }

    cJSON *result = cJSON_GetObjectItemCaseSensitive(response, "result");

    if (cJSON_IsArray(result))
    {
        cJSON *success = cJSON_GetArrayItem(result, 0);
        if (cJSON_IsTrue(success))
        {
            cJSON_Delete(response);
            return 0; // Authentication successful
        }
    }

    cJSON_Delete(response);
    return -1; // Authentication failed
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
    const char *pool_ip = "127.0.0.1";
    int pool_port = 5555;
    const char *username = "hoosattest:qrak3pvyxa7cj0y46zk47epjjal5zydspudma0ges2ul5z2257z7wffwasvsr";
    const char *password = "x";
    int threads = get_cpu_threads(); // Declare as int, not int *

    parse_args(argc, argv, &pool_ip, &pool_port, &username, &password, &threads);

    int sockfd = connect_to_stratum_server(pool_ip, pool_port);
    if (sockfd < 0)
    {
        fprintf(stderr, "Failed to connect to stratum server\n");
        return -1;
    }

    printf("Connected to Stratum server\n");

    if (stratum_subscribe(sockfd, pool_ip, pool_port) != 0)
    {
        fprintf(stderr, "Subscribe failed\n");
    }

    if (stratum_authenticate(sockfd, username, password) != 0)
    {
        fprintf(stderr, "Authentication failed\n");
        close(sockfd);
        return -1;
    }
    printf("Authentication successful\n");

    init_mining_job();

    pthread_t receive_thread, display_thread;
    if (start_stratum_receive_thread(sockfd, &receive_thread) == 0)
    {
        // Start the display thread for hashrate
        if (pthread_create(&display_thread, NULL, hashrate_display_thread, NULL) != 0)
        {
            perror("Failed to create hashrate display thread");
            close(sockfd);
            cleanup_mining_job();
            return -1;
        }

        pthread_join(receive_thread, NULL);
        pthread_join(display_thread, NULL);
    }

    close(sockfd);
    cleanup_mining_job();
    return 0;
}
