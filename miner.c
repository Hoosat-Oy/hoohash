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
int threads = 12;

// Add this to track the number of nonces per second
volatile uint64_t nonces_processed = 0;
volatile uint64_t cpu_accepted = 0;
volatile uint64_t cpu_rejected = 0;
volatile uint64_t cpu_blocks = 0;
pthread_mutex_t hashrate_mutex = PTHREAD_MUTEX_INITIALIZER;

// Helper macros to get the mantissa and exponent of a double
const uint64_t DIFFICULTY_1_TARGET_MANTISSA = 0xffffULL;
const int16_t DIFFICULTY_1_TARGET_EXPONENT = 208;

void divide_256_by_64(uint8_t *target, uint64_t divisor)
{
    uint64_t carry = 0;

    // We will use 8 uint64_t values to represent the 256-bit number
    uint64_t value[4];

    // Convert the target (256-bit) from little-endian format to a uint64_t array
    for (int i = 0; i < 4; i++)
    {
        value[i] = 0;
        for (int j = 0; j < 8; j++)
        {
            value[i] |= (uint64_t)target[i * 8 + j] << (8 * j);
        }
    }

    // Perform the division for 256-bit value divided by the divisor (difficulty)
    for (int i = 0; i < 4; i++)
    {
        value[i] = value[i] / divisor;
    }

    // Convert the result back to little-endian and store it in the target
    for (int i = 0; i < 4; i++)
    {
        for (int j = 0; j < 8; j++)
        {
            target[i * 8 + j] = (uint8_t)(value[i] >> (8 * j) & 0xFF);
        }
    }
}

uint8_t *target_from_difficulty(double difficulty)
{
    // Allocate memory for 32 bytes (256-bit target)
    uint8_t *target = (uint8_t *)malloc(DOMAIN_HASH_SIZE);
    if (target == NULL)
    {
        fprintf(stderr, "Memory allocation failed\n");
        return NULL;
    }
    if (difficulty <= 0)
    {
        fprintf(stderr, "Error: Difficulty must be greater than 0.\n");
        return NULL;
    }

    // Reciprocal of difficulty
    double recip_difficulty = 1.0 / difficulty;

    // Decode mantissa and exponent from reciprocal difficulty
    int exponent;
    double mantissa = frexp(recip_difficulty, &exponent);

    // Convert mantissa to an integer (scale it up to 53 bits of precision for double)
    uint64_t mantissa_int = (uint64_t)(mantissa * (1ULL << 53));

    // Adjust the exponent to account for DIFFICULTY_1_TARGET
    int64_t new_exponent = DIFFICULTY_1_TARGET_EXPONENT + exponent - 53;

    // Multiply mantissa by DIFFICULTY_1_TARGET's mantissa
    uint64_t new_mantissa = mantissa_int * DIFFICULTY_1_TARGET_MANTISSA;

    // Clear the target buffer
    memset(target, 0, DOMAIN_HASH_SIZE);

    // Calculate start position and bit remainder
    int start = new_exponent / 8;     // Byte position
    int remainder = new_exponent % 8; // Bit offset within the byte

    // Check bounds
    if (start < 0 || start >= DOMAIN_HASH_SIZE)
    {
        fprintf(stderr, "Error: Target is out of bounds.\n");
        return NULL;
    }

    // Insert the mantissa into the target buffer
    uint64_t shifted_mantissa = new_mantissa << remainder; // Align the mantissa to the target buffer
    for (int i = 0; i < 8 && start + i < DOMAIN_HASH_SIZE; i++)
    {
        target[start + i] = (shifted_mantissa >> (56 - 8 * i)) & 0xff;
    }

    // Handle carry into the next byte if necessary
    if (start + 8 < DOMAIN_HASH_SIZE && remainder > 0)
    {
        target[start + 8] = (new_mantissa >> (64 - remainder)) & 0xff;
    }
    printf("target:\t0x");
    for (int i = 0; i < 32; i++)
    {
        printf("%02x", target[i]);
    }
    printf("\n");
    return target;
}

double difficulty_from_target(uint8_t *target)
{
    uint64_t target_value = 0;

    // Convert the target (byte array) back to a 64-bit integer
    for (int i = 0; i < DOMAIN_HASH_SIZE; i++)
    {
        target_value = (target_value << 8) | target[i];
    }

    // Calculate difficulty (inverse of the scaling we applied earlier)
    double difficulty = (double)0xFFFFFFFFFFFFFFFF / target_value;
    return difficulty;
}

int compare_target(uint8_t *hash, uint8_t *target)
{
    // Compare byte by byte in a way that simulates numerical comparison
    for (int i = 0; i < DOMAIN_HASH_SIZE; i++)
    {
        if (hash[i] < target[i])
        {
            return -1; // Hash is numerically smaller than the target, valid hash
        }
        else if (hash[i] > target[i])
        {
            return 1; // Hash is numerically larger than the target, invalid hash
        }
    }
    return 0; // Hash is equal to the target
}

uint8_t *target;

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

int handle_mining_submission_response(const char *response)
{
    int ret = 0;
    cJSON *json = cJSON_Parse(response);
    if (!json)
    {
        fprintf(stderr, "Failed to parse JSON response\n");
        return -1;
    }

    cJSON *error = cJSON_GetObjectItemCaseSensitive(json, "error");
    cJSON *id = cJSON_GetObjectItemCaseSensitive(json, "id");
    if (cJSON_IsNull(error) || error == NULL)
    {
        // Successful submission
        printf("Mining solution accepted\n");
        cpu_blocks++;
    }
    else
    {
        // Error occurred
        cJSON *error_code = cJSON_GetArrayItem(error, 0);
        cJSON *error_message = cJSON_GetArrayItem(error, 1);
        printf("%s", cJSON_Print(error_code));
        printf("%s", cJSON_Print(error_message));
        if (error_code && error_message)
        {
            switch (error_code->valueint)
            {
            case 20:
                printf("Incorrect proof of work hash. Retrying solution.\n");
                cpu_rejected++;
                ret = -1;
                break;
            case 21:
                printf("Stale job. Requesting new mining job.\n");
                cpu_rejected++;
                ret = -1;
                break;
            case 22:
                printf("Duplicate share detected.\n");
                cpu_rejected++;
                ret = -1;
                break;
            default:
                printf("Unknown submission error: %d - %s\n",
                       error_code->valueint,
                       error_message->valuestring);
                ret = -1;
            }
        }
    }
    cJSON_Delete(json);
    return ret;
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
    free(submit_msg);
    cJSON_Delete(submit_request);

    char response_buffer[1024];
    int bytes_received = recv(sockfd, response_buffer, sizeof(response_buffer) - 1, 0);
    if (bytes_received > 0)
    {
        response_buffer[bytes_received] = '\0';
        return handle_mining_submission_response(response_buffer);
    }
    else
    {
        return -1;
    }
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

        if (compare_target(result, target) < 0)
        {
            printf("hash:\t0x");
            for (int i = 0; i < 32; i++)
            {
                printf("%02x", result[i]);
            }
            printf("\n");
            printf("target:\t0x");
            for (int i = 0; i < 32; i++)
            {
                printf("%02x", target[i]);
            }
            printf("\n");
            if (submit_mining_solution(job->sockfd, "worker", job->job, nonce, result) == 0)
            {
                printf("Mining solution accepted\n");
                break;
            }
            else
            {
                printf("Failed to submit valid solution\n");
            }
            sleep(1);
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
                    double diff = (difficulty->valuedouble);
                    target = target_from_difficulty(diff);
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

int check_endianness()
{
    unsigned int x = 1;
    char *c = (char *)&x;
    // If the first byte is 1, it's little-endian
    if (*c == 1)
    {
        return 1;
    }
    else
    {
        return 0;
    }
}

int main(int argc, char **argv)
{
    signal(SIGPIPE, SIG_IGN);
    endianness = check_endianness();
    printf("Endianess: %s\n", endianness == 1 ? "Little-endian" : "Big-endian");
    const char *pool_ip = "127.0.0.1";
    int pool_port = 5555;
    const char *username = "    ";
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
