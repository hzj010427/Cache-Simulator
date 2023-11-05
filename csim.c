/**
 * @brief Cache Simulator
 * @author Zijie Huang
 * @date 10/06/2023
 */
#include "cachelab.h"
#include <ctype.h>
#include <errno.h>
#include <getopt.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

/**
 * Constants
 */
#define EXIT_SUCCESS 0
#define EXIT_FAILURE 1
#define LINELEN 64

/**
 * This struct represents a memory-access trace.
 * op: 'L' for load, 'S' for store
 * addr: the 64 bits address of the memory access in hexadecimal
 * size: the size of the memory access in decimal
 */
typedef struct {
    char op;
    unsigned long long addr;
    long int size;
} Trace;

/**
 * This struct store the number of instructions and an dynamic array of Trace
 * structs. numTrace: the number of traces in the trace array capacity: the
 * capacity of the trace array traces: an array of pointers to Trace structs
 */
typedef struct {
    int numTrace;
    int capacity;
    Trace **traces;
} TraceArray;

/**
 * This struct represents a cache block.
 * valid: 1 if the block is valid, 0 otherwise
 * tag: the tag of the block
 * dirty: 1 if the block is dirty, 0 otherwise
 * lru: the lru counter of the block, the smaller the counter, the more recently
 * the block is used
 */
typedef struct {
    unsigned int valid;
    unsigned long long tag;
    unsigned int dirty;
    unsigned int lru;
} CacheBlock;

/**
 * This struct represents a cache.
 * s: the number of set index bits, 2**s sets in total
 * E: the number of lines per set
 * b: the number of block offset bits, each block contains 2**b bytes
 * blocks: an array of pointers to CacheBlock structs
 */
typedef struct {
    unsigned long long int s;
    unsigned long long int E;
    unsigned long long int b;
    CacheBlock **blocks;
} Cache;

/**
 * Simply print out the usage of the program.
 */
void PrintUsage(void);

/**
 * Process a memory-access trace file.
 * The correct format: Op Addr,Size
 * @param traceFile The name of the trace file.
 * @return 0 if the trace file is successfully processed, 1 otherwise.
 */
int ParseTraceFile(const char *traceFile, TraceArray *ta);

/**
 * Create a new Trace struct.
 * @param op The operation of the trace.
 * @param addr The address of the trace.
 * @param size The size of the trace.
 * @return A pointer to the new Trace struct.
 */
Trace *createTrace(char op, unsigned long long int addr, long int size);

/**
 * Create a new TraceArray struct.
 * @return A pointer to the new TraceArray struct.
 */
TraceArray *createTraceArray(void);

/**
 * Add a Trace to a dynamic array of Trace.
 * @param ta The TraceArray struct.
 * @param t The Trace struct.
 */
void addTrace2TraceArray(TraceArray *ta, Trace *t);

/**
 * Free the memory allocated for a TraceArray struct.
 * @param ta The TraceArray struct.
 */
void freeTraceArray(TraceArray *ta);

/**
 * Create a new Cache struct.
 * @param s The number of set index bits.
 * @param E The number of lines per set.
 * @param b The number of block offset bits.
 * @return A pointer to the new Cache struct.
 */
Cache *createCache(unsigned long long int s, unsigned long long int E,
                   unsigned long long int b);

/**
 * Free the memory allocated for a Cache struct.
 * @param c The Cache struct.
 */
void freeCache(Cache *c);

/**
 * Initialize the given csim_stats_t struct.
 * @return A pointer to the new csim_stats_t struct.
 */
csim_stats_t *initStats(void);

/**
 * Free the memory allocated for a csim_stats_t struct.
 */
void freeStats(csim_stats_t *stats);

/**
 * This is the core of the cache simulator.
 * @param c The Cache struct.
 * @param ta The TraceArray struct.
 * @param stats The csim_stats_t struct.
 * @param verbose 1 if the verbose mode is on, 0 otherwise.
 */
void simulateCache(Cache *c, TraceArray *ta, csim_stats_t *stats, int verbose);

/**
 * Check if it is a cache hit.
 * @param c The Cache struct.
 * @param setIndex The set index of the address.
 * @param tag The tag of the address.
 * @return 1 if it is a cache hit, 0 otherwise.
 */
int isHit(Cache *c, unsigned long long int setIndex,
          unsigned long long int tag);

/**
 * Check if it is eviction.
 * @param c The Cache struct.
 * @param setIndex The set index of the address.
 * @return 1 if it is eviction, 0 otherwise.
 */
int isEviction(Cache *c, unsigned long long int setIndex);

/**
 * Check the evicted block is dirty or not.
 * @param c The Cache struct.
 * @param setIndex The set index of the address.
 * @param tag The tag of the address.
 * @return 1 if it is dirty, 0 otherwise.
 */
int isDirty(Cache *c, unsigned long long int setIndex);

/**
 * Update all the LRU counter of the blocks in the set except the block with the
 * given tag.
 * @param c The Cache struct.
 * @param setIndex The set index of the address.
 * @param tag The tag of the address.
 */
void updateLRU(Cache *c, unsigned long long int setIndex,
               unsigned long long int tag);

/**
 * Set the dirty bit of the block to 1.
 * @param c The Cache struct.
 * @param setIndex The set index of the address.
 * @param tag The tag of the address.
 */
void setDirty(Cache *c, unsigned long long int setIndex,
              unsigned long long int tag);

/**
 * Update the cache by LRU replacement policy, but it will fill out the empty
 * block first.
 * @param c The Cache struct.
 * @param setIndex The set index of the address.
 * @param tag The tag of the address.
 */
void updateCache(Cache *c, unsigned long long int setIndex,
                 unsigned long long int tag);

int main(int argc, char **argv) {
    int verbose = 0;
    unsigned long long int s, E, b;
    int sFlag = 0, EFlag = 0, bFlag = 0,
        tFlag =
            0; // flags for checking if the corresponding arguments are provided
    char *traceFile = NULL;
    char *endptr = NULL;
    int opt;

    /* No arguments provided */
    if (argc == 1) {
        fprintf(stderr, "Error: No arguments provided.\n");
        PrintUsage();
        exit(EXIT_FAILURE);
    }

    /* parse arguments */
    while ((opt = getopt(argc, argv, "hvs:E:b:t:")) != -1) {
        switch (opt) {
        case 'h':
            PrintUsage();
            exit(EXIT_SUCCESS);
        case 'v':
            verbose = 1;
            break;
        case 's':
            s = strtoul(optarg, &endptr, 10);
            sFlag = (*endptr != '\0' || endptr == optarg) ? 1 : 0;
            break;
        case 'E':
            E = strtoul(optarg, &endptr, 10);
            EFlag = (*endptr != '\0' || endptr == optarg) ? 1 : 0;
            break;
        case 'b':
            b = strtoul(optarg, &endptr, 10);
            bFlag = (*endptr != '\0' || endptr == optarg) ? 1 : 0;
            break;
        case 't':
            traceFile = optarg;
            tFlag = (traceFile == NULL) ? 1 : 0;
            break;
        case '?': // unrecognized option
            if (optopt == 's' || optopt == 'E' || optopt == 'b' ||
                optopt == 't') {
                fprintf(stderr, "Option -%c requires an argument.\n", optopt);
            } else if (isprint(optopt)) {
                fprintf(stderr, "Unknown option '-%c'.\n", optopt);
            } else {
                fprintf(stderr, "Unknown option character '\\x%x'.\n", optopt);
            }
            PrintUsage();
            exit(EXIT_FAILURE);
        }
    }

    /* Check if all required arguments are provided */
    if (sFlag || EFlag || bFlag || tFlag) {
        fprintf(stderr, "Error: Missing required argument.\n");
        PrintUsage();
        exit(EXIT_FAILURE);
    }

    /* Check if s + b is in 0 ~ 64 (considering the overflow) */
    if (s + b > 64 || s + b < s || s + b < b) {
        fprintf(stderr,
                "Error: s + b is larger than 64 bits. (s = %llu, b = %llu)\n",
                s, b);
        PrintUsage();
        exit(EXIT_FAILURE);
    }

    /* Check if E is positive by checking the msb of E */
    if (E >> 63) {
        fprintf(stderr, "Error: E must be positive.");
        PrintUsage();
        exit(EXIT_FAILURE);
    }

    /* Check if there is any redundant argument
    getopt() will set optind to the index of the first non-option argument */
    if (optind < argc) {
        fprintf(stderr, "Error: Redundant arguments.\n");
        PrintUsage();
        exit(EXIT_FAILURE);
    }

    /* Process the trace file */
    TraceArray *ta = createTraceArray(); // create a new TraceArray struct for
                                         // storing the traces

    if (ParseTraceFile(traceFile, ta)) {
        freeTraceArray(ta);
        exit(EXIT_FAILURE);
    }

    /* Cache simulator */
    csim_stats_t *stats = initStats(); // initialize the stats struct
    Cache *c = createCache(s, E, b);   // create a new Cache struct

    simulateCache(c, ta, stats, verbose);
    printSummary(stats);

    freeTraceArray(ta);
    freeCache(c);
    freeStats(stats);
}

void PrintUsage(void) {
    printf("Usage: ./csim [-v] [-h] -s <num> -E <num> -b <num> -t <trace>\n");
    printf("Options:\n");
    printf("  -h         Print the help message.\n");
    printf("  -v         Optional verbose flag.\n");
    printf("  -s <num>   Number of set index bits. (there are 2**s sets)\n");
    printf("  -E <num>   Number of lines per set.\n");
    printf(
        "  -b <num>   Number of block offset bits. (there are 2**b blocks)\n");
    printf("  -t <trace>  Trace file.\n");
    printf("\nExamples:\n");
    printf("  linux>  ./csim -s 4 -E 1 -b 4 -t traces/traces/yi.trace\n");
    printf("  linux>  ./csim -v -s 8 -E 2 -b 4 -t traces/traces/yi.trace\n");
}

int ParseTraceFile(const char *traceFile, TraceArray *ta) {
    FILE *tfp = fopen(traceFile, "rt");

    /* Cannot open the file */
    if (!tfp) {
        fprintf(stderr, "Error opening '%s': %s\n", traceFile, strerror(errno));
        return 1;
    }

    char linebuf[LINELEN];
    int error = 0;
    int lineNum = 0;

    while (fgets(linebuf, LINELEN, tfp)) {
        lineNum++;

        char *op, *addr, *size, *endptr;
        unsigned long long int addrVal;
        long int sizeVal;

        /* check if the line is too long */
        if (linebuf[strlen(linebuf) - 1] != '\n') {
            fprintf(stderr,
                    "Error: Line is too long in trace file at line %d.\n",
                    lineNum);
            error = 1;
            break;
        }

        /* remove the newline character in the end of the line */
        linebuf[strlen(linebuf) - 1] = '\0';

        /* get Op */
        op = strtok(linebuf, " ,");
        if (!op) {
            fprintf(stderr,
                    "Error: Missing operation in trace file at line %d.\n",
                    lineNum);
            error = 1;
            break;
        }

        /* verify Op */
        if (*op != 'L' && *op != 'S') {
            fprintf(stderr,
                    "Error: Invalid operation in trace file at line %d.\n",
                    lineNum);
            error = 1;
            break;
        }

        /* get Addr */
        addr = strtok(NULL, " ,");
        if (!addr) {
            fprintf(stderr,
                    "Error: Missing address in trace file at line %d.\n",
                    lineNum);
            error = 1;
            break;
        }

        /* verify if addr is valid */
        errno = 0;
        addrVal = strtoul(addr, &endptr,
                          16); // endptr will point to the first invalid
                               // character. if success, it will point to '\0'.
        if ((errno) || (*endptr != '\0')) {
            fprintf(stderr,
                    "Error: Invalid address in trace file at line %d.\n",
                    lineNum);
            error = 1;
            break;
        }

        /* get Size */
        size = strtok(NULL, " ,");
        if (!size) {
            fprintf(stderr, "Error: Missing size in trace file at line %d.\n",
                    lineNum);
            error = 1;
            break;
        }

        /* verify if size is valid */
        errno = 0;
        sizeVal = strtol(size, &endptr, 10);
        if ((errno) || (*endptr != '\0')) {
            fprintf(stderr, "Error: Invalid size in trace file at line %d.\n",
                    lineNum);
            error = 1;
            break;
        }

        /* check any other characters after Size */
        if (strtok(NULL, " ,")) {
            fprintf(stderr,
                    "Error: Redundant characters in trace file at line %d.\n",
                    lineNum);
            error = 1;
            break;
        }

        /* pass all the checks, now we can map the trace arguments to a Trace
         * struct */
        Trace *t = createTrace(*op, addrVal, sizeVal);
        addTrace2TraceArray(ta, t);
    }

    fclose(tfp);

    return error;
}

Trace *createTrace(char op, unsigned long long int addr, long int size) {
    Trace *t = malloc(sizeof(Trace));

    if (!t) {
        fprintf(stderr, "Error: Failed to allocate memory for Trace.\n");
        exit(EXIT_FAILURE);
    }

    t->op = op;
    t->addr = addr;
    t->size = size;

    return t;
}

TraceArray *createTraceArray(void) {
    TraceArray *ta = malloc(sizeof(TraceArray));

    if (!ta) {
        fprintf(stderr, "Error: Failed to allocate memory for TraceArray.\n");
        exit(EXIT_FAILURE);
    }

    ta->numTrace = 0;
    ta->capacity = 2; // initial capacity is 2
    ta->traces = malloc(sizeof(Trace *) *
                        (size_t)ta->capacity); // allocate memory for the array
                                               // of pointers to Trace structs

    if (!ta->traces) {
        fprintf(stderr, "Error: Failed to allocate memory for TraceArray.\n");
        exit(EXIT_FAILURE);
    }

    return ta;
}

void addTrace2TraceArray(TraceArray *ta, Trace *t) {
    if (ta->numTrace == ta->capacity) {
        ta->capacity *= 2; // double the capacity
        ta->traces =
            realloc(ta->traces, sizeof(Trace *) * (size_t)ta->capacity);

        if (!ta->traces) {
            fprintf(stderr,
                    "Error: Failed to allocate memory for TraceArray.\n");
            exit(EXIT_FAILURE);
        }
    }

    ta->traces[ta->numTrace++] = t;
}

void freeTraceArray(TraceArray *ta) {
    for (int i = 0; i < ta->numTrace; i++) {
        free(ta->traces[i]);
    }

    free(ta->traces);
    free(ta);
}

Cache *createCache(unsigned long long int s, unsigned long long int E,
                   unsigned long long int b) {
    Cache *c = malloc(sizeof(Cache));

    if (!c) {
        fprintf(stderr, "Error: Failed to allocate memory for Cache.\n");
        exit(EXIT_FAILURE);
    }

    c->s = s;
    c->E = E;
    c->b = b;
    c->blocks =
        malloc(sizeof(CacheBlock *) * (size_t)(1 << s)); // 2**s sets in total

    if (!c->blocks) {
        fprintf(stderr, "Error: Failed to allocate memory for Cache.\n");
        exit(EXIT_FAILURE);
    }

    /* allocate memory for each set */
    for (unsigned long long int i = 0; i < (1 << s); i++) {
        c->blocks[i] =
            malloc(sizeof(CacheBlock) *
                   (size_t)E); // malloc E CacheBlock structs for each set

        if (!c->blocks[i]) {
            fprintf(stderr, "Error: Failed to allocate memory for Cache.\n");
            exit(EXIT_FAILURE);
        }

        /* initialize each CacheBlock struct */
        for (unsigned long long int j = 0; j < E; j++) {
            c->blocks[i][j].valid = 0;
            c->blocks[i][j].tag = 0;
            c->blocks[i][j].dirty = 0;
            c->blocks[i][j].lru = 0;
        }
    }

    return c;
}

void freeCache(Cache *c) {
    for (unsigned long long int i = 0; i < (1 << c->s); i++) {
        free(c->blocks[i]);
    }

    free(c->blocks);
    free(c);
}

csim_stats_t *initStats(void) {
    csim_stats_t *stats = malloc(sizeof(csim_stats_t));

    if (!stats) {
        fprintf(stderr, "Error: Failed to allocate memory for csim_stats_t.\n");
        exit(EXIT_FAILURE);
    }

    stats->hits = 0;
    stats->misses = 0;
    stats->evictions = 0;
    stats->dirty_bytes = 0;
    stats->dirty_evictions = 0;

    return stats;
}

void freeStats(csim_stats_t *stats) {
    free(stats);
}

void simulateCache(Cache *c, TraceArray *ta, csim_stats_t *stats, int verbose) {
    for (int i = 0; i < ta->numTrace; i++) {
        Trace *currentTrace = ta->traces[i];

        /* extract the set index and tag from the address */
        unsigned long long int setIndex =
            (currentTrace->addr >> c->b) & ((1 << c->s) - 1);
        unsigned long long int tag = currentTrace->addr >> (c->s + c->b);

        switch (currentTrace->op) {
        case 'L':
            if (isHit(c, setIndex, tag)) {
                updateLRU(c, setIndex, tag);
                stats->hits++;

                if (verbose) {
                    printf("%c %llx,%ld hit\n", currentTrace->op,
                           currentTrace->addr, currentTrace->size);
                }

            } else if (isEviction(c, setIndex)) {
                stats->misses++;
                stats->evictions++;

                if (verbose) {
                    printf("%c %llx,%ld miss eviction\n", currentTrace->op,
                           currentTrace->addr, currentTrace->size);
                }

                if (isDirty(c, setIndex)) {
                    stats->dirty_evictions +=
                        (1 << c->b); // increment the total number of dirty
                                     // bytes evicted
                }

                updateCache(c, setIndex, tag);

            } else {
                stats->misses++;

                if (verbose) {
                    printf("%c %llx,%ld miss\n", currentTrace->op,
                           currentTrace->addr, currentTrace->size);
                }

                updateCache(c, setIndex, tag);
            }

            break;

        case 'S':
            if (isHit(c, setIndex, tag)) {
                updateLRU(c, setIndex, tag);
                stats->hits++;
                setDirty(c, setIndex, tag);

                if (verbose) {
                    printf("%c %llx,%ld hit\n", currentTrace->op,
                           currentTrace->addr, currentTrace->size);
                }

            } else if (isEviction(c, setIndex)) {
                stats->misses++;
                stats->evictions++;

                if (verbose) {
                    printf("%c %llx,%ld miss eviction\n", currentTrace->op,
                           currentTrace->addr, currentTrace->size);
                }

                if (isDirty(c, setIndex)) {
                    stats->dirty_evictions += (1 << c->b);
                }

                updateCache(c, setIndex, tag);
                setDirty(c, setIndex, tag);

            } else {
                stats->misses++;

                if (verbose) {
                    printf("%c %llx,%ld miss\n", currentTrace->op,
                           currentTrace->addr, currentTrace->size);
                }

                updateCache(c, setIndex, tag);
                setDirty(c, setIndex, tag);
            }

            break;
        }
    }

    /* count the number of dirty bytes in the cache at the end of simulation */
    for (unsigned long long int i = 0; i < (1 << c->s); i++) {
        for (unsigned long long int j = 0; j < c->E; j++) {
            if (c->blocks[i][j].valid && c->blocks[i][j].dirty) {
                stats->dirty_bytes += (1 << c->b);
            }
        }
    }
}

int isHit(Cache *c, unsigned long long int setIndex,
          unsigned long long int tag) {
    for (unsigned long long int i = 0; i < c->E; i++) {
        if (c->blocks[setIndex][i].valid && c->blocks[setIndex][i].tag == tag) {
            return 1;
        }
    }

    return 0;
}

int isEviction(Cache *c, unsigned long long int setIndex) {
    for (unsigned long long int i = 0; i < c->E; i++) {
        if (!c->blocks[setIndex][i]
                 .valid) { // all the blocks in the set are full
            return 0;
        }
    }

    return 1;
}

int isDirty(Cache *c, unsigned long long int setIndex) {
    unsigned long long int lru = 0;
    unsigned long long int blockIndex = 0;

    for (unsigned long long int i = 0; i < c->E;
         i++) { // find the block with the largest LRU counter
        if (c->blocks[setIndex][i].lru > lru) {
            lru = c->blocks[setIndex][i].lru;
            blockIndex = i;
        }
    }

    return (int)c->blocks[setIndex][blockIndex].dirty;
}

void setDirty(Cache *c, unsigned long long int setIndex,
              unsigned long long int tag) {
    for (unsigned long long int i = 0; i < c->E; i++) {
        if (c->blocks[setIndex][i].valid && c->blocks[setIndex][i].tag == tag) {
            c->blocks[setIndex][i].dirty = 1;
        }
    }
}

void updateLRU(Cache *c, unsigned long long int setIndex,
               unsigned long long int tag) {
    unsigned long long int blockIndex = 0;

    for (unsigned long long int i = 0; i < c->E; i++) { // find the block index
        if (c->blocks[setIndex][i].valid && c->blocks[setIndex][i].tag == tag) {
            blockIndex = i;
            break;
        }
    }

    for (unsigned long long int i = 0; i < c->E; i++) {
        if (i != blockIndex) {
            c->blocks[setIndex][i].lru++;
        }
    }

    c->blocks[setIndex][blockIndex].lru =
        0; // reset the LRU counter of the changed block
}

void updateCache(Cache *c, unsigned long long int setIndex,
                 unsigned long long int tag) {
    unsigned long long int blockIndex = 0;
    int emptyTag = 0;

    for (unsigned long long int i = 0; i < c->E; i++) { // find the empty block
        if (!c->blocks[setIndex][i].valid) {
            blockIndex = i;
            emptyTag = 1;
            break; // break as soon as find an empty block
        }
    }

    if (!emptyTag) { // no empty block, use LRU replacement policy
        unsigned int maxLRU = 0;
        for (unsigned long long int i = 0; i < c->E; i++) {
            if (c->blocks[setIndex][i].lru > maxLRU) {
                maxLRU = c->blocks[setIndex][i].lru;
                blockIndex = i;
            }
        }
    }

    /* update the block */
    c->blocks[setIndex][blockIndex].valid = 1;
    c->blocks[setIndex][blockIndex].tag = tag;
    c->blocks[setIndex][blockIndex].dirty = 0;
    c->blocks[setIndex][blockIndex].lru = 0;

    /* increment the LRU counter of all the other blocks in the set */
    for (unsigned long long int i = 0; i < c->E; i++) {
        if (i != blockIndex) {
            c->blocks[setIndex][i].lru++;
        }
    }
}
