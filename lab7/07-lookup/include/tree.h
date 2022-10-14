#ifndef __TREE_H__
#define __TREE_H__

#include <stdint.h>
#include <stdio.h>
#include <unistd.h>

// do not change it
#define TEST_SIZE 100000


void create_tree(const char*);
uint32_t *lookup_tree(uint32_t *);
void create_tree_advance();
uint32_t *lookup_tree_advance(uint32_t *);

uint32_t* read_test_data(const char* lookup_file);

typedef struct TrieNode {
    struct TrieNode *children[2];
    // Node infos
    uint32_t ip;
    uint32_t prefix;
    int has;
    int port;
}TrieNode;

typedef struct TrieNodeOpt {
    struct TrieNodeOpt *children[4];
    // Node infos
    uint32_t ip;
    uint32_t prefix;
    int has;
    int port;
    int is_odd;
}TrieNodeOpt;

typedef struct SuperTrieNode {
    struct TrieNodeOpt *children[65536];
}SuperTrieNode;

#endif
