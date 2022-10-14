#include "tree.h"
#include <stdio.h>
#include <stdlib.h>

TrieNode *trie;
SuperTrieNode *superTrie;


// Convert the ip to uint32_t
static inline uint32_t convert_ip_to_uint(char *cip) {
    unsigned int a, b, c, d;
    sscanf(cip, "%u.%u.%u.%u", &a, &b, &c, &d);
    uint32_t res = (a << 24) | (b << 16) | (c << 8) | d;
    return res;
}   



// Get the bits from start to end (inclusive)
static inline uint32_t get_bit(uint32_t uip, int pos) {
    uint32_t res = (uip & (1 << pos))? 1 : 0;
    return res;
}

// Get the prefix from an unsigned int (inclusive)
static inline uint32_t get_prefix(uint32_t uip, int prefix) {
    uint32_t mask = (uint32_t)(~(0xFFFFFFFF >> prefix));
    return uip & mask;
}

// return an array of ip represented by an unsigned integer, size is TEST_SIZE
uint32_t* read_test_data(const char* lookup_file) {
    FILE *fp = fopen(lookup_file, "r");
    uint32_t *res = (uint32_t*)malloc(sizeof(uint32_t)*(TEST_SIZE+10));

    int cnt = 0;
    while (!feof(fp)) {
        char sip[30];
        fscanf(fp, "%s", sip);
        res[cnt++] = convert_ip_to_uint(sip);
    }
    return res;
}

// Init a Trie tree
TrieNode* trie_init() {
    TrieNode *root = (TrieNode*)malloc(sizeof(TrieNode));
    root -> ip = 0;
    root -> port = 0;
    root -> prefix = 0;
    root -> has = 0;

    root -> children[0] = root -> children[1] = NULL;
    return root;
}

// Insert a node in Trie tree
void insert_node(TrieNode *root, uint32_t ip, int port, int prefix) {
    TrieNode *pos = root, *next;
    int curr_bit;
    while (pos && pos -> prefix < prefix) {
        curr_bit = get_bit(ip, 31 - pos -> prefix);
        next = pos -> children[curr_bit];
        // If the children node's space has not been allocated.
        if (next == NULL) {
            next = (TrieNode*)malloc(sizeof(TrieNode));
            next -> ip = get_prefix(ip, pos -> prefix + 1);
            next -> port = 0;
            next -> prefix = pos -> prefix + 1;
            next -> has = 0;
            next -> children[0] = next -> children[1] = NULL;
            
            pos -> children[curr_bit] = next;
        }
        pos = next;
    }

    if (pos != NULL) {
        pos -> port = port;
        pos -> has = 1;
    }
}

uint32_t find_ip(TrieNode *root, uint32_t ip) {
    TrieNode *match = NULL;
    TrieNode *curr = root;

    while(curr) {
        if (curr -> has && curr -> ip == get_prefix(ip, curr -> prefix)) {
            match = curr;
        }
        curr = curr -> children[get_bit(ip, 31 - curr -> prefix)];
    }

    return match? match -> port : -1;
}

// Constructing a trie-tree to lookup according to `forward_file`
void create_tree(const char* forward_file) {
    FILE *fp = fopen(forward_file, "r");
    if (fp == NULL) {
        perror("Open source file fails");
        exit(1);
    }

    trie = trie_init();
    char sip[30];
    int prefix, port_num;

    while (!feof(fp)) {
        fscanf(fp, "%s %d %d", sip, &prefix, &port_num);
        uint32_t uip = convert_ip_to_uint(sip);
        insert_node(trie, uip, port_num, prefix);
    }
}


// Look up the ports of ip in file `lookup_file` using the basic tree
uint32_t *lookup_tree(uint32_t* ip_vec) {
    uint32_t *res = (uint32_t*)malloc((TEST_SIZE+1)*sizeof(uint32_t));
    for (int i = 0; i < TEST_SIZE; i++) {
        uint32_t ip = ip_vec[i];
        res[i] = find_ip(trie, ip);
    }
    return res;
}

/* ---------------------------------OPTREE-------------------------- */


// Init a super root
SuperTrieNode* superTrie_init() {
    SuperTrieNode *superTrie = (SuperTrieNode*)malloc(sizeof(SuperTrieNode));
    for (int i = 0; i < 65536; i++) {
        superTrie -> children[i] = (TrieNodeOpt*)malloc(sizeof(TrieNodeOpt));
        superTrie -> children[i] -> prefix = 16;
        superTrie -> children[i] -> ip = i << 16;
        superTrie -> children[i] -> has = 0;
        superTrie -> children[i] -> port = 0;
        superTrie -> children[i] -> is_odd = 0;
        for (int j = 0; j < 4; j++) {
            superTrie -> children[i] -> children[j] = NULL;
        }
    }
    return superTrie;
}

// Compress the tree into 2 bit
void compress_tree(TrieNodeOpt *root, uint32_t ip, int port, int prefix) {
    TrieNodeOpt *pos = root, *next;
    int ori_prefix = root -> prefix;
    pos -> prefix = 16;
    int curr_bit1, curr_bit2;
    while (pos && pos -> prefix < prefix - 1) {
        curr_bit1 = get_bit(ip, 31 - pos -> prefix);
        curr_bit2 = get_bit(ip, 30 - pos -> prefix);
        next = pos -> children[(curr_bit1 << 1) | curr_bit2];
        // If the children node's space has not been allocated.
        if (next == NULL || (next -> is_odd == 1 && next -> prefix == prefix)) {
            next = (TrieNodeOpt*)malloc(sizeof(TrieNodeOpt));
            next -> ip = get_prefix(ip, pos -> prefix + 2);
            next -> port = 0;
            next -> prefix = pos -> prefix + 2;
            next -> has = 0;
            next -> children[0] = next -> children[1] = NULL;
            next -> children[2] = next -> children[3] = NULL;
            next -> is_odd = 0;
            pos -> children[(curr_bit1 << 1) | curr_bit2] = next;
        }
        pos = next;
    }

    if (pos -> prefix == prefix - 1) {
        TrieNodeOpt *next1, *next2;
        curr_bit1 = get_bit(ip, 31 - pos -> prefix);
        next1 = pos -> children[curr_bit1 << 1];
        if (next1 == NULL) {
            next1 = (TrieNodeOpt*)malloc(sizeof(TrieNodeOpt));
            next1 -> ip = get_prefix(ip, pos -> prefix + 1);
            next1 -> port = port;
            next1 -> prefix = pos -> prefix + 2;
            next1 -> has = 1;
            next1 -> children[0] = next1 -> children[1] = NULL;
            next1 -> children[2] = next1 -> children[3] = NULL;
            next1 -> is_odd = 1;
            pos -> children[curr_bit1 << 1] = next1;
        }

        next2 = pos -> children[(curr_bit1 << 1) | 0x1];
        if (next2 == NULL) {
            next2 = (TrieNodeOpt*)malloc(sizeof(TrieNodeOpt));
            next2 -> ip = get_prefix(ip, pos -> prefix + 1);
            next2 -> port = port;
            next2 -> prefix = pos -> prefix + 2;
            next2 -> has = 1;
            next2 -> children[0] = next2 -> children[1] = NULL;
            next2 -> children[2] = next2 -> children[3] = NULL;
            next2 -> is_odd = 1;
            pos -> children[curr_bit1 << 1 | 0x1] = next2;
        }
        pos = NULL;
    }
    

    if (pos != NULL) {
        pos -> port = port;
        pos -> has = 1;
    }
    root -> prefix = ori_prefix;
}


static inline uint32_t advanced_find_ip(TrieNodeOpt *root, uint32_t ip) {
    TrieNodeOpt *match = NULL;
    TrieNodeOpt *curr = root;

    int curr_bit;

    if (curr -> prefix < 16) {
        if (curr -> has && curr -> ip == get_prefix(ip, curr -> prefix - curr -> is_odd)) {
            match = curr;
        }
        curr_bit = (unsigned int)(ip & (0x3 << 14)) >> 14;
        curr = curr -> children[curr_bit];
    }

    while(curr) {
        if (curr -> has && curr -> ip == get_prefix(ip, curr -> prefix - curr -> is_odd)) {
            match = curr;
        }
        int off = 30 - curr -> prefix;
        curr_bit = (unsigned int)(ip & (0x3 << off)) >> off;
        curr = curr -> children[curr_bit];
    }

    return match? match -> port : -1;

}


// Constructing an advanced trie-tree to lookup according to `forwardingtable_filename`
void create_tree_advance(const char* forward_file) {
   FILE *fp = fopen(forward_file, "r");
    if (fp == NULL) {
        perror("Open source file fails");
        exit(1);
    }

    // trieOpt = trieOpt_init();
    superTrie = superTrie_init();
    char sip[30];
    int prefix, port_num;
    while (!feof(fp)) {
        fscanf(fp, "%s %d %d", sip, &prefix, &port_num);
        uint32_t uip = convert_ip_to_uint(sip);
        if (prefix >= 16) {
            TrieNodeOpt *root = superTrie -> children[(unsigned int)(0xffff0000 & uip) >> 16];
            compress_tree(root, uip, port_num, prefix);
        } else {
            uint32_t start = (get_prefix(uip, prefix)) >> 16;
            uint32_t end = start + (1 << (16 - prefix));
            for (int i = start; i < end; i++) {
                if (!superTrie -> children[i] -> has || !(superTrie -> children[i] -> prefix > prefix)) {
                    superTrie -> children[i] -> ip = get_prefix(uip, prefix);
                    superTrie -> children[i] -> prefix = prefix;
                    superTrie -> children[i] -> has = 1;
                    superTrie -> children[i] -> port = port_num;
                    superTrie -> children[i] -> is_odd = 0;
                }
            }
        }
    }


}

// Look up the ports of ip in file `lookup_file` using the advanced tree
uint32_t *lookup_tree_advance(uint32_t* ip_vec) {
    uint32_t *res = (uint32_t*)malloc((TEST_SIZE+1)*sizeof(uint32_t));
    for (int i = 0; i < TEST_SIZE; i++) {
        uint32_t ip = ip_vec[i];
        TrieNodeOpt *find_root = superTrie -> children[(unsigned int)(0xffff0000 & ip) >> 16];
        res[i] = advanced_find_ip(find_root, ip);
    }
    return res;
}
