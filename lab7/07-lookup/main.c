#include <stdio.h>
#include <sys/time.h>
#include <stdlib.h>
#include "util.h"
#include "tree.h"

const char* compare_filename = "compare_file.txt";
const char* lookup_filename  = "lookup_file.txt";
const char* forwardingtable_filename = "forwarding-table.txt";


bool check_result(uint32_t* port_vec);

int main(void){
    struct timeval tv_start, tv_end;
    uint32_t* res1, *res2;
    
    printf("========reading data from lookup_file========\n");
    uint32_t* ip_vec = read_test_data(lookup_filename);


    printf("========Constructing the basic tree========\n");
    create_tree(forwardingtable_filename);

    // lookup and compute the interval
    printf("==========Looking up the port============\n");
    gettimeofday(&tv_start,NULL);
    res1 = lookup_tree(ip_vec);
    gettimeofday(&tv_end,NULL);

    int basic_pass      = check_result(res1);
    long basic_interval = get_interval(tv_start,tv_end);



    printf("========Constructing the advanced tree========\n");
    create_tree_advance(forwardingtable_filename);
    
    // lookup and compute the interval
    printf("==========Looking up the port============\n");
    gettimeofday(&tv_start,NULL);
    res2 = lookup_tree_advance(ip_vec);
    gettimeofday(&tv_end,NULL);

    int advance_pass      = check_result(res2);
    long advance_interval = get_interval(tv_start,tv_end);
    
    printf("=============dump result============\n");
    printf("basic_pass:%d\nbasic_total_lookup_time:%ldus\nadvance_pass:%d\nadvance_total_lookup_time:%ldus\n",basic_pass,basic_interval,advance_pass,advance_interval);
    return 0;
}

bool check_result(uint32_t* port_vec){
    int port;
    FILE* fp = fopen(compare_filename,"r");

    if(NULL == fp){
        perror("Open compare file fails");
        exit(1);
    }

    for(int i = 0;i < TEST_SIZE;i++){
        fscanf(fp,"%d",&port);
        if(port != port_vec[i]){
            fclose(fp);
            return false;
        }
    }
    fclose(fp);

    return true;
}
