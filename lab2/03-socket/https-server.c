#include <errno.h>
#include <unistd.h>
#include <malloc.h>
#include <string.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <stdio.h>
#include <netinet/in.h>
#include <resolv.h>
#include <pthread.h>
#include "openssl/ssl.h"
#include "openssl/err.h"

typedef struct listen_hd {
	int port_num;
	SSL_CTX *ctx;
} listen_hd;


void* handle_https_request(void *arg) {
    SSL *ssl = (SSL*)arg;
	if (SSL_accept(ssl) == -1){
		perror("SSL_accept failed");
		exit(1);
	}

	char buf[1024] = {0};
	char response_buff[4096] = {0};
	int response_len = 0;
	int total_len;

    int bytes = SSL_read(ssl, buf, sizeof(buf));
	if (bytes < 0) {
		perror("SSL_read failed");
		exit(1);
	}
    
	char method[10], url[50], version[15];
	sscanf(buf, "%s %s %s\r\n", method, url, version);

	if (strcmp(method, "GET")) {
		perror("Not supported method!");
		exit(1);
	}

	FILE *fp = fopen(url + 1, "r");
	char message[40] = {0};
	
	// If this file does not exist, return 404.
	if (fp == NULL) {
		strcat(message, "404 Not Found");
		response_len = sprintf(response_buff, "%s %s\r\n", version, message);
		SSL_write(ssl, response_buff, strlen(response_buff));
		int sock = SSL_get_fd(ssl);
    	SSL_free(ssl);
    	close(sock);
		return 0;
	}

	// Check if have range, if have, return 206, else return 200.
	char *range_ptr = strstr(buf, "Range:");
	int range_begin, range_end, range_flag, end_flag = 0;

	if (range_ptr != NULL) {
		int success_trans_num = sscanf(range_ptr, "Range: bytes=%d-%d\r\n", &range_begin, &range_end);
		// Deal with 100- like this.
		if (success_trans_num != 2) {
			range_end = -1;
		}
		strcat(message, "206 Partial Content");
		range_flag = 1;
		total_len = range_begin;
	} else {
		strcat(message, "200 OK");
		range_flag = 0;
	}

	response_len += sprintf(response_buff, "%s %s\r\n", version, message);
	response_len += sprintf(response_buff + response_len, "Transfer-Encoding: chunked\r\n\r\n");
	SSL_write(ssl, response_buff, response_len);

	if (!range_flag) {
		while(!end_flag) {
			response_len = 0;
			char temp_buf[4000] = {0};
			memset(response_buff, 0, sizeof(response_buff));

			char ch;
			while (response_len < 4000 && (ch = fgetc(fp)) != EOF) {
				temp_buf[response_len++] = ch;	
			}
			
			sprintf(response_buff, "%x\r\n%s\r\n", response_len, temp_buf);
			
			SSL_write(ssl, response_buff, response_len + 7);

			if (ch == EOF) {
				end_flag = 1;
			}
		}
	} else if (range_flag && !end_flag) {
		response_len = 0;
		
		char ch;
		
		fseek(fp, range_begin, SEEK_SET);
		if (range_end == -1) {
			while(!end_flag) {
				response_len = 0;
				char temp_buf[4000] = {0};
				memset(response_buff, 0, sizeof(response_buff));

				char ch;
				while (response_len < 4000 && (ch = fgetc(fp)) != EOF) {
					temp_buf[response_len++] = ch;	
				}
				
				sprintf(response_buff, "%x\r\n%s\r\n", response_len, temp_buf);
				
				SSL_write(ssl, response_buff, response_len + 7);

				if (ch == EOF) {
					end_flag = 1;
				}
			}
		} else {
			while(!end_flag) {
				char temp_buf[4000] = {0};
				memset(response_buff, 0, sizeof(response_buff));
				
				while (response_len < 4000 && ((ch = fgetc(fp)) != EOF) && total_len <= range_end) {
					temp_buf[response_len++] = ch;
					total_len++;
				}
				sprintf(response_buff, "%x\r\n%s\r\n", response_len, temp_buf);
				
				SSL_write(ssl, response_buff, strlen(response_buff));	
				if (ch == EOF || total_len > range_end) {
					end_flag = 1;
				}
			}
		}
	}

	memset(response_buff, 0, sizeof(response_buff));
	response_buff[0] = '0';
	response_buff[1] = '\r';
	response_buff[2] = '\n';
	response_buff[3] = '\r';
	response_buff[4] = '\n';
	// ("%s\n", response_buff);
	SSL_write(ssl, response_buff, 5);


	int sock = SSL_get_fd(ssl);
    SSL_free(ssl);
    close(sock);
    return 0;	
}


/* This function aims to deal with the http
 * request from port 80.
 */
void* handle_http_request(void *sockfd) {
	char buf[1024] = {0};
	int csock = *(int*)sockfd;
	int bytes = recv(csock, buf, sizeof(buf), 0);
	if (bytes < 0) {
		perror("HTTP connection failed");
		exit(1);
	}

	char method[10], url[50], version[15], host_name[30];
	sscanf(buf, "%s %s %s\r\n", method, url, version);

	if (strcmp(method, "GET")) {
		perror("Not supported method!");
		exit(1);
	}

	char *host_pos = strstr(buf, "Host:");
	sscanf(host_pos, "Host: %s\r\n", host_name);

	const char *msg = "301 Moved Permanently";
	char location[100];
	strcat(location, "https://");
	strcat(location, host_name);
	strcat(location, url);

	char send_buf[1024] = {0};
	sprintf(send_buf, "%s %s\r\nLocation: %s\r\n", version, msg, location);

	send(csock, send_buf, sizeof(send_buf), 0);
	close(csock);
	return 0;
}


/* This func aims to create a listening port for port
 * 443 and port 80. Port 443 uses https protocol and
 * port 80 uses http protocol.
 */
void* listen_port(void *arg) {
	// Get the arg's domain.
	listen_hd *fd = (listen_hd*)arg;
	int port_num = fd -> port_num;
	SSL_CTX *ctx = fd -> ctx;

	// Initialize the socket, get the handle sock.
	int sock = socket(AF_INET, SOCK_STREAM, 0);
	if (sock < 0) {
		perror("Opening socket failed");
		exit(1);
	}
	int enable = 1;
	if (setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &enable, sizeof(int)) < 0) {
		perror("setsockopt(SO_REUSEADDR) failed");
		exit(1);
	}

	struct sockaddr_in addr;
	bzero(&addr, sizeof(addr));
	addr.sin_family = AF_INET;
	addr.sin_addr.s_addr = INADDR_ANY;
	addr.sin_port = htons(port_num);

	if (bind(sock, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
		perror("Bind failed.");
		exit(1);
	}

	listen(sock, 10);

	while(1) {
		struct sockaddr_in caddr;
		socklen_t len;
		int csock = accept(sock, (struct sockaddr*)&caddr, &len);
		
		if (csock < 0) {
			perror("Accept failed");
			exit(1);
		}

		pthread_t client;
		if (port_num == 443) {
			SSL *ssl = SSL_new(ctx); 
			SSL_set_fd(ssl, csock);
			pthread_create(&client, NULL, handle_https_request, (void*)ssl);
			pthread_join(client, NULL);
		} else {
			pthread_create(&client, NULL, handle_http_request, (void*)&csock);
			pthread_join(client, NULL);
		}
	}
	close(sock);
}


int main() {
	// init SSL Library
	SSL_library_init();
	OpenSSL_add_all_algorithms();
	SSL_load_error_strings();
    
	// enable TLS method
	const SSL_METHOD *method = TLS_server_method();
	SSL_CTX *ctx = SSL_CTX_new(method);
    
	// load certificate and private key
	if (SSL_CTX_use_certificate_file(ctx, "./keys/cnlab.cert", SSL_FILETYPE_PEM) <= 0) {
		perror("load cert failed");
		exit(1);
	}

	if (SSL_CTX_use_PrivateKey_file(ctx, "./keys/cnlab.prikey", SSL_FILETYPE_PEM) <= 0) {
		perror("load prikey failed");
		exit(1);
	}

	// Create 2 threads to listen to 2 ports.
	pthread_t listen1, listen2;
	listen_hd p443, p80;

	p443.port_num = 443;
	p443.ctx = ctx;
	p80.port_num = 80;
	p80.ctx = NULL;

	int ret1 = pthread_create(&listen1, NULL, listen_port, (void*)&p443);
	int ret2 = pthread_create(&listen2, NULL, listen_port, (void*)&p80);

	if (ret1 || ret2) {
		perror("Creating new threads failed.");
		exit(1);
	}

	pthread_join(listen1, NULL);
	pthread_join(listen2, NULL);
	SSL_CTX_free(ctx);
}
