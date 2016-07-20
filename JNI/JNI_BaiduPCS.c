#include "JNI_BaiduPCS.h"
#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <ctype.h>
#include <string.h>
#include <assert.h>
#include <time.h>
#include <locale.h>
#ifdef WIN32
# include <conio.h>
# include <direct.h>
# include <WinSock2.h>
# include <Windows.h>
# include "pcs/openssl_aes.h"
# include "pcs/openssl_md5.h"
#else
# include <unistd.h>
# include <termios.h>
# include <pthread.h>
# include <openssl/aes.h>
# include <openssl/md5.h>
#endif

#include "pcs/pcs_mem.h"
#include "pcs/cJSON.h"
#include "pcs/pcs_utils.h"
#include "pcs/pcs.h"
#include "rb_tree/red_black_tree.h"
#include "version.h"
#include "dir.h"
#include "utils.h"
#include "arg.h"

#include "MQTTClient.h"
#define P_ADDRESS     "tcp://localhost:1883"
#define P_CLIENTID    "ExampleClientPub"
#define P_QOS         0
#define P_TIMEOUT     1000L

MQTTClient client;

#ifdef WIN32
# include "utf8.h"
# define lseek _lseek
# define fileno _fileno
# define fseeko _fseeki64
# define ftello _ftelli64
#endif
#define PRINT_PAGE_SIZE			20		/*列出目录或列出比较结果时，分页大小*/
#define OP_NONE					0
#define OP_EQ					1		/*文件相同*/
#define OP_LEFT					2		/*文件应更新到左边*/
#define OP_RIGHT				4		/*文件应更新到右边*/
#define OP_CONFUSE				8		/*困惑，不知道如何更新*/

#define OP_ST_NONE				0
#define OP_ST_SUCC				1		/*操作成功*/
#define OP_ST_FAIL				2		/*操作失败*/
#define OP_ST_SKIP				4		/*跳过本操作*/
#define OP_ST_CONFUSE			8		/*困惑操作*/
#define OP_ST_PROCESSING		16		/*正在执行操作*/

#define FLAG_NONE				0
#define FLAG_ON_LOCAL			1
#define FLAG_ON_REMOTE			2
#define FLAG_PARENT_NOT_ON_REMOTE 4

#define THREAD_STATE_MAGIC			(((int)'T' << 24) | ((int)'S' << 16) | ((int)'H' << 8) | ((int)'T'))

#define DOWNLOAD_STATUS_OK				0
#define DOWNLOAD_STATUS_PENDDING		1
#define DOWNLOAD_STATUS_WRITE_FILE_FAIL	2
#define DOWNLOAD_STATUS_FAIL			3
#define DOWNLOAD_STATUS_DOWNLOADING		4

#define UPLOAD_STATUS_OK				0
#define UPLOAD_STATUS_PENDDING			1
#define UPLOAD_STATUS_WRITE_FILE_FAIL	2
#define UPLOAD_STATUS_FAIL				3
#define UPLOAD_STATUS_UPLOADING			4
#define USAGE "Mozilla/5.0 (Windows NT 6.3; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/35.0.1916.153 Safari/537.36"
#define TIMEOUT						60
#define CONNECTTIMEOUT				10
#define MAX_THREAD_NUM				100
#define MIN_SLICE_SIZE				(512 * 1024) /*最小分片大小*/
#define MAX_SLICE_SIZE				(10 * 1024 * 1024) /*最大分片大小*/
#define MAX_FFLUSH_SIZE				(10 * 1024 * 1024) /*最大缓存大小*/
#define MIN_UPLOAD_SLICE_SIZE		(512 * 1024) /*最小分片大小*/
#define MAX_UPLOAD_SLICE_SIZE		(10 * 1024 * 1024) /*最大分片大小*/
#define MAX_UPLOAD_SLICE_COUNT		1024
#define PCS_CONTEXT_ENV				"PCS_CONTEXT"
#define PCS_COOKIE_ENV				"PCS_COOKIE"
#define PCS_CAPTCHA_ENV				"PCS_CAPTCHA"
#define SLICE_FILE_SUFFIX			".slice"
ShellContext context = { 0 };
jclass callbackClass = NULL;
char *app_name;
char *jobid;

#define convert_to_real_speed(speed) ((speed) * 1024)
#define sleep(s) Sleep((s) * 1000)
void sendMessageviaMqtt(char* mbsString, char errLevel);

struct UploadThreadState;
struct UploadState {
	FILE *pf;
	char *path;
	char *slice_file;
	int64_t uploaded_size; /*已经下载的字节数*/
	time_t time; /*最后一次在屏幕打印信息的时间*/
	size_t speed; /*用于统计下载速度*/
	int64_t file_size; /*完整的文件的字节大小*/
	ShellContext *context;
	void *mutex;
	int	num_of_running_thread; /*已经启动的线程数量*/
	int num_of_slice; /*分片数量*/
	char **pErrMsg;
	int	status;
	struct UploadThreadState *threads;
};

struct UploadThreadState {
	struct UploadState *us;
	curl_off_t	start;
	curl_off_t	end;
	int		status;
	size_t  uploaded_size;
	Pcs		*pcs;
	char	md5[33]; /*上传成功后的分片MD5值*/
	int		tid;
	struct UploadThreadState *next;
};

int Base64Encode(const unsigned char* buffer, size_t length, char** b64text) { //Encodes a binary safe base 64 string
	BIO *bio, *b64;
	BUF_MEM *bufferPtr;

	b64 = BIO_new(BIO_f_base64());
	bio = BIO_new(BIO_s_mem());
	bio = BIO_push(b64, bio);

	BIO_set_flags(bio, BIO_FLAGS_BASE64_NO_NL); //Ignore newlines - write everything in one line
	BIO_write(bio, buffer, length);
	BIO_flush(bio);
	BIO_get_mem_ptr(bio, &bufferPtr);
	BIO_set_close(bio, BIO_NOCLOSE);
	*b64text = (char*)malloc((bufferPtr->length + 1) * sizeof(char));
	memcpy(*b64text, bufferPtr->data, bufferPtr->length);
	(*b64text)[bufferPtr->length] = '\0';
	BIO_free_all(bio);

	//*b64text = (*bufferPtr).data;

	return (0); //success
}

/*输出验证码图片，并等待用户输入识别结果*/
static PcsBool verifycode(unsigned char *ptr, size_t size, char *captcha, size_t captchaSize, void *state)
{
	//static char filename[1024] = { 0 };
	ShellContext *context = (ShellContext *)state;
	/*const char *savedfile;
	FILE *pf;

	if (!filename[0]) {
	#ifdef WIN32
	strcpy(filename, getenv("UserProfile"));
	strcat(filename, "\\.pcs");
	CreateDirectoryRecursive(filename);
	strcat(filename, "\\vc.gif");
	#else
	strcpy(filename, getenv("HOME"));
	strcat(filename, "/.pcs");
	CreateDirectoryRecursive(filename);
	strcat(filename, "/vc.gif");
	#endif
	}

	if (context->captchafile)
	savedfile = context->captchafile;
	else
	savedfile = filename;

	pf = fopen(savedfile, "wb");
	if (!pf) {
	printf("Can't save the captcha image to %s.\n", savedfile);
	return PcsFalse;
	}
	fwrite(ptr, 1, size, pf);
	fclose(pf);

	printf("The captcha image at %s.\nPlease input the captcha code: ", savedfile);
	std_string(captcha, captchaSize);
	return PcsTrue;
	*/
	char* base64EncodeOutput;

	Base64Encode(ptr, size, &base64EncodeOutput);
	sendMessageviaMqtt(base64EncodeOutput, 'c');
	return PcsFalse;
	//return PcsTrue;
}

/*显示上传进度*/
static int upload_progress(void *clientp, double dltotal, double dlnow, double ultotal, double ulnow)
{
	char *path = (char *)clientp;
	static char tmp[64];
	char tmpcat[1000] = "Progress:";
	tmp[63] = '\0';
	/*if (path)
		printf("Upload %s ", path);
	printf("%s", pcs_utils_readable_size(ulnow, tmp, 63, NULL));
	printf("/%s      \r", pcs_utils_readable_size(ultotal, tmp, 63, NULL));
	fflush(stdout);
	*/
	if (path) {
		strcat(tmpcat, "Upload ");
		strcat(tmpcat, path);
		strcat(tmpcat, " ");
	}
	strcat(tmpcat, pcs_utils_readable_size(ulnow, tmp, 63, NULL));
	strcat(tmpcat, "/");
	strcat(tmpcat, pcs_utils_readable_size(ultotal, tmp, 63, NULL));
	sendMessageviaMqtt(tmpcat,'s');
	return 0;
}

/*初始化PCS*/
static Pcs *create_pcs(ShellContext *context)
{
	Pcs *pcs = pcs_create(context->cookiefile);
	if (!pcs) return NULL;
	pcs_setopt(pcs, PCS_OPTION_CAPTCHA_FUNCTION, (void *)&verifycode);
	pcs_setopt(pcs, PCS_OPTION_CAPTCHA_FUNCTION_DATA, (void *)context);
	pcs_setopts(pcs,
		PCS_OPTION_PROGRESS_FUNCTION, (void *)&upload_progress,
		PCS_OPTION_PROGRESS, (void *)((long)PcsFalse),
		PCS_OPTION_USAGE, (void *)USAGE,
		//PCS_OPTION_TIMEOUT, (void *)((long)TIMEOUT),
		PCS_OPTION_CONNECTTIMEOUT, (void *)((long)CONNECTTIMEOUT),
		PCS_OPTION_END);
	return pcs;
}

static void destroy_pcs(Pcs *pcs)
{
	pcs_destroy(pcs);
}


/*多字节字符转换成UTF-8编码*/
int u8_mbs_toutf8(char *dest, int sz, const char *src, int srcsz)
{
	wchar_t *unicode;
	int wchars, err;

	wchars = MultiByteToWideChar(CP_ACP, MB_PRECOMPOSED, src, srcsz, NULL, 0);
	if (wchars == 0) {
		fprintf(stderr, "Unicode translation error %d\n", GetLastError());
		return -1;
	}

	unicode = (wchar_t *)alloca((wchars + 1) * sizeof(unsigned short));
	err = MultiByteToWideChar(CP_ACP, MB_PRECOMPOSED, src, srcsz, unicode, wchars);
	if (err != wchars) {
		fprintf(stderr, "Unicode translation error %d\n", GetLastError());
		return -1;
	}
	unicode[wchars] = L'\0';
	return u8_toutf8(dest, sz, unicode, wchars);
}

int u8_mbs_toutf8_size(const char *src, int srcsz)
{
	wchar_t *unicode;
	int wchars, err;

	wchars = MultiByteToWideChar(CP_ACP, MB_PRECOMPOSED, src, srcsz, NULL, 0);
	if (wchars == 0) {
		fprintf(stderr, "Unicode translation error %d\n", GetLastError());
		return -1;
	}

	unicode = (wchar_t *)alloca((wchars + 1) * sizeof(unsigned short));
	err = MultiByteToWideChar(CP_ACP, MB_PRECOMPOSED, src, srcsz, unicode, wchars);
	if (err != wchars) {
		fprintf(stderr, "Unicode translation error %d\n", GetLastError());
		return -1;
	}
	unicode[wchars] = L'\0';
	//wprintf(L"UNICODE: %ls\n", unicode);
	return u8_size(unicode, wchars);
}

int u8_tombs(char *dest, int sz, const char *src, int srcsz)
{
	int unicode_size;
	wchar_t *unicode;
	//int unicode_len;
	int /*chars,*/ err;

	unicode_size = u8_wc_size(src, srcsz);
	unicode = (wchar_t *)alloca((unicode_size + 1) * sizeof(unsigned short));
	unicode[unicode_size] = L'\0';
	u8_toucs(unicode, unicode_size, src, srcsz);

	err = WideCharToMultiByte(GetConsoleCP(), WC_COMPOSITECHECK, unicode, unicode_size, dest, sz, NULL, NULL);
	if (err < 1)
	{
		fprintf(stderr, "Unicode translation error %d\n", GetLastError());
		return -1;
	}

	return err;
}

int u8_tombs_size(const char *src, int srcsz)
{
	int unicode_size;
	wchar_t *unicode;
	//int unicode_len;
	int /*chars,*/ err;

	unicode_size = u8_wc_size(src, srcsz);
	unicode = (wchar_t *)alloca((unicode_size + 1) * sizeof(unsigned short));
	unicode[unicode_size] = L'\0';
	u8_toucs(unicode, unicode_size, src, srcsz);

	err = WideCharToMultiByte(GetConsoleCP(), WC_COMPOSITECHECK, unicode, unicode_size, NULL, 0, NULL, NULL);
	return err;
}

char *mbs2utf8(const char *s)
{
	int sl = strlen(s);
	int sz = u8_mbs_toutf8_size(s, sl);
	char *res = 0;
	res = (char *)pcs_malloc(sz + 1);
	if (!res)
		return 0;
	memset(res, 0, sz + 1);
	u8_mbs_toutf8(res, sz, s, sl);
	return res;
}

char *utf82mbs(const char *s)
{
	int sl = strlen(s);
	int sz = u8_tombs_size(s, sl);
	char *res = 0;
	res = (char *)pcs_malloc(sz + 1);
	if (!res)
		return 0;
	memset(res, 0, sz + 1);
	u8_tombs(res, sz, s, sl);
	return res;
}

void sendMessageviaMqtt(char* mbsString, char errLevel) {
	char topic[100] = { 0 };
	char errorlevel[2] = { 0 };
	char* payload;
	sprintf(topic,"uploaderBroadcast/%s/", app_name);
	sprintf(errorlevel, "%c", errLevel);
	cJSON *root;
	root = cJSON_CreateObject();
	cJSON_AddItemToObject(root, "uploader_id", cJSON_CreateString(app_name));
	cJSON_AddItemToObject(root, "job_id", cJSON_CreateString(jobid));
	cJSON_AddItemToObject(root, "err_level", cJSON_CreateString(errorlevel));
	cJSON_AddItemToObject(root, "msg", cJSON_CreateString(mbsString));
	payload = cJSON_Print(root);	cJSON_Delete(root);

	MQTTClient_message pubmsg = MQTTClient_message_initializer;
	pubmsg.payload = payload;
	pubmsg.payloadlen = strlen(payload);
	pubmsg.qos = P_QOS;
	pubmsg.retained = 0;
	MQTTClient_publishMessage(client, topic, &pubmsg, NULL);
}

static void init_upload_state(struct UploadState *us)
{
	memset(us, 0, sizeof(struct UploadState));
#ifdef _WIN32
	us->mutex = CreateMutex(NULL, FALSE, NULL);
#else
	us->mutex = (pthread_mutex_t *)pcs_malloc(sizeof(pthread_mutex_t));
	pthread_mutex_init((pthread_mutex_t *)us->mutex, NULL);
#endif
}

static void uninit_upload_state(struct UploadState *us)
{
	struct UploadThreadState *ts = us->threads, *ps = NULL;
#ifdef _WIN32
	CloseHandle(us->mutex);
#else
	pthread_mutex_destroy((pthread_mutex_t *)us->mutex);
	pcs_free(us->mutex);
#endif
	while (ts) {
		ps = ts;
		ts = ts->next;
		pcs_free(ps);
	}
}

static void lock_for_upload(struct UploadState *us)
{
#ifdef _WIN32
	WaitForSingleObject(us->mutex, INFINITE);
#else
	pthread_mutex_lock((pthread_mutex_t *)us->mutex);
#endif
}

static void unlock_for_upload(struct UploadState *us)
{
#ifdef _WIN32
	ReleaseMutex(us->mutex);
#else
	pthread_mutex_unlock((pthread_mutex_t *)us->mutex);
#endif
}

static int restore_upload_state(struct UploadState *us, const char *slice_local_path, int *pendding_count)
{
	LocalFileInfo *tmpFileInfo;
	int64_t slice_file_size = 0;
	FILE *pf;
	int magic;
	int thread_count = 0;
	struct UploadThreadState *ts, *tail = NULL;

	tmpFileInfo = GetLocalFileInfo(slice_local_path);
	if (!tmpFileInfo) {
		return -1;
	}
	slice_file_size = tmpFileInfo->size;
	DestroyLocalFileInfo(tmpFileInfo);

	pf = fopen(slice_local_path, "rb");
	if (!pf) return -1;
	if (fread(&magic, 4, 1, pf) != 1) {
		fclose(pf);
		return -1;
	}
	if (magic != THREAD_STATE_MAGIC) {
		fclose(pf);
		return -1;
	}
	if (pendding_count) (*pendding_count) = 0;
	us->uploaded_size = 0;
	while (1) {
		ts = (struct UploadThreadState *) pcs_malloc(sizeof(struct UploadThreadState));
		if (fread(ts, sizeof(struct UploadThreadState), 1, pf) != 1) {
			pcs_free(ts);
			break;
		}
		ts->us = us;
		//printf("%d: ", thread_count);
		if (ts->status != UPLOAD_STATUS_OK) {
			ts->status = UPLOAD_STATUS_PENDDING;
			if (pendding_count) (*pendding_count)++;
			ts->uploaded_size = 0;
			//printf("*");
		}
		us->uploaded_size += ts->uploaded_size;
		//printf("%d/%d\n", (int)ts->start, (int)ts->end);
		if (tail == NULL) {
			us->threads = tail = ts;
		}
		else {
			tail->next = ts;
			tail = ts;
		}
		thread_count++;
		ts->tid = thread_count;
		if (!ts->next) {
			ts->next = NULL;
			break;
		}
		ts->next = NULL;
	}
	fclose(pf);
	us->num_of_slice = thread_count;
	return 0;
}


static int save_upload_thread_states_to_file(const char *filename, struct UploadThreadState *state_link)
{
	static int magic = THREAD_STATE_MAGIC;
	FILE *pf;
	int rc;
	struct UploadThreadState *pts;
	pf = fopen(filename, "wb");
	if (!pf) return -1;
	rc = fwrite(&magic, 4, 1, pf);
	if (rc != 1) {
		fclose(pf);
		return -1;
	}
	pts = state_link;
	while (pts) {
		rc = fwrite(pts, sizeof(struct UploadThreadState), 1, pf);
		if (rc != 1) {
			fclose(pf);
			return -1;
		}
		pts = pts->next;
	}
	fclose(pf);
	return 0;
}


static struct UploadThreadState *pop_upload_threadstate(struct UploadState *us)
{
	struct UploadThreadState *ts = NULL;
	lock_for_upload(us);
	ts = us->threads;
	while (ts && ts->status != UPLOAD_STATUS_PENDDING) {
		ts = ts->next;
	}
	if (ts && ts->status == UPLOAD_STATUS_PENDDING)
		ts->status = UPLOAD_STATUS_UPLOADING;
	else
		ts = NULL;
	unlock_for_upload(us);
	return ts;
}


/*see http://curl.haxx.se/libcurl/c/CURLOPT_READFUNCTION.html */
static size_t read_slice(void *ptr, size_t size, size_t nmemb, void *userdata)
{
	static char tmp[64];
	struct UploadThreadState *ts = (struct UploadThreadState*)userdata;
	struct UploadState *us = ts->us;

	ShellContext *shellContext = us->context;

	time_t tm;
	size_t sz;

	lock_for_upload(us);

	if (shellContext->isAbort > 0) {
		us->status = UPLOAD_STATUS_FAIL;
		unlock_for_upload(us);
		return CURL_READFUNC_ABORT;
	}

	if (ts->start + ts->uploaded_size >= ts->end) {
		unlock_for_upload(us);
		return 0;
	}

	if (fseeko(us->pf, ts->start + ts->uploaded_size, SEEK_SET)) {
		if (us->pErrMsg && !(*us->pErrMsg)) {
			(*(us->pErrMsg)) = pcs_utils_sprintf("Can't fseeko().");
		}
		us->status = UPLOAD_STATUS_FAIL;
		unlock_for_upload(us);
		return CURL_READFUNC_ABORT;
	}
	sz = size * nmemb;
	if (ts->start + ts->uploaded_size + sz > ts->end) {
		sz = (size_t)(ts->end - ts->start - ts->uploaded_size);
	}
	sz = fread(ptr, 1, sz, us->pf);
	if (sz == 0) {
		if (us->pErrMsg && !(*us->pErrMsg)) {
			(*(us->pErrMsg)) = pcs_utils_sprintf("Can't read the file.");
		}
		us->status = UPLOAD_STATUS_FAIL;
		unlock_for_upload(us);
		return CURL_READFUNC_ABORT;
	}
	//printf("%llu - %llu (%llu) \n", (long long)ts->start + ts->uploaded_size, (long long)ts->start + ts->uploaded_size + sz, (long long)sz);
	us->speed += sz;
	us->uploaded_size += sz;
	ts->uploaded_size += sz;


	tm = time(&tm);
	if (tm != us->time) {
		char tmpcat[1000] = "Progress:" ;
		int64_t left_size = us->file_size - us->uploaded_size;
		int64_t remain_tm = (us->speed > 0) ? (left_size / us->speed) : 0;
		us->time = tm;
		tmp[63] = '\0';
		//printf("\r                                                \r");
		//printf("%s", pcs_utils_readable_size((double)us->uploaded_size, tmp, 63, NULL));
		//printf("/%s \t", pcs_utils_readable_size((double)us->file_size, tmp, 63, NULL));
		//printf("%s/s \t", pcs_utils_readable_size((double)us->speed, tmp, 63, NULL));
		//printf(" %s        ", pcs_utils_readable_left_time(remain_tm, tmp, 63, NULL));
		//printf("\r");
		//fflush(stdout);
		strcat(tmpcat, pcs_utils_readable_size((double)us->uploaded_size, tmp, 63, NULL));
		strcat(tmpcat, "/");
		strcat(tmpcat, pcs_utils_readable_size((double)us->file_size, tmp, 63, NULL));
		strcat(tmpcat, " ");
		strcat(tmpcat, pcs_utils_readable_size((double)us->speed, tmp, 63, NULL));
		strcat(tmpcat, "/s ");
		strcat(tmpcat, pcs_utils_readable_left_time(remain_tm, tmp, 63, NULL));
		sendMessageviaMqtt(tmpcat, 's');
		us->speed = 0;
	}

	unlock_for_upload(us);
	return sz;
}

#ifdef _WIN32
static DWORD WINAPI upload_thread(LPVOID params)
#else
static void *upload_thread(void *params)
#endif
{
	PcsFileInfo *res;
	int dsstatus;
	struct UploadState *ds = (struct UploadState *)params;
	ShellContext *context = ds->context;
	struct UploadThreadState *ts = pop_upload_threadstate(ds);
	Pcs *pcs;

	if (ts == NULL) {
		lock_for_upload(ds);
		ds->num_of_running_thread--;
		unlock_for_upload(ds);
#ifdef _WIN32
		return (DWORD)0;
#else
		return NULL;
#endif
	}
	pcs = create_pcs(context);
	if (!pcs) {
		lock_for_upload(ds);
		if (ds->pErrMsg) {
			if (*(ds->pErrMsg)) pcs_free(*(ds->pErrMsg));
			(*(ds->pErrMsg)) = pcs_utils_sprintf("Can't create pcs context.");
		}
		//ds->status = DOWNLOAD_STATUS_FAIL;
		ds->num_of_running_thread--;
		ts->status = UPLOAD_STATUS_PENDDING;
		unlock_for_upload(ds);
#ifdef _WIN32
		return (DWORD)0;
#else
		return NULL;
#endif
	}
	pcs_clone_userinfo(pcs, context->pcs);
	while (ts) {
		ts->pcs = pcs;
		lock_for_upload(ds);
		dsstatus = ds->status;
		unlock_for_upload(ds);
		if (dsstatus != UPLOAD_STATUS_OK) {
			lock_for_upload(ds);
			ts->status = UPLOAD_STATUS_PENDDING;
			unlock_for_upload(ds);
			break;
		}
		ds->uploaded_size -= ts->uploaded_size;
		ts->uploaded_size = 0;

		res = pcs_upload_slicefile(pcs, &read_slice, ts, (size_t)(ts->end - ts->start),
			convert_to_real_speed(context->max_upload_speed_per_thread));
		if (context->isAbort > 0) {
			ts->status = UPLOAD_STATUS_FAIL;
			break;
		}
		if (!res) {
			lock_for_upload(ds);
			if (ds->pErrMsg && !(*ds->pErrMsg)) {
				(*(ds->pErrMsg)) = pcs_utils_sprintf("%s", pcs_strerror(pcs));
			}
			//ds->status = UPLOAD_STATUS_FAIL;
			unlock_for_upload(ds);
			char errmsg[512];
#ifdef _WIN32
			sprintf(errmsg,"Upload slice failed, retry delay 10 second, tid: %x. message: %s\n", GetCurrentThreadId(), pcs_strerror(pcs));
#else
			sprintf(errmsg, "Upload slice failed, retry delay 10 second, tid: %p. message: %s\n", pthread_self(), pcs_strerror(pcs));
#endif
			sendMessageviaMqtt(errmsg, 'e');
			sleep(10); /*10秒后重试*/
			continue;
		}
		lock_for_upload(ds);
		ts->status = UPLOAD_STATUS_OK;
		strcpy(ts->md5, res->md5);
		pcs_fileinfo_destroy(res);
		save_upload_thread_states_to_file(ds->slice_file, ds->threads);
		unlock_for_upload(ds);
		ts = pop_upload_threadstate(ds);
	}

	destroy_pcs(pcs);
	lock_for_upload(ds);
	ds->num_of_running_thread--;
	unlock_for_upload(ds);
#ifdef _WIN32
	return (DWORD)0;
#else
	return NULL;
#endif
}

static void start_upload_thread(struct UploadState *us, void **pHandle)
{
#ifdef _WIN32
	DWORD tid;
	HANDLE thandle;
	/* hThread = CreateThread (&security_attributes, dwStackSize, ThreadProc, pParam, dwFlags, &idThread)
	WINBASEAPI HANDLE WINAPI CreateThread(LPSECURITY_ATTRIBUTES,DWORD,LPTHREAD_START_ROUTINE,PVOID,DWORD,PDWORD);
	第一个参数是指向SECURITY_ATTRIBUTES型态的结构的指针。在Windows 98中忽略该参数。在Windows NT中，它被设为NULL。
	第二个参数是用于新线程的初始堆栈大小，默认值为0。在任何情况下，Windows根据需要动态延长堆栈的大小。
	第三个参数是指向线程函数的指标。函数名称没有限制，但是必须以下列形式声明:DWORD WINAPI ThreadProc (PVOID pParam) ;
	第四个参数为传递给ThreadProc的参数。这样主线程和从属线程就可以共享数据。
	第五个参数通常为0，但当建立的线程不马上执行时为旗标
	第六个参数是一个指针，指向接受执行绪ID值的变量
	*/
	thandle = CreateThread(NULL, 0, upload_thread, (LPVOID)us, 0, &tid); // 建立线程
	if (pHandle) *pHandle = thandle;
	if (!thandle) {
		printf("Error: Can't create download thread.\n");
		lock_for_upload(us);
		us->num_of_running_thread--;
		unlock_for_upload(us);
	}
#else
	int err;
	pthread_t main_tid;
	err = pthread_create(&main_tid, NULL, upload_thread, us);
	if (err) {
		printf("Error: Can't create download thread.\n");
		lock_for_upload(us);
		us->num_of_running_thread--;
		unlock_for_upload(us);
	}
#endif
}






/*hood cJSON 库中分配内存的方法，用于检查内存泄漏*/
static void hook_cjson()
{
	cJSON_Hooks hooks = { 0 };
#if defined(DEBUG) || defined(_DEBUG)
	hooks.malloc_fn = &pcs_mem_malloc_arg1;
	hooks.free_fn = &pcs_mem_free;
#else

#endif
	cJSON_InitHooks(&hooks);
}

/*还原保存的上下文。
成功返回0，失败返回非0值。*/
static int restore_context(ShellContext *context, const char *filename)
{
	char *filecontent = NULL;
	int filesize = 0;
	cJSON *root, *item;

	if (!filename) {
		filename = context->contextfile;
	}
	else {
		if (context->contextfile) pcs_free(context->contextfile);
#ifdef WIN32
		context->contextfile = pcs_utils_strdup(filename);
#else
		/* Can't open the path that start with '~/'. why? It's not good, but work. */
		if (filename[0] == '~' && filename[1] == '/') {
			static char tmp[1024] = { 0 };
			strcpy(tmp, getenv("HOME"));
			strcat(tmp, filename + 1);
			context->contextfile = pcs_utils_strdup(tmp);
		}
		else {
			context->contextfile = pcs_utils_strdup(filename);
		}
#endif
	}
	filesize = read_file(context->contextfile, &filecontent);
	if (filesize <= 0) {
		fprintf(stderr, "Error: Can't read the context file (%s).\n", context->contextfile);
		if (filecontent) pcs_free(filecontent);
		return -1;
	}
	root = cJSON_Parse(filecontent);
	if (!root) {
		fprintf(stderr, "Error: Broken context file (%s).\n", context->contextfile);
		pcs_free(filecontent);
		return -1;
	}

	item = cJSON_GetObjectItem(root, "cookiefile");
	if (item && item->valuestring && item->valuestring[0]) {
		if (!is_absolute_path(item->valuestring)) {
			printf("warning: Invalid context.cookiefile, the value should be absolute path, use default value: %s.\n", context->cookiefile);
		}
		else {
			if (context->cookiefile) pcs_free(context->cookiefile);
			context->cookiefile = pcs_utils_strdup(item->valuestring);
		}
	}

	item = cJSON_GetObjectItem(root, "captchafile");
	if (item && item->valuestring && item->valuestring[0]) {
		if (!is_absolute_path(item->valuestring)) {
			printf("warning: Invalid context.captchafile, the value should be absolute path, use default value: %s.\n", context->captchafile);
		}
		else {
			if (context->captchafile) pcs_free(context->captchafile);
			context->captchafile = pcs_utils_strdup(item->valuestring);
		}
	}

	item = cJSON_GetObjectItem(root, "workdir");
	if (item && item->valuestring && item->valuestring[0]) {
		if (item->valuestring[0] != '/') {
			printf("warning: Invalid context.workdir, the value should be absolute path, use default value: %s.\n", context->workdir);
		}
		else {
			if (context->workdir) pcs_free(context->workdir);
			context->workdir = pcs_utils_strdup(item->valuestring);
		}
	}

	item = cJSON_GetObjectItem(root, "list_page_size");
	if (item) {
		if (((int)item->valueint) < 1) {
			printf("warning: Invalid context.list_page_size, the value should be great than 0, use default value: %d.\n", context->list_page_size);
		}
		else {
			context->list_page_size = (int)item->valueint;
		}
	}

	item = cJSON_GetObjectItem(root, "list_sort_name");
	if (item && item->valuestring && item->valuestring[0]) {
		if (strcmp(item->valuestring, "name") && strcmp(item->valuestring, "time") && strcmp(item->valuestring, "size")) {
			printf("warning: Invalid context.list_sort_name, the value should be one of [name|time|size], use default value: %s.\n", context->list_sort_name);
		}
		else {
			if (context->list_sort_name) pcs_free(context->list_sort_name);
			context->list_sort_name = pcs_utils_strdup(item->valuestring);
		}
	}

	item = cJSON_GetObjectItem(root, "list_sort_direction");
	if (item && item->valuestring && item->valuestring[0]) {
		if (strcmp(item->valuestring, "asc") && strcmp(item->valuestring, "desc")) {
			printf("warning: Invalid context.list_sort_direction, the value should be one of [asc|desc], use default value: %s.\n", context->list_sort_direction);
		}
		else {
			if (context->list_sort_direction) pcs_free(context->list_sort_direction);
			context->list_sort_direction = pcs_utils_strdup(item->valuestring);
		}
	}

	item = cJSON_GetObjectItem(root, "secure_method");
	if (item && item->valuestring && item->valuestring[0]) {
		if (strcmp(item->valuestring, "plaintext") && strcmp(item->valuestring, "aes-cbc-128") && strcmp(item->valuestring, "aes-cbc-192") && strcmp(item->valuestring, "aes-cbc-256")) {
			printf("warning: Invalid context.secure_method, the value should be one of [plaintext|aes-cbc-128|aes-cbc-192|aes-cbc-256], use default value: %s.\n", context->secure_method);
		}
		else {
			if (context->secure_method) pcs_free(context->secure_method);
			context->secure_method = pcs_utils_strdup(item->valuestring);
		}
	}

	item = cJSON_GetObjectItem(root, "secure_key");
	if (item && item->valuestring && item->valuestring[0]) {
		if (context->secure_key) pcs_free(context->secure_key);
		context->secure_key = pcs_utils_strdup(item->valuestring);
	}

	item = cJSON_GetObjectItem(root, "secure_enable");
	if (item) {
		context->secure_enable = item->valueint ? 1 : 0;
	}

	item = cJSON_GetObjectItem(root, "timeout_retry");
	if (item) {
		context->timeout_retry = item->valueint ? 1 : 0;
	}

	item = cJSON_GetObjectItem(root, "max_thread");
	if (item) {
		if (((int)item->valueint) < 1) {
			printf("warning: Invalid context.max_thread, the value should be great than 0, use default value: %d.\n", context->max_thread);
		}
		else {
			context->max_thread = (int)item->valueint;
		}
	}

	item = cJSON_GetObjectItem(root, "max_speed_per_thread");
	if (item) {
		if (((int)item->valueint) < 0) {
			printf("warning: Invalid context.max_speed_per_thread, the value should be >= 0, use default value: %d.\n", context->max_speed_per_thread);
		}
		else {
			context->max_speed_per_thread = (int)item->valueint;
		}
	}

	item = cJSON_GetObjectItem(root, "max_upload_speed_per_thread");
	if (item) {
		if (((int)item->valueint) < 0) {
			printf("warning: Invalid context.max_upload_speed_per_thread, the value should be >= 0, use default value: %d.\n", context->max_upload_speed_per_thread);
		}
		else {
			context->max_upload_speed_per_thread = (int)item->valueint;
		}
	}

	cJSON_Delete(root);
	pcs_free(filecontent);
	return 0;
}
/*返回COOKIE文件路径*/
static const char *cookiefile()
{
	static char filename[1024] = { 0 };
	char *env_value = getenv(PCS_COOKIE_ENV);
	if (env_value) return env_value;
	if (!filename[0]) { /*如果已经处理过，则直接返回*/
#ifdef WIN32
		strcpy(filename, getenv("UserProfile"));
		strcat(filename, "\\.pcs");
		strcat(filename, "\\");
		strcat(filename, app_name);
		CreateDirectoryRecursive(filename);
		strcat(filename, "\\");
		strcat(filename, "default.cookie");
#else
		strcpy(filename, getenv("HOME"));
		strcat(filename, "/.pcs");
		strcat(filename, "/");
		strcat(filename, app_name);
		CreateDirectoryRecursive(filename);
		strcat(filename, "/");
		strcat(filename, "default.cookie");
#endif
	}
	return filename;
}

/*获取上下文存储文件路径*/
static const char *contextfile()
{
	static char filename[1024] = { 0 };
	char *env_value = getenv(PCS_CONTEXT_ENV);
	if (env_value) return env_value;
	if (!filename[0]) {
#ifdef WIN32
		strcpy(filename, getenv("UserProfile"));
		strcat(filename, "\\.pcs");
		strcat(filename, "\\");
		strcat(filename, app_name);
		CreateDirectoryRecursive(filename);
		strcat(filename, "\\pcs.context");
#else
		strcpy(filename, getenv("HOME"));
		strcat(filename, "/.pcs");
		strcat(filename, "/");
		strcat(filename, app_name);
		CreateDirectoryRecursive(filename);
		strcat(filename, "/pcs.context");
#endif
	}
	return filename;
}
/*返回验证码图片文件路径*/
static const char *captchafile()
{
	static char filename[1024] = { 0 };
	char *env_value = getenv(PCS_CAPTCHA_ENV);
	if (env_value) return env_value;
	if (!filename[0]) { /*如果已经处理过，则直接返回*/
#ifdef WIN32
		strcpy(filename, getenv("UserProfile"));
		strcat(filename, "\\.pcs");
		strcat(filename, "\\");
		strcat(filename, app_name);
		CreateDirectoryRecursive(filename);
		strcat(filename, "\\");
		strcat(filename, "captcha.gif");
#else
		strcpy(filename, getenv("HOME"));
		strcat(filename, "/.pcs");
		strcat(filename, "/");
		strcat(filename, app_name);
		CreateDirectoryRecursive(filename);
		strcat(filename, "/");
		strcat(filename, "captcha.gif");
#endif
	}
	return filename;
}


/*初始化上下文*/
static void init_context(ShellContext *context)
{
	memset(context, 0, sizeof(ShellContext));
	context->isAbort = 0;
	context->contextfile = pcs_utils_strdup(contextfile());
	context->cookiefile = pcs_utils_strdup(cookiefile());
	context->captchafile = pcs_utils_strdup(captchafile());
	context->workdir = pcs_utils_strdup("/");
	context->list_page_size = PRINT_PAGE_SIZE;
	context->list_sort_name = pcs_utils_strdup("name");
	context->list_sort_direction = pcs_utils_strdup("asc");

	context->secure_method = pcs_utils_strdup("plaintext");
	context->secure_key = pcs_utils_strdup("");
	context->secure_enable = 0;

	context->timeout_retry = 1;
	context->max_thread = 1;
	context->max_speed_per_thread = 0;
	context->max_upload_speed_per_thread = 0;
}

/*把上下文转换为字符串*/
static char *context2str(ShellContext *context)
{
	char *json;
	cJSON *root, *item;

	root = cJSON_CreateObject();
	assert(root);

	item = cJSON_CreateString(context->cookiefile);
	assert(item);
	cJSON_AddItemToObject(root, "cookiefile", item);

	item = cJSON_CreateString(context->captchafile);
	assert(item);
	cJSON_AddItemToObject(root, "captchafile", item);

	item = cJSON_CreateString(context->workdir);
	assert(item);
	cJSON_AddItemToObject(root, "workdir", item);

	item = cJSON_CreateNumber((double)context->list_page_size);
	assert(item);
	cJSON_AddItemToObject(root, "list_page_size", item);

	item = cJSON_CreateString(context->list_sort_name);
	assert(item);
	cJSON_AddItemToObject(root, "list_sort_name", item);

	item = cJSON_CreateString(context->list_sort_direction);
	assert(item);
	cJSON_AddItemToObject(root, "list_sort_direction", item);

	item = cJSON_CreateString(context->secure_method);
	assert(item);
	cJSON_AddItemToObject(root, "secure_method", item);

	item = cJSON_CreateString(context->secure_key);
	assert(item);
	cJSON_AddItemToObject(root, "secure_key", item);

	item = cJSON_CreateBool(context->secure_enable);
	assert(item);
	cJSON_AddItemToObject(root, "secure_enable", item);

	item = cJSON_CreateBool(context->timeout_retry);
	assert(item);
	cJSON_AddItemToObject(root, "timeout_retry", item);

	item = cJSON_CreateNumber(context->max_thread);
	assert(item);
	cJSON_AddItemToObject(root, "max_thread", item);

	item = cJSON_CreateNumber(context->max_speed_per_thread);
	assert(item);
	cJSON_AddItemToObject(root, "max_speed_per_thread", item);

	item = cJSON_CreateNumber(context->max_upload_speed_per_thread);
	assert(item);
	cJSON_AddItemToObject(root, "max_upload_speed_per_thread", item);

	json = cJSON_Print(root);
	assert(json);

	cJSON_Delete(root);
	return json;
}

/*保存上下文*/
static void save_context(ShellContext *context)
{
	const char *filename;
	char *json;
	FILE *pf;

	json = context2str(context);
	assert(json);

	filename = context->contextfile;
	pf = fopen(filename, "wb");
	if (!pf) {
		fprintf(stderr, "Error: Can't open the file: %s\n", filename);
		pcs_free(json);
		return;
	}
	fwrite(json, 1, strlen(json), pf);
	fclose(pf);
	pcs_free(json);
}

static PcsBool is_login(ShellContext *context, const char *msg)
{
	PcsRes pcsres;
	time_t now;
	time(&now);
	pcsres = pcs_islogin(context->pcs);
	if (pcsres == PCS_LOGIN)
		return PcsTrue;
	if (msg) {
		if (msg[0])
			printf("%s\n", msg);
	}
	else if (pcsres == PCS_NOT_LOGIN) {
		printf("You are not logon or your session is time out. You can login by 'login' command.\n");
	}
	else {
		printf("Error: %s\n", pcs_strerror(context->pcs));
	}
	return PcsFalse;
}

static inline int do_upload(ShellContext *context,
	const char *local_file, const char *remote_file, PcsBool is_force,
	const char *local_basedir, const char *remote_basedir,
	char **pErrMsg, int *op_st)
{
	PcsFileInfo *res = NULL;
	char *local_path, *remote_path, *dir;
	int del_local_file = 0;
	int64_t content_length;
	char content_md5[33] = { 0 };

	local_path = combin_path(local_basedir, -1, local_file);
	dir = combin_net_disk_path(context->workdir, remote_basedir);
	remote_path = combin_net_disk_path(dir, remote_file);
	pcs_free(dir);

	content_length = pcs_local_filesize(context->pcs, local_path);
	if (content_length < 0) {
		if (pErrMsg) {
			if (*pErrMsg) pcs_free(*pErrMsg);
			(*pErrMsg) = pcs_utils_sprintf("%s. local_path=%s, remote_path=%s\n",
				pcs_strerror(context->pcs), local_path, remote_path);
		}
		if (op_st) (*op_st) = OP_ST_FAIL;
		if (del_local_file) DeleteFileRecursive(local_path);
		pcs_free(local_path);
		pcs_free(remote_path);
		return -1;
	}

	if (content_length > PCS_RAPIDUPLOAD_THRESHOLD)
		res = pcs_rapid_upload(context->pcs, remote_path, is_force, local_path, content_md5, NULL);
	if (!res && content_length <= MIN_UPLOAD_SLICE_SIZE) {
		pcs_setopts(context->pcs,
			PCS_OPTION_PROGRESS_FUNCTION, &upload_progress,
			PCS_OPTION_PROGRESS_FUNCTION_DATE, NULL,
			PCS_OPTION_PROGRESS, (void *)((long)PcsTrue),
			//PCS_OPTION_TIMEOUT, (void *)0L,
			PCS_OPTION_END);
		res = pcs_upload(context->pcs, remote_path, is_force, local_path,
			convert_to_real_speed(context->max_upload_speed_per_thread));
		//pcs_setopts(context->pcs,
		//	PCS_OPTION_TIMEOUT, (void *)((long)TIMEOUT),
		//	PCS_OPTION_END);
		if (!res || !res->path || !res->path[0]) {
			if (pErrMsg) {
				if (*pErrMsg) pcs_free(*pErrMsg);
				(*pErrMsg) = pcs_utils_sprintf("%s. local_path=%s, remote_path=%s\n",
					pcs_strerror(context->pcs), local_path, remote_path);
			}
			if (op_st) (*op_st) = OP_ST_FAIL;
			if (res) pcs_fileinfo_destroy(res);
			if (del_local_file) DeleteFileRecursive(local_path);
			pcs_free(local_path);
			pcs_free(remote_path);
			return -1;
		}
	}
	else if (!res) {
		struct UploadState us = { 0 };
		struct UploadThreadState *ts, *tail = NULL;
		curl_off_t start = 0;
		int slice_count, pendding_slice_count = 0, thread_count, running_thread_count, i, is_success;
		int64_t slice_size;
#ifdef _WIN32
		HANDLE *handles = NULL;
#endif
		char *slice_file;

		init_upload_state(&us);
		us.context = context;

		if (!(content_md5[0])) {
			if (!pcs_md5_file(context->pcs, local_path, content_md5)) {
				if (pErrMsg) {
					if (*pErrMsg) pcs_free(*pErrMsg);
					(*pErrMsg) = pcs_utils_sprintf("%s. local_path=%s, remote_path=%s\n",
						pcs_strerror(context->pcs), local_path, remote_path);
				}
				if (op_st) (*op_st) = OP_ST_FAIL;
				if (del_local_file) DeleteFileRecursive(local_path);
				pcs_free(local_path);
				pcs_free(remote_path);
				uninit_upload_state(&us);
				return -1;
			}
		}

		/*打开文件*/
		us.pf = fopen(local_path, "rb");
		if (!us.pf) {
			if (pErrMsg) {
				if (*pErrMsg) pcs_free(*pErrMsg);
				(*pErrMsg) = pcs_utils_sprintf("Can't open the file: %s\n", local_path);
			}
			if (op_st) (*op_st) = OP_ST_FAIL;
			if (del_local_file) DeleteFileRecursive(local_path);
			pcs_free(local_path);
			pcs_free(remote_path);
			uninit_upload_state(&us);
			return -1;
		}

		slice_file = (char *)pcs_malloc(strlen(local_path) + 33 + strlen(SLICE_FILE_SUFFIX) + 1);
		strcpy(slice_file, local_path);
		strcat(slice_file, ".");
		strcat(slice_file, content_md5);
		strcat(slice_file, SLICE_FILE_SUFFIX);

		us.slice_file = slice_file;
		us.pErrMsg = pErrMsg;
		us.file_size = content_length;
		slice_count = context->max_thread;
		if (slice_count < 1) slice_count = 1;
		if (restore_upload_state(&us, slice_file, &pendding_slice_count)) {
			//分片开始
			us.uploaded_size = 0;
			slice_size = content_length / slice_count;
			if ((content_length % slice_count))
				slice_size++;
			if (slice_size <= MIN_UPLOAD_SLICE_SIZE)
				slice_size = MIN_UPLOAD_SLICE_SIZE;
			if (slice_size > MAX_UPLOAD_SLICE_SIZE)
				slice_size = MAX_UPLOAD_SLICE_SIZE;
			slice_count = (int)(content_length / slice_size);
			if ((content_length % slice_size)) slice_count++;
			if (slice_count > MAX_UPLOAD_SLICE_COUNT) {
				slice_count = MAX_UPLOAD_SLICE_COUNT;
				slice_size = content_length / slice_count;
				if ((content_length % slice_count))
					slice_size++;
				slice_count = (int)(content_length / slice_size);
				if ((content_length % slice_size)) slice_count++;
			}

			for (i = 0; i < slice_count; i++) {
				ts = (struct UploadThreadState *) pcs_malloc(sizeof(struct UploadThreadState));
				memset(ts, 0, sizeof(struct UploadThreadState));
				ts->us = &us;
				ts->start = start;
				start += slice_size;
				ts->end = start;
				if (ts->end >((curl_off_t)content_length)) ts->end = (curl_off_t)content_length;
				ts->status = UPLOAD_STATUS_PENDDING;
				pendding_slice_count++;
				ts->tid = i + 1;
				ts->next = NULL;
				if (tail == NULL) {
					us.threads = tail = ts;
				}
				else {
					tail->next = ts;
					tail = ts;
				}
			}
			us.num_of_slice = slice_count;
			//分片结束
		}
		//保存分片数据
		sendMessageviaMqtt("Saving slices...\r", 'i');
		if (save_upload_thread_states_to_file(slice_file, us.threads)) {
			if (pErrMsg) {
				if (*pErrMsg) pcs_free(*pErrMsg);
				(*pErrMsg) = pcs_utils_sprintf("Can't save slices into file: %s \n", slice_file);
			}
			if (op_st) (*op_st) = OP_ST_FAIL;
			if (del_local_file) DeleteFileRecursive(local_path);
			DeleteFileRecursive(slice_file);
			pcs_free(local_path);
			pcs_free(remote_path);
			pcs_free(slice_file);
			uninit_upload_state(&us);
			return -1;
		}

		sendMessageviaMqtt("Starting threads...\r", 'i');

		thread_count = pendding_slice_count;
		if (thread_count > context->max_thread && context->max_thread > 0)
			thread_count = context->max_thread;
		us.num_of_running_thread = thread_count;
		//printf("\nthread: %d, slice: %d\n", thread_count, ds.num_of_slice);
#ifdef _WIN32
		handles = (HANDLE *)pcs_malloc(sizeof(HANDLE) * thread_count);
		memset(handles, 0, sizeof(HANDLE) * thread_count);
#endif
		for (i = 0; i < thread_count; i++) {
#ifdef _WIN32
			start_upload_thread(&us, handles + i);
#else
			start_upload_thread(&us, NULL);
#endif
		}

		/*等待所有运行的线程退出*/
		while (1) {
			lock_for_upload(&us);
			running_thread_count = us.num_of_running_thread;
			unlock_for_upload(&us);
			if (running_thread_count < 1) break;
			sleep(1);
		}
		fclose(us.pf);

#ifdef _WIN32
		for (i = 0; i < thread_count; i++) {
			if (handles[i]) {
				CloseHandle(handles[i]);
			}
		}
		pcs_free(handles);
#endif

		/*判断是否所有分片都下载完成了*/
		is_success = 1;
		ts = us.threads;
		while (ts) {
			if (ts->status != UPLOAD_STATUS_OK) {
				is_success = 0;
				break;
			}
			ts = ts->next;
		}

		if (!is_success) {
			if (pErrMsg) {
				if (!(*pErrMsg)) {
					if (context->isAbort > 0) {
						(*pErrMsg) = pcs_utils_sprintf("Upload Aborted.\n");
					}else{
						(*pErrMsg) = pcs_utils_sprintf("Upload fail.\n");
					}
				}
			}
			if (op_st) (*op_st) = OP_ST_FAIL;
			if (del_local_file) DeleteFileRecursive(local_path);
			pcs_free(local_path);
			pcs_free(remote_path);
			pcs_free(slice_file);
			uninit_upload_state(&us);
			return -1;
		}
		else {
			//合并文件
			PcsSList *slist = NULL, *si, *si_tail;
			ts = us.threads;
			while (ts) {
				si = (PcsSList *)pcs_malloc(sizeof(PcsSList));
				si->string = ts->md5;
				si->next = NULL;
				if (slist == NULL) {
					slist = si_tail = si;
				}
				else {
					si_tail->next = si;
					si_tail = si;
				}
				ts = ts->next;
			}
			res = pcs_create_superfile(context->pcs, remote_path, is_force, slist);
			si = slist;
			while (si) {
				si_tail = si;
				si = si->next;
				pcs_free(si_tail);
			}
			if (!res) {
				if (pErrMsg) {
					if ((*pErrMsg)) pcs_free(*pErrMsg);
					(*pErrMsg) = pcs_utils_sprintf("%s", pcs_strerror(context->pcs));
				}
				if (op_st) (*op_st) = OP_ST_FAIL;
				if (del_local_file) DeleteFileRecursive(local_path);
				pcs_free(local_path);
				pcs_free(remote_path);
				pcs_free(slice_file);
				uninit_upload_state(&us);
				return -1;
			}
			uninit_upload_state(&us);
			DeleteFileRecursive(slice_file);
			pcs_free(slice_file);
		}

	}

	/*当文件名以.(点号)开头的话，则网盘会自动去除第一个点。以下if语句的目的就是把网盘文件重命名为以点号开头。*/
	if (res) {
		char *diskName = pcs_utils_filename(res->path),
			*orgName = pcs_utils_filename(remote_file);
		if (diskName && orgName && orgName[0] == '.' && diskName[0] != '.') {
			PcsPanApiRes *res2;
			PcsSList2 sl = {
				res->path,
				orgName,
				NULL
			};
			PcsSList sl2 = {
				res->path, NULL
			};
			pcs_free(orgName);
			orgName = (char *)malloc(strlen(diskName) + 2);
			orgName[0] = '.';
			strcpy(&orgName[1], diskName);
			while (1) {
				sl.string2 = orgName;
				//printf("\nrename %s -> %s \n", sl.string1, sl.string2);
				res2 = pcs_rename(context->pcs, &sl);
				//printf("\nrename %s -> %s %d \n", sl.string1, sl.string2, res2->error);
				if (res2 && res2->error == 0) {
					pcs_pan_api_res_destroy(res2);
					res2 = NULL;
					break;
				}
				else {
					if (res2) { pcs_pan_api_res_destroy(res2); res2 = NULL; }
					if (is_force) {
						sl2.string = remote_path;
						//printf("\ndelete %s \n", sl2.string);
						res2 = pcs_delete(context->pcs, &sl2);
						//printf("\ndelete %s %d \n", sl2.string, res2->error);
						if (!res2 || res2->error != 0) {
							if (pErrMsg) {
								if (*pErrMsg) pcs_free(*pErrMsg);
								(*pErrMsg) = pcs_utils_sprintf("Error: Can't delete the %s, so can't rename %s to %s. You can rename manually.\n",
									remote_path, sl.string1, sl.string2);
							}
							if (res2) { pcs_pan_api_res_destroy(res2); res2 = NULL; }
							break;
						}
						if (res2) { pcs_pan_api_res_destroy(res2); res2 = NULL; }
					}
					else {
						if (pErrMsg) {
							if (*pErrMsg) pcs_free(*pErrMsg);
							(*pErrMsg) = pcs_utils_sprintf("Error: Can't rename %s to %s. You can rename manually.\n",
								sl.string1, sl.string2);
						}
						break;
					}
				}
			}
		}
		if (diskName) pcs_free(diskName);
		if (orgName) pcs_free(orgName);
		//print_fileinfo(res, " ");
	}
	if (op_st) (*op_st) = OP_ST_SUCC;
	if (res) pcs_fileinfo_destroy(res);
	if (del_local_file) DeleteFileRecursive(local_path);
	pcs_free(local_path);
	pcs_free(remote_path);
	return 0;
}

int msgarrvd(void *context, char *topicName, int topicLen, MQTTClient_message *message)
{
	char* payloadptr;

	ShellContext *shellContext = (ShellContext *)context;
	payloadptr = message->payload;
	
	if (*payloadptr == 'a') { // abort
		shellContext->isAbort = 1;
	}

	MQTTClient_freeMessage(&message);
	MQTTClient_free(topicName);
	return 1;
}


JNIEXPORT void JNICALL Java_cn_bbscool_BaiduPCS_init
(JNIEnv *env, jobject o, jstring id) {
	const char* appname;
	char topic[100] = { 0 };
	appname = (*env)->GetStringUTFChars(env, id, NULL);
	app_name = malloc(sizeof(char)*(strlen(appname)+1));
	strcpy(app_name, appname);

	sprintf(topic, "command/%s/", app_name);

	(*env)->ReleaseStringUTFChars(env, id, appname);
	int rc = 0;
	hook_cjson();
	init_context(&context);
	context.pcs = create_pcs(&context);

	MQTTClient_connectOptions conn_opts = MQTTClient_connectOptions_initializer;

	MQTTClient_create(&client, P_ADDRESS, P_CLIENTID,
		MQTTCLIENT_PERSISTENCE_NONE, NULL);
	conn_opts.keepAliveInterval = 20;
	conn_opts.cleansession = 1;

	MQTTClient_setCallbacks(client, &context, NULL, msgarrvd, NULL);

	if ((rc = MQTTClient_connect(client, &conn_opts)) != MQTTCLIENT_SUCCESS)
	{
		printf("Failed to connect, return code %d\n", rc);
	}
	else {
		MQTTClient_subscribe(client, topic, 0);
	}
	
}

JNIEXPORT void JNICALL Java_cn_bbscool_BaiduPCS_destroy
(JNIEnv *env, jobject o) {
	//pcs_free(app_name);
	MQTTClient_disconnect(client, 10000);
	MQTTClient_destroy(&client);
	destroy_pcs(context.pcs);
	save_context(&context);
}

JNIEXPORT jstring JNICALL Java_cn_bbscool_BaiduPCS_pcs_1who
(JNIEnv *env, jobject o) {
	//jstring  result;
	char userid[100];
	if (!is_login(&context, NULL)) {
		sprintf(userid, "");
		//sendMessageviaMqtt(userid, 'e');
	}
	else {
		sprintf(userid, "%s",pcs_sysUID(context.pcs));
		//sendMessageviaMqtt(userid, 'i');
	}
	return (*env)->NewStringUTF(env,userid);
}

JNIEXPORT jstring JNICALL Java_cn_bbscool_BaiduPCS_cmd_1quota
(JNIEnv *env, jobject o) {
	int64_t quota = 0, used = 0;
	PcsRes pcsres;
	char result[100];
	if (is_login(&context, NULL)) {
		pcsres = pcs_quota(context.pcs, &quota, &used);
	}
	sprintf(result, "%"PRIu64",%"PRIu64, used,quota);
	return (*env)->NewStringUTF(env, result);
}

JNIEXPORT void JNICALL Java_cn_bbscool_BaiduPCS_pcs_1upload
(JNIEnv *env, jobject o, jstring lp, jstring rp) {
	const char *path = NULL, *locPath = NULL; 
	char  *errmsg = NULL, *locPathMbs = NULL;
	char jmsg[10000];
	LocalFileInfo *local;
	locPath = (*env)->GetStringUTFChars(env, lp, NULL);
	path = (*env)->GetStringUTFChars(env, rp, NULL);
	locPathMbs = utf82mbs(locPath);
	local = GetLocalFileInfo(locPathMbs);
	if (!local) {
		sprintf(jmsg, "Error: The local file \"%s\" not exist. \n", locPathMbs);
		sendMessageviaMqtt(jmsg, 'e');
		goto finalize;
	}
	context.isAbort = 0;
	if (do_upload(&context,
		locPathMbs, path, PcsTrue,
		"", context.workdir,
		&errmsg, NULL)) {
		sprintf(jmsg, "Error: %s\n", errmsg);
		sendMessageviaMqtt(jmsg, 'e');
		goto finalize;
	}
	sprintf(jmsg, "Upload %s to %s Success.\n", locPathMbs, path);
	sendMessageviaMqtt(jmsg, 'i');
finalize:
	if (errmsg) pcs_free(errmsg);
	pcs_free(locPathMbs);
	DestroyLocalFileInfo(local);
	(*env)->ReleaseStringUTFChars(env, lp, locPath);
	(*env)->ReleaseStringUTFChars(env, rp, path);
	return;
}

JNIEXPORT void JNICALL Java_cn_bbscool_BaiduPCS_pcs_1logout
(JNIEnv *env, jobject o) {
	PcsRes pcsres;
	char errmsg[500] = { 0 };
	pcsres = pcs_logout(context.pcs);
	if (pcsres != PCS_OK) {
		sprintf(errmsg, "Logout Fail: %s\n", pcs_strerror(context.pcs));
		sendMessageviaMqtt(errmsg, 'e');
		return;
	}
	sendMessageviaMqtt("Logout Success.\n", 'i');
	return;
}

JNIEXPORT void JNICALL Java_cn_bbscool_BaiduPCS_pcs_1login
(JNIEnv *env, jobject o, jstring u, jstring p) {
	const char *user = NULL, *pass = NULL;
	char errmsg[500] = { 0 };
	PcsRes pcsres;
#ifdef _WIN32
	context.mutex = CreateMutex(NULL, FALSE, NULL);
#else
	context.mutex = (pthread_mutex_t *)pcs_malloc(sizeof(pthread_mutex_t));
	pthread_mutex_init((pthread_mutex_t *)context.mutex, NULL);
#endif
	user = (*env)->GetStringUTFChars(env, u, NULL);
	pass = (*env)->GetStringUTFChars(env, p, NULL);
	pcs_setopt(context.pcs, PCS_OPTION_USERNAME, user);
	pcs_setopt(context.pcs, PCS_OPTION_PASSWORD, pass);
	pcsres = pcs_login(context.pcs);
	if (pcsres != PCS_OK) {
		sprintf(errmsg,"Login Failed: %s\n", pcs_strerror(context.pcs));
		sendMessageviaMqtt(errmsg, 'e');
	}else{
		sprintf(errmsg,"Login Success. UID: %s\n", pcs_sysUID(context.pcs));
		sendMessageviaMqtt(errmsg, 'i');
	}
	(*env)->ReleaseStringUTFChars(env, u, user);
	(*env)->ReleaseStringUTFChars(env, p, pass);
#ifdef _WIN32
	CloseHandle(context.mutex);
#else
	pthread_mutex_destroy((pthread_mutex_t *)context.mutex);
	pcs_free(context.mutex);
#endif
}

JNIEXPORT void JNICALL Java_cn_bbscool_BaiduPCS_cmd_1setjobid
(JNIEnv *env, jobject o, jstring j) {
	const char* t_jobid;
	t_jobid = (*env)->GetStringUTFChars(env, j, NULL);
	jobid = malloc(sizeof(char)*(strlen(t_jobid) + 1));
	strcpy(jobid, t_jobid);

	(*env)->ReleaseStringUTFChars(env, j, t_jobid);
}
/*callback function :

 jclass clsj = NULL;
jmethodID mj = NULL;
char* jmsgU8 = NULL;

jmsgU8 = mbs2utf8(mbsString);

clsj = (*env)->FindClass(env, "cn/bbscool/BaiduPCS");
if (clsj == NULL) return;
mj = (*env)->GetStaticMethodID(env, clsj, "doNotify", "(Ljava/lang/String;)V");
if (mj == NULL) return;
(*env)->CallStaticVoidMethod(env, o, mj, (*env)->NewStringUTF(env, jmsgU8));

*/