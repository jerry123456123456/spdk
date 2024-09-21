#include <stdio.h>
#include <spdk/event.h>
#include <spdk/blob.h>
#include <spdk/bdev.h>
#include <spdk/env.h>
#include <spdk/blob_bdev.h>

#include <unistd.h>
#include <sys/syscall.h>


#define FILENAME_LENGTH 128

//定义全局变量，让回调函数的参数可以直接传递进去
typedef struct zvfs_context_s{
    struct spdk_bs_dev *bsdev;  //这行定义了一个指向 `spdk_bs_dev` 结构体的指针变量 `bsdev`，用于表示 Blobstore 的设备
    struct spdk_blob_store *blobstore; //这行定义了一个指向 `spdk_blob_store` 结构体的指针变量 `blobstore`，用于表示 Blobstore
    //struct spdk_bs_dev *bsdev;` 表示底层的 Blobstore 设备，而 `struct spdk_blob_store *blobstore;` 则表示对 Blob 对象的管理实体
    
    spdk_blob_id blobid; //用于存储 Blob 的 ID
    struct spdk_blob *blob; //用于表示 Blob 对象
    struct spdk_io_channel *channel; //这行定义了一个指向 `spdk_io_channel` 结构体的指针变量 `channel`，用于表示 I/O 通道

    uint8_t *write_buffer;
    uint8_t *read_buffer;

    uint64_t io_unit_size;  //这行定义了一个 `uint64_t` 类型的变量 `io_unit_size`，用于表示 I/O 单元的大小
    bool finished;
}zvfs_context_t;

struct spdk_thread *global_thread=NULL;

struct zvfs_filesystem_s;
//文件
typedef struct zvfs_files_s{
    char filename[FILENAME_LENGTH];

    uint8_t *write_buffer;
    uint8_t *read_buffer;

    struct spdk_blob *blob;
    struct zvfs_filesystem_s *fs;
}zvfs_file_t;

//文件系统
typedef struct zvfs_filesystem_s{
    struct  spdk_bs_dev *bsdev;
    struct spdk_blob_store *blobstore;
    struct spdk_io_channel *channel;

    uint64_t io_unit_size;
    struct spdk_thread *thread;
    bool finished;
}zvfs_filesystem_t;

zvfs_filesystem_t *fs_instance = NULL;

//回调函数
// // 在这里定义了一个名为 zvfs_bdev_event_call 的回调函数，用于处理块设备事件
static void zvfs_bdev_event_call(enum spdk_bdev_event_type type, struct spdk_bdev *bdev,
				     void *event_ctx) {
    SPDK_NOTICELOG("%s-->enter\n",__func__);
}

//最大的轮询次数
static const int POLLER_MAX_TIME = 100000;
//`poller` 函数的作用是在指定的 SPDK 线程上执行一个函数，
//并在一定的轮询次数内等待该函数执行完成。
//在这个特定的上下文中，`poller` 函数用于等待异步操作完成。
static bool poller(struct spdk_thread *thread,spdk_msg_fn start_fn,void *ctx,bool *finished){
    spdk_thread_send_msg(thread,start_fn,ctx);  //发送消息，在新开的线程执行start_fn函数
    int poller_count=0;
    do{
        //加到100000加到100000次就代表超时
        spdk_thread_poll(thread,0,0);  //轮询，确保这个线程的消息得到即使处理
        poller_count++;
    }while (!(*finished) && poller_count < POLLER_MAX_TIME);
    if (!(*finished) && poller_count >= POLLER_MAX_TIME) {
		return false;
	}
	return true;

}

//////////////////////////close
//分配失败调用unload完成之后的回调函数
static void zvfs_bs_unload_complete(void *arg,int bserrno){
    zvfs_filesystem_t *fs=(zvfs_filesystem_t *)arg;
    fs->finished=true;
    spdk_app_stop(1);
}


static void zvfs_file_close(zvfs_file_t *file){
    if(file->read_buffer){
        spdk_free(file->read_buffer);
        file->read_buffer=NULL;
    }
    if(file->write_buffer){
        spdk_free(file->write_buffer);
        file->write_buffer=NULL;
    }
}

//分配失败调用的unload函数
static void zvfs_bs_unload(void *arg){
    zvfs_filesystem_t *fs=(zvfs_filesystem_t *)arg;
    if(fs->blobstore){
        if(fs->channel){
            spdk_bs_free_io_channel(fs->channel);
        }
        spdk_bs_unload(fs->blobstore,zvfs_bs_unload_complete,fs);
    }
}

/////////////////////////////////////读操作
static void zvfs_blob_read_complete(void *arg,int bserrno){
    zvfs_file_t *file=(zvfs_file_t *)arg;
    zvfs_filesystem_t *fs=file->fs;
    SPDK_NOTICELOG("size: %ld, buffer: %s\n", fs->io_unit_size, file->read_buffer);
    fs->finished=true;
}

static void zvfs_do_read(void *arg){
    zvfs_file_t *file = (zvfs_file_t *)arg;
	zvfs_filesystem_t *fs = file->fs;

	SPDK_NOTICELOG("%s --> enter\n", __func__);

	memset(file->read_buffer, '\0', fs->io_unit_size);
    //0是块偏移，1是以字节为单位
	spdk_blob_io_read(file->blob, fs->channel, file->read_buffer, 0, 1, zvfs_blob_read_complete, file);
}

static void zvfs_file_read(zvfs_file_t *file){
    zvfs_filesystem_t *fs=file->fs;
    fs->finished=false;
    poller(fs->thread,zvfs_do_read,file,&fs->finished);
}

////////////////////////////////////写操作
static void zvfs_blob_write_complete(void *arg, int bserrno) {

	zvfs_file_t *file = (zvfs_file_t *)arg;
	zvfs_filesystem_t *fs = file->fs;

	fs->finished = true;
}

static void zvfs_do_write(void *arg){
    zvfs_file_t *file=(zvfs_file_t *)arg;
    zvfs_filesystem_t *fs=file->fs;
    SPDK_NOTICELOG("%s --> enter 11111\n", __func__);
    spdk_blob_io_write(file->blob,fs->channel,file->write_buffer,0,1,zvfs_blob_write_complete,file);
}

static void zvfs_file_write(zvfs_file_t *file){
    zvfs_filesystem_t *fs=file->fs;
    fs->finished=false;
    poller(fs->thread,zvfs_do_write,file,&fs->finished);
}

////////////////////open
static void zvfs_blob_sync_complete(void *arg,int bserrno){
    zvfs_file_t *file=(zvfs_file_t *)arg;
    zvfs_filesystem_t *fs=file->fs;
    fs->finished=true;
    SPDK_NOTICELOG("%s --> %lu enter\n", __func__, fs->io_unit_size);
}

static void zvfs_blob_resize_complete(void *arg,int bserrno){
    zvfs_file_t *file=(zvfs_file_t *)arg;
    SPDK_NOTICELOG("%s --> enter\n", __func__);
	spdk_blob_sync_md(file->blob, zvfs_blob_sync_complete, file);
}

static void zvfs_blob_open_complete(void *arg,struct spdk_blob *blob,int bserrno){
    zvfs_file_t *file=(zvfs_file_t *)arg;
    zvfs_filesystem_t *fs=file->fs;
    file->blob=blob;
    SPDK_NOTICELOG("%s --> enter\n", __func__);
    //用于获取 Blob 存储空间中的空闲的大小
	uint64_t freed = spdk_bs_free_cluster_count(fs->blobstore);
    file->write_buffer = spdk_malloc(fs->io_unit_size, 0x1000, NULL, SPDK_ENV_LCORE_ID_ANY, SPDK_MALLOC_DMA);
	if (file->write_buffer == NULL) {
		// zvfs(ctx); close
		return ;
	}

	file->read_buffer = spdk_malloc(fs->io_unit_size, 0x1000, NULL, SPDK_ENV_LCORE_ID_ANY, SPDK_MALLOC_DMA);
	if (file->read_buffer == NULL) {
		// zvfs(ctx); close
		spdk_free(file->write_buffer);
		return ;
	}
    //调整指定 Blob 存储对象的大小
    spdk_blob_resize(blob,freed,zvfs_blob_resize_complete,file);
}

//////////////////////create
static void zvfs_bs_create_complete(void *arg, spdk_blob_id blobid, int bserrno) {
    zvfs_file_t *file=(zvfs_file_t *)arg;
    zvfs_filesystem_t *fs=file->fs;
    SPDK_NOTICELOG("%s --> enter\n", __func__);
    //创建完成之后我们就可以开始打开
    spdk_bs_open_blob(fs->blobstore,blobid,zvfs_blob_open_complete,file);
}

static void zvfs_do_create(void *arg){
    zvfs_file_t *file=(zvfs_file_t *)arg;
    zvfs_filesystem_t *fs=file->fs;
    spdk_bs_create_blob(fs->blobstore,zvfs_bs_create_complete,file);
}

static void zvfs_file_create(zvfs_file_t *file){
    zvfs_filesystem_t *fs=file->fs;
    fs->finished=false;
    poller(fs->thread,zvfs_do_create,file,&fs->finished);
}

////////////////////init
static void zvfs_bs_init_complete(void *arg, struct spdk_blob_store *bs,
		int bserrno) {
        //// 这是blob存储初始化完成的回调函数
    zvfs_filesystem_t *fs=(zvfs_filesystem_t *)arg;
    fs->blobstore=bs;
    //用于获取Blobstore的I/O单元大小。在SPDK中，Blobstore是一种用于存储数据块的机制，
    //而I/O单元大小指的是Blobstore上执行读写操作时使用的最小单位大小
    fs->io_unit_size=spdk_bs_get_io_unit_size(bs);
    //给定的Blobstore实例分配一个I/O通道（IO channel）的函数调用。
    //在SPDK中，I/O通道是与特定的存储设备或存储机制进行交互的接口，
    //它提供了一种管理和处理I/O操作的方式
    struct spdk_io_channel *channel=spdk_bs_alloc_io_channel(fs->blobstore);
    if (channel == NULL) {
		zvfs_bs_unload(fs);
		return ;
	}
	fs->channel = channel;
	SPDK_NOTICELOG("%s --> enter: %lu\n", __func__, fs->io_unit_size);
	fs->finished = true;
}

static void zvfs_entry(void *arg){
    zvfs_filesystem_t *fs=(zvfs_filesystem_t *)arg;
    SPDK_NOTICELOG("%s --> enter\n", __func__);
    //跟json文件里的名字一样
	const char *bdev_name = "Malloc0";
    //创建一个Blobstore设备的函数调用。
    //具体来说，spdk_bdev_create_bs_dev_ext函数用于将指定的块设备（bdev）与Blobstore相关联，
    //并创建一个新的Blobstore设备
    int rc=spdk_bdev_create_bs_dev_ext(bdev_name,zvfs_bdev_event_call,NULL,&fs->bsdev);
    if (rc != 0) {
		spdk_app_stop(-1);
		return ;
	}
    //用于初始化Blobstore的函数调用。
    //具体来说，spdk_bs_init函数用于初始化给定的Blobstore设备
    spdk_bs_init(fs->bsdev,NULL,zvfs_bs_init_complete,fs);
}

////////////////////////////////json
static const char *json_file="/root/zvfs/hello_blob.json";
static void json_app_load_done(int rc,void *ctx){
    bool *done=ctx;
    *done=true;
}
//加载json配置
static void zvfs_json_load_fn(void *arg) {
	spdk_subsystem_init_from_json_config(json_file, SPDK_DEFAULT_RPC_ADDR, json_app_load_done, arg, true);
}

////////////////////////////////文件描述符管理器

//文件描述符（File Descriptor）管理器的实现，用于管理打开的文件描述符
#define MAX_FD_COUNT 1024  //最大文件描述符数量为1024
#define DEFAULT_FD_NUM 3   //定义了默认文件描述符起始编号为3

//声明了一个指针数组，用于存储对应文件描述符的文件对象
zvfs_file_t *files[MAX_FD_COUNT] = {0};
static unsigned fd_table[MAX_FD_COUNT / 8] = {0};
//声明了一个位图数组，用于标记哪些文件描述符已被占用

static int zvfs_get_fd(void) {
    int fd = DEFAULT_FD_NUM;
	for ( ; fd < MAX_FD_COUNT; fd++) {
		if ((fd_table[fd/8] & (0x1 << (fd % 8))) == 0) {
			fd_table[fd/8] |= (0x1 << (fd % 8));
			return fd;
		}
	}
	return -1;
}

static void zvfs_set_fd(int fd) {
	if (fd >= MAX_FD_COUNT) return ; // errno
	fd_table[fd/8] &= ~(0x1 << fd % 8);
}

////////////////////////////////文件系统初始化
static int zvfs_filesystem_setup(void){
    struct spdk_env_opts opts;  //声明一个类型为spdk_env_opts的结构体变量opts
    spdk_env_opts_init(&opts);  //初始化SPDK环境选项结构体
    if (spdk_env_init(&opts) != 0) {
		return -1;
	}
    spdk_log_set_print_level(SPDK_LOG_NOTICE);
	spdk_log_set_level(SPDK_LOG_NOTICE);
	spdk_log_open(NULL);
    zvfs_filesystem_t *fs = calloc(1, sizeof(zvfs_filesystem_t));
    if (!fs) {
		return 0;
	}
	fs_instance = fs;
    spdk_thread_lib_init(NULL, 0);  //初始化SPDK线程库，创建一个默认线程池
    //创建名为“global”的线程，并将其保存在文件系统对象中的线程指针中
    fs->thread=spdk_thread_create("global",NULL);
    spdk_set_thread(fs->thread);  //设置当前线程为新创建的线程，用于后续操作执行
    
    bool done = false;  // load_config
	poller(fs->thread, zvfs_json_load_fn, &done, &done);

    fs->finished = false;  // filesystem_register;
	poller(fs->thread, zvfs_entry, fs, &fs->finished);

    return 0;
}

static int zvfs_create(const char *pathname,int flags){
    if(!fs_instance){
        zvfs_filesystem_setup();
    }
    //先获取再分配
    int fd=zvfs_get_fd();
    zvfs_file_t *file=calloc(1,sizeof(zvfs_file_t));
    if (!file) {
		return -1;
	}

    strcpy(file->filename,pathname);
    files[fd]=file;
    file->fs=fs_instance;

    zvfs_file_create(file);
    return fd;
}

///////////////////////////////zvfs的具体接口
static ssize_t zvfs_write(int fd, const void *buf, size_t count) {

	zvfs_file_t *file = files[fd];
	if(!file) return -1;
	
	memcpy(file->write_buffer, buf, count);
	zvfs_file_write(file);

	return 0;
}

static ssize_t zvfs_read(int fd, void *buf, size_t count) {

	zvfs_file_t *file = files[fd];
	if(!file) return -1;

	zvfs_file_read(file);
	memcpy(buf, file->read_buffer, count);

	return 0;

}

static int zvfs_close(int fd) {

	zvfs_file_t *file = files[fd];
	if (!file) return 0;

	zvfs_file_close(file);
	zvfs_set_fd(fd);

	free(file);
	files[fd] = NULL;

	return 0;
}

///////////////////////////////hook
/// hook
#include <dlfcn.h>


#define DEBUG_ENABLE	1

#if DEBUG_ENABLE
#define dblog(fmt, ...) printf(fmt, ##__VA_ARGS__)
#else
#define dblog(fmt, ...)
#endif

typedef int (*open_t)(const char *pathname, int flags);
open_t open_f = NULL;

typedef ssize_t (*write_t)(int fd, const void *buf, size_t n);
write_t write_f = NULL;

typedef ssize_t (*read_t)(int fd, void *buf, size_t n);
read_t read_f = NULL;

typedef int (*close_t)(int fd);
close_t close_f = NULL;

int open(const char *pathname, int flags, ...) {

	if (!open_f) {
		open_f = dlsym(RTLD_NEXT, "open");
	}

	dblog("open.. %s\n", pathname);

	return open_f(pathname, flags);
}

ssize_t read(int fd, void *buf, size_t count) {

	ssize_t ret;

	if (!read_f) {
		read_f = dlsym(RTLD_NEXT, "read");
	}

	ret = read_f(fd, buf, count);
	dblog("read.. : %ld, %ld\n", ret, count);

	return ret;
}

ssize_t write(int fd, const void *buf, size_t count) {

	if (!write_f) {
		write_f = dlsym(RTLD_NEXT, "write");
	}

	dblog("write.. : %ld\n", count);

	return write_f(fd, buf, count);

}

int close(int fd) {

	if (!close_f) {
		close_f = dlsym(RTLD_NEXT, "close");
	}

	dblog("close..\n");

	return close_f(fd);

}


///////////////////////////////main
#if 0
int main(int argc,char *argv[]){
    printf("hello spdk\n");
    int fd = open("a.txt", O_RDWR | O_CREAT);
    char *wbuffer = "zvoice.jerry"; 
	int ret = write(fd, wbuffer, strlen(wbuffer));
	char rbuffer[1024] = {0};
	ret = read(fd, rbuffer, 1024);
	printf("ret: %d, rbuffer: %s\n", ret, rbuffer);
	close(fd);
    return 0;
}
#endif