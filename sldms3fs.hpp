#pragma once

#define FUSE_USE_VERSION 26

#include <fuse.h>
#include <curl/curl.h>
#include <rocksdb/db.h>
#include <iostream>
#include <string>
#include <memory>
#include <vector>
#include <map>
#include <thread>
#include <mutex>
#include <condition_variable>
#include <atomic>
#include <queue>
#include <fstream>
#include <algorithm>
#include <set>

// Define chunk size (e.g., 1MB) as off_t type
#define CHUNK_SIZE (static_cast<off_t>(1 * 1024 * 1024))

struct FileMetadata {
    mode_t mode;
    off_t size;
    time_t atime;
    time_t mtime;
    time_t ctime;
    bool is_directory;
    std::string etag;  // For consistency checking
};

struct ChunkInfo {
    size_t chunk_id;
    size_t offset;
    size_t size;
    std::string cache_path;  // Path to cached chunk file
};

struct WriteOperation {
    std::string path;
    time_t timestamp;
    bool dirty;  // true if needs to be uploaded to S3
};

// Add these structures for directory caching
struct DirectoryEntry {
    std::string name;
    bool is_directory;
    size_t size;
    time_t mtime;
};

struct DirectoryListing {
    std::string path;
    time_t last_updated;
    std::vector<DirectoryEntry> entries;
    std::string etag;  // For consistency checking with S3
};

// Add this structure definition before the SLDMS3FS class
struct MemoryStruct {
    char* memory;
    size_t size;
};

class SLDMS3FS {
private:
    static std::string endpoint_url;
    static std::string bucket_name;
    static std::string mount_point;
    static std::string cache_dir;    // Directory for chunk cache files
    static CURL* curl;
    static rocksdb::DB* db;
    static rocksdb::DB* readdir_cache_db;  // Add this line

    // RocksDB column families
    static rocksdb::ColumnFamilyHandle* cf_metadata;
    static rocksdb::ColumnFamilyHandle* cf_chunks;
    static rocksdb::ColumnFamilyHandle* cf_directory;

    // Helper methods
    static std::string get_full_path(const char* path);
    static void init_curl();
    static void init_rocksdb();
    static std::string get_chunk_cache_path(const std::string& path, size_t chunk_id);
    
    // Add this callback function declaration
    static size_t write_callback(void* contents, size_t size, size_t nmemb, void* userp);
    static struct curl_slist* prepare_headers();

    // Cache operations
    static bool get_metadata_from_cache(const std::string& path, FileMetadata& metadata);
    static void put_metadata_to_cache(const std::string& path, const FileMetadata& metadata);
    static bool get_chunks_from_cache(const std::string& path, std::vector<ChunkInfo>& chunks);
    static void put_chunks_to_cache(const std::string& path, const std::vector<ChunkInfo>& chunks);
    
    // Original directory cache functions
    static bool get_directory_from_cache(const std::string& path, std::vector<std::string>& entries);
    static void put_directory_to_cache(const std::string& path, const std::vector<std::string>& entries);
    
    // New directory listing cache functions
    static bool get_directory_listing_from_cache(const std::string& path, DirectoryListing& listing);
    static void put_directory_listing_to_cache(const std::string& path, const DirectoryListing& listing);

    // S3 operations
    static bool fetch_metadata_from_s3(const std::string& path, FileMetadata& metadata);
    static bool fetch_chunk_from_s3(const std::string& path, const ChunkInfo& chunk);
    static bool fetch_directory_from_s3(const std::string& path, std::vector<std::string>& entries);

    // Background thread methods
    static void background_upload_thread();
    static void queue_write_operation(const std::string& path);
    static bool upload_to_s3(const std::string& path);

    // Add these new members to the private section:
    static std::thread background_thread;
    static std::mutex write_mutex;
    static std::condition_variable write_cv;
    static std::atomic<bool> should_stop;
    static std::queue<WriteOperation> write_queue;
    static const int UPLOAD_DELAY_SECONDS;  // Add this line
    static const int DIRECTORY_CACHE_TTL = 60;  // Directory cache timeout in seconds

    // Add logging helper methods
    static void log_success(const char* operation, const char* path);
    static void log_error(const char* operation, const char* path, CURLcode res, const char* curl_error);
    static void log_error(const char* operation, const char* path, int error_code);
    static void log_s3_request(const char* operation, const std::string& url, const char* method);
    static void log_s3_response(const char* operation, CURLcode res, long http_code, size_t data_size);
    static void log_fs_mapping(const char* operation, const char* s3_path, const char* fs_path, const char* details);

    // Existing helper methods...

    static size_t write_callback_memory(void* contents, size_t size, size_t nmemb, void* userp);
    static size_t write_callback_file(void* contents, size_t size, size_t nmemb, void* userp);

public:
    static void set_storage(const std::string& endpoint);
    static void set_bucket(const std::string& bucket);
    static void set_mount_point(const std::string& mount);
    static void set_cache_dir(const std::string& dir);
    static bool initialize();
    static void cleanup();

    // FUSE operations
    static int getattr(const char* path, struct stat* stbuf);
    static int readdir(const char* path, void* buf, fuse_fill_dir_t filler,
                      off_t offset, struct fuse_file_info* fi);
    static int open(const char* path, struct fuse_file_info* fi);
    static int read(const char* path, char* buf, size_t size, off_t offset,
                   struct fuse_file_info* fi);
    static int write(const char* path, const char* buf, size_t size, off_t offset,
                    struct fuse_file_info* fi);
    static int truncate(const char* path, off_t size);
    static int create(const char* path, mode_t mode, struct fuse_file_info* fi);
    static int mkdir(const char* path, mode_t mode);
    static int rmdir(const char* path);
    static int unlink(const char* path);
}; 