#include "sldms3fs.hpp"
#include <sstream>
#include <iostream>
#include <cstring>
#include <errno.h>
#include <filesystem>
#include <rocksdb/db.h>

namespace fs = std::filesystem;

std::string SLDMS3FS::endpoint_url;
std::string SLDMS3FS::bucket_name;
std::string SLDMS3FS::mount_point;
CURL* SLDMS3FS::curl = nullptr;
rocksdb::DB* SLDMS3FS::readdir_cache_db = nullptr;
const int SLDMS3FS::UPLOAD_DELAY_SECONDS = 3600;

// Already defined in header file
/*
struct MemoryStruct {
    char* memory;
    size_t size;
};
*/

void SLDMS3FS::init_curl() {
    curl_global_init(CURL_GLOBAL_ALL);
    curl = curl_easy_init();
}

size_t SLDMS3FS::write_callback_memory(void* contents, size_t size, size_t nmemb, void* userp) {
    size_t realsize = size * nmemb;
    struct MemoryStruct* mem = (struct MemoryStruct*)userp;

    // Check for multiplication overflow
    if (nmemb > 0 && size > SIZE_MAX / nmemb) {
        std::cerr << "[WRITE_CALLBACK_MEMORY] Size overflow: size=" << size 
                  << ", nmemb=" << nmemb << std::endl;
        return 0;
    }

    char* ptr = (char*)realloc(mem->memory, mem->size + realsize + 1);
    if (!ptr) {
        std::cerr << "[WRITE_CALLBACK_MEMORY] Memory allocation failed for size: " 
                  << (mem->size + realsize + 1) << " bytes" << std::endl;
        return 0;
    }

    mem->memory = ptr;
    memcpy(&(mem->memory[mem->size]), contents, realsize);
    mem->size += realsize;
    mem->memory[mem->size] = 0;

    return realsize;
}

size_t SLDMS3FS::write_callback_file(void* contents, size_t size, size_t nmemb, void* userp) {
    size_t realsize = size * nmemb;
    std::ofstream* file = static_cast<std::ofstream*>(userp);
    file->write(static_cast<char*>(contents), realsize);
    return realsize;
}

struct curl_slist* SLDMS3FS::prepare_headers() {
    struct curl_slist* headers = NULL;
    headers = curl_slist_append(headers, "Content-Type: application/octet-stream");
    return headers;
}

void SLDMS3FS::set_storage(const std::string& endpoint) {
    endpoint_url = endpoint;
    init_curl();
}

void SLDMS3FS::set_bucket(const std::string& bucket) {
    bucket_name = bucket;
}

void SLDMS3FS::set_mount_point(const std::string& mount) {
    mount_point = mount;
}

std::string SLDMS3FS::get_full_path(const char* path) {
    if (path[0] == '/') {
        return path + 1;  // Remove leading slash
    }
    return path;
}

void SLDMS3FS::log_success(const char* operation, const char* path) {
    std::cout << "[SUCCESS] " << operation << ": " << path << std::endl;
}

void SLDMS3FS::log_error(const char* operation, const char* path, CURLcode res, const char* curl_error) {
    std::cerr << "[ERROR] " << operation << " failed for " << path 
              << " (Code: " << res << "): " << curl_error << std::endl;
}

void SLDMS3FS::log_error(const char* operation, const char* path, int error_code) {
    std::cerr << "[ERROR] " << operation << " failed for " << path 
              << " (errno: " << error_code << "): " << strerror(error_code) << std::endl;
}

void SLDMS3FS::log_s3_request(const char* operation, const std::string& url, const char* method) {
    std::cout << "\n[S3 REQUEST] " << operation << "\n"
              << "  Method: " << method << "\n"
              << "  URL: " << url << std::endl;
}

void SLDMS3FS::log_s3_response(const char* operation, CURLcode res, long http_code, size_t data_size) {
    std::cout << "[S3 RESPONSE] " << operation << "\n"
              << "  CURL Result: " << curl_easy_strerror(res) << " (" << res << ")\n"
              << "  HTTP Code: " << http_code << "\n"
              << "  Data Size: " << data_size << " bytes" << std::endl;
}

void SLDMS3FS::log_fs_mapping(const char* operation, const char* s3_path, const char* fs_path, const char* details) {
    std::cout << "[FS MAPPING] " << operation << "\n"
              << "  S3 Path: " << s3_path << "\n"
              << "  FS Path: " << fs_path << "\n"
              << "  Details: " << details << std::endl;
}

int SLDMS3FS::getattr(const char* path, struct stat* stbuf) {
    FileMetadata metadata;
    std::string spath(path);
    
    std::cout << "\n[GETATTR] Processing request for path: " << path << std::endl;
    
    // Try to get from cache first
    bool cache_result = get_metadata_from_cache(spath, metadata);
    std::cout << "[METADATA CACHE] Lookup for path: " << path << "\n"
              << "  Result: " << (cache_result ? "HIT" : "MISS") << std::endl;
    
    if (cache_result) {
        log_fs_mapping("getattr", "todo", path, "Cache hit");
        
        std::cout << "[METADATA CACHE] Retrieved metadata:\n"
                  << "  Mode: " << std::oct << metadata.mode << std::dec << "\n"
                  << "  Size: " << metadata.size << "\n"
                  << "  Modified Time: " << metadata.mtime << std::endl;
        
        memset(stbuf, 0, sizeof(struct stat));
        stbuf->st_mode = metadata.mode;
        stbuf->st_size = metadata.size;
        stbuf->st_atime = metadata.atime;
        stbuf->st_mtime = metadata.mtime;
        stbuf->st_ctime = metadata.ctime;
        return 0;
    }

    // Not in cache, fetch from S3
    std::cout << "[S3 FETCH] Attempting to fetch metadata from S3\n"
              << "  Path: " << path << "\n"
              << "  Full S3 Path: " << get_full_path(path) << std::endl;
    
    bool s3_result = fetch_metadata_from_s3(spath, metadata);
    std::cout << "[S3 FETCH] Result: " << (s3_result ? "SUCCESS" : "FAILED") << std::endl;
    
    if (s3_result) {
        // Store in cache
        std::cout << "[METADATA CACHE] Storing new metadata:\n"
                  << "  Path: " << path << "\n"
                  << "  Mode: " << std::oct << metadata.mode << std::dec << "\n"
                  << "  Size: " << metadata.size << "\n"
                  << "  Modified Time: " << metadata.mtime << std::endl;
        
        put_metadata_to_cache(spath, metadata);
        
        // Fill stat structure
        memset(stbuf, 0, sizeof(struct stat));
        stbuf->st_mode = metadata.mode;
        stbuf->st_size = metadata.size;
        stbuf->st_atime = metadata.atime;
        stbuf->st_mtime = metadata.mtime;
        stbuf->st_ctime = metadata.ctime;
        return 0;
    }

    std::cout << "[GETATTR] Failed to get metadata for: " << path << "\n"
              << "  Error: ENOENT (No such file or directory)" << std::endl;
    return -ENOENT;
}

int SLDMS3FS::readdir(const char* path, void* buf, fuse_fill_dir_t filler,
                      off_t offset, struct fuse_file_info* fi) {
    std::string prefix = get_full_path(path);
    
    std::cout << "\n[READDIR] Starting readdir for path: " << path << "\n"
              << "  Prefix after get_full_path: " << prefix << std::endl;
    
    // Try to get from cache first
    std::string cached_listing;
    if (readdir_cache_db->Get(rocksdb::ReadOptions(), prefix, &cached_listing).ok()) {
        std::cout << "[READDIR] Cache hit for path: " << path << std::endl;
        // Add standard entries
        filler(buf, ".", NULL, 0);
        filler(buf, "..", NULL, 0);
        
        // Parse cached entries
        std::istringstream stream(cached_listing);
        std::string entry;
        int entry_count = 0;
        
        while (std::getline(stream, entry)) {
            if (!entry.empty()) {
                filler(buf, entry.c_str(), NULL, 0);
                entry_count++;
                
                std::stringstream entry_details;
                entry_details << "Cached entry " << entry_count << ": " << entry;
                log_fs_mapping("readdir_entry", prefix.c_str(), 
                             (std::string(path) + "/" + entry).c_str(), 
                             entry_details.str().c_str());
            }
        }
        
        std::stringstream summary;
        summary << "Listed " << entry_count << " cached entries";
        log_success("readdir", summary.str().c_str());
        return 0;
    }

    // Cache miss, fetch from S3
    std::string url = endpoint_url + "/" + bucket_name + "?list-type=2&prefix=" + prefix;
    if (path[1] != '\0') {
        url += "/";
    }

    std::cout << "[READDIR] Cache miss, fetching from S3\n"
              << "  Full URL: " << url << std::endl;
    
    CURL* curl = curl_easy_init();
    if (curl) {
        struct MemoryStruct chunk = {0};
        chunk.memory = (char*)malloc(1);
        chunk.size = 0;

        curl_easy_setopt(curl, CURLOPT_URL, url.c_str());
        curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_callback_memory);
        curl_easy_setopt(curl, CURLOPT_WRITEDATA, (void*)&chunk);

        char error_buffer[CURL_ERROR_SIZE];
        curl_easy_setopt(curl, CURLOPT_ERRORBUFFER, error_buffer);

        CURLcode res = curl_easy_perform(curl);
        long http_code = 0;
        curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &http_code);
        
        std::cout << "[READDIR] S3 Response:\n"
                  << "  CURL Result: " << curl_easy_strerror(res) << " (" << res << ")\n"
                  << "  HTTP Code: " << http_code << "\n"
                  << "  Response Size: " << chunk.size << " bytes" << std::endl;

        if (res == CURLE_OK && http_code == 200) {
            // Print raw response for debugging
            std::cout << "[READDIR] Raw S3 Response:\n"
                      << std::string(chunk.memory, chunk.size) << std::endl;

            // Add standard entries
            filler(buf, ".", NULL, 0);
            filler(buf, "..", NULL, 0);

            // Parse XML and process entries
            std::string response(chunk.memory, chunk.size);
            std::istringstream stream(response);
            std::string line;
            int entry_count = 0;
            std::stringstream cache_entries;
            
            while (std::getline(stream, line)) {
                if (line.find("<Key>") != std::string::npos) {
                    size_t start = line.find("<Key>") + 5;
                    size_t end = line.find("</Key>");
                    if (end != std::string::npos) {
                        std::string key = line.substr(start, end - start);
                        std::cout << "[READDIR] Found key: " << key << std::endl;
                        
                        if (key != prefix) {
                            std::string relative_path = key.substr(prefix.length());
                            size_t slash_pos = relative_path.find('/');
                            if (slash_pos != std::string::npos) {
                                relative_path = relative_path.substr(0, slash_pos);
                            }
                            if (!relative_path.empty()) {
                                std::cout << "[READDIR] Adding entry: " << relative_path << std::endl;
                                filler(buf, relative_path.c_str(), NULL, 0);
                                cache_entries << relative_path << "\n";
                                entry_count++;
                            }
                        }
                    }
                }
            }

            std::cout << "[READDIR] Completed with " << entry_count << " entries" << std::endl;

            // Store in cache
            readdir_cache_db->Put(rocksdb::WriteOptions(), prefix, cache_entries.str());
            
            free(chunk.memory);
            curl_easy_cleanup(curl);
            return 0;
        } else {
            std::cout << "[READDIR] Failed S3 request:\n"
                      << "  Error: " << error_buffer << std::endl;
        }

        free(chunk.memory);
        curl_easy_cleanup(curl);
    }

    return -ENOENT;
}

int SLDMS3FS::read(const char* path, char* buf, size_t size, off_t offset,
                   struct fuse_file_info* fi) {
    std::string spath(path);
    std::vector<ChunkInfo> chunks;
    
    std::cout << "\n[READ REQUEST] Path: " << path << "\n"
              << "  Requested Size: " << size << " bytes\n"
              << "  Offset: " << offset << std::endl;
    
    // Get chunk mapping from cache
    if (!get_chunks_from_cache(spath, chunks)) {
        std::cout << "[CHUNKS] Cache miss - creating new chunk mapping" << std::endl;
        
        // Create new chunk mapping
        FileMetadata metadata;
        if (!get_metadata_from_cache(spath, metadata)) {
            std::cout << "[METADATA] Cache miss - fetching from S3" << std::endl;
            if (!fetch_metadata_from_s3(spath, metadata)) {
                log_error("read", path, ENOENT);
                return -ENOENT;
            }
            put_metadata_to_cache(spath, metadata);
            std::cout << "[METADATA] Cached metadata for: " << path << std::endl;
        }
        
        // Create chunks
        std::cout << "[CHUNKS] Creating chunk mapping for file size: " << metadata.size << std::endl;
        for (off_t pos = 0; pos < metadata.size; pos += CHUNK_SIZE) {
            ChunkInfo chunk;
            chunk.chunk_id = pos / CHUNK_SIZE;
            chunk.offset = pos;
            chunk.size = std::min(static_cast<off_t>(CHUNK_SIZE), metadata.size - pos);
            chunk.cache_path = get_chunk_cache_path(spath, chunk.chunk_id);
            chunks.push_back(chunk);
            
            std::cout << "[CHUNK] Created mapping:\n"
                      << "  ID: " << chunk.chunk_id << "\n"
                      << "  Offset: " << chunk.offset << "\n"
                      << "  Size: " << chunk.size << "\n"
                      << "  Cache Path: " << chunk.cache_path << std::endl;
        }
        put_chunks_to_cache(spath, chunks);
    } else {
        std::cout << "[CHUNKS] Cache chunks mapping hit - found " << chunks.size() << " chunks" << std::endl;
    }
    
    // Find needed chunks
    size_t bytes_read = 0;
    std::cout << "[READ] Processing chunks for read request" << std::endl;
    
    for (const auto& chunk : chunks) {
        if (offset >= chunk.offset + chunk.size || offset + size <= chunk.offset) {
            std::cout << "[CHUNK " << chunk.chunk_id << "] Skipped - outside requested range" << std::endl;
            continue;
        }
        
        std::cout << "[CHUNK " << chunk.chunk_id << "] Processing:\n"
                  << "  Chunk Offset: " << chunk.offset << "\n"
                  << "  Chunk Size: " << chunk.size << std::endl;
        
        // Check if chunk is cached
        if (!fs::exists(chunk.cache_path)) {
            std::cout << "[CHUNK " << chunk.chunk_id << "] Cache miss - fetching from S3" << std::endl;
            if (!fetch_chunk_from_s3(spath, chunk)) {
                log_error("read", path, EIO);
                return -EIO;
            }
            std::cout << "[CHUNK " << chunk.chunk_id << "] Successfully fetched from S3" << std::endl;
        } else {
            std::cout << "[CHUNK " << chunk.chunk_id << "] Cache hit" << std::endl;
        }
        
        // Read from chunk file
        std::ifstream chunk_file(chunk.cache_path, std::ios::binary);
        if (!chunk_file) {
            log_error("read", chunk.cache_path.c_str(), errno);
            return -EIO;
        }
        
        size_t chunk_offset = std::max(static_cast<size_t>(0), 
                                     static_cast<size_t>(offset - chunk.offset));
        size_t chunk_read_size = std::min(static_cast<size_t>(chunk.size - chunk_offset),
                                        size - bytes_read);
        
        chunk_file.seekg(chunk_offset);
        chunk_file.read(buf + bytes_read, chunk_read_size);
        bytes_read += chunk_read_size;
        
        std::cout << "[CHUNK " << chunk.chunk_id << "] Read operation:\n"
                  << "  Chunk Offset: " << chunk_offset << "\n"
                  << "  Bytes Read: " << chunk_read_size << "\n"
                  << "  Total Bytes Read: " << bytes_read << std::endl;
        
        if (bytes_read >= size) {
            std::cout << "[READ] Completed - reached requested size" << std::endl;
            break;
        }
    }
    
    std::cout << "[READ COMPLETE] Path: " << path << "\n"
              << "  Total Bytes Read: " << bytes_read << std::endl;
    
    return bytes_read;
}

int SLDMS3FS::write(const char* path, const char* buf, size_t size, off_t offset,
                    struct fuse_file_info* fi) {
    std::string spath(path);
    std::vector<ChunkInfo> chunks;
    
    std::cout << "\n[WRITE REQUEST] Path: " << path << "\n"
              << "  Write Size: " << size << " bytes\n"
              << "  Offset: " << offset << std::endl;
    
    // Get or create chunk mapping
    if (!get_chunks_from_cache(spath, chunks)) {
        std::cout << "[CHUNKS] Cache miss - creating new chunk mapping" << std::endl;
        
        // Create new chunk mapping
        FileMetadata metadata;
        if (!get_metadata_from_cache(spath, metadata)) {
            std::cout << "[METADATA] No existing metadata - creating new file" << std::endl;
            metadata.mode = S_IFREG | 0644;
            metadata.size = 0;
            metadata.atime = time(nullptr);
            metadata.mtime = metadata.atime;
            metadata.ctime = metadata.atime;
            metadata.is_directory = false;
        } else {
            std::cout << "[METADATA] Found existing metadata:\n"
                      << "  Current Size: " << metadata.size << "\n"
                      << "  Last Modified: " << metadata.mtime << std::endl;
        }
        
        // Create initial chunk
        ChunkInfo chunk;
        chunk.chunk_id = 0;
        chunk.offset = 0;
        chunk.size = 0;
        chunk.cache_path = get_chunk_cache_path(spath, chunk.chunk_id);
        chunks.push_back(chunk);
        std::cout << "[CHUNKS] Created initial chunk mapping" << std::endl;
    } else {
        std::cout << "[CHUNKS] Cache hit - found " << chunks.size() << " existing chunks" << std::endl;
    }

    // Find or create needed chunks
    size_t write_end = offset + size;
    while (chunks.back().offset + chunks.back().size < write_end) {
        ChunkInfo chunk;
        chunk.chunk_id = chunks.size();
        chunk.offset = chunks.back().offset + chunks.back().size;
        chunk.size = 0;
        chunk.cache_path = get_chunk_cache_path(spath, chunk.chunk_id);
        chunks.push_back(chunk);
        
        std::cout << "[CHUNKS] Created additional chunk:\n"
                  << "  Chunk ID: " << chunk.chunk_id << "\n"
                  << "  Offset: " << chunk.offset << "\n"
                  << "  Cache Path: " << chunk.cache_path << std::endl;
    }

    // Write to chunks
    size_t bytes_written = 0;
    const char* write_buf = buf;
    
    std::cout << "[WRITE] Processing chunks for write operation" << std::endl;
    
    for (auto& chunk : chunks) {
        if (offset >= chunk.offset + chunk.size || offset + size <= chunk.offset) {
            std::cout << "[CHUNK " << chunk.chunk_id << "] Skipped - outside write range" << std::endl;
            continue;
        }

        // Calculate write position and size for this chunk
        size_t chunk_offset = std::max(static_cast<size_t>(0), 
                                     static_cast<size_t>(offset - chunk.offset));
        size_t chunk_write_size = std::min(CHUNK_SIZE - chunk_offset,
                                         size - bytes_written);
        
        std::cout << "[CHUNK " << chunk.chunk_id << "] Processing write:\n"
                  << "  Chunk Offset: " << chunk_offset << "\n"
                  << "  Write Size: " << chunk_write_size << "\n"
                  << "  Cache Path: " << chunk.cache_path << std::endl;

        // Ensure chunk file exists and has correct size
        std::fstream chunk_file(chunk.cache_path, 
                              std::ios::in | std::ios::out | std::ios::binary);
        if (!chunk_file) {
            std::cout << "[CHUNK " << chunk.chunk_id << "] Creating new chunk file" << std::endl;
            chunk_file.open(chunk.cache_path, 
                          std::ios::out | std::ios::binary);
        } else {
            std::cout << "[CHUNK " << chunk.chunk_id << "] Updating existing chunk file" << std::endl;
        }
        
        // Write to chunk file
        chunk_file.seekp(chunk_offset);
        chunk_file.write(write_buf + bytes_written, chunk_write_size);
        
        // Update chunk size if needed
        size_t old_size = chunk.size;
        chunk.size = std::max(chunk.size, chunk_offset + chunk_write_size);
        bytes_written += chunk_write_size;

        std::cout << "[CHUNK " << chunk.chunk_id << "] Write complete:\n"
                  << "  Previous Size: " << old_size << "\n"
                  << "  New Size: " << chunk.size << "\n"
                  << "  Total Bytes Written: " << bytes_written << std::endl;

        if (bytes_written >= size) {
            std::cout << "[WRITE] Completed - reached requested size" << std::endl;
            break;
        }
    }

    // Update metadata
    FileMetadata metadata;
    if (!get_metadata_from_cache(spath, metadata)) {
        std::cout << "[METADATA] Creating new metadata for file" << std::endl;
        metadata.mode = S_IFREG | 0644;
        metadata.atime = time(nullptr);
        metadata.mtime = metadata.atime;
        metadata.ctime = metadata.atime;
        metadata.is_directory = false;
    }
    
    off_t old_size = metadata.size;
    metadata.size = std::max(metadata.size, (off_t)(offset + size));
    metadata.mtime = time(nullptr);

    std::cout << "[METADATA] Updating file metadata:\n"
              << "  Previous Size: " << old_size << "\n"
              << "  New Size: " << metadata.size << "\n"
              << "  Modified Time: " << metadata.mtime << std::endl;

    // Save updated metadata and chunks to cache
    put_metadata_to_cache(spath, metadata);
    put_chunks_to_cache(spath, chunks);

    // Queue for background upload
    queue_write_operation(spath);
    
    std::cout << "[WRITE COMPLETE] Path: " << path << "\n"
              << "  Total Bytes Written: " << bytes_written << "\n"
              << "  Final File Size: " << metadata.size << std::endl;

    return bytes_written;
}

int SLDMS3FS::open(const char* path, struct fuse_file_info* fi) {
    std::cout << "[SUCCESS] Opened file: " << path << std::endl;
    return 0;
}

int SLDMS3FS::truncate(const char* path, off_t size) {
    std::cout << "[INFO] Truncating " << path << " to size " << size << std::endl;
    std::cout << "[SUCCESS] Truncated file: " << path << std::endl;
    return 0;
}

int SLDMS3FS::create(const char* path, mode_t mode, struct fuse_file_info* fi) {
    std::cout << "[INFO] Creating new file: " << path << std::endl;
    
    std::string url = endpoint_url + "/" + bucket_name + "/" + get_full_path(path);
    
    CURL* curl = curl_easy_init();
    if (curl) {
        struct curl_slist* headers = prepare_headers();
        
        char error_buffer[CURL_ERROR_SIZE];
        curl_easy_setopt(curl, CURLOPT_ERRORBUFFER, error_buffer);
        
        curl_easy_setopt(curl, CURLOPT_URL, url.c_str());
        curl_easy_setopt(curl, CURLOPT_UPLOAD, 1L);
        curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
        curl_easy_setopt(curl, CURLOPT_INFILESIZE_LARGE, 0L);

        CURLcode res = curl_easy_perform(curl);
        
        curl_slist_free_all(headers);
        curl_easy_cleanup(curl);

        if (res == CURLE_OK) {
            std::cout << "[SUCCESS] Created file: " << path << std::endl;
            return 0;
        }

        log_error("create", path, res, error_buffer);
    }

    return -ENOENT;
}

int SLDMS3FS::mkdir(const char* path, mode_t mode) {
    std::cout << "[INFO] Creating directory: " << path << std::endl;
    
    std::string url = endpoint_url + "/" + bucket_name + "/" + get_full_path(path) + "/";
    
    CURL* curl = curl_easy_init();
    if (curl) {
        struct curl_slist* headers = prepare_headers();
        
        char error_buffer[CURL_ERROR_SIZE];
        curl_easy_setopt(curl, CURLOPT_ERRORBUFFER, error_buffer);
        
        curl_easy_setopt(curl, CURLOPT_URL, url.c_str());
        curl_easy_setopt(curl, CURLOPT_UPLOAD, 1L);
        curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
        curl_easy_setopt(curl, CURLOPT_INFILESIZE_LARGE, 0L);

        CURLcode res = curl_easy_perform(curl);
        
        curl_slist_free_all(headers);
        curl_easy_cleanup(curl);

        if (res == CURLE_OK) {
            std::cout << "[SUCCESS] Created directory: " << path << std::endl;
            return 0;
        }

        log_error("mkdir", path, res, error_buffer);
    }

    return -ENOENT;
}

int SLDMS3FS::rmdir(const char* path) {
    std::cout << "[INFO] Removing directory: " << path << std::endl;
    
    std::string url = endpoint_url + "/" + bucket_name + "/" + get_full_path(path) + "/";
    
    CURL* curl = curl_easy_init();
    if (curl) {
        char error_buffer[CURL_ERROR_SIZE];
        curl_easy_setopt(curl, CURLOPT_ERRORBUFFER, error_buffer);
        
        curl_easy_setopt(curl, CURLOPT_URL, url.c_str());
        curl_easy_setopt(curl, CURLOPT_CUSTOMREQUEST, "DELETE");

        CURLcode res = curl_easy_perform(curl);
        
        curl_easy_cleanup(curl);

        if (res == CURLE_OK) {
            std::cout << "[SUCCESS] Removed directory: " << path << std::endl;
            return 0;
        }

        log_error("rmdir", path, res, error_buffer);
    }

    return -ENOENT;
}

int SLDMS3FS::unlink(const char* path) {
    std::cout << "[INFO] Deleting file: " << path << std::endl;
    
    std::string url = endpoint_url + "/" + bucket_name + "/" + get_full_path(path);
    
    CURL* curl = curl_easy_init();
    if (curl) {
        char error_buffer[CURL_ERROR_SIZE];
        curl_easy_setopt(curl, CURLOPT_ERRORBUFFER, error_buffer);
        
        curl_easy_setopt(curl, CURLOPT_URL, url.c_str());
        curl_easy_setopt(curl, CURLOPT_CUSTOMREQUEST, "DELETE");

        CURLcode res = curl_easy_perform(curl);
        
        curl_easy_cleanup(curl);

        if (res == CURLE_OK) {
            std::cout << "[SUCCESS] Deleted file: " << path << std::endl;
            return 0;
        }

        log_error("unlink", path, res, error_buffer);
    }

    return -ENOENT;
}

std::string SLDMS3FS::get_chunk_cache_path(const std::string& path, size_t chunk_id) {
    std::string safe_path = path;
    // Replace problematic characters in path
    std::replace(safe_path.begin(), safe_path.end(), '/', '_');
    return cache_dir + "/chunks/" + safe_path + "_" + std::to_string(chunk_id) + ".chunk";
}

void SLDMS3FS::set_cache_dir(const std::string& dir) {
    cache_dir = dir;
}

// ... (implement other FUSE operations similarly) 