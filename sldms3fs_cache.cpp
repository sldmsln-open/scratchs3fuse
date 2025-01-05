#include "sldms3fs.hpp"
#include <sstream>
#include <filesystem>
#include <rocksdb/options.h>
#include <rocksdb/utilities/options_util.h>

namespace fs = std::filesystem;

rocksdb::DB* SLDMS3FS::db = nullptr;
rocksdb::ColumnFamilyHandle* SLDMS3FS::cf_metadata = nullptr;
rocksdb::ColumnFamilyHandle* SLDMS3FS::cf_chunks = nullptr;
rocksdb::ColumnFamilyHandle* SLDMS3FS::cf_directory = nullptr;
std::string SLDMS3FS::cache_dir = "/mnt/nvme0n1/scratchsldms3fuse/cache";
std::thread SLDMS3FS::background_thread;
std::mutex SLDMS3FS::write_mutex;
std::condition_variable SLDMS3FS::write_cv;
std::atomic<bool> SLDMS3FS::should_stop(false);
std::queue<WriteOperation> SLDMS3FS::write_queue;

void SLDMS3FS::init_rocksdb() {
    // Create cache directories if they don't exist
    std::string chunks_dir = cache_dir + "/chunks";
    
    std::cout << "[INIT] Cleaning up cache directories:\n"
              << "  Cache dir: " << cache_dir << "\n"
              << "  Chunks dir: " << chunks_dir << std::endl;
              
    // Remove and recreate chunks directory
    try {
        if (fs::exists(chunks_dir)) {
            std::cout << "[CLEANUP] Removing existing chunks directory" << std::endl;
            fs::remove_all(chunks_dir);
        }
        fs::create_directories(chunks_dir);
        std::cout << "[INIT] Created chunks directory: " << chunks_dir << std::endl;
    } catch (const fs::filesystem_error& e) {
        std::cerr << "[ERROR] Failed to clean/create chunks directory: " 
                  << e.what() << std::endl;
    }

    // Delete existing database files
    std::string db_path = cache_dir + "/sldms3fs.db";
    std::string readdir_db_path = cache_dir + "/readdir.db";
    
    std::cout << "[ROCKSDB] Cleaning up existing databases:\n"
              << "  Main DB: " << db_path << "\n"
              << "  Readdir DB: " << readdir_db_path << std::endl;
              
    rocksdb::DestroyDB(db_path, rocksdb::Options());
    rocksdb::DestroyDB(readdir_db_path, rocksdb::Options());

    // Initialize main DB
    rocksdb::Options options;
    options.create_if_missing = true;
    options.create_missing_column_families = true;

    // Define column families
    std::vector<rocksdb::ColumnFamilyDescriptor> column_families;
    column_families.push_back(rocksdb::ColumnFamilyDescriptor(
        rocksdb::kDefaultColumnFamilyName, rocksdb::ColumnFamilyOptions()));
    column_families.push_back(rocksdb::ColumnFamilyDescriptor(
        "metadata", rocksdb::ColumnFamilyOptions()));
    column_families.push_back(rocksdb::ColumnFamilyDescriptor(
        "chunks", rocksdb::ColumnFamilyOptions()));
    column_families.push_back(rocksdb::ColumnFamilyDescriptor(
        "directory", rocksdb::ColumnFamilyOptions()));

    // Open main DB
    std::vector<rocksdb::ColumnFamilyHandle*> handles;
    std::cout << "[ROCKSDB] Creating new database instance" << std::endl;
    rocksdb::Status status = rocksdb::DB::Open(options, db_path, column_families, &handles, &db);

    if (status.ok()) {
        cf_metadata = handles[1];
        cf_chunks = handles[2];
        cf_directory = handles[3];
        std::cout << "[ROCKSDB] Successfully initialized main database" << std::endl;
    } else {
        std::cerr << "[ROCKSDB] Failed to open main RocksDB: " << status.ToString() << std::endl;
        return;
    }

    // Initialize readdir cache DB
    rocksdb::Options readdir_options;
    readdir_options.create_if_missing = true;
    
    std::cout << "[ROCKSDB] Creating readdir cache database" << std::endl;
    status = rocksdb::DB::Open(readdir_options, readdir_db_path, &readdir_cache_db);
    
    if (status.ok()) {
        std::cout << "[ROCKSDB] Successfully initialized readdir cache database" << std::endl;
    } else {
        std::cerr << "[ROCKSDB] Failed to open readdir cache DB: " << status.ToString() << std::endl;
    }
}

bool SLDMS3FS::initialize() {
    // Create cache directory if it doesn't exist
    fs::create_directories(cache_dir);
    fs::create_directories(cache_dir + "/chunks");
    
    init_rocksdb();
    init_curl();
    
    // Start background upload thread
    should_stop = false;
    background_thread = std::thread(&SLDMS3FS::background_upload_thread);
    
    return (db != nullptr);
}

void SLDMS3FS::cleanup() {
    // Stop background thread
    should_stop = true;
    write_cv.notify_one();
    if (background_thread.joinable()) {
        background_thread.join();
    }

    if (db) {
        delete cf_metadata;
        delete cf_chunks;
        delete cf_directory;
        delete db;
    }
}

// Add these logging helper functions
void log_cache_hit(const char* cf_name, const std::string& path) {
    std::cout << "[CACHE HIT] " << cf_name << ": " << path << std::endl;
}

void log_cache_miss(const char* cf_name, const std::string& path) {
    std::cout << "[CACHE MISS] " << cf_name << ": " << path << std::endl;
}

void log_cache_store(const char* cf_name, const std::string& path, size_t data_size) {
    std::cout << "[CACHE STORE] " << cf_name << ": " << path 
              << " (size: " << data_size << " bytes)" << std::endl;
}

// Cache operations implementations
bool SLDMS3FS::get_metadata_from_cache(const std::string& path, FileMetadata& metadata) {
    std::string value;
    rocksdb::Status status = db->Get(rocksdb::ReadOptions(), cf_metadata, path, &value);
    
    if (status.ok()) {
        std::istringstream is(value);
        
        // Deserialize POD members
        is.read(reinterpret_cast<char*>(&metadata.mode), sizeof(mode_t));
        is.read(reinterpret_cast<char*>(&metadata.size), sizeof(off_t));
        is.read(reinterpret_cast<char*>(&metadata.atime), sizeof(time_t));
        is.read(reinterpret_cast<char*>(&metadata.mtime), sizeof(time_t));
        is.read(reinterpret_cast<char*>(&metadata.ctime), sizeof(time_t));
        is.read(reinterpret_cast<char*>(&metadata.is_directory), sizeof(bool));
        
        // Deserialize string properly
        size_t etag_size;
        is.read(reinterpret_cast<char*>(&etag_size), sizeof(size_t));
        metadata.etag.resize(etag_size);
        is.read(&metadata.etag[0], etag_size);
        
        log_cache_hit("metadata", path + " [mode=" + std::to_string(metadata.mode) + 
                     ", size=" + std::to_string(metadata.size) + "]");
        return true;
    }
    log_cache_miss("metadata", path);
    return false;
}

void SLDMS3FS::put_metadata_to_cache(const std::string& path, const FileMetadata& metadata) {
    // Serialize POD members first
    std::ostringstream os;
    os.write(reinterpret_cast<const char*>(&metadata.mode), sizeof(mode_t));
    os.write(reinterpret_cast<const char*>(&metadata.size), sizeof(off_t));
    os.write(reinterpret_cast<const char*>(&metadata.atime), sizeof(time_t));
    os.write(reinterpret_cast<const char*>(&metadata.mtime), sizeof(time_t));
    os.write(reinterpret_cast<const char*>(&metadata.ctime), sizeof(time_t));
    os.write(reinterpret_cast<const char*>(&metadata.is_directory), sizeof(bool));
    
    // Serialize string length and content separately
    size_t etag_size = metadata.etag.size();
    os.write(reinterpret_cast<const char*>(&etag_size), sizeof(size_t));
    os.write(metadata.etag.c_str(), etag_size);
    
    std::string value = os.str();
    db->Put(rocksdb::WriteOptions(), cf_metadata, path, value);
    
    log_cache_store("metadata", path + " [mode=" + std::to_string(metadata.mode) + 
                    ", size=" + std::to_string(metadata.size) + "]", value.size());
}

bool SLDMS3FS::get_chunks_from_cache(const std::string& path, std::vector<ChunkInfo>& chunks) {
    std::string value;
    rocksdb::Status status = db->Get(rocksdb::ReadOptions(), cf_chunks, path, &value);
    
    if (status.ok()) {
        // Deserialize chunks vector
        size_t chunk_count = value.size() / sizeof(ChunkInfo);
        chunks.resize(chunk_count);
        memcpy(chunks.data(), value.data(), value.size());
        
        std::stringstream details;
        details << "Found " << chunk_count << " chunks [";
        for (const auto& chunk : chunks) {
            details << "chunk" << chunk.chunk_id << "=" << chunk.size << "B, ";
        }
        details << "]";
        log_cache_hit("chunks", path + " " + details.str());
        return true;
    }
    log_cache_miss("chunks", path);
    return false;
}

void SLDMS3FS::put_chunks_to_cache(const std::string& path, const std::vector<ChunkInfo>& chunks) {
    // Serialize chunks vector
    std::string value;
    value.resize(chunks.size() * sizeof(ChunkInfo));
    memcpy(&value[0], chunks.data(), value.size());
    
    std::stringstream details;
    details << "Storing " << chunks.size() << " chunks [";
    for (const auto& chunk : chunks) {
        details << "chunk" << chunk.chunk_id << "=" << chunk.size << "B, ";
    }
    details << "]";
    
    db->Put(rocksdb::WriteOptions(), cf_chunks, path, value);
    log_cache_store("chunks", path + " " + details.str(), value.size());
}

bool SLDMS3FS::get_directory_from_cache(const std::string& path, std::vector<std::string>& entries) {
    std::string value;
    rocksdb::Status status = db->Get(rocksdb::ReadOptions(), cf_directory, path, &value);
    
    if (status.ok()) {
        // Deserialize directory entries
        std::istringstream is(value);
        std::string entry;
        while (std::getline(is, entry, '\0')) {
            entries.push_back(entry);
        }
        log_cache_hit("directory", path + " [" + std::to_string(entries.size()) + " entries]");
        return true;
    }
    log_cache_miss("directory", path);
    return false;
}

void SLDMS3FS::put_directory_to_cache(const std::string& path, const std::vector<std::string>& entries) {
    // Serialize directory entries
    std::ostringstream os;
    for (const auto& entry : entries) {
        os.write(entry.c_str(), entry.size() + 1);  // Include null terminator
    }
    std::string value = os.str();
    
    db->Put(rocksdb::WriteOptions(), cf_directory, path, value);
    log_cache_store("directory", path + " [" + std::to_string(entries.size()) + " entries]", 
                    value.size());
}

// Update fetch operations with cache ingestion logging
bool SLDMS3FS::fetch_metadata_from_s3(const std::string& path, FileMetadata& metadata) {
    std::cout << "[S3 FETCH] Fetching metadata for: " << path << std::endl;
    std::cout << "[S3 FETCH] URL Components:\n"
              << "  endpoint_url: '" << endpoint_url << "'\n"
              << "  bucket_name: '" << bucket_name << "'\n"
              << "  path: '" << path << "'" << std::endl;
    
    // Special handling for root directory
    if (path == "/") {
        metadata.mode = S_IFDIR | 0755;  // Directory with rwxr-xr-x permissions
        metadata.size = 0;
        metadata.atime = time(nullptr);
        metadata.mtime = metadata.atime;
        metadata.ctime = metadata.atime;
        metadata.is_directory = true;
        
        std::cout << "[S3 FETCH] Setting root directory metadata:\n"
                  << "  Mode: " << std::oct << metadata.mode << std::dec << " (directory)\n"
                  << "  Permissions: 0755" << std::endl;
        
        put_metadata_to_cache(path, metadata);
        return true;
    }

    // Remove leading slash for S3 path
    std::string s3_path = path;
    if (!s3_path.empty() && s3_path[0] == '/') {
        s3_path = s3_path.substr(1);
    }
    
    std::string url = endpoint_url + "/" + bucket_name + "/" + s3_path;
    std::cout << "[S3 FETCH] Constructed URL: '" << url << "'" << std::endl;
    
    CURL* curl = curl_easy_init();
    if (curl) {
        curl_easy_setopt(curl, CURLOPT_URL, url.c_str());
        curl_easy_setopt(curl, CURLOPT_NOBODY, 1L);
        
        CURLcode res = curl_easy_perform(curl);
        long http_code = 0;
        curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &http_code);
        
        std::cout << "[S3 FETCH] Response:\n"
                  << "  CURL Result: " << curl_easy_strerror(res) << "\n"
                  << "  HTTP Code: " << http_code << std::endl;
        
        if (res == CURLE_OK && http_code == 200) {
            double size;
            curl_easy_getinfo(curl, CURLINFO_CONTENT_LENGTH_DOWNLOAD, &size);
            
            metadata.mode = S_IFREG | 0644;  // Regular file
            metadata.size = size;
            metadata.atime = time(nullptr);
            metadata.mtime = metadata.atime;
            metadata.ctime = metadata.atime;
            metadata.is_directory = false;
            
            std::cout << "[CACHE INGEST] Storing fetched metadata for: " << path 
                      << " [size=" << size << "B]" << std::endl;
            put_metadata_to_cache(path, metadata);
            
            curl_easy_cleanup(curl);
            return true;
        }
        
        std::cout << "[S3 FETCH] Failed to fetch metadata" << std::endl;
        curl_easy_cleanup(curl);
    } else {
        std::cout << "[S3 FETCH] Failed to initialize CURL" << std::endl;
    }
    return false;
}

bool SLDMS3FS::fetch_chunk_from_s3(const std::string& path, const ChunkInfo& chunk) {
    // Remove leading slash if present
    std::string s3_path = path;
    if (!s3_path.empty() && s3_path[0] == '/') {
        s3_path = s3_path.substr(1);
    }
    
    std::cout << "[S3 FETCH] Fetching chunk " << chunk.chunk_id 
              << " (offset=" << chunk.offset << ", size=" << chunk.size 
              << ") for: " << s3_path << std::endl;
    
    bool success = false;
    std::string url = endpoint_url + "/" + bucket_name + "/" + s3_path;  // Fixed URL construction
    CURL* curl = curl_easy_init();
    
    if (curl) {
        // Open file for writing
        std::ofstream chunk_file(chunk.cache_path, std::ios::binary);
        if (!chunk_file) {
            curl_easy_cleanup(curl);
            return false;
        }

        // Set up range request (fixed format)
        std::string range = std::to_string(chunk.offset) + "-" + 
                           std::to_string(chunk.offset + chunk.size - 1);
                           
        // Initialize headers
        struct curl_slist* headers = nullptr;
        headers = curl_slist_append(headers, ("Range: bytes=" + range).c_str());  // Fixed Range header
        headers = curl_slist_append(headers, "Accept: */*");
        headers = curl_slist_append(headers, "Connection: keep-alive");
        
        std::cout << "[S3 FETCH] URL Components:\n"
                  << "  endpoint_url: '" << endpoint_url << "'\n"
                  << "  bucket_name: '" << bucket_name << "'\n"
                  << "  path: '" << s3_path << "'\n"
                  << "  range: '" << range << "'" << std::endl;
        
        // Basic curl options
        curl_easy_setopt(curl, CURLOPT_URL, url.c_str());
        curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_callback_file);
        curl_easy_setopt(curl, CURLOPT_WRITEDATA, &chunk_file);
        curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
        curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION, 1L);
        curl_easy_setopt(curl, CURLOPT_MAXREDIRS, 3L);
        curl_easy_setopt(curl, CURLOPT_VERBOSE, 1L);  // Keep verbose for debugging
        
        // Perform request
        CURLcode res = curl_easy_perform(curl);
        
        if (res == CURLE_OK) {
            long http_code = 0;
            curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &http_code);
            
            if (http_code == 206 || http_code == 200) {
                success = true;
                std::cout << "[S3 FETCH] Successfully downloaded chunk with HTTP code: " 
                         << http_code << std::endl;
            } else {
                std::cerr << "[S3 FETCH] Failed with HTTP code: " << http_code << std::endl;
                chunk_file.close();
                fs::remove(chunk.cache_path);
            }
        } else {
            std::cerr << "[S3 FETCH] CURL error: " << curl_easy_strerror(res) << std::endl;
        }

        curl_slist_free_all(headers);
        curl_easy_cleanup(curl);
        chunk_file.close();
    }
    
    if (success) {
        std::cout << "[CACHE INGEST] Stored chunk " << chunk.chunk_id 
                  << " in: " << chunk.cache_path << std::endl;
    }
    return success;
}

void SLDMS3FS::background_upload_thread() {
    while (!should_stop) {
        std::unique_lock<std::mutex> lock(write_mutex);
        if (write_cv.wait_for(lock, std::chrono::seconds(UPLOAD_DELAY_SECONDS),
                             []{ return !write_queue.empty() || should_stop; })) {
            
            if (should_stop && write_queue.empty()) {
                break;
            }

            // Process all pending writes
            std::set<std::string> processed_paths;
            while (!write_queue.empty()) {
                WriteOperation op = write_queue.front();
                write_queue.pop();
                
                // Only process the most recent write for each path
                if (processed_paths.find(op.path) != processed_paths.end()) {
                    continue;
                }
                processed_paths.insert(op.path);
                
                // Release lock while uploading
                lock.unlock();
                bool success = upload_to_s3(op.path);
                lock.lock();
                
                if (success) {
                    std::cout << "[BACKGROUND] Successfully uploaded: " << op.path << std::endl;
                } else {
                    std::cerr << "[BACKGROUND] Failed to upload: " << op.path << std::endl;
                    // Re-queue for retry
                    WriteOperation retry_op = {op.path, time(nullptr), true};
                    write_queue.push(retry_op);
                }
            }
        }
    }
}

bool SLDMS3FS::upload_to_s3(const std::string& path) {
    std::vector<ChunkInfo> chunks;
    if (!get_chunks_from_cache(path, chunks)) {
        return false;
    }

    // Combine chunks and upload
    std::string url = endpoint_url + "/" + bucket_name + "/" + path;
    CURL* curl = curl_easy_init();
    if (!curl) return false;

    struct curl_slist* headers = prepare_headers();
    
    // Calculate total size
    size_t total_size = 0;
    for (const auto& chunk : chunks) {
        total_size += chunk.size;
    }

    // Create upload buffer
    std::vector<char> upload_buffer(total_size);
    size_t offset = 0;
    
    // Combine chunks
    for (const auto& chunk : chunks) {
        std::ifstream chunk_file(chunk.cache_path, std::ios::binary);
        if (!chunk_file) {
            curl_easy_cleanup(curl);
            return false;
        }
        chunk_file.read(upload_buffer.data() + offset, chunk.size);
        offset += chunk.size;
    }

    // Set up upload
    curl_easy_setopt(curl, CURLOPT_URL, url.c_str());
    curl_easy_setopt(curl, CURLOPT_UPLOAD, 1L);
    curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
    curl_easy_setopt(curl, CURLOPT_READDATA, upload_buffer.data());
    curl_easy_setopt(curl, CURLOPT_INFILESIZE_LARGE, (curl_off_t)total_size);

    CURLcode res = curl_easy_perform(curl);
    
    curl_slist_free_all(headers);
    curl_easy_cleanup(curl);

    return (res == CURLE_OK);
}

void SLDMS3FS::queue_write_operation(const std::string& path) {
    std::lock_guard<std::mutex> lock(write_mutex);
    WriteOperation op = {path, time(nullptr), true};
    write_queue.push(op);
    write_cv.notify_one();
}

// Add serialization helpers
std::string serialize_directory_listing(const DirectoryListing& listing) {
    std::ostringstream os;
    
    // Write header
    os.write(reinterpret_cast<const char*>(&listing.last_updated), sizeof(time_t));
    size_t etag_size = listing.etag.size();
    os.write(reinterpret_cast<const char*>(&etag_size), sizeof(size_t));
    os.write(listing.etag.c_str(), etag_size);
    
    // Write entries
    size_t entry_count = listing.entries.size();
    os.write(reinterpret_cast<const char*>(&entry_count), sizeof(size_t));
    
    for (const auto& entry : listing.entries) {
        size_t name_size = entry.name.size();
        os.write(reinterpret_cast<const char*>(&name_size), sizeof(size_t));
        os.write(entry.name.c_str(), name_size);
        os.write(reinterpret_cast<const char*>(&entry.is_directory), sizeof(bool));
        os.write(reinterpret_cast<const char*>(&entry.size), sizeof(size_t));
        os.write(reinterpret_cast<const char*>(&entry.mtime), sizeof(time_t));
    }
    
    return os.str();
}

bool deserialize_directory_listing(const std::string& data, DirectoryListing& listing) {
    std::istringstream is(data);
    
    // Read header
    is.read(reinterpret_cast<char*>(&listing.last_updated), sizeof(time_t));
    size_t etag_size;
    is.read(reinterpret_cast<char*>(&etag_size), sizeof(size_t));
    listing.etag.resize(etag_size);
    is.read(&listing.etag[0], etag_size);
    
    // Read entries
    size_t entry_count;
    is.read(reinterpret_cast<char*>(&entry_count), sizeof(size_t));
    listing.entries.resize(entry_count);
    
    for (auto& entry : listing.entries) {
        size_t name_size;
        is.read(reinterpret_cast<char*>(&name_size), sizeof(size_t));
        entry.name.resize(name_size);
        is.read(&entry.name[0], name_size);
        is.read(reinterpret_cast<char*>(&entry.is_directory), sizeof(bool));
        is.read(reinterpret_cast<char*>(&entry.size), sizeof(size_t));
        is.read(reinterpret_cast<char*>(&entry.mtime), sizeof(time_t));
    }
    
    return is.good();
}

bool SLDMS3FS::get_directory_listing_from_cache(const std::string& path, DirectoryListing& listing) {
    std::string value;
    rocksdb::Status status = db->Get(rocksdb::ReadOptions(), cf_directory, path, &value);
    
    if (status.ok()) {
        if (deserialize_directory_listing(value, listing)) {
            // Check if cache is still valid (e.g., not too old)
            time_t now = time(nullptr);
            if (now - listing.last_updated < DIRECTORY_CACHE_TTL) {
                std::cout << "[CACHE HIT] directory: " << path 
                         << " [" << listing.entries.size() << " entries, age=" 
                         << (now - listing.last_updated) << "s]" << std::endl;
                return true;
            }
            std::cout << "[CACHE EXPIRED] directory: " << path 
                     << " [age=" << (now - listing.last_updated) << "s]" << std::endl;
        }
    }
    std::cout << "[CACHE MISS] directory: " << path << std::endl;
    return false;
}

void SLDMS3FS::put_directory_listing_to_cache(const std::string& path, const DirectoryListing& listing) {
    std::string serialized = serialize_directory_listing(listing);
    
    db->Put(rocksdb::WriteOptions(), cf_directory, path, serialized);
    
    std::cout << "[CACHE STORE] directory: " << path 
              << " [" << listing.entries.size() << " entries, "
              << serialized.size() << " bytes]" << std::endl;
} 