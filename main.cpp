#include "sldms3fs.hpp"
#include <iostream>
#include <cstring>

static struct fuse_operations sldms3fs_operations;

int main(int argc, char* argv[]) {
    if (argc < 4) {
        std::cerr << "Usage: " << argv[0] 
                  << " <endpoint_url> <bucket_name> <mount_point> [FUSE options]" 
                  << std::endl;
        return 1;
    }

    std::string endpoint_url = argv[1];
    std::string bucket_name = argv[2];
    std::string mount_point = argv[3];

    // Set up storage and cache
    SLDMS3FS::set_storage(endpoint_url);
    SLDMS3FS::set_bucket(bucket_name);
    SLDMS3FS::set_mount_point(mount_point);
    
    // Set cache directory in user's home
    //char* home = getenv("HOME");
    std::string cache_dir = "/mnt/nvme0n1/scratchsldms3fuse/cache";
    SLDMS3FS::set_cache_dir(cache_dir);

    if (!SLDMS3FS::initialize()) {
        std::cerr << "Failed to initialize cache system" << std::endl;
        return 1;
    }

    // Initialize FUSE operations
    memset(&sldms3fs_operations, 0, sizeof(struct fuse_operations));
    sldms3fs_operations.getattr = SLDMS3FS::getattr;
    sldms3fs_operations.readdir = SLDMS3FS::readdir;
    sldms3fs_operations.open = SLDMS3FS::open;
    sldms3fs_operations.read = SLDMS3FS::read;
    sldms3fs_operations.write = SLDMS3FS::write;
    sldms3fs_operations.mkdir = SLDMS3FS::mkdir;
    sldms3fs_operations.rmdir = SLDMS3FS::rmdir;
    sldms3fs_operations.unlink = SLDMS3FS::unlink;
    sldms3fs_operations.truncate = SLDMS3FS::truncate;
    sldms3fs_operations.create = SLDMS3FS::create;

    // Prepare FUSE arguments
    char** fuse_argv = (char**)malloc((argc + 1) * sizeof(char*));
    fuse_argv[0] = argv[0];
    fuse_argv[1] = argv[3];  // mount point
    for(int i = 4; i < argc; i++) {
        fuse_argv[i-2] = argv[i];
    }
    int fuse_argc = argc - 2;

    // Run FUSE
    int ret = fuse_main(fuse_argc, fuse_argv, &sldms3fs_operations, nullptr);

    // Clean up
    SLDMS3FS::cleanup();
    free(fuse_argv);

    return ret;
} 