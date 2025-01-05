# Try to find RocksDB
#
# Once done this will define
#  ROCKSDB_FOUND - System has RocksDB
#  ROCKSDB_INCLUDE_DIRS - The RocksDB include directories
#  ROCKSDB_LIBRARIES - The libraries needed to use RocksDB

find_path(ROCKSDB_INCLUDE_DIR rocksdb/db.h
    PATHS
    /usr/include
    /usr/local/include
    /opt/local/include
    /sw/include
)

find_library(ROCKSDB_LIBRARY
    NAMES rocksdb
    PATHS
    /usr/lib
    /usr/local/lib
    /opt/local/lib
    /sw/lib
)

include(FindPackageHandleStandardArgs)
find_package_handle_standard_args(RocksDB DEFAULT_MSG
    ROCKSDB_LIBRARY ROCKSDB_INCLUDE_DIR)

mark_as_advanced(ROCKSDB_INCLUDE_DIR ROCKSDB_LIBRARY)

set(ROCKSDB_LIBRARIES ${ROCKSDB_LIBRARY})
set(ROCKSDB_INCLUDE_DIRS ${ROCKSDB_INCLUDE_DIR}) 