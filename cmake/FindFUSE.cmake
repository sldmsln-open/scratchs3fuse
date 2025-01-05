# Find the FUSE includes and library
#
# FUSE_INCLUDE_DIR - where to find fuse.h, etc.
# FUSE_LIBRARIES   - List of libraries when using FUSE.
# FUSE_FOUND      - True if FUSE lib is found.

find_path(FUSE_INCLUDE_DIR fuse.h
  /usr/local/include/fuse
  /usr/local/include
  /usr/include/fuse
  /usr/include
)

find_library(FUSE_LIBRARIES
  NAMES fuse fuse3
  PATHS /usr/local/lib64 /usr/lib64 /usr/local/lib /usr/lib
)

include(FindPackageHandleStandardArgs)
find_package_handle_standard_args(FUSE DEFAULT_MSG
  FUSE_INCLUDE_DIR FUSE_LIBRARIES)

mark_as_advanced(FUSE_INCLUDE_DIR FUSE_LIBRARIES) 