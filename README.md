How to play this PoC?
currently it also support GetAttr and List and read
setup S3 proxy following its document
then build this project
run below command to setup fuse for S3
prepare one gen5 NVMe SSD, and change the path according, then run
./sldms3fs http://localhost:8080 my-test-bucket /mnt/s3fs -f
/mnt/s3fs is your mounted FS path for backend S3