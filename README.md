How to play this PoC?
1. currently it also support GetAttr and List and read
2. setup S3 proxy following its document
3. then build this project
4. run below command to setup fuse for S3
5. prepare one gen5 NVMe SSD, and change the path according, then run
6. ./sldms3fs http://localhost:8080 my-test-bucket /mnt/s3fs -f
7. /mnt/s3fs is your mounted FS path for backend S3
