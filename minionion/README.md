This project aims to create a minimal implementation of a tor client/hidden service.
The primary goal is small executable size, which is why this project uses a stripped-down mbedtls.
A statically linked release build is about 500K in size, compressable with UPX to 200K.

Do not rely on this implementation for security, as it's designed as a fun research project only and is probably insecure.