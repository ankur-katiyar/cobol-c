echo "Installing openssl-devel"
sudo yum install openssl-devel

echo "Building AES Encryption C module"
gcc -fPIC -shared -o libopenssl_aes.so openssl_aes.c -lcrypto
sudo cp libopenssl_aes.so /usr/lib64/

echo "Compiling AES based encryption module"
cob -x -d openssl_aes PTCRYPT.cbl -L. -lcrypto -l:libopenssl_aes.so -o PTCRYPT

echo "Compiling GPG based encryption module"
cob -x PTPCRYPG.cbl -o PTPCRYPG

echo "Now running benchmarks"

chmod +x ./*.sh

echo "Running AES Benchmark".
./benchmark_aes.sh 100

read -p "Press any key to continue..."

echo  "Running GPG Benchmark".
./benchmark_gpg.sh 100