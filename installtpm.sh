sudo apt -y install   autoconf-archive   libcmocka0   libcmocka-dev   procps   iproute2   build-essential   git   pkg-config   gcc   libtool   automake   libssl-dev   uthash-dev   autoconf   doxygen   libjson-c-dev   libini-config-dev   libcurl4-openssl-dev   uuid-dev   libltdl-dev   libusb-1.0-0-dev   libftdi-dev

git clone https://github.com/tpm2-software/tpm2-tss.git
cd tpm2-tss
./bootstrap
./configure
make -j$(nproc)
sudo make install
cd ..
mkdir ./mytpm

sudo apt-get install git g++ gcc automake autoconf libtool make gcc libc-dev libssl-dev pkg-config libtasn1-6-dev libjson-glib-dev expect gawk socat libseccomp-dev  gnutls-bin libgnutls28-dev -y

cd ~
git clone https://github.com/stefanberger/swtpm.git
git clone https://github.com/stefanberger/libtpms.git
cd libtpms
./autogen.sh --prefix=/usr --with-tpm2 --with-openssl
make
sudo make install
cd ../swtpm
./autogen.sh --prefix=/usr
make
sudo make install
cd ..
rm -rf swtpm/ libtpms/
swtpm_setup --tpm2 --tpmstate dir=/home/ryan/mytpm --createek --create-ek-cert --create-platform-cert --lock-nvra
swtpm socket --tpmstate dir=./mytpm  --ctrl type=tcp,port=2322 --server type=tcp,port=2321 --flags not-need-init --daemon
sudo apt install python3-tpm2-pytss
sudo apt install libtss2-dev tpm2-tools swig pkg-config python3-dev
sudo apt install python3.12-venv
python3 -m venv --system-site-packages .linuxenv
source ./.linuxenv/bin/activate
pip install -r final_requirements.txt 
