
-----------------INSTALLATION---------------------------------
1) Have linux running natively on a computer with a TPM 2.0 chip or create a linux virtual machine with a tpm 2.0 chip
2) Run tpmsetup.sh
3) Add your current user to the tss user group
3) Create a python virtual environment using python -m venv --system-site-packages env
4) activate the virtual environment
5) run pip install -r reqs.txt
6) remove the cryptography library due to clashes with other dependencies
7) ensure server/signHandle.key is empty on the first time running it on your system
8) CD into the server folder and run main.py set the database password to strong value at least 16 random characters
9)in different terminal cd into client and run main.py this should connect to the server and show the sign up menu

you can sign up as an ordinary user or use the code printed out in the server terminal to setup the first admin account
