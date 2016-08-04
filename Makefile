SGX_SDK ?= /opt/intel/sgxsdk
SGX_EDGER8R := $(SGX_SDK)/bin/x64/sgx_edger8r
SGX_SIGN := $(SGX_SDK)/bin/x64/sgx_sign
SGX_LIB_PATH := $(SGX_SDK)/lib64

SIGNER_KEY_FILE := reencrypt/reencrypt_private.pem
REENCRYPT_CONF_FILE := reencrypt/reencrypt.config.xml

TRTS_LIB := sgx_trts
URTS_LIB := sgx_urts
CRYPTO_LIB := sgx_tcrypto
SERVICE_LIB := sgx_tservice

APP_INC := -Ireencrypt -I$(SGX_SDK)/include
APP_C_FLAGS := $(APP_INC)
APP_CPP_FLAGS := $(APP_INC) -std=c++11
APP_LINK_FLAGS := -L$(SGX_LIB_PATH) -l$(URTS_LIB) -pthread

ENCLAVE_INC := -I$(SGX_SDK)/include \
	-I$(SGX_SDK)/include/tlibc -I$(SGX_SDK)/include/stlport 

ENCLAVE_C_FLAGS := $(ENCLAVE_INC) -nostdinc -fvisibility=hidden \
	-fpie -fstack-protector

ENCLAVE_LINK_FLAGS := -Wl,--no-undefined -L$(SGX_LIB_PATH) \
	-nostdlib -nodefaultlibs -nostartfiles \
	-Wl,--whole-archive -l$(TRTS_LIB) -Wl,--no-whole-archive \
	-Wl,--start-group -lsgx_tstdc -lsgx_tstdcxx -l$(CRYPTO_LIB) \
	-l$(SERVICE_LIB) -Wl,--end-group  \
	-Wl,-Bstatic -Wl,-Bsymbolic -Wl,--no-undefined \
	-Wl,-pie,-eenclave_entry -Wl,--export-dynamic \
	-Wl,--defsym,__ImageBase=0 \
	-Wl,--version-script=reencrypt/reencrypt.lds

APP_SRCS := $(wildcard test-app/*.c test-app/tweetnacl/*.c) test-app/reencrypt_u.o
APP_SRCS_CPP := $(wildcard test-app/*.cpp)
APP_OBJS := $(APP_SRCS:.c=.o) $(APP_SRCS_CPP:.cpp=.o) test-app/nacl_box.o test-app/serialize.o

ENCLAVE_SRCS := $(wildcard reencrypt/*.c reencrypt/ciphers/*.c \
	reencrypt/blake2/*.c reencrypt/tweetnacl/*.c)
ENCLAVE_OBJS := $(ENCLAVE_SRCS:.c=.o) reencrypt/reencrypt_t.o

all: bin/test-app bin/reencrypt.signed.so
	@mkdir -p bin

### test-app ###

test-app/reencrypt_u.c: reencrypt/reencrypt.edl
	@$(SGX_EDGER8R) --untrusted reencrypt/reencrypt.edl \
		--untrusted-dir test-app
	@echo "sgx_edger8r => $@"

test-app/reencrypt_u.o: test-app/reencrypt_u.c
	@$(CC) $(APP_C_FLAGS) -c $< -o $@
	@echo "CC <= $<"

test-app/nacl_box.o: reencrypt/nacl_box.c
	@$(CC) $(APP_C_FLAGS) -c $< -o $@
	@echo "CC <= $<"

test-app/serialize.o: reencrypt/serialize.c
	@$(CC) $(APP_C_FLAGS) -c $< -o $@
	@echo "CC <= $<"

test-app/%.o: test-app/%.c
	@$(CC) $(APP_C_FLAGS) -c $< -o $@
	@echo "CC <= $<"

test-app/%.o: test-app/%.cpp
	@$(CXX) $(APP_CPP_FLAGS) -c $< -o $@
	@echo "CXX <= $<"

bin/test-app: $(APP_OBJS)
	@$(CXX) $^ -o $@ $(APP_LINK_FLAGS)
	@echo "LINK => $@"


### reencrypt enclave ###

reencrypt/reencrypt_t.c: reencrypt/reencrypt.edl
	@$(SGX_EDGER8R) --trusted reencrypt/reencrypt.edl \
		--trusted-dir reencrypt
	@echo "sgx_edger8r => $@"

#reencrypt/reencrypt_t.o: reencrypt/reencrypt_t.c
#	$(CC) $(ENCLAVE_FLAGS) -c $< -o $@

reencrypt/%.o: reencrypt/%.c
	@$(CC) $(ENCLAVE_C_FLAGS) -c $< -o $@
	@echo "CC <= $<"

reencrypt.so: reencrypt/reencrypt_t.o $(ENCLAVE_OBJS)
	@$(CC) $^ -o $@ $(ENCLAVE_LINK_FLAGS)
	@echo "LINK => $@"

bin/reencrypt.signed.so: reencrypt.so
	@$(SGX_SIGN) sign -key $(SIGNER_KEY_FILE) -enclave $< \
		-out $@ -config $(REENCRYPT_CONF_FILE)
	@echo "SIGN => $@"


clean:
	rm -f reencrypt/reencrypt_t.*
	rm -f test-app/reencrypt_u.*
	rm -f *.so
	rm -f reencrypt/*.o
	rm -f reencrypt/blake2/*.o
	rm -f reencrypt/ciphers/*.o
	rm -f reencrypt/tweetnacl/*.o
	rm -f test-app/*.o
	rm -f test-app/tweetnacl/*.o
