# Compiler and flags
CXX = g++
CXXFLAGS = -std=c++17 -Wall -Wextra -g
LDFLAGS = -pthread

# Libraries
LIBS_COMMON = -lssl -lcrypto
LIBS_BASTION_SRV = -lssh
LIBS_PAM = -lpam

# Source files
SRC_DIR = src
MAINTENANCE_DIR = maintenance_scripts

SRC_COMMON = $(SRC_DIR)/common.cpp
SRC_BASTION = $(SRC_DIR)/bastion.cpp $(SRC_COMMON)
SRC_BASTION_SRV = $(SRC_DIR)/bastion-srv.cpp $(SRC_COMMON)
SRC_BASTION_AUTH = $(SRC_DIR)/bastion-auth.cpp $(SRC_COMMON)
SRC_CLEAN_AUTHORIZED_KEYS = $(MAINTENANCE_DIR)/clean_authorized_keys.cpp

# Executables
BIN_DIR = bin
TARGETS = bastion bastion-srv bastion-auth clean_authorized_keys

all: $(BIN_DIR) $(addprefix $(BIN_DIR)/,$(TARGETS))

# Create directory if it doesn't exist
$(BIN_DIR):
	mkdir -p $(BIN_DIR)

$(BIN_DIR)/bastion: $(SRC_BASTION)
	$(CXX) $(CXXFLAGS) $(LDFLAGS) -o $@ $^ $(LIBS_COMMON)

$(BIN_DIR)/bastion-srv: $(SRC_BASTION_SRV)
	$(CXX) $(CXXFLAGS) $(LDFLAGS) -o $@ $^ $(LIBS_COMMON) $(LIBS_BASTION_SRV) $(LIBS_PAM)

$(BIN_DIR)/bastion-auth: $(SRC_BASTION_AUTH)
	$(CXX) $(CXXFLAGS) $(LDFLAGS) -o $@ $^ $(LIBS_COMMON) $(LIBS_BASTION_SRV) $(LIBS_PAM)

$(BIN_DIR)/clean_authorized_keys: $(SRC_CLEAN_AUTHORIZED_KEYS)
	$(CXX) $(CXXFLAGS) -o $@ $^

clean:
	rm -f $(addprefix $(BIN_DIR)/,$(TARGETS)) *.pem *.db

.PHONY: all clean
