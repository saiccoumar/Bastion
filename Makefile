# Compiler and flags
CXX = g++
CXXFLAGS = -std=c++17 -Wall -Wextra -g # Added -Wall -Wextra -g for better debugging
LDFLAGS = -pthread # Linker flags, moved -pthread here

# Libraries
LIBS_COMMON = -lssl -lcrypto
LIBS_BASTION_SRV = -lssh

# Source files
SRC_COMMON = common.cpp
SRC_BASTION = bastion.cpp $(SRC_COMMON)
SRC_BASTION_SRV = bastion-srv.cpp $(SRC_COMMON)
# Renamed source file variable and updated the source filename
SRC_BASTION_AUTH = bastion-auth.cpp $(SRC_COMMON)

# Executables
# Updated target name in the list
TARGETS = bastion bastion-srv bastion-auth

all: $(TARGETS)

bastion: $(SRC_BASTION)
	$(CXX) $(CXXFLAGS) $(LDFLAGS) -o $@ $^ $(LIBS_COMMON)

bastion-srv: $(SRC_BASTION_SRV)
	$(CXX) $(CXXFLAGS) $(LDFLAGS) -o $@ $^ $(LIBS_COMMON) $(LIBS_BASTION_SRV)

# Renamed target and updated source variable
bastion-auth: $(SRC_BASTION_AUTH)
	$(CXX) $(CXXFLAGS) $(LDFLAGS) -o $@ $^ $(LIBS_COMMON)

clean:
	rm -f $(TARGETS) *.pem *.db # Added *.pem and *.db to clean up generated key/db files

.PHONY: all clean
