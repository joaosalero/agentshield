CC ?= cc
CXX ?= c++
CFLAGS ?= -O2 -std=c11 -Wall -Wextra -Wpedantic -Werror
CXXFLAGS ?= -O2 -std=c++17 -Wall -Wextra -Wpedantic -Werror
CPPFLAGS := -Icore/include -Iengine/include
LDFLAGS ?=
LDLIBS := -lcrypto
BUILD := build
OBJECTS := $(BUILD)/sensor.o $(BUILD)/risk_engine.o $(BUILD)/audit_log.o $(BUILD)/main.o
.PHONY: all test cgroup-test-required sanitize java java-test run-gui clean
all: $(BUILD)/agentshield
$(BUILD):
	mkdir -p $@
$(BUILD)/sensor.o: core/src/sensor_linux.c core/include/agentshield/sensor.h | $(BUILD)
	$(CC) $(CPPFLAGS) $(CFLAGS) -c $< -o $@
$(BUILD)/risk_engine.o: engine/src/risk_engine.cpp engine/include/risk_engine.hpp core/include/agentshield/sensor.h | $(BUILD)
	$(CXX) $(CPPFLAGS) $(CXXFLAGS) -c $< -o $@
$(BUILD)/audit_log.o: engine/src/audit_log.cpp engine/include/audit_log.hpp | $(BUILD)
	$(CXX) $(CPPFLAGS) $(CXXFLAGS) -c $< -o $@
$(BUILD)/main.o: cli/src/main.cpp engine/include/risk_engine.hpp engine/include/audit_log.hpp core/include/agentshield/sensor.h | $(BUILD)
	$(CXX) $(CPPFLAGS) $(CXXFLAGS) -c $< -o $@
$(BUILD)/agentshield: $(OBJECTS)
	$(CXX) $(LDFLAGS) $^ $(LDLIBS) -o $@
$(BUILD)/test_risk: tests/test_risk.cpp $(BUILD)/sensor.o $(BUILD)/risk_engine.o $(BUILD)/audit_log.o
	$(CXX) $(CPPFLAGS) $(CXXFLAGS) $(LDFLAGS) $^ $(LDLIBS) -o $@
test: all $(BUILD)/test_risk
	./$(BUILD)/test_risk
	bash tests/test_cli.sh ./$(BUILD)/agentshield
	bash tests/test_cgroup.sh ./$(BUILD)/agentshield
cgroup-test-required: all
	AGENTSHIELD_REQUIRE_CGROUP_TEST=1 bash tests/test_cgroup.sh ./$(BUILD)/agentshield
sanitize: CFLAGS := -O1 -g -std=c11 -Wall -Wextra -Wpedantic -Werror -fsanitize=address,undefined
sanitize: CXXFLAGS := -O1 -g -std=c++17 -Wall -Wextra -Wpedantic -Werror -fsanitize=address,undefined
sanitize: LDFLAGS := -fsanitize=address,undefined
sanitize: clean test
java: | $(BUILD)
	javac --release 17 -d $(BUILD)/java desktop/src/main/java/io/agentshield/DesktopApp.java
java-test: java
	javac --release 17 -cp $(BUILD)/java -d $(BUILD)/java desktop/src/test/java/io/agentshield/DesktopAppTest.java
	java -Djava.awt.headless=true -cp $(BUILD)/java io.agentshield.DesktopAppTest
run-gui: all java
	java -cp $(BUILD)/java io.agentshield.DesktopApp ./$(BUILD)/agentshield
clean:
	rm -rf $(BUILD)
