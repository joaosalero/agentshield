CC ?= cc
CXX ?= c++
CFLAGS ?= -O2 -std=c11 -Wall -Wextra -Wpedantic -Werror
CXXFLAGS ?= -O2 -std=c++17 -Wall -Wextra -Wpedantic -Werror
CPPFLAGS := -Icore/include -Iengine/include
VERSION := $(strip $(shell python3 scripts/read_version.py VERSION))
ifeq ($(VERSION),)
$(error VERSION must contain one semantic x.y.z version)
endif
CPPFLAGS += -DAGENTSHIELD_VERSION=\"$(VERSION)\"
LDFLAGS ?=
LDLIBS := -lcrypto
BUILD := build
PREFIX ?= /usr/local
OBJECTS := $(BUILD)/sensor.o $(BUILD)/risk_engine.o $(BUILD)/audit_log.o $(BUILD)/main.o
.PHONY: all check-version test portfolio-check fuzz-smoke soak cgroup-test-required sanitize java java-test jar sbom provenance dist verify-dist deterministic-package deb verify-deb install uninstall run-gui clean
all: check-version $(BUILD)/agentshield
check-version:
	printf '%s\n' '$(VERSION)' | grep -Eq '^[0-9]+\.[0-9]+\.[0-9]+$$'
$(BUILD):
	mkdir -p $@
$(BUILD)/sensor.o: core/src/sensor_linux.c core/include/agentshield/sensor.h | $(BUILD)
	$(CC) $(CPPFLAGS) $(CFLAGS) -c $< -o $@
$(BUILD)/risk_engine.o: engine/src/risk_engine.cpp engine/include/risk_engine.hpp core/include/agentshield/sensor.h | $(BUILD)
	$(CXX) $(CPPFLAGS) $(CXXFLAGS) -c $< -o $@
$(BUILD)/audit_log.o: engine/src/audit_log.cpp engine/include/audit_log.hpp | $(BUILD)
	$(CXX) $(CPPFLAGS) $(CXXFLAGS) -c $< -o $@
$(BUILD)/main.o: cli/src/main.cpp engine/include/risk_engine.hpp engine/include/audit_log.hpp core/include/agentshield/sensor.h VERSION scripts/read_version.py | $(BUILD)
	$(CXX) $(CPPFLAGS) $(CXXFLAGS) -c $< -o $@
$(BUILD)/agentshield: $(OBJECTS)
	$(CXX) $(LDFLAGS) $^ $(LDLIBS) -o $@
$(BUILD)/test_risk: tests/test_risk.cpp $(BUILD)/sensor.o $(BUILD)/risk_engine.o $(BUILD)/audit_log.o
	$(CXX) $(CPPFLAGS) $(CXXFLAGS) $(LDFLAGS) $^ $(LDLIBS) -o $@
$(BUILD)/test_behavior_eval: tests/test_behavior_eval.cpp $(BUILD)/sensor.o $(BUILD)/risk_engine.o $(BUILD)/audit_log.o
	$(CXX) $(CPPFLAGS) $(CXXFLAGS) $(LDFLAGS) $^ $(LDLIBS) -o $@
test: all $(BUILD)/test_risk $(BUILD)/test_behavior_eval
	./$(BUILD)/test_risk
	./$(BUILD)/test_behavior_eval
	python3 tests/test_version_contract.py
	bash tests/test_make_version_rebuild.sh
	bash tests/test_cli.sh ./$(BUILD)/agentshield
	bash tests/test_cgroup.sh ./$(BUILD)/agentshield
portfolio-check:
	python3 scripts/validate_portfolio.py
fuzz-smoke: $(BUILD)/sensor.o
	$(CXX) $(CPPFLAGS) -O1 -g -std=c++17 -Wall -Wextra -Wpedantic -Werror -fsanitize=address,undefined tests/fuzz_parsers.cpp engine/src/risk_engine.cpp engine/src/audit_log.cpp $(BUILD)/sensor.o $(LDLIBS) -o $(BUILD)/fuzz_parsers
	./$(BUILD)/fuzz_parsers
soak: all
	AGENTSHIELD_SOAK_SECONDS=$${AGENTSHIELD_SOAK_SECONDS:-10} bash tests/test_soak.sh ./$(BUILD)/agentshield
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
jar: java
	jar --create --file $(BUILD)/agentshield-desktop.jar --main-class io.agentshield.DesktopApp -C $(BUILD)/java .
sbom:
	python3 scripts/generate_sbom.py --output $(BUILD)/agentshield-source.cdx.json
provenance: all jar sbom
	python3 scripts/generate_provenance.py --output $(BUILD)/agentshield-provenance.json $(BUILD)/agentshield $(BUILD)/agentshield-desktop.jar $(BUILD)/agentshield-source.cdx.json
dist: all jar sbom provenance
	bash scripts/package-linux.sh
verify-dist: dist
	bash scripts/verify-package.sh $(BUILD)/dist/agentshield-$(VERSION)-linux.tar.gz
	python3 tests/test_package_verifier.py
	python3 tests/test_release_metadata.py $(BUILD)/agentshield $(BUILD)/agentshield-desktop.jar $(BUILD)/agentshield-source.cdx.json $(BUILD)/agentshield-provenance.json $(BUILD)/dist/agentshield-$(VERSION)-linux.tar.gz
deterministic-package: verify-dist
	cp $(BUILD)/dist/agentshield-$(VERSION)-linux.tar.gz $(BUILD)/dist/first.tar.gz
	bash scripts/package-linux.sh
	cmp $(BUILD)/dist/first.tar.gz $(BUILD)/dist/agentshield-$(VERSION)-linux.tar.gz
deb: all jar
	bash scripts/package-deb.sh
verify-deb: deb
	cp $(BUILD)/dist/agentshield_$(VERSION)_$$(dpkg --print-architecture).deb $(BUILD)/dist/agentshield-first.deb
	bash scripts/package-deb.sh
	cmp $(BUILD)/dist/agentshield-first.deb $(BUILD)/dist/agentshield_$(VERSION)_$$(dpkg --print-architecture).deb
	bash scripts/verify-deb.sh $(BUILD)/dist/agentshield_$(VERSION)_$$(dpkg --print-architecture).deb
install: all jar
	install -d $(DESTDIR)$(PREFIX)/bin $(DESTDIR)$(PREFIX)/lib/agentshield $(DESTDIR)$(PREFIX)/share/agentshield/policies $(DESTDIR)$(PREFIX)/share/doc/agentshield
	install -d $(DESTDIR)$(PREFIX)/share/applications $(DESTDIR)$(PREFIX)/share/icons/hicolor/scalable/apps $(DESTDIR)$(PREFIX)/share/metainfo
	install -m 0755 $(BUILD)/agentshield $(DESTDIR)$(PREFIX)/bin/agentshield
	install -m 0755 scripts/agentshield-desktop $(DESTDIR)$(PREFIX)/bin/agentshield-desktop
	install -m 0644 $(BUILD)/agentshield-desktop.jar $(DESTDIR)$(PREFIX)/lib/agentshield/agentshield-desktop.jar
	install -m 0644 policies/*.policy $(DESTDIR)$(PREFIX)/share/agentshield/policies/
	install -m 0644 README.md SECURITY.md SUPPORT.md CONTRIBUTING.md CHANGELOG.md LICENSE $(DESTDIR)$(PREFIX)/share/doc/agentshield/
	install -m 0644 docs/*.md $(DESTDIR)$(PREFIX)/share/doc/agentshield/
	install -m 0644 packaging/linux/io.agentshield.AgentShield.desktop $(DESTDIR)$(PREFIX)/share/applications/
	install -m 0644 packaging/linux/io.agentshield.AgentShield.svg $(DESTDIR)$(PREFIX)/share/icons/hicolor/scalable/apps/
	install -m 0644 packaging/linux/io.agentshield.AgentShield.metainfo.xml $(DESTDIR)$(PREFIX)/share/metainfo/
uninstall:
	test -n "$(DESTDIR)$(PREFIX)" && rm -f $(DESTDIR)$(PREFIX)/bin/agentshield
	test -n "$(DESTDIR)$(PREFIX)" && rm -f $(DESTDIR)$(PREFIX)/bin/agentshield-desktop $(DESTDIR)$(PREFIX)/lib/agentshield/agentshield-desktop.jar
	test -n "$(DESTDIR)$(PREFIX)" && rm -f $(DESTDIR)$(PREFIX)/share/applications/io.agentshield.AgentShield.desktop $(DESTDIR)$(PREFIX)/share/icons/hicolor/scalable/apps/io.agentshield.AgentShield.svg $(DESTDIR)$(PREFIX)/share/metainfo/io.agentshield.AgentShield.metainfo.xml
run-gui: all java
	java -cp $(BUILD)/java io.agentshield.DesktopApp ./$(BUILD)/agentshield
clean:
	rm -rf $(BUILD)
