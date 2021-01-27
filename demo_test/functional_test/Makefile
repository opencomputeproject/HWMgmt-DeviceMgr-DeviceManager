# Edgecore DeviceManager
# Copyright 2020-2021 Edgecore Networks, Inc.
#
# Licensed to the Apache Software Foundation (ASF) under one
# or more contributor license agreements. See the NOTICE file
# distributed with this work for additional information
# regarding copyright ownership. The ASF licenses this file
# to you under the Apache License, Version 2.0 (the
# "License"); you may not use this file except in compliance
# with the License. You may obtain a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing,
# software distributed under the License is distributed on an
# "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
# KIND, either express or implied. See the License for the
# specific language governing permissions and limitations
# under the License.

SHELL = /bin/bash
PWD=$(shell pwd)
VERSION=$(shell cat ../../VERSION)
DEMOTESTDIR = ..
DEMOTESTLOG = demotest.log
TESTSDIR := tests
TESTTAG = tc
DMTOOL = ${PWD}/dm
DETECT = $(shell \
if [ -f "${DMTOOL}" ]; \
then \
pushd . > /dev/null; \
cd ${DEMOTESTDIR}; \
./demotest > ${DEMOTESTLOG} 2>&1 & sleep 2; \
popd>/dev/null; \
${DMTOOL} attach $1:$2:120 > /dev/null; \
${DMTOOL} setsessionservice $1:$2:"":true:300 > /dev/null; \
token=`${DMTOOL} logindevice $1:$2:$3:$4| cut -d' ' -f4`; \
${DMTOOL} detach $1:$2:$$token > /dev/null; \
pidof demotest > /dev/null && pkill demotest; \
fi \
)
TESTS = $(shell find ${TESTSDIR} -name "*.${TESTTAG}")
DIRPATH = $(firstword $(subst ., ,$1))
RESULTSDIR = results
RED = \033[0;31m
GREEN = \033[0;32m
NC = \033[0m # No Color

.PHONY : check-arg detect test clean demotest $(TESTS) results

.DEFAULT_GOAL := dm

check-arg:
ifeq ($(strip $(TESTS)),)
	$(error no test found)
endif
ifeq "$(and $(IP1),$(PORT1),$(IP2),$(PORT2),$(USER1),$(PWD1),$(USER2),$(PWD2))" ""
	$(error IP1, PORT1, IP2, PORT2, USER1, PWD1, USER2 and PWD2 are not all defined)
endif

demotest:
	@cd ${DEMOTESTDIR}; make demotest || exit 1; ./demotest > ${DEMOTESTLOG} 2>&1 & \
	sleep 2
	@[ -z ${TERM} ] && : || tput clear

dm: test_cli.go
	go build -i -v -o $@

detect:
	@$(eval $(call DETECT,${IP1},${PORT1},${USER1},${PWD1}))
	@$(eval $(call DETECT,${IP2},${PORT2},${USER2},${PWD2}))

test: check-arg dm detect clean demotest $(TESTS) results
	@make -C . clean
	@echo "Device-Manager Automation Test Finished!"

$(TESTS):
	@printf "===== Running case $@ ===== : "
	@./$@ $(IP1) $(PORT1) $(IP2) $(PORT2) $(USER1) $(PWD1) $(USER2) $(PWD2) $(call DIRPATH,$@) > /dev/null >> $(call DIRPATH,$@).out
	@diff -Nuar $(call DIRPATH,$@).out $(call DIRPATH,$@).e > $(call DIRPATH,$@).diff && \
		printf "${GREEN}Pass${NC}\n" || printf "${RED}Fail${NC}\n" || true

results:
	@mkdir -p ${RESULTSDIR}
	$(eval FileDate:=$(shell date +%Y%m%d%H%M%S))
	@tar czf ${RESULTSDIR}/test_result_v${VERSION}_$(FileDate).tgz ${DEMOTESTDIR}/${DEMOTESTLOG} \
		$(shell find ${TESTSDIR} -regex '.*\.\(out\|e\|diff\)') > /dev/null 2>&1
	@echo "------------------------------------------------------------------------------------------------------"
	@echo "The test result file locates in the ${RESULTSDIR}/test_result_v${VERSION}_$(FileDate).tgz"

clean:
	@pidof demotest > /dev/null && pkill demotest || true
	@[ -f ${DEMOTESTDIR}/${DEMOTESTLOG} ] && rm ${DEMOTESTDIR}/${DEMOTESTLOG} || true
	@find ${TESTSDIR} -regex '.*\.\(out\|e\|diff\)' | xargs rm -rf
