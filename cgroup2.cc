/*

   nsjail - cgroup2 namespacing
   -----------------------------------------

   Copyright 2014 Google Inc. All Rights Reserved.

   Licensed under the Apache License, Version 2.0 (the "License");
   you may not use this file except in compliance with the License.
   You may obtain a copy of the License at

     http://www.apache.org/licenses/LICENSE-2.0

   Unless required by applicable law or agreed to in writing, software
   distributed under the License is distributed on an "AS IS" BASIS,
   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
   See the License for the specific language governing permissions and
   limitations under the License.

*/

#include "cgroup2.h"

#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <linux/magic.h>
#include <stdarg.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/vfs.h>
#include <unistd.h>

#include <fstream>
#include <iostream>
#include <sstream>

#include "logs.h"
#include "util.h"

namespace cgroup2 {

static bool addPidToProcList(const std::string &cgroup_path, pid_t pid) {
	std::string pid_str = std::to_string(pid);

	LOG_D("Adding pid='%s' to cgroup.procs", pid_str.c_str());
	if (!util::writeBufToFile((cgroup_path + "/cgroup.procs").c_str(), pid_str.c_str(),
		pid_str.length(), O_WRONLY)) {
		LOG_W("Could not update cgroup.procs");
		return false;
	}
	return true;
}

static std::string getCgroupPath(nsjconf_t *nsjconf, pid_t pid) {
	return nsjconf->cgroupv2_mount + "/NSJAIL." + std::to_string(pid);
}
static std::string getJailCgroupPath(nsjconf_t *nsjconf) {
	return nsjconf->cgroupv2_mount + "/NSJAIL_SELF." + std::to_string(getpid());
}

static bool createCgroup(const std::string &cgroup_path, pid_t pid) {
	LOG_D("Create '%s' for pid=%d", cgroup_path.c_str(), (int)pid);
	if (mkdir(cgroup_path.c_str(), 0700) == -1 && errno != EEXIST) {
		PLOG_W("mkdir('%s', 0700) failed", cgroup_path.c_str());
		return false;
	}
	return true;
}

static bool moveSelfIntoChildCgroup(nsjconf_t *nsjconf) {
	/*
	 * Move ourselves into another group to avoid the 'No internal processes' rule
	 * https://unix.stackexchange.com/a/713343
	 */
	std::string jail_cgroup_path = getJailCgroupPath(nsjconf);
	LOG_I("nsjail is moving itself to a new child cgroup: %s\n", jail_cgroup_path.c_str());
	RETURN_ON_FAILURE(createCgroup(jail_cgroup_path, getpid()));
	RETURN_ON_FAILURE(addPidToProcList(jail_cgroup_path, 0));
	return true;
}

static bool enableCgroupSubtree(nsjconf_t *nsjconf, const std::string &controller, pid_t pid) {
	std::string cgroup_path = nsjconf->cgroupv2_mount;
	LOG_D("Enable cgroup.subtree_control +'%s' to '%s' for pid=%d", controller.c_str(),
	    cgroup_path.c_str(), pid);
	std::string val = "+" + controller;

	/*
	 * Try once without moving the nsjail process and if that fails then try moving the nsjail
	 * process into a child cgroup before trying a second time.
	 */
	if (util::writeBufToFile((cgroup_path + "/cgroup.subtree_control").c_str(), val.c_str(),
		val.length(), O_WRONLY, false)) {
		return true;
	}
	if (errno == EBUSY) {
		RETURN_ON_FAILURE(moveSelfIntoChildCgroup(nsjconf));
		if (util::writeBufToFile((cgroup_path + "/cgroup.subtree_control").c_str(),
			val.c_str(), val.length(), O_WRONLY)) {
			return true;
		}
	}
	LOG_E(
	    "Could not apply '%s' to cgroup.subtree_control in '%s'. nsjail MUST be run from root "
	    "and the cgroup mount path must refer to the root/host cgroup to use cgroupv2. If you "
	    "use Docker, you may need to run the container with --cgroupns=host so that nsjail can"
	    " access the host/root cgroupv2 hierarchy. An alternative is mounting (or remounting) "
	    "the cgroupv2 filesystem but using the flag is just simpler.",
	    val.c_str(), cgroup_path.c_str());
	return false;
}

static bool writeToCgroup(
    const std::string &cgroup_path, const std::string &resource, const std::string &value) {
	LOG_I("Setting '%s' to '%s'", resource.c_str(), value.c_str());

	if (!util::writeBufToFile(
		(cgroup_path + "/" + resource).c_str(), value.c_str(), value.length(), O_WRONLY)) {
		LOG_W("Could not update %s", resource.c_str());
		return false;
	}
	return true;
}

static bool readIntFromCgroup(
    const std::string &cgroup_path, const std::string &resource, long long int *ptr) {
	static const int ndigits = 24; /* max of sint64 is about 9.2e18 */
	char buf[ndigits];
	const std::string fname = cgroup_path + "/" + resource;
	if (util::readFromFile(fname.c_str(), buf, ndigits) < 0) {
		LOG_W("Could not read %s from %s", resource.c_str(), cgroup_path.c_str());
		return false;
	}

	*ptr = atoll(buf);
	LOG_D("Reading '%s': %lld", fname.c_str(), *ptr);
	return true;
}

static bool readKeyedIntFromCgroup(const std::string &cgroup_path, const std::string &resource,
    const std::string key, long long int *ptr) {
	static const size_t bufsize = 128;
	const std::string fname = cgroup_path + "/" + resource;
	int fd = TEMP_FAILURE_RETRY(open(fname.c_str(), O_RDONLY | O_CLOEXEC));
	if (fd == -1) {
		PLOG_E("open('%s', O_RDONLY|O_CLOEXEC)", fname.c_str());
		return false;
	}
	FILE *f = fdopen(fd, "r");
	if (f == NULL) {
		PLOG_E("fdopen(fd=%d)", fd);
		close(fd);
		return false;
	}

	char buf[bufsize];
	bool found = false;
	char *valptr = NULL;
	while (!feof(f)) {
		/* to detect the usage of last byte; any non-zero char should work */
		buf[bufsize - 1] = '\n';
		char *res = fgets(buf, bufsize, f);
		if (res == NULL) {
			if (errno == EINTR || feof(f)) {
				continue;
			}
			PLOG_E("fgets(fd=%d)", fd);
			fclose(f);
			return false;
		}
		if (buf[bufsize - 1] == '\0' && buf[bufsize - 2] != '\n') {
			/* should not happen if the buffer size is large enough,
			 * so we simply bail out here
			 */
			PLOG_E("Couldn't fit a line of '%s' into buffer (len=%zd)", fname.c_str(),
			    bufsize);
			fclose(f);
			return false;
		}
		if (strncmp(res, key.c_str(), key.size()) == 0) {
			found = true;
		}
		char *psep = strchr(res, ' ');
		if (psep == NULL) {
			LOG_E("Expect key value pairs in '%s'", fname.c_str());
			fclose(f);
			return false;
		}
		*psep = '\0';
		valptr = psep + 1;
		/* remove the trailing newline char */
		valptr[strlen(valptr) - 1] = '\0';
		LOG_D("Reading '%s': key '%s', value '%s'", fname.c_str(), res, valptr);
		if (found) {
			break;
		}
	}

	if (found) {
		*ptr = atoll(valptr);
		LOG_D("Reading '%s' of '%s': %lld", buf, fname.c_str(), *ptr);
	} else {
		LOG_E("Couldn't find key '%s' in '%s'", key.c_str(), fname.c_str());
	}

	fclose(f);
	return found;
}

static void removeCgroup(const std::string &cgroup_path) {
	LOG_D("Remove '%s'", cgroup_path.c_str());
	if (rmdir(cgroup_path.c_str()) == -1) {
		PLOG_W("rmdir('%s') failed", cgroup_path.c_str());
	}
}

static bool needMemoryController(nsjconf_t *nsjconf) {
	/*
	 * Check if we need 'memory'
	 * This matches the check in initNsFromParentMem()
	 */
	ssize_t swap_max = nsjconf->cgroup_mem_swap_max;
	if (nsjconf->cgroup_mem_memsw_max > (size_t)0) {
		swap_max = nsjconf->cgroup_mem_memsw_max - nsjconf->cgroup_mem_max;
	}
	if (nsjconf->cgroup_mem_max == (size_t)0 && swap_max < (ssize_t)0) {
		return false;
	}
	return true;
}

static bool needPidsController(nsjconf_t *nsjconf) {
	return nsjconf->cgroup_pids_max != 0;
}

static bool needCpuController(nsjconf_t *nsjconf) {
	return nsjconf->cgroup_cpu_ms_per_sec != 0U;
}

/*
 * We will use this buf to read from cgroup.subtree_control to see if
 * the root cgroup has the necessary controllers listed
 */
#define SUBTREE_CONTROL_BUF_LEN 0x40

bool setup(nsjconf_t *nsjconf) {
	/*
	 * Read from cgroup.subtree_control in the root to see if
	 * the controllers we need are there.
	 */
	auto p = nsjconf->cgroupv2_mount + "/cgroup.subtree_control";
	char buf[SUBTREE_CONTROL_BUF_LEN];
	int read = util::readFromFile(p.c_str(), buf, SUBTREE_CONTROL_BUF_LEN - 1);
	if (read < 0) {
		LOG_W("cgroupv2 setup: Could not read root subtree_control");
		return false;
	}
	buf[read] = 0;

	/* Are the controllers we need there? */
	bool subtree_ok = (!needMemoryController(nsjconf) || strstr(buf, "memory")) &&
			  (!needPidsController(nsjconf) || strstr(buf, "pids")) &&
			  (!needCpuController(nsjconf) || strstr(buf, "cpu"));
	if (!subtree_ok) {
		/* Now we can write to the root cgroup.subtree_control */
		if (needMemoryController(nsjconf)) {
			RETURN_ON_FAILURE(enableCgroupSubtree(nsjconf, "memory", getpid()));
		}

		if (needPidsController(nsjconf)) {
			RETURN_ON_FAILURE(enableCgroupSubtree(nsjconf, "pids", getpid()));
		}

		if (needCpuController(nsjconf)) {
			RETURN_ON_FAILURE(enableCgroupSubtree(nsjconf, "cpu", getpid()));
		}
	}
	return true;
}

bool detectCgroupv2(nsjconf_t *nsjconf) {
	/*
	 * Check cgroupv2_mount, if it is a cgroup2 mount, use it.
	 */
	struct statfs buf;
	if (statfs(nsjconf->cgroupv2_mount.c_str(), &buf)) {
		LOG_D("statfs %s failed with %d", nsjconf->cgroupv2_mount.c_str(), errno);
		nsjconf->use_cgroupv2 = false;
		return false;
	}
	nsjconf->use_cgroupv2 = (buf.f_type == CGROUP2_SUPER_MAGIC);
	return true;
}

static bool initNsFromParentMem(nsjconf_t *nsjconf, pid_t pid) {
	ssize_t swap_max = nsjconf->cgroup_mem_swap_max;
	if (nsjconf->cgroup_mem_memsw_max > (size_t)0) {
		swap_max = nsjconf->cgroup_mem_memsw_max - nsjconf->cgroup_mem_max;
	}

	if (nsjconf->cgroup_mem_max == (size_t)0 && swap_max < (ssize_t)0) {
		return true;
	}

	std::string cgroup_path = getCgroupPath(nsjconf, pid);
	RETURN_ON_FAILURE(createCgroup(cgroup_path, pid));
	RETURN_ON_FAILURE(addPidToProcList(cgroup_path, pid));

	if (nsjconf->cgroup_mem_max > (size_t)0) {
		RETURN_ON_FAILURE(writeToCgroup(
		    cgroup_path, "memory.max", std::to_string(nsjconf->cgroup_mem_max)));
	}

	if (swap_max >= (ssize_t)0) {
		RETURN_ON_FAILURE(
		    writeToCgroup(cgroup_path, "memory.swap.max", std::to_string(swap_max)));
	}

	return true;
}

static bool initNsFromParentPids(nsjconf_t *nsjconf, pid_t pid) {
	if (nsjconf->cgroup_pids_max == 0U) {
		return true;
	}
	std::string cgroup_path = getCgroupPath(nsjconf, pid);
	RETURN_ON_FAILURE(createCgroup(cgroup_path, pid));
	RETURN_ON_FAILURE(addPidToProcList(cgroup_path, pid));
	return writeToCgroup(cgroup_path, "pids.max", std::to_string(nsjconf->cgroup_pids_max));
}

static bool initNsFromParentCpu(nsjconf_t *nsjconf, pid_t pid) {
	if (nsjconf->cgroup_cpu_ms_per_sec == 0U) {
		return true;
	}

	std::string cgroup_path = getCgroupPath(nsjconf, pid);
	RETURN_ON_FAILURE(createCgroup(cgroup_path, pid));
	RETURN_ON_FAILURE(addPidToProcList(cgroup_path, pid));

	/*
	 * The maximum bandwidth limit in the format: `$MAX $PERIOD`.
	 * This indicates that the group may consume up to $MAX in each $PERIOD
	 * duration.
	 */
	std::string cpu_ms_per_sec_str = std::to_string(nsjconf->cgroup_cpu_ms_per_sec * 1000U);
	cpu_ms_per_sec_str += " 1000000";
	return writeToCgroup(cgroup_path, "cpu.max", cpu_ms_per_sec_str);
}

bool initNsFromParent(nsjconf_t *nsjconf, pid_t pid) {
	RETURN_ON_FAILURE(initNsFromParentMem(nsjconf, pid));
	RETURN_ON_FAILURE(initNsFromParentPids(nsjconf, pid));
	return initNsFromParentCpu(nsjconf, pid);
}

void finishFromParent(nsjconf_t *nsjconf, pid_t pid) {
	if (nsjconf->cgroup_mem_max != (size_t)0 || nsjconf->cgroup_pids_max != 0U ||
	    nsjconf->cgroup_cpu_ms_per_sec != 0U) {
		removeCgroup(getCgroupPath(nsjconf, pid));
	}
}

void printStat(nsjconf_t *nsjconf, pid_t pid) {
	if (!needMemoryController(nsjconf)) {
		return;
	}

	std::string cgroup_path = getCgroupPath(nsjconf, pid);

	long long int tmp = -1;
	bool success;

	success = readIntFromCgroup(cgroup_path, "memory.peak", &tmp);
	if (!success) {
		tmp = -1;
	}
	LOG_STAT("%d:cgroup_memory_max_usage = %lld", pid, tmp);

	success = readKeyedIntFromCgroup(cgroup_path, "memory.events", "max", &tmp);
	if (!success) {
		tmp = -1;
	}
	LOG_STAT("%d:cgroup_memory_failcnt = %lld", pid, tmp);
}

}  // namespace cgroup2
