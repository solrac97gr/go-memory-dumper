package main

/*
#include <sys/ptrace.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/user.h>
#include <unistd.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <mach/mach.h>

#ifndef PTRACE_PEEKDATA
#define PTRACE_PEEKDATA 2
#endif

#ifdef __linux__
long get_memory_usage(pid_t pid) {
    char filename[256];
    FILE *file;
    unsigned long int vmrss = 0; // Variable to store the RSS value

    // Construct the file path for /proc/[pid]/statm
    snprintf(filename, sizeof(filename), "/proc/%d/statm", pid);

    // Open the file
    file = fopen(filename, "r");
    if (file == NULL) {
        perror("fopen");
        return -1;
    }

    // Read the memory usage (RSS) from the file
    fscanf(file, "%*s %lu", &vmrss);

    // Close the file
    fclose(file);

    // Return the RSS value (in pages)
    return vmrss * sysconf(_SC_PAGESIZE); // Convert pages to bytes
}
#endif

#ifdef __APPLE__
long get_memory_usage(pid_t pid) {
    struct task_basic_info info;
    mach_msg_type_number_t info_count = TASK_BASIC_INFO_COUNT;
    kern_return_t kr;

    kr = task_info(mach_task_self(), TASK_BASIC_INFO, (task_info_t)&info, &info_count);
    if (kr != KERN_SUCCESS) {
        fprintf(stderr, "task_info failed: %s\n", mach_error_string(kr));
        return -1;
    }

    return info.resident_size; // Return the RSS value in bytes
}

int read_memory_macos(pid_t pid, unsigned long addr, char *buf, size_t size) {
    mach_port_t task;
    kern_return_t kr;

    kr = task_for_pid(mach_task_self(), pid, &task);
    if (kr != KERN_SUCCESS) {
        fprintf(stderr, "task_for_pid failed: %s\n", mach_error_string(kr));
        return -1;
    }

    vm_offset_t data;
    mach_msg_type_number_t data_count;
    kr = vm_read(task, addr, size, &data, &data_count);
    if (kr != KERN_SUCCESS) {
        fprintf(stderr, "vm_read failed: %s\n", mach_error_string(kr));
        return -1;
    }

    memcpy(buf, (char *)data, size);
    vm_deallocate(mach_task_self(), data, data_count);

    return 0;
}
#endif

int read_memory(pid_t pid, unsigned long addr, char *buf, size_t size) {
#ifdef __linux__
    // Use ptrace to read memory on Linux
    errno = 0;
    long data;
    size_t i;
    for (i = 0; i < size; i += sizeof(long)) {
        data = ptrace(PTRACE_PEEKDATA, pid, (caddr_t)(addr + i), 0);
        if (errno != 0) {
            perror("ptrace");
            return -1;
        }
        memcpy(buf + i, &data, sizeof(long));
    }
    return 0;
#elif defined(__APPLE__)
    // Use vm_read to read memory on macOS
    return read_memory_macos(pid, addr, buf, size);
#else
    return -1;
#endif
}
*/
import "C"
import (
	"fmt"
	"os"
	"runtime"
	"strconv"
	"unsafe"
)

func main() {
	if len(os.Args) < 2 {
		fmt.Println("Usage: sudo go run main.go <pid>")
		return
	}

	// Validate if the program is executed in supported systems
	if runtime.GOOS != "linux" && runtime.GOOS != "darwin" {
		fmt.Println("This program only works on Linux and macOS systems.")
		return
	}

	// Parse the PID from command line arguments
	pid, err := strconv.Atoi(os.Args[1])
	if err != nil {
		fmt.Println("Invalid PID:", err)
		return
	}

	// Create the output file for dumping memory
	dumpFile, err := os.Create(fmt.Sprintf("dump-%d.bin", pid))
	if err != nil {
		fmt.Println("Error creating dump file:", err)
		return
	}
	defer dumpFile.Close()

	// Buffer to store memory data
	buffer := make([]byte, 4096) // Adjust size as needed

	if runtime.GOOS == "linux" {
		// Open the maps file to read memory regions
		file, err := os.Open(fmt.Sprintf("/proc/%d/maps", pid))
		if err != nil {
			fmt.Println("Error opening maps file:", err)
			return
		}
		defer file.Close()

		var startAddr, endAddr uintptr
		var perms string
		for {
			var offset int64
			var dev, inode int
			n, err := fmt.Fscanf(file, "%x-%x %s %x %x:%x %d\n", &startAddr, &endAddr, &perms, &offset, &dev, &inode)
			if n == 0 || err != nil {
				break
			}

			// Check for readable and writable permissions
			if perms[0] == 'r' && perms[1] == 'w' {
				for addr := startAddr; addr < endAddr; addr += uintptr(len(buffer)) {
					size := len(buffer)
					if uintptr(endAddr)-addr < uintptr(size) {
						size = int(uintptr(endAddr) - addr)
					}

					if C.read_memory(C.pid_t(pid), C.ulong(addr), (*C.char)(unsafe.Pointer(&buffer[0])), C.size_t(size)) == 0 {
						if _, err := dumpFile.Write(buffer[:size]); err != nil {
							fmt.Println("Error writing to dump file:", err)
							return
						}
					} else {
						fmt.Println("Error reading memory at address:", addr)
					}
				}
			}
		}
	} else if runtime.GOOS == "darwin" {
		// macOS specific memory reading logic
		// Note: macOS does not have /proc/[pid]/maps, so you need to use other methods to get memory regions
		// Here we assume you have a way to get the memory regions (startAddr and endAddr)
		// This is a placeholder for the actual implementation
		var startAddr, endAddr uintptr = 0x100000000, 0x100010000 // Example addresses
		for addr := startAddr; addr < endAddr; addr += uintptr(len(buffer)) {
			size := len(buffer)
			if uintptr(endAddr)-addr < uintptr(size) {
				size = int(uintptr(endAddr) - addr)
			}

			if C.read_memory(C.pid_t(pid), C.ulong(addr), (*C.char)(unsafe.Pointer(&buffer[0])), C.size_t(size)) == 0 {
				if _, err := dumpFile.Write(buffer[:size]); err != nil {
					fmt.Println("Error writing to dump file:", err)
					return
				}
			} else {
				fmt.Println("Error reading memory at address:", addr)
			}
		}
	}

	fmt.Printf("Memory dump for process %d completed.\n", pid)
}
