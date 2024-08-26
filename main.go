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

int read_memory(pid_t pid, unsigned long addr, char *buf, size_t size) {
    // Use ptrace to read memory
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
		fmt.Println("Usage: go run main.go <pid>")
		return
	}

	// Validate if the program is executed in Linux system using Go
	if runtime.GOOS != "linux" {
		fmt.Println("This program only works on Linux systems.")
		return
	}

	// Parse the PID from command line arguments
	pid, err := strconv.Atoi(os.Args[1])
	if err != nil {
		fmt.Println("Invalid PID:", err)
		return
	}

	// Open the maps file to read memory regions
	file, err := os.Open(fmt.Sprintf("/proc/%d/maps", pid))
	if err != nil {
		fmt.Println("Error opening maps file:", err)
		return
	}
	defer file.Close()

	// Create the output file for dumping memory
	dumpFile, err := os.Create(fmt.Sprintf("dump-%d.bin", pid))
	if err != nil {
		fmt.Println("Error creating dump file:", err)
		return
	}
	defer dumpFile.Close()

	// Buffer to store memory data
	buffer := make([]byte, 4096) // Adjust size as needed

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

	fmt.Printf("Memory dump for process %d completed.\n", pid)
}
