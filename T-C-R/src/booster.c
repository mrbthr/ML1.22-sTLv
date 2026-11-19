
int write_sysctl(const char *path, const char *value) {
    FILE *fp = fopen(path, "w");
    if (!fp) {
        fprintf(stderr, "[WARN] Could not open %s: %s\n", path, strerror(errno));
        return -1;
    }
    if (fprintf(fp, "%s\n", value) < 0) {
        fprintf(stderr, "[WARN] Failed writing to %s: %s\n", path, strerror(errno));
        fclose(fp);
        return -1;
    }
    fclose(fp);
    printf("[OK]   %s -> %s\n", path, value);
    return 0;
}


long get_available_ram_mb(void) {
    FILE *fp = fopen("/proc/meminfo", "r");
    if (!fp) return -1;

    char line;
    long mem_kb = -1;
    while (fgets(line, sizeof(line), fp)) {
        if (sscanf(line, "MemAvailable: %ld kB", &mem_kb) == 1) {
            break;
        }
    }
    fclose(fp);
    return (mem_kb > 0) ? (mem_kb / 1024) : -1;
}

void boost_memory_and_io(void) {
    printf("\n--- [1/3] Optimizing Memory, Swap & Disk Cache ---\n");
    
    sync();


    write_sysctl("/proc/sys/vm/drop_caches", "3");

    
    write_sysctl("/proc/sys/vm/swappiness", "10");

    
    write_sysctl("/proc/sys/vm/vfs_cache_pressure", "50");

    
    write_sysctl("/proc/sys/vm/dirty_background_ratio", "5");
    write_sysctl("/proc/sys/vm/dirty_ratio", "15");
}

void boost_network_stack(void) {
    printf("\n--- [2/3] Tuning TCP/IP Stack & Enabling BBR ---\n");
    
    write_sysctl("/proc/sys/net/core/default_qdisc", "fq");
    write_sysctl("/proc/sys/net/ipv4/tcp_congestion_control", "bbr");

    
    write_sysctl("/proc/sys/net/ipv4/tcp_fastopen", "3");

    
    write_sysctl("/proc/sys/net/core/rmem_max", "16777216");
    write_sysctl("/proc/sys/net/core/wmem_max", "16777216");
    write_sysctl("/proc/sys/net/ipv4/tcp_rmem", "4096 87380 16777216");
    write_sysctl("/proc/sys/net/ipv4/tcp_wmem", "4096 65536 16777216");

    
    write_sysctl("/proc/sys/net/core/netdev_max_backlog", "16384");
}

void boost_cpu_governor(void) {
    printf("\n--- [3/3] Setting CPU Frequency Governor to Performance ---\n");
    char path;
    int updated = 0;

    for (int cpu = 0; cpu < 256; cpu++) {
        snprintf(path, sizeof(path),
                 "/sys/devices/system/cpu/cpu%d/cpufreq/scaling_governor", cpu);
        if (access(path, W_OK) == 0) {
            if (write_sysctl(path, "performance") == 0) {
                updated++;
            }
        } else {
            break;
        }
    }

    if (updated == 0) {
        printf("[INFO] cpufreq governor interface not exposed (common in VMs/containers).\n");
    }
}

int main(void) {
    if (geteuid() != 0) {
        fprintf(stderr, "Error: linux-booster must be run as root (use: sudo ./linux-booster)\n");
        return 1;
    }

    long ram_before = get_available_ram_mb();
    printf("==================================================\n");
    printf(" Linux Kernel & Network Booster\n");
    if (ram_before > 0) {
        printf(" Available RAM (Before): %ld MB\n", ram_before);
    }
    printf("==================================================\n");

    boost_memory_and_io();
    boost_network_stack();
    boost_cpu_governor();

    long ram_after = get_available_ram_mb();
    printf("\n==================================================\n");
    if (ram_before > 0 && ram_after > 0) {
        printf(" Available RAM (After):  %ld MB (+%ld MB freed)\n",
               ram_after, (ram_after - ram_before > 0) ? (ram_after - ram_before) : 0);
    }
    printf(" Optimization Complete.\n");
    printf("==================================================\n");

    return 0;
}
  
