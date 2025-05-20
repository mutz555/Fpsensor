#include <fstream>
#include <unistd.h> // Untuk getpid()

// Tidak ada header xhook atau android/log.h yang dibutuhkan untuk tes ini

__attribute__((constructor)) static void my_simple_constructor() {
    std::ofstream outfile("/data/local/tmp/ld_preload_test.txt", std::ios_base::app);
    if (outfile.is_open()) {
        outfile << "LD_PRELOAD_SIMPLE_TEST: Constructor DIPANGGIL! PID: " << getpid() << std::endl;
        outfile.close();
    }
}
