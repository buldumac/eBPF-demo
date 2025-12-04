#include <stdio.h>
#include <unistd.h>
#include <sys/prctl.h>   // for prctl
#include <string.h>

// Prevent inlining
#define NOINLINE __attribute__((noinline))

#define WORKER_LOOP_COUNT 10000000

// Function declarations
void func1(void) NOINLINE;
void func2(void) NOINLINE;
void func3(void) NOINLINE;
void func4(void) NOINLINE;
void func5(void) NOINLINE;
void func6(void) NOINLINE;
void func7(void) NOINLINE;
void func8(void) NOINLINE;
void func9(void) NOINLINE;
void Worker(void) NOINLINE;
const char* HelperHelper(int n) NOINLINE;

// Function definitions
void func1(void) { printf("In func1\n"); sleep(1); func2(); }
void func2(void) { printf("In func2\n"); sleep(1); func3(); }
void func3(void) { printf("In func3\n"); sleep(1); func4(); }
void func4(void) { printf("In func4\n"); sleep(1); func5(); }
void func5(void) { printf("In func5\n"); sleep(1); func6(); }
void func6(void) { printf("In func6\n"); sleep(1); func7(); }
void func7(void) { printf("In func7\n"); sleep(1); func8(); }
void func8(void) { printf("In func8\n"); sleep(1); func9(); }
void func9(void) { printf("In func9\n"); sleep(1); Worker(); }

void Worker(void) {
    printf("In Worker\n");
    for (int i = 1; i <= WORKER_LOOP_COUNT; i++) {
        volatile int mmm = i*i;
	int abcde = 50 + 1;
        sleep(1);
        const char* msg = HelperHelper(i);
        printf("%s\n", msg);
    }
}

const char* HelperHelper(int n) {
    static char buf[128];
    snprintf(buf, sizeof(buf), "Hello from HelperHelper, hello number: %d", n);
    return buf;
}

int main(void) {
    // Set process name to "hello-hello"
    prctl(PR_SET_NAME, (unsigned long)"hello-hello", 0, 0, 0);

    func1();  // Start the chain
    return 0;
}
