#include <cmath>
#include <random>

extern "C" void randombytes(unsigned char *b, unsigned long long n) {
#ifdef __MSC_VER
	std::random_device gen;
	const size_t sample_bytes = sizeof(std::random_device::result_type);
	int i;
	for (i = 0; i < n; i+=sample_bytes) {
		std::random_device::result_type sample = gen();
		memcpy(&b[i], &sample, ((n-i) < sample_bytes ? (n-i) : sample_bytes));
	}
#endif
}
