
#include <random>

// shared objects for random num generation
inline std::random_device rd;
inline std::mt19937 rng(rd());
inline std::uniform_int_distribution<uint32_t> dist;
