#include <sycl/sycl.hpp>
#include <iostream>
#include <array>
#include "sha2.hpp"

// icpx -fsycl -std=c++20 -O3 -o main.exe main.cpp

enum class HASH_TYPE {
    SHA224, SHA256,
    SHA384, SHA512, SHA512_224, SHA512_256
};

constexpr static auto hash_type = HASH_TYPE::SHA256;      // Set the hash type to use for the VOW algorithm (can be changed to any of the supported hash types)
constexpr static auto N = 8;                              // Partial collision length
constexpr static auto K = 2;                              // Distinguishable point condition length (K <= N)
constexpr auto prefix = std::array<uint8_t, 4>{0x00, 0x11, 0x22, 0x33}; // Define a prefix for the input data
constexpr auto suffix = std::array<uint8_t, 4>{0x33, 0x22, 0x11, 0x00}; // Define a suffix for the input data



constexpr auto THREADS = 20'000;                   // Define the number of parallel threads to use
constexpr auto BATCH_SIZE = 100'000;             // Define the number of hash computations each thread performs before synchronizing and checking for DP collisions (should be large enough to find DPs but not too large to cause long synchronization delays)  
constexpr auto DP_ARRAY_LEN = 100;             // Define the maximum number of distinguishable points to store per thread (should be large enough to store all DPs found in one batch) 


template <typename HASH>
using HASH_OUT = std::array<uint8_t, HASH::OUTPUT_SIZE>;

template <typename HASH>
using HASH_IN = std::array<uint8_t, prefix.size() + suffix.size() + N>;

template<std::size_t N>
void print_arr(std::ostream &os, const std::array<uint8_t, N> &arr) noexcept{
    for (auto byte : arr)
        os << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(byte);
}

template<typename HASH>
constexpr static auto format_input(const auto &hash) noexcept {
    HASH_IN<HASH> input;
    std::copy(prefix.begin(), prefix.end(), input.begin());
    constexpr auto INPUT_SPACE = input.size() - (prefix.size() + suffix.size());
    std::copy(hash.begin(), hash.begin() + INPUT_SPACE, input.begin() + prefix.size());
    std::copy(suffix.begin(), suffix.end(), input.begin() + prefix.size() + INPUT_SPACE);
    return input;
}

template<typename HASH>
struct DP {
    HASH_IN<HASH> in;
    HASH_OUT<HASH> hash;
    std::size_t steps_since_last_dp = 0;
};

template<typename HASH>
struct DP_KEY {
    HASH_OUT<HASH> hash;
    DP_KEY(const HASH_OUT<HASH> &hash): hash(hash) {}
    bool operator==(const DP_KEY<HASH> &other) const noexcept {
        return std::memcmp(hash.data(), other.hash.data(), N) == 0;
    }
};

template<typename HASH>
struct std::hash<DP_KEY<HASH>> {
    std::size_t operator()(const DP_KEY<HASH> &v) const noexcept {
        return *reinterpret_cast<const std::size_t *>(v.hash.data() + K);
    }
};

template<typename HASH>
struct DPArray {
    std::array<DP<HASH>, DP_ARRAY_LEN> data;
    std::size_t dp_count = 0;

    DP<HASH> *begin() noexcept {
        return data.data();
    }
    DP<HASH> *end() noexcept {
        return data.data() + dp_count;  
    }

    void append(const HASH_IN<HASH> &in, const HASH_OUT<HASH> &hash, std::size_t steps_since_last_dp) noexcept {
        data[dp_count] = DP<HASH>{in, hash, steps_since_last_dp};
        ++dp_count;
    }

};

template<typename HASH>
constexpr static auto hash_from_seed(auto seed) {
    HASH_OUT<HASH> hash = {0};
    *reinterpret_cast<decltype(seed) *>(hash.data()) = seed;
    return hash;
}

template<typename HASH>
struct State {
    std::size_t hash_count = 0;
    std::size_t steps_since_last_dp = 0;
    HASH_IN<HASH> last_dp = {0};
    HASH_OUT<HASH> hash;
    DPArray<HASH> *dp_array = nullptr;

    State(uint32_t seed): hash{hash_from_seed<HASH>(seed)} {
        HASH hash_func;
        auto input = format_input<HASH>(hash);
        last_dp = input;
        hash_func.update(input.data(), input.size());
        hash_func.digest(hash.data());
        ++steps_since_last_dp;
        ++hash_count;
    }

    constexpr static HASH_OUT<HASH> ZERO_HASH = HASH_OUT<HASH>{0};

    bool is_dp() const noexcept {
        return std::memcmp(hash.data() , ZERO_HASH.data(), K) == 0;
    }

    void step() noexcept {
        HASH hash_func;
        auto input = format_input<HASH>(hash);
        hash_func.update(input.data(), input.size());
        hash_func.digest(hash.data());

        ++steps_since_last_dp;
        ++hash_count;

        if (is_dp()) {
            dp_array->append(input, hash, steps_since_last_dp);
            last_dp = std::move(input);
            steps_since_last_dp = 0;
        }
    }

};


template <typename HASH>
struct StageOneResult {
    std::size_t x_steps = 0;
    std::size_t y_steps = 0;
    std::size_t total_hash_counts = 0;
    HASH_IN<HASH> x;
    HASH_IN<HASH> y;
    HASH_OUT<HASH> dp_collided;
    bool found = false;
};


template<typename HASH>
struct StageTwoState {
    HASH_IN<HASH> in;
    HASH_OUT<HASH> out;
    std::size_t hash_count = 0;

    StageTwoState(const HASH_IN<HASH> &in): in{in} {
        HASH hash_func;
        hash_func.update(in.data(), in.size());
        hash_func.digest(out.data());
        ++hash_count;
    }
    bool operator==(const StageTwoState &other) const noexcept {
        return std::memcmp(out.data(), other.out.data(), N) == 0;
    }
    void step() noexcept {
        HASH hash_func;
        in = format_input<HASH>(out);
        hash_func.update(in.data(), in.size());
        hash_func.digest(out.data());
        ++hash_count;
    }
};

template <typename HASH>
class StageOneKernel;


template <typename HASH>
StageOneResult<HASH> vow_stage_one(sycl::queue &q, std::ostream &os=std::cout) {

    StageOneResult<HASH> result;

    std::cout << "Allocating Memory: ";
    State<HASH>* states = malloc_shared<State<HASH>>(THREADS, q); // malloc_host, malloc_device, malloc_shared
    DPArray<HASH> *device_dp_arrays = malloc_device<DPArray<HASH>>(THREADS, q);
    DPArray<HASH> *host_dp_arrays = malloc_host<DPArray<HASH>>(THREADS, q);
    
    std::unordered_map<
        DP_KEY<HASH>, 
        std::tuple<HASH_IN<HASH>, std::size_t>
    > dp_map;
    std::array<HASH_IN<HASH>, THREADS> last_dp;
    q.wait();
    std::cout << "Done" << std::endl;

    std::cout << "Initial batch: ";
    q.submit([&](sycl::handler& h) {
        h.parallel_for(sycl::range<1>(THREADS), [=](sycl::id<1> idx) {
            states[idx] = State<HASH>{static_cast<uint32_t>(idx)};
            states[idx].dp_array = device_dp_arrays + idx;
            device_dp_arrays[idx].dp_count = 0;         // Clear the new DP array for the next batch
            for (std::size_t i = 0; i < BATCH_SIZE; ++i) {
                states[idx].step();
            }
        });
    });
    for (std::size_t i = 0; i < THREADS; ++i) {
        last_dp[i] = format_input<HASH>(hash_from_seed<HASH>(i));
    }
    q.wait();
    std::cout << "Done" << std::endl;
    
    std::size_t batch_count = 1;
    while (!result.found) {

        q.wait();
        q.submit([&](sycl::handler& h) {
            h.memcpy(host_dp_arrays, device_dp_arrays, sizeof(DPArray<HASH>) * THREADS);
        });
        
        result.total_hash_counts = 0;
        for (auto i = 0; i < THREADS; ++i) {
            result.total_hash_counts += states[i].hash_count;
        }
    
        q.wait();
        q.submit([&](sycl::handler& h) {
            h.parallel_for<StageOneKernel<HASH>>(sycl::range<1>(THREADS), [=](sycl::id<1> idx) {
                device_dp_arrays[idx].dp_count = 0;                 // Clear the new DP array for the next batch
                for (std::size_t i = 0; i < BATCH_SIZE; ++i) {
                    states[idx].step();
                }
            });
        });

        // merge DP arrays and check for DP collision
        decltype(host_dp_arrays[0].dp_count) max_dp_count = 0;
        os << std::dec << "Batch: " << batch_count << ",\tTotal hash counts: " << result.total_hash_counts;
        for (std::size_t i = 0; i < THREADS; ++i) {
            max_dp_count = max_dp_count > host_dp_arrays[i].dp_count ? max_dp_count : host_dp_arrays[i].dp_count;
            for (const DP<HASH> &dp: host_dp_arrays[i]) {
                auto k = DP_KEY<HASH>(dp.hash);
                if (dp_map.contains(k)) {
                    result.x = std::get<0>(dp_map[k]);
                    result.x_steps = std::get<1>(dp_map[k]);
                    result.y = last_dp[i];
                    result.y_steps = dp.steps_since_last_dp;
                    result.dp_collided = dp.hash;
                    result.found = true;
                    goto stage_one_end; // break out of both loops
                }
                dp_map[k] = std::make_tuple(last_dp[i], dp.steps_since_last_dp);
                last_dp[i] = format_input<HASH>(dp.hash);
            }
        }
        os << ",\tDP chain counts: " << dp_map.size() << ",\tmax_dp_count: " << max_dp_count << std::endl;
        ++batch_count;
    }

    stage_one_end:
    os << "\nStage 1 ended with the following DP collision:";
    os << "\nDP Collided: ";
    print_arr(os, result.dp_collided);
    os << "\nX (" << std::dec << result.x_steps << " steps before DP Collided):\n";
    print_arr(os, result.x);
    os << "\nY (" << std::dec << result.y_steps << " steps before DP Collided):\n";
    print_arr(os, result.y);
    os << std::endl;


    os << "Freeing Memory: ";
    free(states, q); 
    free(device_dp_arrays, q);
    free(host_dp_arrays, q);
    os << "Done" << std::endl;

    return result;
}



template<typename HASH>
std::tuple<StageTwoState<HASH>, StageTwoState<HASH>> vow_stage_two(const StageOneResult<HASH> &stage_one, std::ostream &os=std::cout) {

    auto x_state = StageTwoState<HASH>(stage_one.x);
    auto y_state = StageTwoState<HASH>(stage_one.y);
    auto x_steps = stage_one.x_steps;
    auto y_steps = stage_one.y_steps;
    
    os << std::dec << "Before: " << "x_steps: " << x_steps << ", y_steps: " << y_steps << "\n";
    print_arr(os, x_state.out);
    os << "\t";
    print_arr(os, y_state.out);
    os << std::endl;

    for (; x_steps > y_steps; --x_steps) {
        x_state.step();
    }
    for (; x_steps < y_steps; --y_steps) {
        y_state.step();
    }
    os << std::dec << "Equal: " << "x_steps: " << x_steps << ", y_steps: " << y_steps << "\n";
    print_arr(os, x_state.out);
    os << "\t";
    print_arr(os, y_state.out);
    os << std::endl;

    for (; x_state != y_state && x_steps > 0 && y_steps > 0; --x_steps, --y_steps) {
        x_state.step();
        y_state.step();
    }
    os << std::dec << "Result:\n"
        << "x_steps: " << x_steps << ", y_steps: " << y_steps << "\n"
        << "x_state == y_state: " << (x_state == y_state ? "true" : "false") << std::endl;
    print_arr(os, x_state.out);
    os << "\t";
    print_arr(os, y_state.out);
    os << std::endl;
    return std::make_tuple(x_state, y_state);
}


template<typename HASH>
std::size_t print_collision(
    const StageTwoState<HASH> &x_state, 
    const StageTwoState<HASH> &y_state, 
    auto total_hash_counts, 
    auto duration, 
    std::ostream &os=std::cout
) {
    std::size_t n = 0;
    for (; n < HASH::OUTPUT_SIZE && x_state.out[n] == y_state.out[n]; ++n);
    
    if (x_state == y_state) {
        os << std::dec << "Found a partial collision! (" << n << " bytes matched)\n"
            << "Total hash counts: " << total_hash_counts << "\n"
            << "Duration: " << duration << " seconds\n"
            << "Hashing speed: " << total_hash_counts / duration << " hashes per second\n";
        os << "Input 1: ";
        print_arr(os, x_state.in);
        os << "\nOutput 1: ";
        print_arr(os, x_state.out);
        os << "\nInput 2: ";
        print_arr(os, y_state.in);
        os << "\nOutput 2: ";
        print_arr(os, y_state.out);
        os << std::endl;
        return n;
    } else {
        os << "no collision." << std::endl;
        return n;
    }
}


void print_device_info(sycl::queue &q, std::ostream &os=std::cout) {
    os << "Selected device: "
        << q.get_device().get_info<sycl::info::device::name>() << std::endl;
}

void divider(std::ostream &os=std::cout) {
    os << "\n\n=====================================================================" << std::endl;
}


template<typename HASH>
void vow_partial_collide() {

    sycl::queue q{sycl::default_selector_v};
    // sycl::queue q{sycl::gpu_selector_v};
    // sycl::queue q{sycl::cpu_selector_v};


    divider();
    print_device_info(q, std::cout);

    std::cout << "Starting VOW partial collision attack on " << typeid(HASH).name() << " with N = " << N << " and K = " << K << std::endl;
    std::cout << "Prefix: ";
    print_arr(std::cout, prefix);
    std::cout << "\nSuffix: ";
    print_arr(std::cout, suffix);
    std::cout << std::endl;

    divider();
    auto start1 = std::chrono::steady_clock::now();
    std::cout << std::dec << "Stage 1 started at: " << std::chrono::duration_cast<std::chrono::seconds>(start1.time_since_epoch()).count() << " seconds since epoch" << std::endl;
    auto stage_one = vow_stage_one<HASH>(q);
    auto end1 = std::chrono::steady_clock::now();
    auto seconds1 = std::chrono::duration_cast<std::chrono::seconds>(end1 - start1).count();
    std::cout << std::dec << "\nStage 1 ended in: " << seconds1 << " seconds (" <<  stage_one.total_hash_counts / seconds1 << " hashes per second)" << std::endl;

    divider();
    auto start2 = std::chrono::steady_clock::now();
    std::cout << std::dec << "Stage 2 started at: " << std::chrono::duration_cast<std::chrono::seconds>(start2.time_since_epoch()).count() << " seconds since epoch" << std::endl;
    auto [x_state, y_state] = vow_stage_two<HASH>(stage_one);
    auto end2 = std::chrono::steady_clock::now();
    auto seconds2 = std::chrono::duration_cast<std::chrono::seconds>(end2 - start2).count();
    auto hashes_per_second_stage2 = seconds2 > 0 ? (x_state.hash_count + y_state.hash_count) / seconds2 : (x_state.hash_count + y_state.hash_count);
    std::cout << std::dec << "\nStage 2 ended in: " << seconds2 << " seconds (" <<  hashes_per_second_stage2 << " hashes per second)" << std::endl;

    divider();
    std::size_t total_hash_counts = stage_one.total_hash_counts + x_state.hash_count + y_state.hash_count;
    (void) print_collision<HASH>(x_state, y_state, total_hash_counts, seconds1 + seconds2);
}

int main() {
    
    switch (hash_type) {
    case HASH_TYPE::SHA224:
        vow_partial_collide<SHA224>();
        break;
    case HASH_TYPE::SHA256:
        vow_partial_collide<SHA256>();
        break;
    case HASH_TYPE::SHA384:
        vow_partial_collide<SHA384>();
        break;
    case HASH_TYPE::SHA512:
        vow_partial_collide<SHA512>();
        break;
    case HASH_TYPE::SHA512_224:
        vow_partial_collide<SHA512_224>();
        break;
    case HASH_TYPE::SHA512_256:
        vow_partial_collide<SHA512_256>();
        break;
    }

    return 0;
}



