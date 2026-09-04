#pragma once

#include <cstddef>
#include <exception>
#include <functional>
#include <iostream>
#include <string_view>
#include <type_traits>
#include <utility>

namespace test_support {

class Runner {
public:
    template<typename Function>
    void run(std::string_view name, Function&& function) {
        ++total_;
        std::cout << "[ RUN      ] " << name << '\n' << std::flush;

        try {
            using Result = std::invoke_result_t<Function>;
            if constexpr(std::is_same_v<Result, bool>) {
                if(!std::invoke(std::forward<Function>(function))) {
                    ++failed_;
                    std::cerr << "[  FAILED  ] " << name << '\n';
                    return;
                }
            } else {
                static_assert(std::is_same_v<Result, void>);
                std::invoke(std::forward<Function>(function));
            }
        } catch(const std::exception& error) {
            ++failed_;
            std::cerr << "[  FAILED  ] " << name << ": "
                      << error.what() << '\n';
            return;
        } catch(...) {
            ++failed_;
            std::cerr << "[  FAILED  ] " << name
                      << ": unknown exception\n";
            return;
        }

        std::cout << "[       OK ] " << name << '\n';
    }

    [[nodiscard]] int finish() const {
        const std::size_t passed = total_ - failed_;
        std::cout << "[==========] " << passed << '/' << total_
                  << " test function(s) passed\n";
        return failed_ == 0 ? 0 : 1;
    }

private:
    std::size_t total_ = 0;
    std::size_t failed_ = 0;
};

} // namespace test_support
