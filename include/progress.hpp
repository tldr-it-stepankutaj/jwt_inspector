#pragma once
#include <atomic>
#include <chrono>
#include <thread>

class ProgressReporter {
public:
    // json_mode: if true, emit JSON lines to stderr instead of human-readable
    ProgressReporter(size_t total, bool json_mode = false);
    ~ProgressReporter();

    // Call from worker threads to increment attempt count
    void increment(size_t count = 1);

    // Start background reporting thread (reports every 500ms)
    void start();

    // Stop reporting, print final stats
    void stop();

    // Get current attempt count
    size_t attempts() const;

private:
    std::atomic<size_t> attempts_{0};
    size_t total_;
    bool json_mode_;
    bool running_ = false;
    std::thread reporter_thread_;
    std::chrono::high_resolution_clock::time_point start_time_;

    void report_loop();
    void print_status();
};
