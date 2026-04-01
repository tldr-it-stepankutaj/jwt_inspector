#include "progress.hpp"
#include <iostream>
#include <iomanip>
#include <sstream>
#include <cmath>

ProgressReporter::ProgressReporter(size_t total, bool json_mode)
    : total_(total), json_mode_(json_mode) {}

ProgressReporter::~ProgressReporter() {
    if (running_) {
        stop();
    }
}

void ProgressReporter::increment(size_t count) {
    attempts_.fetch_add(count, std::memory_order_relaxed);
}

void ProgressReporter::start() {
    if (running_) return;
    running_ = true;
    start_time_ = std::chrono::high_resolution_clock::now();
    reporter_thread_ = std::thread(&ProgressReporter::report_loop, this);
}

void ProgressReporter::stop() {
    if (!running_) return;
    running_ = false;
    if (reporter_thread_.joinable()) {
        reporter_thread_.join();
    }
    print_status();
    if (!json_mode_) {
        std::cerr << std::endl;
    }
}

size_t ProgressReporter::attempts() const {
    return attempts_.load(std::memory_order_relaxed);
}

void ProgressReporter::report_loop() {
    while (running_) {
        print_status();
        std::this_thread::sleep_for(std::chrono::milliseconds(500));
    }
}

void ProgressReporter::print_status() {
    size_t current = attempts_.load(std::memory_order_relaxed);
    auto now = std::chrono::high_resolution_clock::now();
    double elapsed_sec = std::chrono::duration<double>(now - start_time_).count();

    double progress = (total_ > 0) ? static_cast<double>(current) / static_cast<double>(total_) : 0.0;
    if (progress > 1.0) progress = 1.0;

    double hashes_per_sec = (elapsed_sec > 0.0) ? static_cast<double>(current) / elapsed_sec : 0.0;

    double eta_sec = 0.0;
    if (hashes_per_sec > 0.0 && current < total_) {
        eta_sec = static_cast<double>(total_ - current) / hashes_per_sec;
    }

    if (json_mode_) {
        std::ostringstream oss;
        oss << std::fixed << std::setprecision(3)
            << "{\"progress\": " << progress
            << ", \"attempts\": " << current
            << ", \"total\": " << total_
            << ", \"hashes_per_sec\": " << static_cast<size_t>(std::round(hashes_per_sec))
            << ", \"eta_sec\": " << std::setprecision(1) << eta_sec
            << "}";
        std::cerr << oss.str() << "\n";
    } else {
        // Build progress bar: 20 characters wide
        int filled = static_cast<int>(progress * 20.0);
        if (filled > 20) filled = 20;
        int empty = 20 - filled;

        std::ostringstream oss;
        oss << "\r[";
        for (int i = 0; i < filled; ++i) oss << '#';
        for (int i = 0; i < empty; ++i) oss << '-';
        oss << "] "
            << std::fixed << std::setprecision(1) << (progress * 100.0) << "%"
            << " | " << current << "/" << total_
            << " | " << static_cast<size_t>(std::round(hashes_per_sec)) << " h/s"
            << " | ETA: " << std::fixed << std::setprecision(1) << eta_sec << "s";

        std::cerr << oss.str() << std::flush;
    }
}
