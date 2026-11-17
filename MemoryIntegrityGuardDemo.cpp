#include <windows.h>
#include <psapi.h>

#include <atomic>
#include <array>
#include <chrono>
#include <condition_variable>
#include <cstdint>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <mutex>
#include <optional>
#include <sstream>
#include <string>
#include <string_view>
#include <thread>

#pragma comment(lib, "Psapi.lib")

class MemoryIntegrityGuard {
public:
    MemoryIntegrityGuard(const std::atomic<std::uint8_t>* region, std::size_t length,
                         std::chrono::milliseconds interval)
        : atomicRegion_(region), length_(length), interval_(interval) {}

    MemoryIntegrityGuard(const std::uint8_t* region, std::size_t length,
                         std::chrono::milliseconds interval, bool monitorProtection = false)
        : plainRegion_(region), length_(length), interval_(interval), monitorProtection_(monitorProtection) {}

    bool Start() {
        if ((atomicRegion_ == nullptr && plainRegion_ == nullptr) || length_ == 0 || running_.exchange(true)) {
            return false;
        }
        referenceHash_ = CalculateHash();
        if (monitorProtection_) {
            MEMORY_BASIC_INFORMATION memoryInfo{};
            if (VirtualQuery(plainRegion_, &memoryInfo, sizeof(memoryInfo)) == 0) {
                running_ = false;
                return false;
            }
            referenceProtection_ = BaseProtection(memoryInfo.Protect);
        }
        worker_ = std::thread(&MemoryIntegrityGuard::Monitor, this);
        WriteLog("Monitoring started. Reference hash: " + ToHex(referenceHash_));
        return true;
    }

    void Stop() {
        running_ = false;
        wakeUp_.notify_one();
        if (worker_.joinable()) {
            worker_.join();
        }
    }

    bool IncidentDetected() const { return incidentDetected_; }

    std::uint64_t ChecksPerformed() const { return checksPerformed_.load(); }

    bool WaitForIncident(std::chrono::milliseconds timeout) const {
        const auto deadline = std::chrono::steady_clock::now() + timeout;
        while (std::chrono::steady_clock::now() < deadline) {
            if (incidentDetected_.load()) {
                return true;
            }
            std::this_thread::sleep_for(std::chrono::milliseconds(10));
        }
        return incidentDetected_.load();
    }

    ~MemoryIntegrityGuard() { Stop(); }

private:
    static DWORD BaseProtection(DWORD protection) {
        return protection & 0xFF;
    }

    std::uint32_t CalculateHash() const {
        std::uint32_t hash = 2166136261u;
        for (std::size_t i = 0; i < length_; ++i) {
            const auto byte = atomicRegion_ == nullptr
                ? plainRegion_[i]
                : atomicRegion_[i].load(std::memory_order_relaxed);
            hash ^= byte;
            hash *= 16777619u;
        }
        return hash;
    }

    static std::string ToHex(std::uint32_t value) {
        std::ostringstream stream;
        stream << "0x" << std::hex << std::uppercase << value;
        return stream.str();
    }

    static void WriteLog(const std::string& message) {
        std::ofstream log("security_audit.log", std::ios::app);
        log << message << '\n';
    }

    void Monitor() {
        std::unique_lock<std::mutex> lock(waitMutex_);
        while (running_) {
            if (wakeUp_.wait_for(lock, interval_, [this] { return !running_.load(); })) {
                break;
            }
            lock.unlock();
            if (monitorProtection_) {
                MEMORY_BASIC_INFORMATION memoryInfo{};
                const bool querySucceeded = VirtualQuery(plainRegion_, &memoryInfo, sizeof(memoryInfo)) != 0;
                if (!querySucceeded || BaseProtection(memoryInfo.Protect) != referenceProtection_) {
                    incidentDetected_ = true;
                    WriteLog("SECURITY INCIDENT: memory page protection changed.");
                    running_ = false;
                    lock.lock();
                    continue;
                }
            }
            const auto currentHash = CalculateHash();
            checksPerformed_.fetch_add(1);
            if (currentHash != referenceHash_) {
                incidentDetected_ = true;
                WriteLog("SECURITY INCIDENT: guarded region was modified. Current hash: " + ToHex(currentHash));
                running_ = false;
            }
            lock.lock();
        }
    }

    const std::atomic<std::uint8_t>* atomicRegion_ = nullptr;
    const std::uint8_t* plainRegion_ = nullptr;
    std::size_t length_;
    std::chrono::milliseconds interval_;
    std::uint32_t referenceHash_ = 0;
    std::atomic<bool> running_ = false;
    std::atomic<bool> incidentDetected_ = false;
    std::atomic<std::uint64_t> checksPerformed_ = 0;
    std::condition_variable wakeUp_;
    std::mutex waitMutex_;
    bool monitorProtection_ = false;
    DWORD referenceProtection_ = 0;
    std::thread worker_;
};

struct ExecutableSection {
    const std::uint8_t* address = nullptr;
    std::size_t size = 0;
};

std::optional<ExecutableSection> FindTextSection() {
    const auto moduleBase = reinterpret_cast<const std::uint8_t*>(GetModuleHandleW(nullptr));
    if (moduleBase == nullptr) {
        return std::nullopt;
    }

    const auto* dosHeader = reinterpret_cast<const IMAGE_DOS_HEADER*>(moduleBase);
    if (dosHeader->e_magic != IMAGE_DOS_SIGNATURE) {
        return std::nullopt;
    }

    const auto* ntHeaders = reinterpret_cast<const IMAGE_NT_HEADERS*>(moduleBase + dosHeader->e_lfanew);
    if (ntHeaders->Signature != IMAGE_NT_SIGNATURE) {
        return std::nullopt;
    }

    const auto* section = IMAGE_FIRST_SECTION(ntHeaders);
    for (WORD index = 0; index < ntHeaders->FileHeader.NumberOfSections; ++index, ++section) {
        const std::string_view name(reinterpret_cast<const char*>(section->Name), 5);
        if (name == ".text") {
            const std::size_t sectionSize = section->Misc.VirtualSize == 0
                ? section->SizeOfRawData
                : section->Misc.VirtualSize;
            return ExecutableSection{ moduleBase + section->VirtualAddress, sectionSize };
        }
    }

    return std::nullopt;
}

int RunModuleCheck() {
    const auto textSection = FindTextSection();
    if (!textSection.has_value()) {
        std::cerr << "Unable to locate the .text section of the current executable.\n";
        return 1;
    }

    constexpr auto checkInterval = std::chrono::milliseconds(500);
    MemoryIntegrityGuard guard(textSection->address, textSection->size, checkInterval, true);
    if (!guard.Start()) {
        std::cerr << "Unable to start the .text section monitor.\n";
        return 1;
    }

    std::cout << "Module check: monitoring .text section (" << textSection->size
        << " bytes) for 3 seconds...\n";
    std::this_thread::sleep_for(std::chrono::seconds(3));
    guard.Stop();

    std::cout << "Checks performed: " << guard.ChecksPerformed() << '\n';
    std::cout << (guard.IncidentDetected()
        ? "Result: unexpected modification detected in .text.\n"
        : "Result: .text section remained unchanged.\n");
    return guard.IncidentDetected() ? 2 : 0;
}

int RunProtectionSelfTest() {
    constexpr std::size_t pageSize = 4096;
    constexpr auto checkInterval = std::chrono::milliseconds(250);
    auto* testPage = static_cast<std::uint8_t*>(VirtualAlloc(
        nullptr, pageSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE));
    if (testPage == nullptr) {
        std::cerr << "Unable to allocate the test page.\n";
        return 1;
    }

    testPage[0] = 0x42;
    MemoryIntegrityGuard guard(testPage, pageSize, checkInterval, true);
    if (!guard.Start()) {
        VirtualFree(testPage, 0, MEM_RELEASE);
        std::cerr << "Unable to start the page protection monitor.\n";
        return 1;
    }

    std::cout << "Protection self-test: changing the protection of an owned test page...\n";
    std::this_thread::sleep_for(std::chrono::milliseconds(100));
    DWORD oldProtection = 0;
    if (!VirtualProtect(testPage, pageSize, PAGE_READONLY, &oldProtection)) {
        guard.Stop();
        VirtualFree(testPage, 0, MEM_RELEASE);
        std::cerr << "Unable to change the protection of the test page.\n";
        return 1;
    }

    const bool detected = guard.WaitForIncident(checkInterval + std::chrono::milliseconds(250));
    guard.Stop();
    VirtualFree(testPage, 0, MEM_RELEASE);
    std::cout << (detected
        ? "Result: page protection change detected.\n"
        : "Result: page protection change was not detected.\n");
    return detected ? 0 : 2;
}

struct ProcessSnapshot {
    std::uint64_t cpuTime100ns = 0;
    std::size_t workingSetBytes = 0;
    std::size_t privateUsageBytes = 0;
};

std::uint64_t FileTimeToUInt64(const FILETIME& value) {
    ULARGE_INTEGER result{};
    result.LowPart = value.dwLowDateTime;
    result.HighPart = value.dwHighDateTime;
    return result.QuadPart;
}

std::optional<ProcessSnapshot> CaptureProcessSnapshot() {
    FILETIME creationTime{};
    FILETIME exitTime{};
    FILETIME kernelTime{};
    FILETIME userTime{};
    if (!GetProcessTimes(GetCurrentProcess(), &creationTime, &exitTime, &kernelTime, &userTime)) {
        return std::nullopt;
    }

    PROCESS_MEMORY_COUNTERS_EX memoryCounters{};
    memoryCounters.cb = sizeof(memoryCounters);
    if (!GetProcessMemoryInfo(GetCurrentProcess(),
                              reinterpret_cast<PROCESS_MEMORY_COUNTERS*>(&memoryCounters),
                              sizeof(memoryCounters))) {
        return std::nullopt;
    }

    return ProcessSnapshot{
        FileTimeToUInt64(kernelTime) + FileTimeToUInt64(userTime),
        memoryCounters.WorkingSetSize,
        memoryCounters.PrivateUsage
    };
}

double CalculateCpuPercent(const ProcessSnapshot& before, const ProcessSnapshot& after,
                           std::chrono::milliseconds elapsed) {
    if (elapsed.count() == 0 || after.cpuTime100ns < before.cpuTime100ns) {
        return 0.0;
    }
    const double elapsed100ns = static_cast<double>(elapsed.count()) * 10000.0;
    return 100.0 * static_cast<double>(after.cpuTime100ns - before.cpuTime100ns) / elapsed100ns;
}

int RunPerformanceTest() {
    const auto textSection = FindTextSection();
    if (!textSection.has_value()) {
        std::cerr << "Unable to locate the .text section of the current executable.\n";
        return 1;
    }

    const std::array intervals{
        std::chrono::milliseconds(100),
        std::chrono::milliseconds(250),
        std::chrono::milliseconds(500),
        std::chrono::milliseconds(1000)
    };
    constexpr auto duration = std::chrono::seconds(10);
    std::ofstream csv("performance_results.csv");
    csv << "mode,interval_ms,checks,cpu_percent,working_set_kib,private_usage_kib\n";

    const auto baselineBefore = CaptureProcessSnapshot();
    if (!baselineBefore.has_value()) {
        std::cerr << "Unable to read process metrics.\n";
        return 1;
    }
    std::cout << "Performance test: measuring idle baseline for 10 seconds...\n";
    std::this_thread::sleep_for(duration);
    const auto baselineAfter = CaptureProcessSnapshot();
    if (!baselineAfter.has_value()) {
        std::cerr << "Unable to read process metrics.\n";
        return 1;
    }
    const double baselineCpu = CalculateCpuPercent(*baselineBefore, *baselineAfter,
                                                    std::chrono::duration_cast<std::chrono::milliseconds>(duration));
    csv << "baseline,0,0," << std::fixed << std::setprecision(4) << baselineCpu << ','
        << baselineAfter->workingSetBytes / 1024 << ',' << baselineAfter->privateUsageBytes / 1024 << '\n';
    std::cout << "Baseline CPU: " << std::fixed << std::setprecision(4) << baselineCpu << "%\n";

    bool allStable = true;
    for (const auto interval : intervals) {
        MemoryIntegrityGuard guard(textSection->address, textSection->size, interval, true);
        const auto before = CaptureProcessSnapshot();
        if (!before.has_value() || !guard.Start()) {
            std::cerr << "Unable to start a performance measurement.\n";
            return 1;
        }
        std::this_thread::sleep_for(duration);
        guard.Stop();
        const auto after = CaptureProcessSnapshot();
        if (!after.has_value()) {
            std::cerr << "Unable to read process metrics.\n";
            return 1;
        }

        const double cpuPercent = CalculateCpuPercent(*before, *after,
            std::chrono::duration_cast<std::chrono::milliseconds>(duration));
        const auto workingSetKib = after->workingSetBytes / 1024;
        const auto privateUsageKib = after->privateUsageBytes / 1024;
        csv << "monitor," << interval.count() << ',' << guard.ChecksPerformed() << ','
            << std::fixed << std::setprecision(4) << cpuPercent << ',' << workingSetKib
            << ',' << privateUsageKib << '\n';
        std::cout << "Interval " << interval.count() << " ms: "
            << guard.ChecksPerformed() << " checks, CPU " << std::fixed << std::setprecision(4)
            << cpuPercent << "%, working set " << workingSetKib << " KiB\n";
        allStable = allStable && !guard.IncidentDetected();
    }

    std::cout << "Results saved to performance_results.csv\n";
    return allStable ? 0 : 2;
}

struct SelfTestResult {
    bool detected = false;
    long long latencyMs = 0;
};

struct NormalTestResult {
    bool falseAlarm = false;
    std::uint64_t checks = 0;
};

SelfTestResult RunSelfTest(std::chrono::milliseconds checkInterval,
                           std::chrono::milliseconds modificationDelay) {
    std::array<std::atomic<std::uint8_t>, 64> testRegion{};
    testRegion[0] = 0x42;

    MemoryIntegrityGuard guard(testRegion.data(), testRegion.size(), checkInterval);
    if (!guard.Start()) {
        return {};
    }

    std::this_thread::sleep_for(modificationDelay);
    const auto modificationTime = std::chrono::steady_clock::now();
    testRegion[0] = 0x99;
    const bool detected = guard.WaitForIncident(checkInterval + std::chrono::milliseconds(250));
    const auto latency = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::steady_clock::now() - modificationTime);
    guard.Stop();

    return { detected, latency.count() };
}

NormalTestResult RunNormalTest(std::chrono::milliseconds checkInterval,
                               std::chrono::milliseconds duration) {
    std::array<std::atomic<std::uint8_t>, 64> testRegion{};
    testRegion[0] = 0x42;

    MemoryIntegrityGuard guard(testRegion.data(), testRegion.size(), checkInterval);
    if (!guard.Start()) {
        return { true, 0 };
    }

    std::this_thread::sleep_for(duration);
    guard.Stop();
    return { guard.IncidentDetected(), guard.ChecksPerformed() };
}

int RunBenchmark() {
    const std::array intervals{
        std::chrono::milliseconds(100),
        std::chrono::milliseconds(250),
        std::chrono::milliseconds(500),
        std::chrono::milliseconds(1000)
    };
    constexpr int trialsPerInterval = 5;
    std::ofstream csv("benchmark_results.csv");
    csv << "interval_ms,trial,detected,latency_ms\n";

    bool allDetected = true;
    std::cout << "Benchmark: " << trialsPerInterval << " trials for each interval.\n";
    for (const auto interval : intervals) {
        for (int trial = 1; trial <= trialsPerInterval; ++trial) {
            const auto result = RunSelfTest(interval, interval / 2);
            csv << interval.count() << ',' << trial << ',' << result.detected << ','
                << result.latencyMs << '\n';
            std::cout << "Interval " << interval.count() << " ms, trial " << trial
                << ": " << (result.detected ? "detected in " : "not detected, timeout after ")
                << result.latencyMs << " ms\n";
            allDetected = allDetected && result.detected;
        }
    }

    std::cout << "Results saved to benchmark_results.csv\n";
    return allDetected ? 0 : 2;
}

int RunStabilityTest() {
    const std::array intervals{
        std::chrono::milliseconds(100),
        std::chrono::milliseconds(250),
        std::chrono::milliseconds(500),
        std::chrono::milliseconds(1000)
    };
    constexpr int trialsPerInterval = 10;
    std::ofstream csv("stability_results.csv");
    csv << "interval_ms,trial,checks,false_alarm\n";

    std::uint64_t totalChecks = 0;
    std::uint64_t falseAlarms = 0;
    std::cout << "Stability test: no memory modification is performed.\n";
    for (const auto interval : intervals) {
        const auto duration = interval + interval / 4;
        for (int trial = 1; trial <= trialsPerInterval; ++trial) {
            const auto result = RunNormalTest(interval, duration);
            csv << interval.count() << ',' << trial << ',' << result.checks << ','
                << result.falseAlarm << '\n';
            std::cout << "Interval " << interval.count() << " ms, trial " << trial
                << ": " << result.checks << " check(s), "
                << (result.falseAlarm ? "false alarm" : "no false alarm") << '\n';
            totalChecks += result.checks;
            falseAlarms += result.falseAlarm ? 1 : 0;
        }
    }

    const double falsePositiveRate = totalChecks == 0
        ? 0.0
        : 100.0 * static_cast<double>(falseAlarms) / static_cast<double>(totalChecks);
    std::cout << std::fixed << std::setprecision(2)
        << "Total checks: " << totalChecks << ", false alarms: " << falseAlarms
        << ", FPR: " << falsePositiveRate << "%\n";
    std::cout << "Results saved to stability_results.csv\n";
    return falseAlarms == 0 && totalChecks > 0 ? 0 : 2;
}

int main(int argc, char* argv[]) {
    const std::string_view mode = argc == 2 ? argv[1] : "";
    const bool normalRun = mode == "--normal";
    const bool benchmarkRun = mode == "--benchmark";
    const bool stabilityRun = mode == "--stability";
    const bool moduleCheckRun = mode == "--module-check";
    const bool protectionSelfTestRun = mode == "--protection-self-test";
    const bool performanceRun = mode == "--performance";
    if (argc > 1 && !normalRun && !benchmarkRun && !stabilityRun && !moduleCheckRun && !protectionSelfTestRun && !performanceRun) {
        std::cerr << "Usage: ProtectedDemo.exe [--normal | --benchmark | --stability | --module-check | --protection-self-test | --performance]\n";
        return 1;
    }

    if (benchmarkRun) {
        return RunBenchmark();
    }
    if (stabilityRun) {
        return RunStabilityTest();
    }
    if (moduleCheckRun) {
        return RunModuleCheck();
    }
    if (protectionSelfTestRun) {
        return RunProtectionSelfTest();
    }
    if (performanceRun) {
        return RunPerformanceTest();
    }

    constexpr auto checkInterval = std::chrono::milliseconds(1000);
    if (!normalRun) {
        std::cout << "Self-test mode: modifying this program's own test region...\n";
        const auto result = RunSelfTest(checkInterval, std::chrono::milliseconds(300));
        std::cout << (result.detected
            ? "Detection latency: " + std::to_string(result.latencyMs) + " ms\n"
            : "Detection timeout exceeded.\n");
        return result.detected ? 0 : 2;
    }

    std::array<std::atomic<std::uint8_t>, 64> testRegion{};
    testRegion[0] = 0x42;

    MemoryIntegrityGuard guard(testRegion.data(), testRegion.size(), checkInterval);
    if (!guard.Start()) {
        std::cerr << "Unable to start memory monitor.\n";
        return 1;
    }

    std::cout << "Normal mode: monitoring an unchanged region for 3 seconds...\n";
    std::this_thread::sleep_for(std::chrono::seconds(3));

    guard.Stop();
    std::cout << (guard.IncidentDetected()
        ? "Result: false alarm detected; see security_audit.log\n"
        : "Result: no modification and no false alarm.\n");
    return guard.IncidentDetected() ? 2 : 0;
}
