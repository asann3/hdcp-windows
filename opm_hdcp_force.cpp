// opm_hdcp_force.cpp
//
// Small Win32 GUI that forces HDCP ON/OFF on the primary monitor's display
// outputs via the public Output Protection Manager (OPM) API, WITHOUT playing
// any real DRM content. Purpose: find out whether a plain Win32 app can make
// the driver actually run an HDCP authentication (AKE) on the physical link,
// or whether the driver just reports "HDCP is on" without doing anything on
// the wire.
//
// The OPM handshake and request signing live in opm_session.h. This file is
// only the window, and a worker thread that owns the OPM sessions: it applies
// ON/OFF requests from the buttons, polls the actual/virtual protection level
// and, when "auto-recover" is enabled, forces OFF -> ON whenever the actual
// level drops (re-sending ON alone may be a no-op for the driver).
//
// Command line (all optional):
//   /on            turn HDCP ON right after start-up
//   /watch         start with auto-recover enabled
//   /interval:N    polling interval in ms while auto-recover is active
//   /cert:N        use certificate N of the OPM chain (debugging aid)
//
// Research / testing tool only. Certificate chain validation is deliberately
// skipped (see opm_session.h); this is not a DRM client.

#include "opm_session.h"

#include <commctrl.h>
#include <shellapi.h>
#include <objidl.h>
#include <gdiplus.h>

#include <algorithm>
#include <atomic>
#include <chrono>
#include <condition_variable>
#include <cstdarg>
#include <cstdio>
#include <cwchar>
#include <deque>
#include <mutex>
#include <optional>
#include <thread>

#pragma comment(lib, "dxva2.lib")
#pragma comment(lib, "d3d9.lib")
#pragma comment(lib, "bcrypt.lib")
#pragma comment(lib, "crypt32.lib")
#pragma comment(lib, "user32.lib")
#pragma comment(lib, "gdi32.lib")
#pragma comment(lib, "ole32.lib")
#pragma comment(lib, "shell32.lib")
#pragma comment(lib, "comctl32.lib")
#pragma comment(lib, "gdiplus.lib")
#pragma comment(linker, "\"/manifestdependency:type='win32' name='Microsoft.Windows.Common-Controls' version='6.0.0.0' processorArchitecture='*' publicKeyToken='6595b64144ccf1df' language='*'\"")

namespace gp = Gdiplus;
using Clock = std::chrono::steady_clock;

// ---------------------------------------------------------------------------
// Messages from the worker thread to the window (payloads are heap-allocated
// and owned by the receiver).
// ---------------------------------------------------------------------------

constexpr UINT WM_APP_LOG = WM_APP + 1;          // lParam: std::wstring*
constexpr UINT WM_APP_STATE = WM_APP + 2;        // lParam: Snapshot*
constexpr UINT WM_APP_WORKER_DONE = WM_APP + 3;

constexpr UINT_PTR TIMER_CLOSE_FALLBACK = 1;
constexpr UINT_PTR TIMER_COPY_LABEL = 2;
constexpr UINT_PTR TIMER_DISPLAY_CHANGE = 3;

// ERROR_GRAPHICS_OPM_HDCP_NOT_SUPPORTED: "the video output does not support HDCP".
constexpr HRESULT kErrHdcpNotSupported = static_cast<HRESULT>(0xC0262513L);

enum class Phase { Connecting, Ready, Busy, Error };

struct OutputStatus {
    std::wstring label;  // e.g. "DISPLAY2 #0"
    bool ok = false;
    bool hdcpUnsupported = false;  // driver said this output can't do HDCP
    bool actualKnown = true;  // false if the driver rejects OPM_GET_ACTUAL_PROTECTION_LEVEL
    ULONG actual = 0;
    ULONG virt = 0;
};

struct Snapshot {
    Phase phase = Phase::Connecting;
    bool requestedOn = false;
    std::vector<OutputStatus> outputs;
    int drops = 0;
    double downtimeMs = 0.0;
    std::wstring error;

    bool operator==(const Snapshot& o) const {
        if (phase != o.phase || requestedOn != o.requestedOn || drops != o.drops ||
            downtimeMs != o.downtimeMs || error != o.error ||
            outputs.size() != o.outputs.size())
            return false;
        for (size_t i = 0; i < outputs.size(); ++i) {
            if (outputs[i].label != o.outputs[i].label || outputs[i].ok != o.outputs[i].ok ||
                outputs[i].actualKnown != o.outputs[i].actualKnown ||
                outputs[i].hdcpUnsupported != o.outputs[i].hdcpUnsupported ||
                outputs[i].actual != o.outputs[i].actual ||
                outputs[i].virt != o.outputs[i].virt)
                return false;
        }
        return true;
    }
};

// Written by the UI thread, read by the worker thread when posting.
static std::atomic<HWND> g_hwnd{nullptr};

void OpmLog(const wchar_t* fmt, ...) {
    wchar_t body[1024];
    va_list ap;
    va_start(ap, fmt);
    _vsnwprintf_s(body, _countof(body), _TRUNCATE, fmt, ap);
    va_end(ap);

    SYSTEMTIME t;
    GetLocalTime(&t);
    wchar_t line[1100];
    _snwprintf_s(line, _countof(line), _TRUNCATE, L"%02d:%02d:%02d.%03d  %ls",
                 t.wHour, t.wMinute, t.wSecond, t.wMilliseconds, body);

    auto* s = new std::wstring(line);
    HWND h = g_hwnd.load();
    if (!h || !PostMessageW(h, WM_APP_LOG, 0, reinterpret_cast<LPARAM>(s))) delete s;
}

static std::wstring DescribeHr(HRESULT hr) {
    wchar_t* sys = nullptr;
    FormatMessageW(FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM |
                       FORMAT_MESSAGE_IGNORE_INSERTS,
                   nullptr, static_cast<DWORD>(hr), 0, reinterpret_cast<LPWSTR>(&sys), 0, nullptr);
    wchar_t code[16];
    _snwprintf_s(code, _countof(code), _TRUNCATE, L"0x%08lX", static_cast<unsigned long>(hr));
    std::wstring s = code;
    if (sys) {
        std::wstring text = sys;
        LocalFree(sys);
        while (!text.empty() && (text.back() == L'\n' || text.back() == L'\r' || text.back() == L' '))
            text.pop_back();
        if (!text.empty()) s += L" " + text;
    }
    return s;
}

static std::wstring DescribeError(const OpmError& e) {
    return e.where + L": " + DescribeHr(e.hr);
}

// ---------------------------------------------------------------------------
// Worker thread: owns every OPM session. Only talks to the UI through
// PostMessage, so it can never deadlock against the window.
// ---------------------------------------------------------------------------

enum class Cmd { On, Off, Reconnect, Quit };

class Worker {
public:
    std::atomic<bool> watch{false};
    std::atomic<int> intervalMs{100};
    bool startOn = false;

    void Start() { thread_ = std::thread([this] { Run(); }); }

    void Post(Cmd c) {
        {
            std::lock_guard<std::mutex> lk(m_);
            q_.push_back(c);
        }
        cv_.notify_one();
    }

    void Join() {
        if (thread_.joinable()) thread_.join();
    }
    void Detach() {
        if (thread_.joinable()) thread_.detach();
    }

private:
    struct Output {
        std::wstring label;
        std::unique_ptr<OpmSession> session;
        OutputStatus status;
        bool wasOn = false;
        std::optional<Clock::time_point> dropStart;
        Clock::time_point lastReinit{};
        Clock::time_point lastNudge{};
        bool actualUnsupported = false;
        int reinitFailures = 0;
    };

    // Give the driver this long after an ON request before the watchdog starts
    // treating "still not ON" as a failure that needs an OFF -> ON nudge.
    static constexpr auto kOnGrace = std::chrono::milliseconds(1500);
    static constexpr int kIdlePollMs = 500;
    // While HDCP stays down, wait this long between OFF -> ON nudges. Nudging
    // on every poll (50-100 ms) can restart the authentication before it has
    // had a chance to finish, so the link would never come back.
    static constexpr auto kNudgeBackoff = std::chrono::milliseconds(1000);

    void Publish() {
        Snapshot s;
        s.phase = phase_;
        s.requestedOn = requestedOn_;
        s.drops = drops_;
        s.downtimeMs = downtimeMs_;
        s.error = error_;
        for (auto& o : outs_) s.outputs.push_back(o.status);
        if (lastPublished_ && *lastPublished_ == s) return;
        lastPublished_ = s;
        auto* p = new Snapshot(std::move(s));
        if (!PostMessageW(g_hwnd, WM_APP_STATE, 0, reinterpret_cast<LPARAM>(p))) delete p;
    }

    static BOOL CALLBACK CollectMonitor(HMONITOR mon, HDC, LPRECT, LPARAM lp) {
        reinterpret_cast<std::vector<HMONITOR>*>(lp)->push_back(mon);
        return TRUE;
    }

    static std::wstring MonitorName(HMONITOR mon) {
        MONITORINFOEXW mi{};
        mi.cbSize = sizeof(mi);
        if (!GetMonitorInfoW(mon, &mi)) return L"(不明なモニタ)";
        std::wstring name = mi.szDevice;
        if (name.rfind(L"\\\\.\\", 0) == 0) name.erase(0, 4);  // "\\.\DISPLAY1" -> "DISPLAY1"
        if (mi.dwFlags & MONITORINFOF_PRIMARY) name += L"(プライマリ)";
        return name;
    }

    // Opens an OPM session on every output of every monitor. Extended desktops
    // have one HMONITOR per display, so looking only at the primary one misses
    // the external display entirely; in duplicate mode both panels sit behind
    // a single HMONITOR as separate outputs.
    bool Connect() {
        outs_.clear();
        phase_ = Phase::Connecting;
        error_.clear();
        Publish();

        std::vector<HMONITOR> monitors;
        EnumDisplayMonitors(nullptr, nullptr, CollectMonitor, reinterpret_cast<LPARAM>(&monitors));
        OpmLog(L"モニタ: %zu 台", monitors.size());

        OpmError lastError{L"OPMGetVideoOutputsFromHMONITOR (出力 0 個)", E_FAIL};
        for (HMONITOR mon : monitors) {
            const std::wstring mname = MonitorName(mon);
            ULONG n = 0;
            try {
                n = CountVideoOutputs(mon);
            } catch (const OpmError& e) {
                lastError = e;
                OpmLog(L"%ls: OPM 出力を取得できない (%ls)", mname.c_str(), DescribeError(e).c_str());
                continue;
            }
            OpmLog(L"%ls: OPM 出力 %lu 個", mname.c_str(), n);
            for (ULONG i = 0; i < n; ++i) {
                Output o;
                o.label = mname + L" #" + std::to_wstring(i);
                o.status.label = o.label;
                o.session = std::make_unique<OpmSession>(mon, i);
                OpmLog(L"%ls: OPM ハンドシェイク中…", o.label.c_str());
                try {
                    o.session->Initialize();
                } catch (const OpmError& e) {
                    lastError = e;
                    OpmLog(L"[エラー] %ls: %ls", o.label.c_str(), DescribeError(e).c_str());
                    continue;
                }
                OpmLog(L"%ls: OPM セッション確立 (%ls)", o.label.c_str(), o.session->Variant().c_str());
                outs_.push_back(std::move(o));
            }
        }

        if (outs_.empty()) {
            error_ = DescribeError(lastError);
            phase_ = Phase::Error;
            OpmLog(L"[エラー] %ls", error_.c_str());
            OpmLog(L"  → この GPU / ドライバ / 接続は OPM に対応していない可能性があります。"
                   L"仮想マシンやリモートデスクトップ、Basic Display Adapter では動作しません。");
            Publish();
            return false;
        }
        phase_ = Phase::Ready;
        Publish();
        return true;
    }

    // Returns how many outputs accepted the request. An output whose driver
    // says it doesn't support HDCP at all is excluded from then on (until the
    // next reconnect): a monitor can have several OPM outputs, and one that
    // can never do HDCP must not keep the overall state at "waiting".
    size_t ApplyAll(ULONG level) {
        size_t accepted = 0;
        for (size_t i = 0; i < outs_.size(); ++i) {
            Output& o = outs_[i];
            if (o.status.hdcpUnsupported) continue;
            HRESULT hr = o.session->TrySetHdcp(level);
            if (SUCCEEDED(hr)) {
                ++accepted;
                OpmLog(L"%ls: HDCP %ls 要求 OK (type=0x%lx)", outs_[i].label.c_str(),
                       level == OPM_HDCP_ON ? L"ON" : L"OFF",
                       static_cast<unsigned long>(o.session->HdcpType()));
            } else if (hr == kErrHdcpNotSupported) {
                OpmLog(L"%ls: HDCP 非対応 (type=0x%lx, %ls)", outs_[i].label.c_str(),
                       static_cast<unsigned long>(o.session->HdcpType()), DescribeHr(hr).c_str());
                Exclude(o, i);
            } else {
                OpmLog(L"[エラー] %ls: HDCP %ls 要求に失敗 (%ls)", outs_[i].label.c_str(),
                       level == OPM_HDCP_ON ? L"ON" : L"OFF", DescribeHr(hr).c_str());
            }
        }
        return accepted;
    }

    // Marks an output that can never do HDCP as excluded and closes its OPM
    // session. Keeping a session open (and re-handshaking it) on such an
    // output was observed to make the HDCP-capable output's ON request fail
    // with 0x8007001F, while the old tool, which only ever opened output #0,
    // worked.
    void Exclude(Output& o, size_t i) {
        o.status.hdcpUnsupported = true;
        o.status.ok = false;
        o.session.reset();
        OpmLog(L"%ls: 対象外にしてセッションを閉じた", outs_[i].label.c_str());
    }

    void Nudge(Output& o) {
        o.lastNudge = Clock::now();
        o.session->TrySetHdcp(OPM_HDCP_OFF);
        o.session->TrySetHdcp(OPM_HDCP_ON);
    }

    void HandleCommand(Cmd c) {
        switch (c) {
        case Cmd::On:
            phase_ = Phase::Busy;
            Publish();
            if (outs_.empty() && !Connect()) return;
            OpmLog(L"HDCP ON を要求");
            if (ApplyAll(OPM_HDCP_ON) == 0) {
                // Nothing accepted ON: don't sit in "waiting" forever.
                ApplyAll(OPM_HDCP_OFF);
                requestedOn_ = false;
                error_ = L"どの出力も HDCP ON を受け付けなかった（ログを参照）";
                phase_ = Phase::Error;
                OpmLog(L"[エラー] %ls", error_.c_str());
                break;
            }
            requestedOn_ = true;
            onSince_ = Clock::now();
            for (auto& o : outs_) {
                o.wasOn = false;
                o.dropStart.reset();
            }
            phase_ = Phase::Ready;
            break;
        case Cmd::Off:
            if (outs_.empty()) {
                requestedOn_ = false;
                break;
            }
            OpmLog(L"HDCP OFF を要求");
            ApplyAll(OPM_HDCP_OFF);
            requestedOn_ = false;
            phase_ = Phase::Ready;
            break;
        case Cmd::Reconnect:
            if (Connect() && requestedOn_) {
                ApplyAll(OPM_HDCP_ON);
                onSince_ = Clock::now();
            }
            break;
        case Cmd::Quit:
            break;
        }
        Publish();
    }

    void Poll() {
        const bool watching = watch.load();
        const auto now = Clock::now();
        const bool inGrace = requestedOn_ && (now - onSince_) < kOnGrace;

        for (size_t i = 0; i < outs_.size(); ++i) {
            Output& o = outs_[i];
            if (o.status.hdcpUnsupported) continue;
            OPM_STANDARD_INFORMATION actual{}, virt{};
            HRESULT hrA = S_OK;
            if (!o.actualUnsupported)
                hrA = o.session->TryQueryHdcp(OPM_GET_ACTUAL_PROTECTION_LEVEL, actual);
            HRESULT hrV = o.session->TryQueryHdcp(OPM_GET_VIRTUAL_PROTECTION_LEVEL, virt);

            if (hrV == kErrHdcpNotSupported) {
                OpmLog(L"%ls: HDCP 非対応 (%ls)", outs_[i].label.c_str(), DescribeHr(hrV).c_str());
                Exclude(o, i);
                continue;
            }

            if (FAILED(hrV)) {
                o.status.ok = false;
                if (requestedOn_ && o.wasOn) {
                    o.wasOn = false;
                    o.dropStart = now;
                    ++drops_;
                }
                // The video output object may have been invalidated (e.g. by a
                // display mode change). Redo the handshake, backing off from
                // 1 s up to 30 s while it keeps failing.
                const auto backoff = std::chrono::seconds(1 << (std::min)(o.reinitFailures, 5));
                if (now - o.lastReinit > backoff) {
                    o.lastReinit = now;
                    ++o.reinitFailures;
                    if (o.actualUnsupported) {
                        OpmLog(L"[警告] %ls: virtual の取得に失敗 (%ls) → 再ハンドシェイク", outs_[i].label.c_str(),
                               DescribeHr(hrV).c_str());
                    } else {
                        OpmLog(L"[警告] %ls: 状態取得に失敗 actual=%ls / virtual=%ls → 再ハンドシェイク",
                               outs_[i].label.c_str(), DescribeHr(hrA).c_str(), DescribeHr(hrV).c_str());
                    }
                    try {
                        o.session->Initialize();
                        OpmLog(L"%ls: OPM セッション再確立 (%ls)", outs_[i].label.c_str(),
                               o.session->Variant().c_str());
                        if (requestedOn_) o.session->TrySetHdcp(OPM_HDCP_ON);
                    } catch (const OpmError& e) {
                        OpmLog(L"[エラー] %ls: %ls", outs_[i].label.c_str(), DescribeError(e).c_str());
                    }
                }
                continue;
            }
            o.reinitFailures = 0;

            if (FAILED(hrA)) {
                // Some drivers reject OPM_GET_ACTUAL_PROTECTION_LEVEL while the
                // virtual level works. Fall back to the virtual level from now on
                // (until the next reconnect) instead of failing forever.
                o.actualUnsupported = true;
                OpmLog(L"[警告] %ls: actual の取得に失敗 (%ls) → 以降は virtual で判定", outs_[i].label.c_str(),
                       DescribeHr(hrA).c_str());
            }

            o.status.ok = true;
            o.status.actualKnown = !o.actualUnsupported;
            o.status.actual = o.actualUnsupported ? 0 : actual.ulInformation;
            o.status.virt = virt.ulInformation;
            const ULONG level = o.actualUnsupported ? virt.ulInformation : actual.ulInformation;
            const bool isOn = level == static_cast<ULONG>(OPM_HDCP_ON);

            if (!requestedOn_) {
                o.wasOn = isOn;
                continue;
            }

            if (o.wasOn && !isOn) {
                ++drops_;
                o.dropStart = now;
                OpmLog(L"[ドロップ #%d] %ls: actual=0x%lx virtual=0x%lx%ls", drops_, outs_[i].label.c_str(),
                       static_cast<unsigned long>(actual.ulInformation),
                       static_cast<unsigned long>(virt.ulInformation),
                       watching ? L" → OFF→ON で復帰を試行" : L"");
                if (watching) Nudge(o);
            } else if (!o.wasOn && isOn) {
                if (o.dropStart) {
                    double gap = std::chrono::duration<double, std::milli>(now - *o.dropStart).count();
                    downtimeMs_ += gap;
                    o.dropStart.reset();
                    OpmLog(L"[復帰] %ls: HDCP ON に戻った (%.1f ms)", outs_[i].label.c_str(), gap);
                } else {
                    double t = std::chrono::duration<double, std::milli>(now - onSince_).count();
                    OpmLog(L"%ls: HDCP ON を確認 (要求から %.0f ms)", outs_[i].label.c_str(), t);
                }
            } else if (!o.wasOn && !isOn && watching && !inGrace &&
                       now - o.lastNudge >= kNudgeBackoff) {
                // Still down: keep nudging (with a back-off) rather than
                // assuming the earlier attempt is still in flight.
                if (!o.dropStart) {
                    o.dropStart = now;
                    OpmLog(L"%ls: HDCP が ON にならない → OFF→ON を再試行", outs_[i].label.c_str());
                }
                Nudge(o);
            }
            o.wasOn = isOn;
        }
    }

    void Run() {
        HRESULT hr = CoInitializeEx(nullptr, COINIT_MULTITHREADED);
        Connect();
        if (startOn && phase_ == Phase::Ready) {
            Poll();  // find and close outputs without HDCP before requesting ON
            HandleCommand(Cmd::On);
        }

        for (;;) {
            std::optional<Cmd> cmd;
            {
                const int wait = (requestedOn_ && watch.load()) ? intervalMs.load() : kIdlePollMs;
                std::unique_lock<std::mutex> lk(m_);
                cv_.wait_for(lk, std::chrono::milliseconds(wait), [this] { return !q_.empty(); });
                if (!q_.empty()) {
                    cmd = q_.front();
                    q_.pop_front();
                }
            }
            if (cmd == Cmd::Quit) break;
            try {
                if (cmd) HandleCommand(*cmd);
                if (!outs_.empty()) Poll();
            } catch (const OpmError& e) {
                error_ = DescribeError(e);
                phase_ = Phase::Error;
                OpmLog(L"[エラー] %ls", error_.c_str());
            }
            Publish();
        }

        if (requestedOn_ && !outs_.empty()) {
            OpmLog(L"終了前に HDCP OFF を要求");
            try {
                ApplyAll(OPM_HDCP_OFF);
            } catch (const OpmError&) {
            }
        }
        outs_.clear();
        if (SUCCEEDED(hr)) CoUninitialize();
        PostMessageW(g_hwnd, WM_APP_WORKER_DONE, 0, 0);
    }

    std::thread thread_;
    std::mutex m_;
    std::condition_variable cv_;
    std::deque<Cmd> q_;

    // Worker-thread-only state.
    std::vector<Output> outs_;
    Phase phase_ = Phase::Connecting;
    bool requestedOn_ = false;
    Clock::time_point onSince_{};
    int drops_ = 0;
    double downtimeMs_ = 0.0;
    std::wstring error_;
    std::optional<Snapshot> lastPublished_;
};

// ---------------------------------------------------------------------------
// UI
// ---------------------------------------------------------------------------

namespace ui {

enum : int { IDC_ON = 101, IDC_OFF, IDC_WATCH, IDC_INTERVAL, IDC_LOG, IDC_RECONNECT, IDC_COPY, IDC_TOGGLE_LOG };

const int kIntervals[] = {50, 100, 200, 500, 1000};

// Palette (light).
constexpr COLORREF kBg = RGB(0xF4, 0xF5, 0xF7);
constexpr COLORREF kText = RGB(0x1F, 0x23, 0x28);
constexpr COLORREF kSubtle = RGB(0x5E, 0x66, 0x70);
constexpr COLORREF kPanel = RGB(0xFF, 0xFF, 0xFF);
constexpr COLORREF kBorder = RGB(0xD6, 0xDA, 0xE0);
constexpr COLORREF kGreen = RGB(0x1E, 0x8E, 0x4E);
constexpr COLORREF kGreenDark = RGB(0x17, 0x70, 0x3D);
constexpr COLORREF kDisabledFill = RGB(0xE6, 0xE8, 0xEC);
constexpr COLORREF kDisabledText = RGB(0x9A, 0xA1, 0xA9);

struct Tone {
    COLORREF fill, border, accent;
};
constexpr Tone kToneOn{RGB(0xE8, 0xF6, 0xEE), RGB(0x9F, 0xD8, 0xB5), RGB(0x1E, 0x8E, 0x4E)};
constexpr Tone kToneOff{RGB(0xFF, 0xFF, 0xFF), RGB(0xD6, 0xDA, 0xE0), RGB(0x6B, 0x73, 0x7D)};
constexpr Tone kToneBusy{RGB(0xFF, 0xF6, 0xE3), RGB(0xF0, 0xD0, 0x8A), RGB(0xB4, 0x6B, 0x00)};
constexpr Tone kToneError{RGB(0xFD, 0xEE, 0xEE), RGB(0xF0, 0xB4, 0xB4), RGB(0xC0, 0x2D, 0x2D)};

HWND btnOn, btnOff, chkWatch, cmbInterval, edtLog, btnReconnect, btnCopy, btnToggleLog;
HFONT fontUi, fontTitle, fontStatus, fontButton, fontSmall, fontMono;
HBRUSH brBg, brPanel;
UINT dpi = 96;
RECT rcCard, rcLogBox, rcOptionsLabel, rcLogLabel;
Snapshot state;
// Log panel visible? Hidden = "demo" view where the status card fills the window.
bool logVisible = true;
bool haveState = false;
bool closing = false;
bool workerDone = false;
Worker* worker = nullptr;

int S(int v) { return MulDiv(v, static_cast<int>(dpi), 96); }

UINT QueryDpi(HWND hwnd) {
    using Fn = UINT(WINAPI*)(HWND);
    static Fn fn = reinterpret_cast<Fn>(
        reinterpret_cast<void*>(GetProcAddress(GetModuleHandleW(L"user32.dll"), "GetDpiForWindow")));
    if (fn && hwnd) return fn(hwnd);
    HDC dc = GetDC(nullptr);
    UINT d = static_cast<UINT>(GetDeviceCaps(dc, LOGPIXELSY));
    ReleaseDC(nullptr, dc);
    return d;
}

HFONT MakeFont(int pt10, int weight, const wchar_t* face) {
    LOGFONTW lf{};
    lf.lfHeight = -MulDiv(pt10, static_cast<int>(dpi), 720);
    lf.lfWeight = weight;
    lf.lfCharSet = DEFAULT_CHARSET;
    lf.lfQuality = CLEARTYPE_QUALITY;
    wcscpy_s(lf.lfFaceName, face);
    return CreateFontIndirectW(&lf);
}

void CreateFonts() {
    for (HFONT f : {fontUi, fontTitle, fontStatus, fontButton, fontSmall, fontMono})
        if (f) DeleteObject(f);
    fontUi = MakeFont(95, FW_NORMAL, L"Segoe UI");
    fontSmall = MakeFont(90, FW_NORMAL, L"Segoe UI");
    fontTitle = MakeFont(140, FW_SEMIBOLD, L"Segoe UI");
    fontStatus = MakeFont(200, FW_BOLD, L"Segoe UI");
    fontButton = MakeFont(105, FW_SEMIBOLD, L"Segoe UI");
    fontMono = MakeFont(90, FW_NORMAL, L"Consolas");
}

void ApplyFonts() {
    for (HWND h : {btnOn, btnOff, btnReconnect, btnCopy, btnToggleLog})
        SendMessageW(h, WM_SETFONT, (WPARAM)fontButton, TRUE);
    SendMessageW(chkWatch, WM_SETFONT, (WPARAM)fontUi, TRUE);
    SendMessageW(cmbInterval, WM_SETFONT, (WPARAM)fontUi, TRUE);
    SendMessageW(edtLog, WM_SETFONT, (WPARAM)fontMono, TRUE);
    SendMessageW(edtLog, EM_SETMARGINS, EC_LEFTMARGIN | EC_RIGHTMARGIN, MAKELONG(S(6), S(6)));
    SendMessageW(btnReconnect, WM_SETFONT, (WPARAM)fontSmall, TRUE);
}

void Layout(HWND hwnd) {
    RECT rc;
    GetClientRect(hwnd, &rc);
    const int W = rc.right, H = rc.bottom;
    const int m = S(16);

    // Header: small buttons on the right.
    const int hbw = S(92), hbh = S(28), hby = S(18);
    MoveWindow(btnToggleLog, W - m - hbw, hby, hbw, hbh, TRUE);
    MoveWindow(btnReconnect, W - m - 2 * hbw - S(8), hby, hbw, hbh, TRUE);

    const int gap = S(12);
    const int bh = S(52);
    const int rowH = S(26);
    // Height of the button row + option row below the card.
    const int controlsH = S(16) + bh + S(14) + rowH;

    int y = S(68);
    if (logVisible) {
        rcCard = {m, y, W - m, y + S(180)};
    } else {
        // Demo view: the status card takes everything that is left.
        rcCard = {m, y, W - m, (std::max)(static_cast<int>(y + S(180)), static_cast<int>(H - m - controlsH))};
    }
    y = rcCard.bottom + S(16);

    const int bw = (W - 2 * m - gap) / 2;
    MoveWindow(btnOn, m, y, bw, bh, TRUE);
    MoveWindow(btnOff, m + bw + gap, y, W - 2 * m - bw - gap, bh, TRUE);
    y += bh + S(14);

    const int comboW = S(96);
    MoveWindow(cmbInterval, W - m - comboW, y, comboW, S(200), TRUE);
    rcOptionsLabel = {W - m - comboW - S(52), y, W - m - comboW - S(8), y + rowH};
    MoveWindow(chkWatch, m, y, rcOptionsLabel.left - m - S(8), rowH, TRUE);
    y += rowH + S(18);

    const int rbw = S(92);
    rcLogLabel = {m, y, W - m - rbw - S(8), y + S(22)};
    MoveWindow(btnCopy, W - m - rbw, y - S(2), rbw, S(24), TRUE);
    y += S(26);

    rcLogBox = {m, y, W - m, (std::max)(static_cast<int>(y + S(60)), static_cast<int>(H - m))};
    const int in = S(1);
    MoveWindow(edtLog, rcLogBox.left + in + S(2), rcLogBox.top + in + S(4),
               rcLogBox.right - rcLogBox.left - 2 * in - S(4),
               rcLogBox.bottom - rcLogBox.top - 2 * in - S(8), TRUE);

    const int show = logVisible ? SW_SHOW : SW_HIDE;
    ShowWindow(edtLog, show);
    ShowWindow(btnCopy, show);
}

void SetLogVisible(HWND hwnd, bool visible) {
    logVisible = visible;
    SetWindowTextW(btnToggleLog, visible ? L"ログを隠す" : L"ログを表示");
    Layout(hwnd);
    InvalidateRect(hwnd, nullptr, FALSE);
}

gp::Color C(COLORREF c, BYTE a = 255) {
    return gp::Color(a, GetRValue(c), GetGValue(c), GetBValue(c));
}

void RoundRectPath(gp::GraphicsPath& p, const RECT& r, float radius) {
    const float x = static_cast<float>(r.left) + 0.5f, y = static_cast<float>(r.top) + 0.5f;
    const float w = static_cast<float>(r.right - r.left) - 1.0f;
    const float h = static_cast<float>(r.bottom - r.top) - 1.0f;
    const float d = radius * 2;
    p.AddArc(x, y, d, d, 180, 90);
    p.AddArc(x + w - d, y, d, d, 270, 90);
    p.AddArc(x + w - d, y + h - d, d, d, 0, 90);
    p.AddArc(x, y + h - d, d, d, 90, 90);
    p.CloseFigure();
}

void FillRound(HDC dc, const RECT& r, float radius, COLORREF fill, COLORREF border) {
    gp::Graphics g(dc);
    g.SetSmoothingMode(gp::SmoothingModeAntiAlias);
    gp::GraphicsPath path;
    RoundRectPath(path, r, radius);
    gp::SolidBrush b(C(fill));
    g.FillPath(&b, &path);
    gp::Pen pen(C(border), 1.0f);
    g.DrawPath(&pen, &path);
}

void FillCircle(HDC dc, int cx, int cy, int radius, COLORREF c, BYTE alpha = 255) {
    gp::Graphics g(dc);
    g.SetSmoothingMode(gp::SmoothingModeAntiAlias);
    gp::SolidBrush b(C(c, alpha));
    g.FillEllipse(&b, static_cast<float>(cx - radius), static_cast<float>(cy - radius),
                  static_cast<float>(radius * 2), static_cast<float>(radius * 2));
}

void DrawTextAt(HDC dc, const std::wstring& s, RECT r, HFONT f, COLORREF c,
                UINT flags = DT_LEFT | DT_TOP | DT_SINGLELINE | DT_END_ELLIPSIS | DT_NOPREFIX) {
    HGDIOBJ old = SelectObject(dc, f);
    SetTextColor(dc, c);
    SetBkMode(dc, TRANSPARENT);
    DrawTextW(dc, s.c_str(), -1, &r, flags);
    SelectObject(dc, old);
}

COLORREF Mix(COLORREF a, COLORREF b, double t) {
    auto ch = [t](int x, int y) { return static_cast<int>(x + (y - x) * t + 0.5); };
    return RGB(ch(GetRValue(a), GetRValue(b)), ch(GetGValue(a), GetGValue(b)), ch(GetBValue(a), GetBValue(b)));
}

HFONT MakeFontPx(int px, int weight, const wchar_t* face) {
    LOGFONTW lf{};
    lf.lfHeight = -px;
    lf.lfWeight = weight;
    lf.lfCharSet = DEFAULT_CHARSET;
    lf.lfQuality = CLEARTYPE_QUALITY;
    wcscpy_s(lf.lfFaceName, face);
    return CreateFontIndirectW(&lf);
}

SIZE TextSize(HDC dc, HFONT f, const std::wstring& s) {
    HGDIOBJ old = SelectObject(dc, f);
    SIZE sz{};
    GetTextExtentPoint32W(dc, s.c_str(), static_cast<int>(s.size()), &sz);
    SelectObject(dc, old);
    return sz;
}

std::wstring LevelText(ULONG v) {
    if (v == static_cast<ULONG>(OPM_HDCP_ON)) return L"ON";
    if (v == static_cast<ULONG>(OPM_HDCP_OFF)) return L"OFF";
    wchar_t b[16];
    _snwprintf_s(b, _countof(b), _TRUNCATE, L"0x%lx", static_cast<unsigned long>(v));
    return b;
}

constexpr wchar_t kIconLock = 0xE72E;    // Segoe MDL2 Assets: Lock
constexpr wchar_t kIconUnlock = 0xE785;  // Unlock
constexpr wchar_t kIconBusy = 0xE916;    // Stopwatch
constexpr wchar_t kIconError = 0xE7BA;   // Warning

struct CardView {
    Tone tone;
    wchar_t icon;  // Segoe MDL2 Assets glyph
    std::wstring title;
    std::wstring line1;
    std::wstring line2;
};

CardView Describe() {
    CardView v{kToneBusy, kIconBusy, L"接続中…", L"OPM セッションを確立しています", L""};
    if (closing) return {kToneBusy, kIconBusy, L"終了中…", L"HDCP を OFF にしています", L""};
    if (!haveState) return v;

    const Snapshot& s = state;
    wchar_t buf[256];
    _snwprintf_s(buf, _countof(buf), _TRUNCATE, L"出力 %zu 個  ·  ドロップ %d 回  ·  停止 計 %.0f ms",
                 s.outputs.size(), s.drops, s.downtimeMs);
    v.line2 = buf;

    if (s.phase == Phase::Error) {
        return {kToneError, kIconError, L"エラー", s.error.empty() ? L"OPM を利用できません" : s.error,
                L"「再接続」で再試行できます"};
    }
    if (s.phase == Phase::Connecting) return {kToneBusy, kIconBusy, L"接続中…", L"OPM ハンドシェイク中", L""};
    if (s.phase == Phase::Busy) {
        v.title = L"処理中…";
        v.line1 = L"ドライバに要求を送信しています";
        return v;
    }

    bool allOn = true, anyOk = false;
    std::wstring detail;
    for (size_t i = 0; i < s.outputs.size(); ++i) {
        const auto& o = s.outputs[i];
        if (!detail.empty()) detail += L"   |   ";
        if (s.outputs.size() > 1) detail += o.label + L"  ";
        if (o.hdcpUnsupported) {
            detail += L"HDCP 非対応";
            continue;
        }
        if (!o.ok) {
            detail += L"状態取得失敗";
            allOn = false;
            continue;
        }
        anyOk = true;
        detail += L"actual " + (o.actualKnown ? LevelText(o.actual) : std::wstring(L"取得不可")) +
                  L"  ·  virtual " + LevelText(o.virt);
        if ((o.actualKnown ? o.actual : o.virt) != static_cast<ULONG>(OPM_HDCP_ON)) allOn = false;
    }
    v.line1 = detail.empty() ? L"—" : detail;

    if (allOn && anyOk) {
        v.tone = kToneOn;
        v.icon = kIconLock;
        v.title = s.requestedOn ? L"HDCP ON" : L"HDCP ON（他アプリの要求）";
    } else if (s.requestedOn) {
        v.tone = kToneBusy;
        v.icon = kIconBusy;
        v.title = s.drops > 0 ? L"HDCP 低下 — 復帰待ち" : L"HDCP 認証待ち…";
    } else {
        v.tone = kToneOff;
        v.icon = kIconUnlock;
        v.title = L"HDCP OFF";
    }
    return v;
}

void Paint(HWND hwnd) {
    PAINTSTRUCT ps;
    HDC wdc = BeginPaint(hwnd, &ps);
    RECT rc;
    GetClientRect(hwnd, &rc);

    HDC dc = CreateCompatibleDC(wdc);
    HBITMAP bmp = CreateCompatibleBitmap(wdc, rc.right, rc.bottom);
    HGDIOBJ oldBmp = SelectObject(dc, bmp);
    FillRect(dc, &rc, brBg);

    const int m = S(16);
    // Header
    const int headerRight = rc.right - m - 2 * S(92) - S(16);
    DrawTextAt(dc, L"HDCP Control", {m, S(14), headerRight, S(40)}, fontTitle, kText);
    DrawTextAt(dc, L"Output Protection Manager  ·  全モニタ", {m, S(40), headerRight, S(60)},
               fontSmall, kSubtle);

    // Status card: solid colour, large centred icon + title, sized to the
    // card so it stays readable from a distance in the demo view.
    CardView v = Describe();
    const COLORREF fill = v.tone.accent;
    const COLORREF white = RGB(0xFF, 0xFF, 0xFF);
    FillRound(dc, rcCard, static_cast<float>(S(14)), fill, fill);

    const int cardW = rcCard.right - rcCard.left, cardH = rcCard.bottom - rcCard.top;
    const int pad = S(20);
    const int detailH = S(46);  // two small lines at the bottom
    const int bigAreaH = cardH - detailH - S(12);
    int titlePx = (std::min)(static_cast<int>(bigAreaH * 0.55), S(150));
    HFONT fBig = nullptr, fIcon = nullptr;
    SIZE tsz{}, isz{};
    const std::wstring iconStr(1, v.icon);
    for (;; titlePx = titlePx * 9 / 10) {
        if (fBig) DeleteObject(fBig);
        if (fIcon) DeleteObject(fIcon);
        fBig = MakeFontPx(titlePx, FW_BOLD, L"Segoe UI");
        fIcon = MakeFontPx(titlePx * 8 / 10, FW_NORMAL, L"Segoe MDL2 Assets");
        tsz = TextSize(dc, fBig, v.title);
        isz = TextSize(dc, fIcon, iconStr);
        if (tsz.cx + isz.cx + S(16) <= cardW - 2 * pad || titlePx <= S(18)) break;
    }
    const int groupW = isz.cx + S(16) + tsz.cx;
    const int gx = rcCard.left + (cardW - groupW) / 2;
    const int midY = rcCard.top + S(6) + bigAreaH / 2;
    RECT ri{gx, midY - isz.cy / 2, gx + isz.cx, midY + isz.cy / 2 + 1};
    DrawTextAt(dc, iconStr, ri, fIcon, white, DT_LEFT | DT_VCENTER | DT_SINGLELINE | DT_NOPREFIX);
    RECT rt{gx + isz.cx + S(16), midY - tsz.cy / 2, rcCard.right - pad, midY + tsz.cy / 2 + 1};
    DrawTextAt(dc, v.title, rt, fBig, white, DT_LEFT | DT_VCENTER | DT_SINGLELINE | DT_END_ELLIPSIS | DT_NOPREFIX);
    DeleteObject(fBig);
    DeleteObject(fIcon);

    const UINT center = DT_CENTER | DT_TOP | DT_SINGLELINE | DT_END_ELLIPSIS | DT_NOPREFIX;
    RECT r1{rcCard.left + pad, rcCard.bottom - detailH - S(6), rcCard.right - pad, rcCard.bottom - S(26)};
    DrawTextAt(dc, v.line1, r1, fontUi, Mix(fill, white, 0.92), center);
    RECT r2{rcCard.left + pad, rcCard.bottom - S(26), rcCard.right - pad, rcCard.bottom - S(6)};
    DrawTextAt(dc, v.line2, r2, fontSmall, Mix(fill, white, 0.75), center);

    // Option row label and log header
    DrawTextAt(dc, L"間隔", rcOptionsLabel, fontUi, kSubtle,
               DT_RIGHT | DT_VCENTER | DT_SINGLELINE | DT_NOPREFIX);
    if (logVisible) {
        DrawTextAt(dc, L"ログ", rcLogLabel, fontButton, kText,
                   DT_LEFT | DT_VCENTER | DT_SINGLELINE | DT_NOPREFIX);
        FillRound(dc, rcLogBox, static_cast<float>(S(8)), kPanel, kBorder);
    }

    BitBlt(wdc, 0, 0, rc.right, rc.bottom, dc, 0, 0, SRCCOPY);
    SelectObject(dc, oldBmp);
    DeleteObject(bmp);
    DeleteDC(dc);
    EndPaint(hwnd, &ps);
}

void DrawButton(const DRAWITEMSTRUCT* di) {
    const bool enabled = !(di->itemState & ODS_DISABLED);
    const bool pressed = (di->itemState & ODS_SELECTED) != 0;
    const bool focused = (di->itemState & ODS_FOCUS) != 0 && !(di->itemState & ODS_NOFOCUSRECT);
    const bool primary = di->CtlID == IDC_ON;
    RECT r = di->rcItem;

    HDC dc = CreateCompatibleDC(di->hDC);
    HBITMAP bmp = CreateCompatibleBitmap(di->hDC, r.right, r.bottom);
    HGDIOBJ oldBmp = SelectObject(dc, bmp);
    FillRect(dc, &r, brBg);

    COLORREF fill, border, text;
    if (!enabled) {
        fill = kDisabledFill;
        border = kDisabledFill;
        text = kDisabledText;
    } else if (primary) {
        fill = pressed ? kGreenDark : kGreen;
        border = fill;
        text = RGB(0xFF, 0xFF, 0xFF);
    } else {
        fill = pressed ? RGB(0xEC, 0xEE, 0xF1) : kPanel;
        border = RGB(0xC4, 0xC9, 0xD1);
        text = kText;
    }
    const bool isSmall = di->CtlID == IDC_RECONNECT || di->CtlID == IDC_COPY ||
                         di->CtlID == IDC_TOGGLE_LOG;
    const float radius = static_cast<float>(S(isSmall ? 6 : 8));
    FillRound(dc, r, radius, fill, border);
    if (focused && enabled) {
        RECT fr = r;
        InflateRect(&fr, -S(3), -S(3));
        gp::Graphics g(dc);
        g.SetSmoothingMode(gp::SmoothingModeAntiAlias);
        gp::GraphicsPath path;
        RoundRectPath(path, fr, radius - S(2));
        gp::Pen pen(primary ? C(RGB(0xFF, 0xFF, 0xFF), 170) : C(kGreen, 170), 1.0f);
        pen.SetDashStyle(gp::DashStyleDot);
        g.DrawPath(&pen, &path);
    }

    wchar_t label[64];
    GetWindowTextW(di->hwndItem, label, _countof(label));
    HFONT f = isSmall ? fontSmall : fontButton;
    if (pressed) OffsetRect(&r, 0, 1);
    DrawTextAt(dc, label, r, f, text, DT_CENTER | DT_VCENTER | DT_SINGLELINE | DT_NOPREFIX);
    if (pressed) OffsetRect(&r, 0, -1);

    BitBlt(di->hDC, 0, 0, r.right, r.bottom, dc, 0, 0, SRCCOPY);
    SelectObject(dc, oldBmp);
    DeleteObject(bmp);
    DeleteDC(dc);
}

void AppendLog(const std::wstring& line) {
    int len = GetWindowTextLengthW(edtLog);
    if (len > 200000) {
        SendMessageW(edtLog, EM_SETSEL, 0, len / 2);
        SendMessageW(edtLog, EM_REPLACESEL, FALSE, reinterpret_cast<LPARAM>(L""));
        len = GetWindowTextLengthW(edtLog);
    }
    std::wstring s = (len > 0 ? L"\r\n" : L"") + line;
    SendMessageW(edtLog, EM_SETSEL, len, len);
    SendMessageW(edtLog, EM_REPLACESEL, FALSE, reinterpret_cast<LPARAM>(s.c_str()));
    SendMessageW(edtLog, EM_SCROLLCARET, 0, 0);
}

void CopyLogToClipboard(HWND owner) {
    const int len = GetWindowTextLengthW(edtLog);
    HGLOBAL mem = GlobalAlloc(GMEM_MOVEABLE, (static_cast<SIZE_T>(len) + 1) * sizeof(wchar_t));
    if (!mem) return;
    auto* buf = static_cast<wchar_t*>(GlobalLock(mem));
    GetWindowTextW(edtLog, buf, len + 1);
    GlobalUnlock(mem);
    if (OpenClipboard(owner)) {
        EmptyClipboard();
        if (SetClipboardData(CF_UNICODETEXT, mem)) mem = nullptr;  // owned by the clipboard now
        CloseClipboard();
    }
    if (mem) GlobalFree(mem);
    else SetWindowTextW(btnCopy, L"コピーしました");
    SetTimer(owner, TIMER_COPY_LABEL, 1500, nullptr);
}

void UpdateButtons() {
    const bool busy = closing || !haveState || state.phase == Phase::Connecting ||
                      state.phase == Phase::Busy;
    EnableWindow(btnOn, !busy && !state.requestedOn);
    EnableWindow(btnOff, !busy && state.requestedOn);
    EnableWindow(btnReconnect, !busy);
    EnableWindow(chkWatch, !closing);
    EnableWindow(cmbInterval, !closing);
}

void InvalidateCard(HWND hwnd) {
    InvalidateRect(hwnd, &rcCard, FALSE);
}

LRESULT CALLBACK WndProc(HWND hwnd, UINT msg, WPARAM wp, LPARAM lp) {
    switch (msg) {
    case WM_CREATE: {
        dpi = QueryDpi(hwnd);
        CreateFonts();
        HINSTANCE hi = reinterpret_cast<CREATESTRUCTW*>(lp)->hInstance;
        auto mk = [&](const wchar_t* cls, const wchar_t* text, DWORD style, DWORD ex, int id) {
            return CreateWindowExW(ex, cls, text, WS_CHILD | WS_VISIBLE | style, 0, 0, 10, 10, hwnd,
                                   reinterpret_cast<HMENU>(static_cast<INT_PTR>(id)), hi, nullptr);
        };
        btnOn = mk(L"BUTTON", L"HDCP ON", BS_OWNERDRAW | WS_TABSTOP, 0, IDC_ON);
        btnOff = mk(L"BUTTON", L"HDCP OFF", BS_OWNERDRAW | WS_TABSTOP, 0, IDC_OFF);
        chkWatch = mk(L"BUTTON", L"自動復帰（落ちたら OFF→ON で再認証）", BS_AUTOCHECKBOX | WS_TABSTOP,
                      0, IDC_WATCH);
        cmbInterval = mk(WC_COMBOBOXW, L"", CBS_DROPDOWNLIST | WS_VSCROLL | WS_TABSTOP, 0, IDC_INTERVAL);
        btnCopy = mk(L"BUTTON", L"ログをコピー", BS_OWNERDRAW | WS_TABSTOP, 0, IDC_COPY);
        btnReconnect = mk(L"BUTTON", L"再接続", BS_OWNERDRAW | WS_TABSTOP, 0, IDC_RECONNECT);
        btnToggleLog = mk(L"BUTTON", logVisible ? L"ログを隠す" : L"ログを表示",
                          BS_OWNERDRAW | WS_TABSTOP, 0, IDC_TOGGLE_LOG);
        edtLog = mk(L"EDIT", L"",
                    ES_MULTILINE | ES_READONLY | ES_AUTOVSCROLL | WS_VSCROLL | WS_TABSTOP, 0, IDC_LOG);

        std::vector<int> items(std::begin(kIntervals), std::end(kIntervals));
        const int cur = worker->intervalMs.load();
        if (std::find(items.begin(), items.end(), cur) == items.end()) {
            items.push_back(cur);
            std::sort(items.begin(), items.end());
        }
        for (int v : items) {
            int idx = static_cast<int>(SendMessageW(cmbInterval, CB_ADDSTRING, 0,
                                                    reinterpret_cast<LPARAM>((std::to_wstring(v) + L" ms").c_str())));
            SendMessageW(cmbInterval, CB_SETITEMDATA, idx, v);
            if (v == cur) SendMessageW(cmbInterval, CB_SETCURSEL, idx, 0);
        }
        SendMessageW(chkWatch, BM_SETCHECK, worker->watch.load() ? BST_CHECKED : BST_UNCHECKED, 0);

        ApplyFonts();
        Layout(hwnd);
        UpdateButtons();
        return 0;
    }
    case WM_SIZE:
        Layout(hwnd);
        InvalidateRect(hwnd, nullptr, FALSE);
        return 0;
    case WM_GETMINMAXINFO: {
        auto* mmi = reinterpret_cast<MINMAXINFO*>(lp);
        mmi->ptMinTrackSize = {S(420), logVisible ? S(600) : S(400)};
        return 0;
    }
    case WM_DPICHANGED: {
        dpi = HIWORD(wp);
        CreateFonts();
        ApplyFonts();
        const RECT* r = reinterpret_cast<RECT*>(lp);
        SetWindowPos(hwnd, nullptr, r->left, r->top, r->right - r->left, r->bottom - r->top,
                     SWP_NOZORDER | SWP_NOACTIVATE);
        Layout(hwnd);
        InvalidateRect(hwnd, nullptr, TRUE);
        return 0;
    }
    case WM_ERASEBKGND:
        return 1;
    case WM_PAINT:
        Paint(hwnd);
        return 0;
    case WM_CTLCOLORSTATIC: {
        HDC dc = reinterpret_cast<HDC>(wp);
        if (reinterpret_cast<HWND>(lp) == edtLog) {
            SetBkColor(dc, kPanel);
            SetTextColor(dc, kText);
            return reinterpret_cast<LRESULT>(brPanel);
        }
        SetBkColor(dc, kBg);
        SetTextColor(dc, kText);
        return reinterpret_cast<LRESULT>(brBg);
    }
    case WM_DRAWITEM:
        DrawButton(reinterpret_cast<DRAWITEMSTRUCT*>(lp));
        return TRUE;
    case WM_COMMAND: {
        const int id = LOWORD(wp), code = HIWORD(wp);
        if ((code == BN_CLICKED || code == BN_DOUBLECLICKED) && id == IDC_COPY) {
            CopyLogToClipboard(hwnd);
        } else if ((code == BN_CLICKED || code == BN_DOUBLECLICKED) && id == IDC_TOGGLE_LOG) {
            SetLogVisible(hwnd, !logVisible);
        } else if ((code == BN_CLICKED || code == BN_DOUBLECLICKED) && !closing) {
            if (id == IDC_ON) {
                worker->Post(Cmd::On);
                EnableWindow(btnOn, FALSE);
            } else if (id == IDC_OFF) {
                worker->Post(Cmd::Off);
                EnableWindow(btnOff, FALSE);
            } else if (id == IDC_RECONNECT) {
                AppendLog(L"—— 再接続 ——");
                worker->Post(Cmd::Reconnect);
                EnableWindow(btnReconnect, FALSE);
            } else if (id == IDC_WATCH) {
                const bool on = SendMessageW(chkWatch, BM_GETCHECK, 0, 0) == BST_CHECKED;
                worker->watch = on;
                OpmLog(L"自動復帰: %ls", on ? L"有効" : L"無効");
            }
        } else if (id == IDC_INTERVAL && code == CBN_SELCHANGE) {
            const LRESULT sel = SendMessageW(cmbInterval, CB_GETCURSEL, 0, 0);
            if (sel != CB_ERR) {
                const int v = static_cast<int>(SendMessageW(cmbInterval, CB_GETITEMDATA, sel, 0));
                worker->intervalMs = v;
                OpmLog(L"監視間隔: %d ms", v);
            }
        }
        return 0;
    }
    case WM_APP_LOG: {
        std::unique_ptr<std::wstring> s(reinterpret_cast<std::wstring*>(lp));
        AppendLog(*s);
        return 0;
    }
    case WM_APP_STATE: {
        std::unique_ptr<Snapshot> s(reinterpret_cast<Snapshot*>(lp));
        state = std::move(*s);
        haveState = true;
        UpdateButtons();
        InvalidateCard(hwnd);
        return 0;
    }
    case WM_APP_WORKER_DONE:
        workerDone = true;
        DestroyWindow(hwnd);
        return 0;
    case WM_TIMER:
        if (wp == TIMER_CLOSE_FALLBACK) DestroyWindow(hwnd);  // worker is stuck in a driver call
        if (wp == TIMER_COPY_LABEL) {
            KillTimer(hwnd, TIMER_COPY_LABEL);
            SetWindowTextW(btnCopy, L"ログをコピー");
        }
        if (wp == TIMER_DISPLAY_CHANGE) {
            KillTimer(hwnd, TIMER_DISPLAY_CHANGE);
            if (!closing) {
                AppendLog(L"—— ディスプレイ構成が変わったので再接続 ——");
                worker->Post(Cmd::Reconnect);
            }
        }
        return 0;
    case WM_DISPLAYCHANGE:
        // Switching between extend / duplicate (or plugging a display) replaces
        // the monitors and invalidates every OPM session. Wait for the change
        // to settle, then reconnect (re-applies ON if it was requested).
        SetTimer(hwnd, TIMER_DISPLAY_CHANGE, 2000, nullptr);
        return 0;
    case WM_CLOSE:
        if (!closing) {
            closing = true;
            UpdateButtons();
            InvalidateCard(hwnd);
            worker->Post(Cmd::Quit);
            SetTimer(hwnd, TIMER_CLOSE_FALLBACK, 5000, nullptr);
        }
        return 0;
    case WM_DESTROY:
        KillTimer(hwnd, TIMER_CLOSE_FALLBACK);
        g_hwnd = nullptr;
        PostQuitMessage(0);
        return 0;
    }
    return DefWindowProcW(hwnd, msg, wp, lp);
}

}  // namespace ui

static void EnableDpiAwareness() {
    HMODULE u32 = GetModuleHandleW(L"user32.dll");
    using SetCtx = BOOL(WINAPI*)(HANDLE);
    auto setCtx = reinterpret_cast<SetCtx>(
        reinterpret_cast<void*>(GetProcAddress(u32, "SetProcessDpiAwarenessContext")));
    // DPI_AWARENESS_CONTEXT_PER_MONITOR_AWARE_V2 == (HANDLE)-4
    if (setCtx && setCtx(reinterpret_cast<HANDLE>(static_cast<INT_PTR>(-4)))) return;
    SetProcessDPIAware();
}

int WINAPI wWinMain(HINSTANCE hInst, HINSTANCE, PWSTR, int nShow) {
    Worker worker;
    ui::worker = &worker;

    int argc = 0;
    LPWSTR* argv = CommandLineToArgvW(GetCommandLineW(), &argc);
    for (int i = 1; argv && i < argc; ++i) {
        if (_wcsicmp(argv[i], L"/on") == 0) worker.startOn = true;
        else if (_wcsicmp(argv[i], L"/watch") == 0) worker.watch = true;
        else if (_wcsicmp(argv[i], L"/nolog") == 0) ui::logVisible = false;
        else if (_wcsnicmp(argv[i], L"/interval:", 10) == 0) {
            int v = _wtoi(argv[i] + 10);
            if (v >= 10) worker.intervalMs = v;
        } else if (_wcsnicmp(argv[i], L"/cert:", 6) == 0) {
            g_forceCertIndex = _wtoi(argv[i] + 6);
        }
    }
    if (argv) LocalFree(argv);

    EnableDpiAwareness();
    INITCOMMONCONTROLSEX icc{};
    icc.dwSize = sizeof(icc);
    icc.dwICC = ICC_STANDARD_CLASSES;
    InitCommonControlsEx(&icc);

    gp::GdiplusStartupInput gsi;
    ULONG_PTR gpToken = 0;
    gp::GdiplusStartup(&gpToken, &gsi, nullptr);

    ui::brBg = CreateSolidBrush(ui::kBg);
    ui::brPanel = CreateSolidBrush(ui::kPanel);

    WNDCLASSEXW wc{};
    wc.cbSize = sizeof(wc);
    wc.lpfnWndProc = ui::WndProc;
    wc.hInstance = hInst;
    wc.hCursor = LoadCursor(nullptr, IDC_ARROW);
    wc.hIcon = LoadIcon(nullptr, IDI_SHIELD);
    wc.hIconSm = LoadIcon(nullptr, IDI_SHIELD);
    wc.lpszClassName = L"OpmHdcpForceWindow";
    RegisterClassExW(&wc);

    const UINT sysDpi = ui::QueryDpi(nullptr);
    RECT wr{0, 0, MulDiv(460, static_cast<int>(sysDpi), 96), MulDiv(660, static_cast<int>(sysDpi), 96)};
    const DWORD style = WS_OVERLAPPEDWINDOW | WS_CLIPCHILDREN;
    AdjustWindowRectEx(&wr, style, FALSE, 0);
    HWND hwnd = CreateWindowExW(0, wc.lpszClassName, L"HDCP Control", style, CW_USEDEFAULT,
                                CW_USEDEFAULT, wr.right - wr.left, wr.bottom - wr.top, nullptr,
                                nullptr, hInst, nullptr);
    if (!hwnd) return 1;
    g_hwnd = hwnd;

    ShowWindow(hwnd, nShow);
    UpdateWindow(hwnd);
    OpmLog(L"起動 (自動復帰 %ls, 監視間隔 %d ms)", worker.watch.load() ? L"有効" : L"無効",
           worker.intervalMs.load());
    worker.Start();

    MSG msg;
    while (GetMessageW(&msg, nullptr, 0, 0) > 0) {
        if (!IsDialogMessageW(hwnd, &msg)) {
            TranslateMessage(&msg);
            DispatchMessageW(&msg);
        }
    }

    if (!ui::workerDone) {
        // The worker is stuck inside a driver call. It still references
        // `worker` on this stack, so leave without unwinding.
        worker.Detach();
        ExitProcess(0);
    }
    worker.Join();
    gp::GdiplusShutdown(gpToken);
    return 0;
}
