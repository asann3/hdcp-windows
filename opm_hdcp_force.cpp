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

enum class Phase { Connecting, Ready, Busy, Error };

struct OutputStatus {
    bool ok = false;
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
            if (outputs[i].ok != o.outputs[i].ok || outputs[i].actual != o.outputs[i].actual ||
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
        std::unique_ptr<OpmSession> session;
        OutputStatus status;
        bool wasOn = false;
        std::optional<Clock::time_point> dropStart;
        Clock::time_point lastReinit{};
        Clock::time_point lastNudge{};
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

    bool Connect() {
        outs_.clear();
        phase_ = Phase::Connecting;
        error_.clear();
        Publish();
        try {
            HMONITOR mon = MonitorFromWindow(GetDesktopWindow(), MONITOR_DEFAULTTOPRIMARY);
            ULONG n = CountVideoOutputs(mon);
            OpmLog(L"プライマリモニタの OPM 出力: %lu 個", n);
            if (n == 0) Fail(L"OPMGetVideoOutputsFromHMONITOR (出力 0 個)", E_FAIL);
            for (ULONG i = 0; i < n; ++i) {
                Output o;
                o.session = std::make_unique<OpmSession>(mon, i);
                OpmLog(L"出力 #%lu: OPM ハンドシェイク中…", i);
                o.session->Initialize();
                OpmLog(L"出力 #%lu: OPM セッション確立", i);
                outs_.push_back(std::move(o));
            }
            phase_ = Phase::Ready;
            Publish();
            return true;
        } catch (const OpmError& e) {
            outs_.clear();
            error_ = DescribeError(e);
            phase_ = Phase::Error;
            OpmLog(L"[エラー] %ls", error_.c_str());
            if (e.hr == E_NOTIMPL || HRESULT_FACILITY(e.hr) == 0x26 /* graphics */ ||
                e.where.find(L"OPMGetVideoOutputsFromHMONITOR") == 0) {
                OpmLog(L"  → この GPU / ドライバ / 接続は OPM に対応していない可能性があります。"
                       L"仮想マシンやリモートデスクトップ、Basic Display Adapter では動作しません。");
            }
            Publish();
            return false;
        }
    }

    void ApplyAll(ULONG level) {
        for (size_t i = 0; i < outs_.size(); ++i) {
            HRESULT hr = outs_[i].session->TrySetHdcp(level);
            if (FAILED(hr)) {
                OpmLog(L"[エラー] 出力 #%zu: HDCP %ls 要求に失敗 (%ls)", i,
                       level == OPM_HDCP_ON ? L"ON" : L"OFF", DescribeHr(hr).c_str());
            }
        }
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
            ApplyAll(OPM_HDCP_ON);
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
            OPM_STANDARD_INFORMATION actual{}, virt{};
            HRESULT hrA = o.session->TryQueryHdcp(OPM_GET_ACTUAL_PROTECTION_LEVEL, actual);
            HRESULT hrV = SUCCEEDED(hrA)
                ? o.session->TryQueryHdcp(OPM_GET_VIRTUAL_PROTECTION_LEVEL, virt)
                : hrA;

            if (FAILED(hrA) || FAILED(hrV)) {
                o.status.ok = false;
                if (requestedOn_ && o.wasOn) {
                    o.wasOn = false;
                    o.dropStart = now;
                    ++drops_;
                }
                // The video output object may have been invalidated (e.g. by a
                // display mode change). Redo the handshake, at most once a second.
                if (now - o.lastReinit > std::chrono::seconds(1)) {
                    o.lastReinit = now;
                    OpmLog(L"[警告] 出力 #%zu: 状態取得に失敗 (%ls) → 再ハンドシェイク", i,
                           DescribeHr(FAILED(hrA) ? hrA : hrV).c_str());
                    try {
                        o.session->Initialize();
                        OpmLog(L"出力 #%zu: OPM セッション再確立", i);
                        if (requestedOn_) o.session->TrySetHdcp(OPM_HDCP_ON);
                    } catch (const OpmError& e) {
                        OpmLog(L"[エラー] 出力 #%zu: %ls", i, DescribeError(e).c_str());
                    }
                }
                continue;
            }

            o.status.ok = true;
            o.status.actual = actual.ulInformation;
            o.status.virt = virt.ulInformation;
            const bool isOn = actual.ulInformation == static_cast<ULONG>(OPM_HDCP_ON);

            if (!requestedOn_) {
                o.wasOn = isOn;
                continue;
            }

            if (o.wasOn && !isOn) {
                ++drops_;
                o.dropStart = now;
                OpmLog(L"[ドロップ #%d] 出力 #%zu: actual=0x%lx virtual=0x%lx%ls", drops_, i,
                       static_cast<unsigned long>(actual.ulInformation),
                       static_cast<unsigned long>(virt.ulInformation),
                       watching ? L" → OFF→ON で復帰を試行" : L"");
                if (watching) Nudge(o);
            } else if (!o.wasOn && isOn) {
                if (o.dropStart) {
                    double gap = std::chrono::duration<double, std::milli>(now - *o.dropStart).count();
                    downtimeMs_ += gap;
                    o.dropStart.reset();
                    OpmLog(L"[復帰] 出力 #%zu: HDCP ON に戻った (%.1f ms)", i, gap);
                } else {
                    double t = std::chrono::duration<double, std::milli>(now - onSince_).count();
                    OpmLog(L"出力 #%zu: HDCP ON を確認 (要求から %.0f ms)", i, t);
                }
            } else if (!o.wasOn && !isOn && watching && !inGrace &&
                       now - o.lastNudge >= kNudgeBackoff) {
                // Still down: keep nudging (with a back-off) rather than
                // assuming the earlier attempt is still in flight.
                if (!o.dropStart) {
                    o.dropStart = now;
                    OpmLog(L"出力 #%zu: HDCP が ON にならない → OFF→ON を再試行", i);
                }
                Nudge(o);
            }
            o.wasOn = isOn;
        }
    }

    void Run() {
        HRESULT hr = CoInitializeEx(nullptr, COINIT_MULTITHREADED);
        Connect();
        if (startOn && phase_ == Phase::Ready) HandleCommand(Cmd::On);

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

enum : int { IDC_ON = 101, IDC_OFF, IDC_WATCH, IDC_INTERVAL, IDC_LOG, IDC_RECONNECT };

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

HWND btnOn, btnOff, chkWatch, cmbInterval, edtLog, btnReconnect;
HFONT fontUi, fontTitle, fontStatus, fontButton, fontSmall, fontMono;
HBRUSH brBg, brPanel;
UINT dpi = 96;
RECT rcCard, rcLogBox, rcOptionsLabel, rcLogLabel;
Snapshot state;
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
    for (HWND h : {btnOn, btnOff, btnReconnect}) SendMessageW(h, WM_SETFONT, (WPARAM)fontButton, TRUE);
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

    int y = S(68);
    rcCard = {m, y, W - m, y + S(124)};
    y = rcCard.bottom + S(14);

    const int gap = S(12);
    const int bw = (W - 2 * m - gap) / 2;
    const int bh = S(46);
    MoveWindow(btnOn, m, y, bw, bh, TRUE);
    MoveWindow(btnOff, m + bw + gap, y, W - 2 * m - bw - gap, bh, TRUE);
    y += bh + S(16);

    const int rowH = S(26);
    const int comboW = S(96);
    MoveWindow(cmbInterval, W - m - comboW, y, comboW, S(200), TRUE);
    rcOptionsLabel = {W - m - comboW - S(52), y, W - m - comboW - S(8), y + rowH};
    MoveWindow(chkWatch, m, y, rcOptionsLabel.left - m - S(8), rowH, TRUE);
    y += rowH + S(18);

    const int rbw = S(84);
    rcLogLabel = {m, y, W - m - rbw, y + S(22)};
    MoveWindow(btnReconnect, W - m - rbw, y - S(2), rbw, S(24), TRUE);
    y += S(26);

    rcLogBox = {m, y, W - m, (std::max)(static_cast<int>(y + S(60)), static_cast<int>(H - m))};
    const int in = S(1);
    MoveWindow(edtLog, rcLogBox.left + in + S(2), rcLogBox.top + in + S(4),
               rcLogBox.right - rcLogBox.left - 2 * in - S(4),
               rcLogBox.bottom - rcLogBox.top - 2 * in - S(8), TRUE);
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

std::wstring LevelText(ULONG v) {
    if (v == static_cast<ULONG>(OPM_HDCP_ON)) return L"ON";
    if (v == static_cast<ULONG>(OPM_HDCP_OFF)) return L"OFF";
    wchar_t b[16];
    _snwprintf_s(b, _countof(b), _TRUNCATE, L"0x%lx", static_cast<unsigned long>(v));
    return b;
}

struct CardView {
    Tone tone;
    std::wstring title;
    std::wstring line1;
    std::wstring line2;
};

CardView Describe() {
    CardView v{kToneBusy, L"接続中…", L"OPM セッションを確立しています", L""};
    if (closing) return {kToneBusy, L"終了中…", L"HDCP を OFF にしています", L""};
    if (!haveState) return v;

    const Snapshot& s = state;
    wchar_t buf[256];
    _snwprintf_s(buf, _countof(buf), _TRUNCATE, L"出力 %zu 個  ·  ドロップ %d 回  ·  停止 計 %.0f ms",
                 s.outputs.size(), s.drops, s.downtimeMs);
    v.line2 = buf;

    if (s.phase == Phase::Error) {
        return {kToneError, L"エラー", s.error.empty() ? L"OPM を利用できません" : s.error,
                L"「再接続」で再試行できます"};
    }
    if (s.phase == Phase::Connecting) return {kToneBusy, L"接続中…", L"OPM ハンドシェイク中", L""};
    if (s.phase == Phase::Busy) {
        v.title = L"処理中…";
        v.line1 = L"ドライバに要求を送信しています";
        return v;
    }

    bool allOn = !s.outputs.empty(), anyOk = false;
    std::wstring detail;
    for (size_t i = 0; i < s.outputs.size(); ++i) {
        const auto& o = s.outputs[i];
        if (!detail.empty()) detail += L"   |   ";
        if (s.outputs.size() > 1) detail += L"#" + std::to_wstring(i) + L"  ";
        if (!o.ok) {
            detail += L"状態取得失敗";
            allOn = false;
            continue;
        }
        anyOk = true;
        detail += L"actual " + LevelText(o.actual) + L"  ·  virtual " + LevelText(o.virt);
        if (o.actual != static_cast<ULONG>(OPM_HDCP_ON)) allOn = false;
    }
    v.line1 = detail.empty() ? L"—" : detail;

    if (allOn && anyOk) {
        v.tone = kToneOn;
        v.title = s.requestedOn ? L"HDCP ON" : L"HDCP ON（他アプリの要求）";
    } else if (s.requestedOn) {
        v.tone = kToneBusy;
        v.title = s.drops > 0 ? L"HDCP 低下 — 復帰待ち" : L"HDCP 認証待ち…";
    } else {
        v.tone = kToneOff;
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
    DrawTextAt(dc, L"HDCP Control", {m, S(14), rc.right - m, S(40)}, fontTitle, kText);
    DrawTextAt(dc, L"Output Protection Manager  ·  プライマリモニタ", {m, S(40), rc.right - m, S(60)},
               fontSmall, kSubtle);

    // Status card
    CardView v = Describe();
    FillRound(dc, rcCard, static_cast<float>(S(10)), v.tone.fill, v.tone.border);
    const int pad = S(18);
    const int dotR = S(7);
    const int titleTop = rcCard.top + S(16);
    const int titleH = S(38);
    FillCircle(dc, rcCard.left + pad + dotR, titleTop + titleH / 2, dotR + S(4), v.tone.accent, 50);
    FillCircle(dc, rcCard.left + pad + dotR, titleTop + titleH / 2, dotR, v.tone.accent);
    RECT rt{rcCard.left + pad + dotR * 2 + S(14), titleTop, rcCard.right - pad, titleTop + titleH};
    DrawTextAt(dc, v.title, rt, fontStatus, v.tone.accent,
               DT_LEFT | DT_VCENTER | DT_SINGLELINE | DT_END_ELLIPSIS | DT_NOPREFIX);
    RECT r1{rcCard.left + pad, titleTop + titleH + S(10), rcCard.right - pad, titleTop + titleH + S(32)};
    DrawTextAt(dc, v.line1, r1, fontUi, kText);
    RECT r2{rcCard.left + pad, r1.bottom + S(2), rcCard.right - pad, r1.bottom + S(24)};
    DrawTextAt(dc, v.line2, r2, fontSmall, kSubtle);

    // Option row label and log header
    DrawTextAt(dc, L"間隔", rcOptionsLabel, fontUi, kSubtle,
               DT_RIGHT | DT_VCENTER | DT_SINGLELINE | DT_NOPREFIX);
    DrawTextAt(dc, L"ログ", rcLogLabel, fontButton, kText,
               DT_LEFT | DT_VCENTER | DT_SINGLELINE | DT_NOPREFIX);
    FillRound(dc, rcLogBox, static_cast<float>(S(8)), kPanel, kBorder);

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
    const float radius = static_cast<float>(S(di->CtlID == IDC_RECONNECT ? 6 : 8));
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
    HFONT f = di->CtlID == IDC_RECONNECT ? fontSmall : fontButton;
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
        btnReconnect = mk(L"BUTTON", L"再接続", BS_OWNERDRAW | WS_TABSTOP, 0, IDC_RECONNECT);
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
        mmi->ptMinTrackSize = {S(420), S(560)};
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
        if ((code == BN_CLICKED || code == BN_DOUBLECLICKED) && !closing) {
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
    RECT wr{0, 0, MulDiv(460, static_cast<int>(sysDpi), 96), MulDiv(600, static_cast<int>(sysDpi), 96)};
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
