// opm_session.h
//
// OPM (Output Protection Manager) session handling used by opm_hdcp_force.
// Everything here only calls documented, public Win32 APIs (opmapi.h,
// shipped with every Windows SDK). See the notes below before reusing it.
//
//   Every structure and method signature used below (OPM_ENCRYPTED_INITIALIZATION_
//   PARAMETERS, OPM_CONFIGURE_PARAMETERS, OPM_GET_INFO_PARAMETERS,
//   OPM_REQUESTED_INFORMATION, OPM_OMAC, OPM_RANDOM_NUMBER, OPM_STANDARD_INFORMATION,
//   and the StartInitialization/FinishInitialization/Configure/GetInformation/
//   OPMGetVideoOutputsFromHMONITOR signatures) has been checked directly against
//   the reference pages under https://learn.microsoft.com/en-us/windows/win32/api/opmapi/
//   rather than reconstructed only from the prose "Using Output Protection Manager"
//   walkthrough. Two mistakes were caught and fixed this way: the size field on
//   OPM_CONFIGURE_PARAMETERS is cbParametersSize (not cbSettingDataSize, which is
//   what the prose page implied), and Configure() takes three arguments, not one.
//
//   The RSA-OAEP hash algorithm is BCRYPT_SHA512_ALGORITHM, confirmed against
//   Microsoft's own "OPM Example Code" page (learn.microsoft.com/en-us/windows/
//   win32/medfound/opm-example-code) -- not a guess. The plaintext order
//   (driver random number, session key, status sequence, command sequence) is
//   confirmed against the same page. SHA-1/SHA-256 and the reversed sequence
//   order are kept in the candidate list purely as a fallback net.
//
//   Certificate CHAIN validation up to Microsoft's OPM root is deliberately NOT
//   performed. This tool only wants to know whether the driver starts a real HDCP
//   AKE; it is not a compliant DRM client and must not be reused as one.
//
// Errors are reported by throwing OpmError (never by exiting the process), and
// progress messages go through OpmLog(), which the application must define.

#pragma once

#include <windows.h>
#include <initguid.h> // MUST come before opmapi.h: without INITGUID, the OPM_* GUID
                       // constants (OPM_SET_PROTECTION_LEVEL, OPM_GET_VIRTUAL_PROTECTION_
                       // LEVEL, ...) are declared extern and expect some .lib to supply
                       // their actual values. None of the libs we link against here do,
                       // which shows up as LNK2019 "unresolved external symbol" for each
                       // GUID actually used. <initguid.h> makes DEFINE_GUID allocate the
                       // GUID's storage directly in this translation unit instead.
#include <d3d9.h>     // MUST come before opmapi.h/dxva2api.h: those headers reference
                       // IDirect3DDevice9, D3DFORMAT, etc. and fail to parse without it.
#include <opmapi.h>   // pulls in dxva2api.h itself. Do NOT also include <ksopmapi.h> --
                       // on current Windows SDKs, opmapi.h already defines OPM_RANDOM_NUMBER,
                       // OPM_OMAC, OPM_GET_INFO_PARAMETERS, OPM_ENCRYPTED_INITIALIZATION_
                       // PARAMETERS, OPM_STANDARD_INFORMATION, etc. itself, and including
                       // both headers causes duplicate-definition errors.
#include <bcrypt.h>
#include <wincrypt.h>

#include <cstring>
#include <iterator>
#include <memory>
#include <string>
#include <vector>

#ifdef __MINGW32__
// mingw-w64's opmapi.h lacks these. Only used for local cross-compile checks;
// the real builds (MSVC + Windows SDK) take them from the SDK header.
DEFINE_GUID(OPM_GET_ACTUAL_PROTECTION_LEVEL, 0x1957210a, 0x7766, 0x452a,
            0xb9, 0x9a, 0xd2, 0x7a, 0xed, 0x54, 0xf0, 0x3a);
DEFINE_GUID(OPM_GET_VIRTUAL_PROTECTION_LEVEL, 0xb2075857, 0x3eda, 0x4d5d,
            0x88, 0xdb, 0x74, 0x8f, 0x8c, 0x1a, 0x05, 0x49);
DEFINE_GUID(OPM_SET_PROTECTION_LEVEL, 0x9bb9327c, 0x4eb5, 0x4727,
            0x9f, 0x00, 0xb4, 0x2b, 0x09, 0x19, 0xc0, 0xda);
#ifndef OPM_PROTECTION_TYPE_HDCP
#define OPM_PROTECTION_TYPE_HDCP 0x00000008
#endif
#ifndef OPM_PROTECTION_TYPE_COPP_COMPATIBLE_HDCP
#define OPM_PROTECTION_TYPE_COPP_COMPATIBLE_HDCP 0x00000001
#endif
#endif

// Defined by the application (GUI log window, console, ...).
void OpmLog(const wchar_t* fmt, ...);

struct OpmError {
    std::wstring where;
    HRESULT hr;
};

[[noreturn]] inline void Fail(const wchar_t* where, HRESULT hr) {
    throw OpmError{where, hr};
}

[[noreturn]] inline void FailNt(const wchar_t* where, NTSTATUS st) {
    throw OpmError{where, static_cast<HRESULT>(st)};
}

using Bytes = std::vector<BYTE>;

// If >= 0, ParseOpmCertificate uses the certificate at this index in the chain
// instead of its own scoring. Set with /cert:N so alternatives can be tried
// without recompiling.
inline int g_forceCertIndex = -1;

// ---------------------------------------------------------------------------
// AES-CMAC (== OMAC1), needed to sign every OPM request/response.
// Implemented directly from RFC 4493 using raw AES-ECB single-block
// encryption via CNG, since CNG does not expose CMAC as a named algorithm
// on every Windows version.
// ---------------------------------------------------------------------------

class AesCmac {
public:
    explicit AesCmac(const BYTE key16[16]) {
        NTSTATUS st = BCryptOpenAlgorithmProvider(&hAlg_, BCRYPT_AES_ALGORITHM, nullptr, 0);
        if (!BCRYPT_SUCCESS(st)) FailNt(L"BCryptOpenAlgorithmProvider(AES)", st);

        st = BCryptSetProperty(hAlg_, BCRYPT_CHAINING_MODE,
                                reinterpret_cast<PUCHAR>(const_cast<wchar_t*>(BCRYPT_CHAIN_MODE_ECB)),
                                sizeof(BCRYPT_CHAIN_MODE_ECB), 0);
        if (!BCRYPT_SUCCESS(st)) { Cleanup(); FailNt(L"BCryptSetProperty(ECB)", st); }

        st = BCryptGenerateSymmetricKey(hAlg_, &hKey_, nullptr, 0,
                                         const_cast<PUCHAR>(key16), 16, 0);
        if (!BCRYPT_SUCCESS(st)) { Cleanup(); FailNt(L"BCryptGenerateSymmetricKey", st); }

        BYTE zero[16] = {0};
        BYTE L[16];
        EncryptBlock(zero, L);

        Shl1(L, k1_);
        if (L[0] & 0x80) Xor87(k1_);
        Shl1(k1_, k2_);
        if (k1_[0] & 0x80) Xor87(k2_);
    }

    ~AesCmac() { Cleanup(); }

    AesCmac(const AesCmac&) = delete;
    AesCmac& operator=(const AesCmac&) = delete;

    // Writes the 16-byte CMAC tag for data[0..len) into tagOut.
    void Compute(const BYTE* data, size_t len, BYTE tagOut[16]) {
        size_t nBlocks = (len + 15) / 16;
        if (nBlocks == 0) nBlocks = 1;
        bool lastComplete = (len != 0) && (len % 16 == 0);

        BYTE x[16] = {0};
        for (size_t i = 0; i < nBlocks; ++i) {
            BYTE block[16] = {0};
            size_t off = i * 16;
            bool isLast = (i == nBlocks - 1);
            if (isLast) {
                size_t remain = len - off;
                if (remain) memcpy(block, data + off, remain);
                if (lastComplete) {
                    XorInto(block, k1_);
                } else {
                    block[remain] = 0x80;
                    XorInto(block, k2_);
                }
            } else {
                memcpy(block, data + off, 16);
            }
            XorInto(x, block);
            BYTE enc[16];
            EncryptBlock(x, enc);
            memcpy(x, enc, 16);
        }
        memcpy(tagOut, x, 16);
    }

private:
    void Cleanup() {
        if (hKey_) { BCryptDestroyKey(hKey_); hKey_ = nullptr; }
        if (hAlg_) { BCryptCloseAlgorithmProvider(hAlg_, 0); hAlg_ = nullptr; }
    }
    void EncryptBlock(const BYTE in[16], BYTE out[16]) {
        ULONG cbResult = 0;
        NTSTATUS st = BCryptEncrypt(hKey_, const_cast<PUCHAR>(in), 16, nullptr, nullptr, 0,
                                     out, 16, &cbResult, 0);
        if (!BCRYPT_SUCCESS(st)) FailNt(L"BCryptEncrypt(ECB block)", st);
    }
    static void Shl1(const BYTE in[16], BYTE out[16]) {
        BYTE carry = 0;
        for (int i = 15; i >= 0; --i) {
            BYTE b = in[i];
            out[i] = static_cast<BYTE>((b << 1) | carry);
            carry = (b & 0x80) ? 1 : 0;
        }
    }
    static void Xor87(BYTE v[16]) { v[15] ^= 0x87; }
    static void XorInto(BYTE dst[16], const BYTE src[16]) {
        for (int i = 0; i < 16; ++i) dst[i] ^= src[i];
    }

    BCRYPT_ALG_HANDLE hAlg_ = nullptr;
    BCRYPT_KEY_HANDLE hKey_ = nullptr;
    BYTE k1_[16] = {0};
    BYTE k2_[16] = {0};
};

// The blob StartInitialization hands back is documented only as "an X.509
// certificate chain" -- not necessarily a single bare DER-encoded
// certificate. Try the simple case first, then fall back to CryptQueryObject,
// which auto-detects PKCS#7 "certificates-only" blobs and other wrappings and
// hands back a cert store we can pull a certificate out of.
inline PCCERT_CONTEXT ParseOpmCertificate(const BYTE* pCert, DWORD certLen) {
    PCCERT_CONTEXT cert = CertCreateCertificateContext(X509_ASN_ENCODING, pCert, certLen);
    if (cert) return cert;

    CERT_BLOB blob{};
    blob.cbData = certLen;
    blob.pbData = const_cast<BYTE*>(pCert);

    HCERTSTORE hStore = nullptr;
    DWORD contentType = 0;
    BOOL ok = CryptQueryObject(
        CERT_QUERY_OBJECT_BLOB, &blob,
        CERT_QUERY_CONTENT_FLAG_ALL, CERT_QUERY_FORMAT_FLAG_ALL,
        0, nullptr, &contentType, nullptr, &hStore, nullptr, nullptr);
    if (!ok) {
        OpmLog(L"[FAIL] CryptQueryObject (0x%08lx)",
               static_cast<unsigned long>(HRESULT_FROM_WIN32(GetLastError())));
        return nullptr;
    }

    // A PKCS#7 "certs-only" blob bundles the whole chain (leaf + intermediate(s)
    // + root), not just the one certificate whose private key the driver will
    // actually use. Rather than guessing at one specific key-usage bit and
    // risking discarding every candidate, enumerate everything and score them:
    // prefer a certificate that can do encipherment and is NOT a CA, but never
    // end up with nothing.
    PCCERT_CONTEXT best = nullptr;
    int bestScore = -1;
    int index = 0;
    PCCERT_CONTEXT ctx = nullptr;

    while ((ctx = CertEnumCertificatesInStore(hStore, ctx)) != nullptr) {
        BYTE usage = 0;
        BOOL haveUsage = CertGetIntendedKeyUsage(X509_ASN_ENCODING, ctx->pCertInfo,
                                                  &usage, sizeof(usage));

        BOOL isCA = FALSE;
        CERT_EXTENSION* ext = CertFindExtension(szOID_BASIC_CONSTRAINTS2,
                                                 ctx->pCertInfo->cExtension,
                                                 ctx->pCertInfo->rgExtension);
        if (ext) {
            CERT_BASIC_CONSTRAINTS2_INFO bc{};
            DWORD cb = sizeof(bc);
            if (CryptDecodeObject(X509_ASN_ENCODING, szOID_BASIC_CONSTRAINTS2,
                                   ext->Value.pbData, ext->Value.cbData, 0, &bc, &cb)) {
                isCA = bc.fCA;
            }
        }

        int score = 0;
        if (!isCA)                                            score += 4;
        if (haveUsage && (usage & CERT_KEY_ENCIPHERMENT_KEY_USAGE)) score += 2;
        if (haveUsage && (usage & CERT_DATA_ENCIPHERMENT_KEY_USAGE)) score += 2;
        if (haveUsage && (usage & CERT_KEY_AGREEMENT_KEY_USAGE))     score += 1;
        if (!haveUsage)                                       score += 1;  // unrestricted

        if (g_forceCertIndex >= 0) {
            if (index == g_forceCertIndex) {
                if (best) CertFreeCertificateContext(best);
                best = CertDuplicateCertificateContext(ctx);
                bestScore = score;
            }
        } else if (score > bestScore) {
            if (best) CertFreeCertificateContext(best);
            best = CertDuplicateCertificateContext(ctx);
            bestScore = score;
        }
        ++index;
    }
    CertCloseStore(hStore, 0);

    if (!best) {
        OpmLog(L"[FAIL] no certificate at the requested index (store has %d).", index);
        return nullptr;
    }
    return best;
}

inline BCRYPT_KEY_HANDLE ImportRsaPublicKeyFromCert(PCCERT_CONTEXT cert) {
    BCRYPT_KEY_HANDLE hKey = nullptr;
    BOOL ok = CryptImportPublicKeyInfoEx2(
        X509_ASN_ENCODING,
        &cert->pCertInfo->SubjectPublicKeyInfo,
        0,
        nullptr,
        &hKey);
    if (!ok) Fail(L"CryptImportPublicKeyInfoEx2", HRESULT_FROM_WIN32(GetLastError()));
    return hKey;
}

inline Bytes RsaOaepEncrypt(BCRYPT_KEY_HANDLE hPubKey, LPCWSTR hashAlgId,
                            const BYTE* plaintext, ULONG ptLen) {
    BCRYPT_OAEP_PADDING_INFO oaep = {};
    oaep.pszAlgId = hashAlgId;

    ULONG cbResult = 0;
    NTSTATUS st = BCryptEncrypt(hPubKey, const_cast<PUCHAR>(plaintext), ptLen, &oaep, nullptr, 0,
                                 nullptr, 0, &cbResult, BCRYPT_PAD_OAEP);
    if (!BCRYPT_SUCCESS(st)) FailNt(L"BCryptEncrypt(OAEP, size query)", st);

    Bytes out(cbResult);
    st = BCryptEncrypt(hPubKey, const_cast<PUCHAR>(plaintext), ptLen, &oaep, nullptr, 0,
                        out.data(), cbResult, &cbResult, BCRYPT_PAD_OAEP);
    if (!BCRYPT_SUCCESS(st)) FailNt(L"BCryptEncrypt(OAEP)", st);
    out.resize(cbResult);
    return out;
}

// COPP semantics (the older, pre-OPM DDI path that the same IOPMVideoOutput
// interface also supports) uses plain RSA encryption -- PKCS#1 v1.5 padding,
// no hash algorithm to guess at -- per the WDK's "Using the OPM DDI" page.
inline Bytes RsaPkcs1Encrypt(BCRYPT_KEY_HANDLE hPubKey, const BYTE* plaintext, ULONG ptLen) {
    ULONG cbResult = 0;
    NTSTATUS st = BCryptEncrypt(hPubKey, const_cast<PUCHAR>(plaintext), ptLen, nullptr, nullptr, 0,
                                 nullptr, 0, &cbResult, BCRYPT_PAD_PKCS1);
    if (!BCRYPT_SUCCESS(st)) FailNt(L"BCryptEncrypt(PKCS1, size query)", st);

    Bytes out(cbResult);
    st = BCryptEncrypt(hPubKey, const_cast<PUCHAR>(plaintext), ptLen, nullptr, nullptr, 0,
                        out.data(), cbResult, &cbResult, BCRYPT_PAD_PKCS1);
    if (!BCRYPT_SUCCESS(st)) FailNt(L"BCryptEncrypt(PKCS1)", st);
    out.resize(cbResult);
    return out;
}

inline void SecureRandom(void* buf, ULONG len) {
    NTSTATUS st = BCryptGenRandom(nullptr, static_cast<PUCHAR>(buf), len,
                                   BCRYPT_USE_SYSTEM_PREFERRED_RNG);
    if (!BCRYPT_SUCCESS(st)) FailNt(L"BCryptGenRandom", st);
}

// Number of OPM video outputs attached to a monitor. Throws on failure.
inline ULONG CountVideoOutputs(HMONITOR mon) {
    IOPMVideoOutput** outputs = nullptr;
    ULONG numOutputs = 0;
    HRESULT hr = OPMGetVideoOutputsFromHMONITOR(mon, OPM_VOS_OPM_SEMANTICS, &numOutputs, &outputs);
    if (FAILED(hr)) Fail(L"OPMGetVideoOutputsFromHMONITOR", hr);
    for (ULONG i = 0; i < numOutputs; ++i) outputs[i]->Release();
    CoTaskMemFree(outputs);
    return numOutputs;
}

// ---------------------------------------------------------------------------
// One OPM session (== one physical video output) and the handshake.
// ---------------------------------------------------------------------------

class OpmSession {
public:
    OpmSession(HMONITOR mon, ULONG outputIndex) : mon_(mon), outputIndex_(outputIndex) {}

    ~OpmSession() {
        if (vo_) vo_->Release();
    }

    OpmSession(const OpmSession&) = delete;
    OpmSession& operator=(const OpmSession&) = delete;

    bool IsReady() const { return vo_ != nullptr; }
    ULONG Index() const { return outputIndex_; }

    // Which handshake variant succeeded, for the log.
    const std::wstring& Variant() const { return variant_; }

    // The HDCP protection type to use with this session. Under COPP semantics
    // the driver only knows the COPP-compatible HDCP type and answers the OPM
    // one with ERROR_GRAPHICS_OPM_HDCP_NOT_SUPPORTED.
    ULONG HdcpType() const {
        return semantics_ == OPM_VOS_COPP_SEMANTICS ? OPM_PROTECTION_TYPE_COPP_COMPATIBLE_HDCP
                                                    : OPM_PROTECTION_TYPE_HDCP;
    }

    // Runs the handshake, trying every known parameter combination. Throws
    // OpmError if none of them works.
    void Initialize() {
        struct Candidate { OPM_VIDEO_OUTPUT_SEMANTICS semantics; LPCWSTR hash; bool commandSeqFirst; };
        // Microsoft's own "OPM Example Code" page confirms the plaintext order
        // (commandSeqFirst=false) and the OAEP hash (SHA-512), so that
        // combination is tried first; the rest stay as a fallback net in case
        // this environment's driver genuinely differs from the documented sample.
        const Candidate candidates[] = {
            { OPM_VOS_OPM_SEMANTICS,  BCRYPT_SHA512_ALGORITHM, false },
            { OPM_VOS_OPM_SEMANTICS,  BCRYPT_SHA512_ALGORITHM, true  },
            { OPM_VOS_OPM_SEMANTICS,  BCRYPT_SHA1_ALGORITHM,   false },
            { OPM_VOS_OPM_SEMANTICS,  BCRYPT_SHA1_ALGORITHM,   true  },
            { OPM_VOS_OPM_SEMANTICS,  BCRYPT_SHA256_ALGORITHM, false },
            { OPM_VOS_OPM_SEMANTICS,  BCRYPT_SHA256_ALGORITHM, true  },
            { OPM_VOS_COPP_SEMANTICS, nullptr,                 false },
            { OPM_VOS_COPP_SEMANTICS, nullptr,                 true  },
        };

        HRESULT lastHr = E_FAIL;
        for (const auto& c : candidates) {
            std::wstring name = (c.semantics == OPM_VOS_COPP_SEMANTICS)
                ? std::wstring(L"COPP")
                : std::wstring(L"OPM/") + c.hash;
            name += c.commandSeqFirst ? L"/command-first" : L"/status-first";
            lastHr = TryInitialize(c.semantics, c.hash, c.commandSeqFirst);
            if (SUCCEEDED(lastHr)) {
                semantics_ = c.semantics;
                variant_ = name;
                return;
            }
            OpmLog(L"  handshake %ls: 0x%08lx", name.c_str(), static_cast<unsigned long>(lastHr));
        }
        Fail(L"OPM handshake (all combinations)", lastHr);
    }

    // Requests an HDCP protection level (OPM_HDCP_ON / OPM_HDCP_OFF).
    HRESULT TrySetHdcp(ULONG level) {
        OPM_SET_PROTECTION_LEVEL_PARAMETERS p{};
        p.ulProtectionType = HdcpType();
        p.ulProtectionLevel = level;
        return TrySendCommand(OPM_SET_PROTECTION_LEVEL, reinterpret_cast<BYTE*>(&p), sizeof(p));
    }

    // Queries OPM_GET_ACTUAL_PROTECTION_LEVEL / OPM_GET_VIRTUAL_PROTECTION_LEVEL
    // for HDCP.
    HRESULT TryQueryHdcp(REFGUID what, OPM_STANDARD_INFORMATION& out) {
        ULONG queryType = HdcpType();
        return TrySendStatusRequest(what, out, reinterpret_cast<BYTE*>(&queryType), sizeof(queryType));
    }

    HRESULT TrySendCommand(REFGUID guidSetting, const BYTE* param, ULONG paramLen) {
        if (!vo_) return E_UNEXPECTED;
        OPM_CONFIGURE_PARAMETERS cp{};
        cp.guidSetting = guidSetting;
        cp.ulSequenceNumber = commandSeq_++;
        if (paramLen > sizeof(cp.abParameters)) return E_INVALIDARG;
        memcpy(cp.abParameters, param, paramLen);
        cp.cbParametersSize = paramLen;

        cmac_->Compute(reinterpret_cast<BYTE*>(&cp) + sizeof(cp.omac),
                        sizeof(cp) - sizeof(cp.omac),
                        cp.omac.abOMAC);

        // OPM_SET_PROTECTION_LEVEL needs no additional out-of-band data.
        return vo_->Configure(&cp, 0, nullptr);
    }

    // param/paramLen is optional input data some status requests need. E.g.
    // OPM_GET_VIRTUAL_PROTECTION_LEVEL and OPM_GET_ACTUAL_PROTECTION_LEVEL
    // require the first 4 bytes of abParameters to contain the protection type
    // being queried -- without it the driver rejects the request with E_INVALIDARG.
    HRESULT TrySendStatusRequest(REFGUID guidInformation, OPM_STANDARD_INFORMATION& outInfo,
                                  const BYTE* param = nullptr, ULONG paramLen = 0) {
        if (!vo_) return E_UNEXPECTED;
        OPM_GET_INFO_PARAMETERS gp{};
        gp.guidInformation = guidInformation;
        gp.ulSequenceNumber = statusSeq_++;
        SecureRandom(gp.rnRandomNumber.abRandomNumber, sizeof(gp.rnRandomNumber.abRandomNumber));
        if (paramLen > 0) {
            if (paramLen > sizeof(gp.abParameters)) return E_INVALIDARG;
            memcpy(gp.abParameters, param, paramLen);
            gp.cbParametersSize = paramLen;
        }

        cmac_->Compute(reinterpret_cast<BYTE*>(&gp) + sizeof(gp.omac),
                        sizeof(gp) - sizeof(gp.omac),
                        gp.omac.abOMAC);

        // OPM_REQUESTED_INFORMATION is ~4 KB; keep it off the stack of the
        // polling loop.
        auto out = std::make_unique<OPM_REQUESTED_INFORMATION>();
        HRESULT hr = vo_->GetInformation(&gp, out.get());
        if (FAILED(hr)) {
            // Don't consume the sequence number on a rejected request: if the
            // driver only advances its expected number on success, one failed
            // query would otherwise make every later one fail with
            // ERROR_GRAPHICS_OPM_INVALID_INFORMATION_REQUEST (bad sequence/OMAC).
            --statusSeq_;
            return hr;
        }

        BYTE checkTag[16];
        cmac_->Compute(reinterpret_cast<BYTE*>(out.get()) + sizeof(out->omac),
                        sizeof(*out) - sizeof(out->omac), checkTag);
        if (memcmp(checkTag, out->omac.abOMAC, 16) != 0) {
            OpmLog(L"[WARN] OMAC mismatch on response -- treat this result with caution");
        }

        memcpy(&outInfo, out->abRequestedInformation, sizeof(outInfo));
        return S_OK;
    }

private:
    // Fetches a brand-new IOPMVideoOutput for the same physical output. Needed
    // because StartInitialization appears to be usable only once per
    // IOPMVideoOutput instance -- calling it again on the same object after an
    // earlier attempt (even a failed one) fails outright.
    IOPMVideoOutput* AcquireFreshOutput(OPM_VIDEO_OUTPUT_SEMANTICS semantics) {
        IOPMVideoOutput** outputs = nullptr;
        ULONG numOutputs = 0;
        HRESULT hr = OPMGetVideoOutputsFromHMONITOR(mon_, semantics, &numOutputs, &outputs);
        if (FAILED(hr)) {
            OpmLog(L"[FAIL] OPMGetVideoOutputsFromHMONITOR (hr=0x%08lx)",
                   static_cast<unsigned long>(hr));
            return nullptr;
        }
        IOPMVideoOutput* picked = nullptr;
        for (ULONG i = 0; i < numOutputs; ++i) {
            if (i == outputIndex_) picked = outputs[i];
            else outputs[i]->Release();
        }
        CoTaskMemFree(outputs);
        if (!picked) {
            OpmLog(L"[FAIL] output index %lu no longer present (only %lu output(s) now)",
                   outputIndex_, numOutputs);
        }
        return picked;
    }

    // Tries one full StartInitialization+FinishInitialization round trip with a
    // specific guess at: semantics (OPM/RSAES-OAEP vs COPP/plain RSA), OAEP hash,
    // and which of the two sequence numbers is encoded first.
    HRESULT TryInitialize(OPM_VIDEO_OUTPUT_SEMANTICS semantics, LPCWSTR hashAlgId,
                          bool commandSeqFirst) {
        IOPMVideoOutput* trialVo = AcquireFreshOutput(semantics);
        if (!trialVo) return E_FAIL;

        OPM_RANDOM_NUMBER driverRandom = {};
        BYTE* pCert = nullptr;
        ULONG certLen = 0;

        HRESULT hr = trialVo->StartInitialization(&driverRandom, &pCert, &certLen);
        if (FAILED(hr)) {
            trialVo->Release();
            return hr;
        }

        PCCERT_CONTEXT cert = ParseOpmCertificate(pCert, certLen);
        CoTaskMemFree(pCert);
        if (!cert) {
            HRESULT certHr = HRESULT_FROM_WIN32(GetLastError());
            trialVo->Release();
            return FAILED(certHr) ? certHr : E_FAIL;
        }

        try {
            // Deliberately not validated up to Microsoft's OPM root -- see the
            // header comment. This tool is a probe, not a DRM client.
            BCRYPT_KEY_HANDLE hPub = ImportRsaPublicKeyFromCert(cert);

            BYTE trialKey[16];
            ULONG trialStatusSeq = 0, trialCommandSeq = 0;
            SecureRandom(trialKey, sizeof(trialKey));
            SecureRandom(&trialStatusSeq, sizeof(trialStatusSeq));
            SecureRandom(&trialCommandSeq, sizeof(trialCommandSeq));

            struct {
                OPM_RANDOM_NUMBER rn;
                BYTE key[16];
                ULONG seqA;
                ULONG seqB;
            } plain{};
            plain.rn = driverRandom;
            memcpy(plain.key, trialKey, 16);
            plain.seqA = commandSeqFirst ? trialCommandSeq : trialStatusSeq;
            plain.seqB = commandSeqFirst ? trialStatusSeq : trialCommandSeq;

            Bytes cipher;
            try {
                cipher = (semantics == OPM_VOS_COPP_SEMANTICS)
                    ? RsaPkcs1Encrypt(hPub, reinterpret_cast<BYTE*>(&plain), sizeof(plain))
                    : RsaOaepEncrypt(hPub, hashAlgId, reinterpret_cast<BYTE*>(&plain), sizeof(plain));
            } catch (...) {
                BCryptDestroyKey(hPub);
                throw;
            }
            BCryptDestroyKey(hPub);

            OPM_ENCRYPTED_INITIALIZATION_PARAMETERS finishParams{};
            if (cipher.size() > sizeof(finishParams.abEncryptedInitializationParameters)) {
                OpmLog(L"[FAIL] RSA ciphertext (%zu bytes) does not fit "
                       L"abEncryptedInitializationParameters (%zu bytes).",
                       cipher.size(), sizeof(finishParams.abEncryptedInitializationParameters));
                Fail(L"FinishInitialization (ciphertext too large)", E_UNEXPECTED);
            }
            // Right-align: if the ciphertext is shorter than the fixed 256-byte
            // field, place it at the END of the buffer with leading zeros.
            size_t offset = sizeof(finishParams.abEncryptedInitializationParameters) - cipher.size();
            memcpy(finishParams.abEncryptedInitializationParameters + offset, cipher.data(), cipher.size());

            hr = trialVo->FinishInitialization(&finishParams);

            if (SUCCEEDED(hr)) {
                auto cmac = std::make_unique<AesCmac>(trialKey);
                if (vo_) vo_->Release();
                vo_ = trialVo;  // keep this one alive for Configure/GetInformation
                memcpy(sessionKey_, trialKey, 16);
                statusSeq_ = trialStatusSeq;
                commandSeq_ = trialCommandSeq;
                cmac_ = std::move(cmac);
                trialVo = nullptr;
            }
        } catch (const OpmError& e) {
            OpmLog(L"  handshake attempt failed in %ls (0x%08lx)", e.where.c_str(),
                   static_cast<unsigned long>(e.hr));
            hr = e.hr;
        }

        CertFreeCertificateContext(cert);
        if (trialVo) trialVo->Release();
        return hr;
    }

    HMONITOR mon_;
    ULONG outputIndex_;
    OPM_VIDEO_OUTPUT_SEMANTICS semantics_ = OPM_VOS_OPM_SEMANTICS;
    std::wstring variant_;
    IOPMVideoOutput* vo_ = nullptr;
    ULONG statusSeq_ = 0;
    ULONG commandSeq_ = 0;
    BYTE sessionKey_[16] = {0};
    std::unique_ptr<AesCmac> cmac_;
};
