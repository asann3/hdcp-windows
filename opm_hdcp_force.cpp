// opm_hdcp_force.cpp
//
// Minimal test tool: forces HDCP ON on every detected display output via the
// public Output Protection Manager (OPM) API, WITHOUT playing any real DRM
// content. Purpose: find out whether a plain Win32 app that never touches
// BitVisor can make the driver actually run an HDCP authentication (AKE) on
// the physical link, or whether the driver just reports "HDCP is on" without
// doing anything on the wire.
//
// This only calls documented, public Win32 APIs (Opmapi.h / Ksopmapi.h,
// shipped with every Windows SDK). It does not touch any DRM-protected
// content, does not bypass any copy protection, and does not need a signed
// "Protected Environment" the way the Protected Media Path does -- OPM itself
// has been a plain public API since the Windows 7 SDK.
//
// IMPORTANT - please read before building:
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
//   That said, this was still written without the actual SDK headers open side by
//   side, so if your compiler disagrees with a field name or size here, trust your
//   local <opmapi.h> / <ksopmapi.h> over this file.
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
// Build (from a "Developer Command Prompt for VS"):
//
//   cl /EHsc /W4 opm_hdcp_force.cpp ^
//      /link dxva2.lib d3d9.lib bcrypt.lib crypt32.lib user32.lib ole32.lib
//
// Usage:
//
//   opm_hdcp_force.exe        enable HDCP, poll status, hold the session
//                             open until Enter is pressed, then disable it
//   opm_hdcp_force.exe /off   just try to turn HDCP off and exit
//
// While this is running with HDCP requested ON, watch BitVisor's AUX trace.
// If a real AKE happens, you should see the same kind of traffic (BKSV/AN
// exchange for 1.4, or an AKE_Init write to DPCD 0x69000 for 2.2) that shows
// up when a real streaming app plays protected content. If nothing appears
// on the AUX channel at all, the driver is reporting success without
// touching the link, and that's a very important negative result in itself.

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

#include <cstdio>
#include <cstdlib>
#include <thread>
#include <atomic>
#include <chrono>
#include <cstring>
#include <iterator>
#include <memory>
#include <vector>

#pragma comment(lib, "dxva2.lib")
#pragma comment(lib, "d3d9.lib")
#pragma comment(lib, "bcrypt.lib")
#pragma comment(lib, "crypt32.lib")
#pragma comment(lib, "user32.lib")
#pragma comment(lib, "ole32.lib")

using Bytes = std::vector<BYTE>;

// If >= 0, ParseOpmCertificate uses the certificate at this index in the chain
// instead of its own scoring. Set with /cert:N so alternatives can be tried
// without recompiling.
static int g_forceCertIndex = -1;

// ---------------------------------------------------------------------------
// small helpers
// ---------------------------------------------------------------------------

static void Fail(const char* where, HRESULT hr) {
    fprintf(stderr, "[FAIL] %s (hr=0x%08lx)\n", where, static_cast<unsigned long>(hr));
    exit(1);
}

static void FailNt(const char* where, NTSTATUS st) {
    fprintf(stderr, "[FAIL] %s (nt=0x%08lx)\n", where, static_cast<unsigned long>(st));
    exit(1);
}

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
        if (!BCRYPT_SUCCESS(st)) FailNt("BCryptOpenAlgorithmProvider(AES)", st);

        st = BCryptSetProperty(hAlg_, BCRYPT_CHAINING_MODE,
                                reinterpret_cast<PUCHAR>(const_cast<wchar_t*>(BCRYPT_CHAIN_MODE_ECB)),
                                sizeof(BCRYPT_CHAIN_MODE_ECB), 0);
        if (!BCRYPT_SUCCESS(st)) FailNt("BCryptSetProperty(ECB)", st);

        st = BCryptGenerateSymmetricKey(hAlg_, &hKey_, nullptr, 0,
                                         const_cast<PUCHAR>(key16), 16, 0);
        if (!BCRYPT_SUCCESS(st)) FailNt("BCryptGenerateSymmetricKey", st);

        BYTE zero[16] = {0};
        BYTE L[16];
        EncryptBlock(zero, L);

        Shl1(L, k1_);
        if (L[0] & 0x80) Xor87(k1_);
        Shl1(k1_, k2_);
        if (k1_[0] & 0x80) Xor87(k2_);
    }

    ~AesCmac() {
        if (hKey_) BCryptDestroyKey(hKey_);
        if (hAlg_) BCryptCloseAlgorithmProvider(hAlg_, 0);
    }

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
    void EncryptBlock(const BYTE in[16], BYTE out[16]) {
        ULONG cbResult = 0;
        NTSTATUS st = BCryptEncrypt(hKey_, const_cast<PUCHAR>(in), 16, nullptr, nullptr, 0,
                                     out, 16, &cbResult, 0);
        if (!BCRYPT_SUCCESS(st)) FailNt("BCryptEncrypt(ECB block)", st);
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
// hands back a cert store we can pull a certificate out of. On failure, dump
// the raw bytes so the actual format can be inspected offline (e.g. with
// `certutil -dump opm_cert_dump.bin`).
static PCCERT_CONTEXT ParseOpmCertificate(const BYTE* pCert, DWORD certLen) {
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
        fprintf(stderr, "  [FAIL] CryptQueryObject (0x%08lx)\n",
                static_cast<unsigned long>(HRESULT_FROM_WIN32(GetLastError())));
        return nullptr;
    }

    // A PKCS#7 "certs-only" blob bundles the whole chain (leaf + intermediate(s)
    // + root), not just the one certificate whose private key the driver will
    // actually use. Rather than guessing at one specific key-usage bit and
    // risking discarding every candidate, enumerate everything, print what was
    // found, and score them: prefer a certificate that can do encipherment and
    // is NOT a CA, but never end up with nothing.
    PCCERT_CONTEXT best = nullptr;
    int bestScore = -1;
    int index = 0;
    PCCERT_CONTEXT ctx = nullptr;

    while ((ctx = CertEnumCertificatesInStore(hStore, ctx)) != nullptr) {
        BYTE usage = 0;
        BOOL haveUsage = CertGetIntendedKeyUsage(X509_ASN_ENCODING, ctx->pCertInfo,
                                                  &usage, sizeof(usage));

        // Is this a CA certificate? Those are the ones we want to avoid.
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
        fprintf(stderr, "  [FAIL] no certificate at the requested index (store has %d).\n",
                index);
        return nullptr;
    }
    return best;
}

static BCRYPT_KEY_HANDLE ImportRsaPublicKeyFromCert(PCCERT_CONTEXT cert) {
    BCRYPT_KEY_HANDLE hKey = nullptr;
    BOOL ok = CryptImportPublicKeyInfoEx2(
        X509_ASN_ENCODING,
        &cert->pCertInfo->SubjectPublicKeyInfo,
        0,
        nullptr,
        &hKey);
    if (!ok) Fail("CryptImportPublicKeyInfoEx2", HRESULT_FROM_WIN32(GetLastError()));

    return hKey;
}

static Bytes RsaOaepEncrypt(BCRYPT_KEY_HANDLE hPubKey, LPCWSTR hashAlgId,
                             const BYTE* plaintext, ULONG ptLen) {
    BCRYPT_OAEP_PADDING_INFO oaep = {0};
    oaep.pszAlgId = hashAlgId;
    oaep.pbLabel = nullptr;
    oaep.cbLabel = 0;

    ULONG cbResult = 0;
    NTSTATUS st = BCryptEncrypt(hPubKey, const_cast<PUCHAR>(plaintext), ptLen, &oaep, nullptr, 0,
                                 nullptr, 0, &cbResult, BCRYPT_PAD_OAEP);
    if (!BCRYPT_SUCCESS(st)) FailNt("BCryptEncrypt(OAEP, size query)", st);

    Bytes out(cbResult);
    st = BCryptEncrypt(hPubKey, const_cast<PUCHAR>(plaintext), ptLen, &oaep, nullptr, 0,
                        out.data(), cbResult, &cbResult, BCRYPT_PAD_OAEP);
    if (!BCRYPT_SUCCESS(st)) FailNt("BCryptEncrypt(OAEP)", st);
    out.resize(cbResult);
    return out;
}

// COPP semantics (the older, pre-OPM DDI path that the same IOPMVideoOutput
// interface also supports) uses plain RSA encryption -- PKCS#1 v1.5 padding,
// no hash algorithm to guess at -- per the WDK's "Using the OPM DDI" page:
// "The data is encrypted with the standard RSA algorithm if the protected
// output has COPP semantics and with the RSAES-OAEP encryption scheme if the
// protected output has OPM semantics."
static Bytes RsaPkcs1Encrypt(BCRYPT_KEY_HANDLE hPubKey, const BYTE* plaintext, ULONG ptLen) {
    ULONG cbResult = 0;
    NTSTATUS st = BCryptEncrypt(hPubKey, const_cast<PUCHAR>(plaintext), ptLen, nullptr, nullptr, 0,
                                 nullptr, 0, &cbResult, BCRYPT_PAD_PKCS1);
    if (!BCRYPT_SUCCESS(st)) FailNt("BCryptEncrypt(PKCS1, size query)", st);

    Bytes out(cbResult);
    st = BCryptEncrypt(hPubKey, const_cast<PUCHAR>(plaintext), ptLen, nullptr, nullptr, 0,
                        out.data(), cbResult, &cbResult, BCRYPT_PAD_PKCS1);
    if (!BCRYPT_SUCCESS(st)) FailNt("BCryptEncrypt(PKCS1)", st);
    out.resize(cbResult);
    return out;
}

static void SecureRandom(void* buf, ULONG len) {
    NTSTATUS st = BCryptGenRandom(nullptr, static_cast<PUCHAR>(buf), len,
                                   BCRYPT_USE_SYSTEM_PREFERRED_RNG);
    if (!BCRYPT_SUCCESS(st)) FailNt("BCryptGenRandom", st);
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

    // Fetches a brand-new IOPMVideoOutput for the same physical output. Needed
    // because StartInitialization appears to be usable only once per
    // IOPMVideoOutput instance -- calling it again on the same object after an
    // earlier attempt (even a failed one) fails outright, silently, with no
    // way to distinguish that from a real handshake problem unless you go
    // looking for it. Re-enumerating gives every attempt a clean object.
    static IOPMVideoOutput* AcquireFreshOutput(HMONITOR mon, ULONG index,
                                                OPM_VIDEO_OUTPUT_SEMANTICS semantics) {
        IOPMVideoOutput** outputs = nullptr;
        ULONG numOutputs = 0;
        HRESULT hr = OPMGetVideoOutputsFromHMONITOR(mon, semantics,
                                                     &numOutputs, &outputs);
        if (FAILED(hr)) {
            fprintf(stderr, "  [FAIL] OPMGetVideoOutputsFromHMONITOR (hr=0x%08lx)\n",
                    static_cast<unsigned long>(hr));
            return nullptr;
        }
        IOPMVideoOutput* picked = nullptr;
        for (ULONG i = 0; i < numOutputs; ++i) {
            if (i == index) picked = outputs[i];
            else outputs[i]->Release();
        }
        CoTaskMemFree(outputs);
        if (!picked) {
            fprintf(stderr, "  [FAIL] output index %lu no longer present "
                            "(only %lu output(s) now)\n", index, numOutputs);
        }
        return picked;
    }

    // Tries one full StartInitialization+FinishInitialization round trip with a
    // specific guess at: which semantics to use (OPM/RSAES-OAEP vs the older
    // COPP/plain-RSA path that the same interface also supports), which hash
    // RSAES-OAEP uses (irrelevant for COPP), and which of the two sequence
    // numbers is encoded first. Returns the HRESULT from FinishInitialization
    // (or from an earlier step, on unusual failures). Every attempt gets its
    // own fresh IOPMVideoOutput (see AcquireFreshOutput) and therefore its own
    // fresh StartInitialization/driver random number/certificate fetch.
    HRESULT TryInitialize(OPM_VIDEO_OUTPUT_SEMANTICS semantics, LPCWSTR hashAlgId,
                          bool commandSeqFirst) {
        IOPMVideoOutput* trialVo = AcquireFreshOutput(mon_, outputIndex_, semantics);
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
            return certHr;
        }

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

        Bytes cipher = (semantics == OPM_VOS_COPP_SEMANTICS)
            ? RsaPkcs1Encrypt(hPub, reinterpret_cast<BYTE*>(&plain), sizeof(plain))
            : RsaOaepEncrypt(hPub, hashAlgId, reinterpret_cast<BYTE*>(&plain), sizeof(plain));

        OPM_ENCRYPTED_INITIALIZATION_PARAMETERS finishParams{};
        if (cipher.size() > sizeof(finishParams.abEncryptedInitializationParameters)) {
            fprintf(stderr, "[FAIL] RSA ciphertext (%zu bytes) does not fit "
                            "abEncryptedInitializationParameters (%zu bytes).\n",
                    cipher.size(), sizeof(finishParams.abEncryptedInitializationParameters));
            exit(1);
        }
        // Right-align: if the ciphertext is shorter than the fixed 256-byte
        // field (i.e. the key is smaller than 2048 bits), place it at the END
        // of the buffer with the leading bytes left zero -- the usual
        // big-endian-integer convention for embedding an RSA block inside a
        // fixed-size buffer sized for the largest supported modulus.
        size_t offset = sizeof(finishParams.abEncryptedInitializationParameters) - cipher.size();
        memcpy(finishParams.abEncryptedInitializationParameters + offset, cipher.data(), cipher.size());

        hr = trialVo->FinishInitialization(&finishParams);

        CertFreeCertificateContext(cert);
        BCryptDestroyKey(hPub);

        if (SUCCEEDED(hr)) {
            if (vo_) vo_->Release();
            vo_ = trialVo;  // keep this one alive for SendCommand/SendStatusRequest
            memcpy(sessionKey_, trialKey, 16);
            statusSeq_ = trialStatusSeq;
            commandSeq_ = trialCommandSeq;
            cmac_ = std::make_unique<AesCmac>(sessionKey_);
            printf("  OPM session established.\n");
        } else {
            trialVo->Release();
        }
        return hr;
    }

    void Initialize() {
        struct Candidate { OPM_VIDEO_OUTPUT_SEMANTICS semantics; LPCWSTR hash; bool commandSeqFirst; };
        // Microsoft's own "OPM Example Code" page (learn.microsoft.com/en-us/windows/
        // win32/medfound/opm-example-code) confirms both previously-ambiguous points:
        // the plaintext order is (driver random, session key, status seq, command seq)
        // -- i.e. commandSeqFirst=false, which was already our first candidate -- and
        // the OAEP hash is BCRYPT_SHA512_ALGORITHM, which we had never actually tried.
        // That combination is tried first; the rest stay as a fallback net in case this
        // environment's driver genuinely differs from the documented sample.
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
            lastHr = TryInitialize(c.semantics, c.hash, c.commandSeqFirst);
            if (SUCCEEDED(lastHr)) return;
        }

        fprintf(stderr, "[FAIL] OPM handshake failed for all %zu combinations (last hr=0x%08lx)\n",
                std::size(candidates), static_cast<unsigned long>(lastHr));
        exit(1);
    }

    void SendCommand(REFGUID guidSetting, const BYTE* param, ULONG paramLen) {
        HRESULT hr = TrySendCommand(guidSetting, param, paramLen);
        if (FAILED(hr)) Fail("Configure", hr);
    }

    // Same as SendCommand, but returns the HRESULT instead of exiting the
    // process on failure. Needed inside the watchdog loop: a transient
    // failure there (e.g. because a display mode change during real DRM
    // playback invalidated this video output object) should be handled, not
    // crash the whole tool.
    HRESULT TrySendCommand(REFGUID guidSetting, const BYTE* param, ULONG paramLen) {
        OPM_CONFIGURE_PARAMETERS cp{};
        cp.guidSetting = guidSetting;
        cp.ulSequenceNumber = commandSeq_++;
        if (paramLen > sizeof(cp.abParameters)) return E_INVALIDARG;
        memcpy(cp.abParameters, param, paramLen);
        cp.cbParametersSize = paramLen;  // verified against opmapi.h: OPM_CONFIGURE_PARAMETERS
                                           // uses cbParametersSize, not cbSettingDataSize

        cmac_->Compute(reinterpret_cast<BYTE*>(&cp) + sizeof(cp.omac),
                        sizeof(cp) - sizeof(cp.omac),
                        cp.omac.abOMAC);

        // Configure() takes 3 arguments; OPM_SET_PROTECTION_LEVEL needs no
        // additional out-of-band data, so the last two are 0/nullptr.
        return vo_->Configure(&cp, 0, nullptr);
    }

    // param/paramLen is optional input data some status requests need. E.g.
    // OPM_GET_VIRTUAL_PROTECTION_LEVEL and OPM_GET_ACTUAL_PROTECTION_LEVEL
    // require the first 4 bytes of abParameters to contain the protection type
    // (e.g. OPM_PROTECTION_TYPE_HDCP) being queried -- without it the driver
    // correctly rejects the request with E_INVALIDARG. Other requests (like
    // OPM_GET_CONNECTOR_TYPE) take no input data; pass nullptr/0 for those.
    OPM_STANDARD_INFORMATION SendStatusRequest(REFGUID guidInformation,
                                                const BYTE* param = nullptr, ULONG paramLen = 0) {
        OPM_STANDARD_INFORMATION info{};
        HRESULT hr = TrySendStatusRequest(guidInformation, info, param, paramLen);
        if (FAILED(hr)) Fail("GetInformation", hr);
        return info;
    }

    // Same as SendStatusRequest, but returns the HRESULT instead of exiting
    // the process on failure, and writes the result through outInfo only on
    // success.
    HRESULT TrySendStatusRequest(REFGUID guidInformation, OPM_STANDARD_INFORMATION& outInfo,
                                  const BYTE* param = nullptr, ULONG paramLen = 0) {
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

        OPM_REQUESTED_INFORMATION out{};
        HRESULT hr = vo_->GetInformation(&gp, &out);
        if (FAILED(hr)) return hr;

        BYTE checkTag[16];
        cmac_->Compute(reinterpret_cast<BYTE*>(&out) + sizeof(out.omac),
                        sizeof(out) - sizeof(out.omac), checkTag);
        if (memcmp(checkTag, out.omac.abOMAC, 16) != 0) {
            fprintf(stderr, "  [WARN] OMAC mismatch on response -- treat this result with caution\n");
        }

        memcpy(&outInfo, out.abRequestedInformation, sizeof(outInfo));
        return S_OK;
    }

private:
    HMONITOR mon_;
    ULONG outputIndex_;
    IOPMVideoOutput* vo_ = nullptr;
    ULONG statusSeq_ = 0;
    ULONG commandSeq_ = 0;
    BYTE sessionKey_[16] = {0};
    std::unique_ptr<AesCmac> cmac_;
};

// ---------------------------------------------------------------------------
// enumerate + main
// ---------------------------------------------------------------------------

// Continuously polls OPM_GET_ACTUAL_PROTECTION_LEVEL -- the real, enforced
// state of the physical connector, not just what our own session happens to
// be requesting (OPM_GET_VIRTUAL_PROTECTION_LEVEL) -- and re-enables it the
// moment it drops. Also prints the virtual level alongside it every poll, so
// it's visible whether our own session's request ever changed at all versus
// only the physical link being affected by someone else.
//
// On a detected drop, this deliberately sends OFF and then ON again, rather
// than just re-sending ON: if our session's own requested level never
// logically changed (it was ON before, it's still ON), re-sending the same
// value may be a no-op from the driver's point of view and might not trigger
// a fresh authentication attempt on the wire. Forcing an explicit transition
// is the only way to be sure a new attempt actually happens.
//
// If a call fails outright (as opposed to just reporting the level as off),
// that's treated as a sign this session's IOPMVideoOutput may have been
// invalidated (e.g. by a display mode change during real DRM playback), and
// the whole handshake is redone via Initialize() rather than giving up.
static void RunWatchdog(OpmSession& session, int intervalMs) {
    std::atomic<bool> stopRequested{false};
    std::thread waiter([&stopRequested]() {
        getchar();
        stopRequested = true;
    });

    using clock = std::chrono::steady_clock;
    bool wasOn = true;  // we just turned it ON right before entering this loop
    clock::time_point dropStart{};
    int dropCount = 0;
    double totalDowntimeMs = 0.0;

    printf("  watchdog: polling every %d ms (showing virtual/actual each time)\n", intervalMs);

    while (!stopRequested) {
        ULONG queryType = OPM_PROTECTION_TYPE_HDCP;
        OPM_STANDARD_INFORMATION actualInfo{}, virtualInfo{};

        HRESULT hrActual = session.TrySendStatusRequest(
            OPM_GET_ACTUAL_PROTECTION_LEVEL, actualInfo,
            reinterpret_cast<BYTE*>(&queryType), sizeof(queryType));
        HRESULT hrVirtual = session.TrySendStatusRequest(
            OPM_GET_VIRTUAL_PROTECTION_LEVEL, virtualInfo,
            reinterpret_cast<BYTE*>(&queryType), sizeof(queryType));

        if (FAILED(hrActual) || FAILED(hrVirtual)) {
            printf("  [warn] status request failed (actual=0x%08lx, virtual=0x%08lx) -- "
                   "re-running the full handshake\n",
                   static_cast<unsigned long>(hrActual), static_cast<unsigned long>(hrVirtual));
            if (wasOn) {
                dropStart = clock::now();
                ++dropCount;
                wasOn = false;
            }
            session.Initialize();  // exits the process if this also fails repeatedly
            std::this_thread::sleep_for(std::chrono::milliseconds(intervalMs));
            continue;
        }

        bool isOn = (actualInfo.ulInformation == static_cast<ULONG>(OPM_HDCP_ON));
        printf("  virtual=0x%lx actual=0x%lx\n",
               static_cast<unsigned long>(virtualInfo.ulInformation),
               static_cast<unsigned long>(actualInfo.ulInformation));

        if (wasOn && !isOn) {
            dropStart = clock::now();
            ++dropCount;
            printf("  [drop #%d] actual protection level is now 0x%lx -- forcing OFF then ON\n",
                   dropCount, static_cast<unsigned long>(actualInfo.ulInformation));

            OPM_SET_PROTECTION_LEVEL_PARAMETERS lvlOff{};
            lvlOff.ulProtectionType = OPM_PROTECTION_TYPE_HDCP;
            lvlOff.ulProtectionLevel = OPM_HDCP_OFF;
            session.TrySendCommand(OPM_SET_PROTECTION_LEVEL,
                                    reinterpret_cast<BYTE*>(&lvlOff), sizeof(lvlOff));

            OPM_SET_PROTECTION_LEVEL_PARAMETERS lvlOn{};
            lvlOn.ulProtectionType = OPM_PROTECTION_TYPE_HDCP;
            lvlOn.ulProtectionLevel = OPM_HDCP_ON;
            session.TrySendCommand(OPM_SET_PROTECTION_LEVEL,
                                    reinterpret_cast<BYTE*>(&lvlOn), sizeof(lvlOn));
        } else if (!wasOn && isOn) {
            double gapMs = std::chrono::duration<double, std::milli>(clock::now() - dropStart).count();
            totalDowntimeMs += gapMs;
            printf("  [recovered] actual protection level is back to ON after %.1f ms\n", gapMs);
        } else if (!wasOn && !isOn) {
            // Still down. Try the OFF-then-ON nudge again rather than assuming
            // the earlier attempt is still "in flight".
            OPM_SET_PROTECTION_LEVEL_PARAMETERS lvlOff{};
            lvlOff.ulProtectionType = OPM_PROTECTION_TYPE_HDCP;
            lvlOff.ulProtectionLevel = OPM_HDCP_OFF;
            session.TrySendCommand(OPM_SET_PROTECTION_LEVEL,
                                    reinterpret_cast<BYTE*>(&lvlOff), sizeof(lvlOff));

            OPM_SET_PROTECTION_LEVEL_PARAMETERS lvlOn{};
            lvlOn.ulProtectionType = OPM_PROTECTION_TYPE_HDCP;
            lvlOn.ulProtectionLevel = OPM_HDCP_ON;
            session.TrySendCommand(OPM_SET_PROTECTION_LEVEL,
                                    reinterpret_cast<BYTE*>(&lvlOn), sizeof(lvlOn));
        }
        wasOn = isOn;

        std::this_thread::sleep_for(std::chrono::milliseconds(intervalMs));
    }

    waiter.join();
    printf("  watchdog stopped. drops observed: %d, total downtime: %.1f ms\n",
           dropCount, totalDowntimeMs);
}

static ULONG CountVideoOutputs(HMONITOR mon) {
    IOPMVideoOutput** outputs = nullptr;
    ULONG numOutputs = 0;
    HRESULT hr = OPMGetVideoOutputsFromHMONITOR(mon, OPM_VOS_OPM_SEMANTICS, &numOutputs, &outputs);
    if (FAILED(hr)) Fail("OPMGetVideoOutputsFromHMONITOR", hr);
    for (ULONG i = 0; i < numOutputs; ++i) outputs[i]->Release();
    CoTaskMemFree(outputs);
    return numOutputs;
}

int main(int argc, char** argv) {
    bool turnOff = false;
    bool watchMode = false;
    int watchIntervalMs = 100;
    for (int i = 1; i < argc; ++i) {
        if (_stricmp(argv[i], "/off") == 0) {
            turnOff = true;
        } else if (_stricmp(argv[i], "/watch") == 0) {
            watchMode = true;
        } else if (_strnicmp(argv[i], "/interval:", 10) == 0) {
            watchIntervalMs = atoi(argv[i] + 10);
        } else if (_strnicmp(argv[i], "/cert:", 6) == 0) {
            g_forceCertIndex = atoi(argv[i] + 6);
        }
    }

    HRESULT hrInit = CoInitializeEx(nullptr, COINIT_MULTITHREADED);
    if (FAILED(hrInit)) Fail("CoInitializeEx", hrInit);

    HMONITOR mon = MonitorFromWindow(GetDesktopWindow(), MONITOR_DEFAULTTOPRIMARY);
    ULONG numOutputs = CountVideoOutputs(mon);
    printf("Found %lu OPM video output(s).\n", numOutputs);

    for (ULONG idx = 0; idx < numOutputs; ++idx) {
        OpmSession session(mon, idx);
        printf("Initializing OPM session...\n");
        session.Initialize();

        OPM_SET_PROTECTION_LEVEL_PARAMETERS lvl{};
        lvl.ulProtectionType = OPM_PROTECTION_TYPE_HDCP;
        lvl.ulProtectionLevel = turnOff ? OPM_HDCP_OFF : OPM_HDCP_ON;

        printf("Requesting HDCP %s...\n", turnOff ? "OFF" : "ON");
        session.SendCommand(OPM_SET_PROTECTION_LEVEL,
                             reinterpret_cast<BYTE*>(&lvl), sizeof(lvl));

        for (int i = 0; i < 5 && !turnOff; ++i) {
            Sleep(300);
            ULONG queryType = OPM_PROTECTION_TYPE_HDCP;
            OPM_STANDARD_INFORMATION info = session.SendStatusRequest(
                OPM_GET_VIRTUAL_PROTECTION_LEVEL,
                reinterpret_cast<BYTE*>(&queryType), sizeof(queryType));
            printf("  virtual protection level = %lu (OPM_HDCP_ON == %d), statusFlags = 0x%lx\n",
                   info.ulInformation, static_cast<int>(OPM_HDCP_ON), info.ulStatusFlags);
            if (info.ulInformation == static_cast<ULONG>(OPM_HDCP_ON)) {
                printf("  -> HDCP is ON.\n");
                break;
            }
        }

        if (!turnOff) {
            printf("\nPress Enter to turn HDCP off and exit.\n");
            if (watchMode) {
                RunWatchdog(session, watchIntervalMs);
            } else {
                getchar();
            }
            lvl.ulProtectionLevel = OPM_HDCP_OFF;
            session.SendCommand(OPM_SET_PROTECTION_LEVEL,
                                 reinterpret_cast<BYTE*>(&lvl), sizeof(lvl));
        }
    }

    CoUninitialize();
    return 0;
}
