import React, {
  useState, useEffect, useCallback, useRef,
} from 'react';
import {
  importRSAPublicKey,
  generateSigningKeyPair,
  hybridEncryptFile,
  hybridDecryptEnvelope,
  downloadDecryptedFile,
} from './crypto';
import './App.css';

const API = '/api/crypto';

// ─── Utility components ──────────────────────────────────────────────────────

const Badge = ({ label, value, color = 'cyan' }) => (
  <span className={`badge badge-${color}`}>
    <span className="badge-label">{label}</span>
    <span className="badge-value">{value}</span>
  </span>
);

const StatusDot = ({ ok }) => (
  <span className={`status-dot ${ok ? 'ok' : 'err'}`} />
);

// ─── Main App ────────────────────────────────────────────────────────────────

export default function App() {
  // ── Server / session state ────────────────────────────────────────────────
  const [serverKeyInfo,    setServerKeyInfo]    = useState(null);
  const [rsaPublicKey,     setRsaPublicKey]     = useState(null);   // CryptoKey
  const [signingKeyPair,   setSigningKeyPair]   = useState(null);   // {privateKey, publicKey}
  const [serverReady,      setServerReady]      = useState(false);

  // ── UI state ──────────────────────────────────────────────────────────────
  const [activeTab,        setActiveTab]        = useState('encrypt');  // encrypt | files | audit
  const [dragOver,         setDragOver]         = useState(false);
  const [selectedFile,     setSelectedFile]     = useState(null);

  // ── Operation state ───────────────────────────────────────────────────────
  const [encrypting,       setEncrypting]       = useState(false);
  const [encryptProgress,  setEncryptProgress]  = useState(0);
  const [lastResult,       setLastResult]       = useState(null);   // success/error message
  const [tamperAlert,      setTamperAlert]      = useState(null);   // null | {id, fileName}
  const [decryptingId,     setDecryptingId]     = useState(null);
  const [verifyingId,      setVerifyingId]      = useState(null);
  const [verifyResult,     setVerifyResult]     = useState({});      // {[id]: bool}
  const [shreddingId,      setShreddingId]      = useState(null);
  const [tamperingId,      setTamperingId]      = useState(null);
  const [tamperLabStates,  setTamperLabStates]  = useState({});       // {[id]: {target, attempts, autoDecrypt, results}}
  const [tamperResults,    setTamperResults]    = useState({});       // {[id]: {steps, detected}}

  // ── Data ──────────────────────────────────────────────────────────────────
  const [envelopes,        setEnvelopes]        = useState([]);
  const [auditLogs,        setAuditLogs]        = useState([]);

  // ── Crypto variable log (real-time transparency) ──────────────────────────
  const [cryptoLog,        setCryptoLog]        = useState([]);

  const fileInputRef = useRef();

  // ── Initialise: fetch server public key & generate session signing keypair
  useEffect(() => {
    (async () => {
      try {
        const res  = await fetch(`${API}/public-key`);
        const info = await res.json();
        const key  = await importRSAPublicKey(info.publicKeyBase64);
        setServerKeyInfo(info);
        setRsaPublicKey(key);

        const kp = await generateSigningKeyPair();
        setSigningKeyPair(kp);
        setServerReady(true);

        appendCryptoLog({
          type:   'key-init',
          msg:    'Session initialised',
          detail: `Server: RSA-${info.keyBits}-OAEP-SHA256 | Fingerprint: ${info.fingerprint}`,
          params: { rsaKeyBits: info.keyBits, sigAlgorithm: 'ECDSA-P256', kdfReady: true },
        });
      } catch {
        setLastResult({ ok: false, msg: 'Cannot reach server. Is Spring Boot running on :8080?' });
      }
    })();
  }, []);

  // Fetch envelopes & audit log on tab change
  useEffect(() => {
    if (activeTab === 'files')  fetchEnvelopes();
    if (activeTab === 'audit')  fetchAuditLog();
  }, [activeTab]);

  const fetchEnvelopes = useCallback(async () => {
    const res  = await fetch(`${API}/envelopes`);
    const data = await res.json();
    setEnvelopes(data);
  }, []);

  const fetchAuditLog = useCallback(async () => {
    const res  = await fetch(`${API}/audit-log`);
    const data = await res.json();
    setAuditLogs(data);
  }, []);

  const appendCryptoLog = (entry) =>
    setCryptoLog(prev => [{ id: Date.now(), ts: new Date().toISOString(), ...entry }, ...prev].slice(0, 50));

  const getTamperTargetMeta = (target) => {
    if (target === 'iv') {
      return {
        label: 'Initialization Vector (IV)',
        expectedSignal: 'AES-GCM authentication failure',
      };
    }
    if (target === 'tag') {
      return {
        label: 'Signature Material',
        expectedSignal: 'Signature verification failure',
      };
    }
    return {
      label: 'Ciphertext Payload',
      expectedSignal: 'AES-GCM authentication failure',
    };
  };

  // ── File selection ────────────────────────────────────────────────────────
  const handleFileSelect = (file) => {
    if (!file) return;
    setSelectedFile(file);
    setLastResult(null);
    setTamperAlert(null);
    appendCryptoLog({
      type:   'file-select',
      msg:    `File selected: ${file.name}`,
      detail: `Size: ${(file.size / 1024).toFixed(1)} KB | Type: ${file.type || 'unknown'}`,
      params: {},
    });
  };

  // ── Encrypt & Upload ──────────────────────────────────────────────────────
  const handleEncryptAndUpload = async () => {
    if (!selectedFile || !serverReady) return;
    setEncrypting(true);
    setEncryptProgress(0);
    setLastResult(null);
    setTamperAlert(null);

    try {
      appendCryptoLog({ type: 'start', msg: 'Starting hybrid encryption...', detail: '', params: {} });

      const envelope = await hybridEncryptFile(
        selectedFile,
        rsaPublicKey,
        signingKeyPair.privateKey,
        signingKeyPair.publicKey,
        (step) => setEncryptProgress(step * 14)
      );

      // Log each crypto parameter for transparency
      const p = envelope.cryptoParams;
      appendCryptoLog({
        type:   'encrypt-done',
        msg:    'Encryption complete',
        detail: `AES-${p.aesKeyBits}-GCM | IV: ${p.ivHex} (${p.ivBits}-bit) | Tag: ${p.tagBits}-bit | RSA: ${p.rsaKeyBits}-OAEP`,
        params: p,
      });

      // Upload to server
      appendCryptoLog({ type: 'upload', msg: 'Uploading digital envelope...', detail: 'Plaintext never leaves browser', params: {} });
      const res  = await fetch(`${API}/upload`, {
        method:  'POST',
        headers: { 'Content-Type': 'application/json' },
        body:    JSON.stringify({
          fileName:              envelope.fileName,
          fileType:              envelope.fileType,
          fileSizeBytes:         envelope.fileSizeBytes,
          encryptedFileBase64:   envelope.encryptedFileBase64,
          ivBase64:              envelope.ivBase64,
          encryptedAesKeyBase64: envelope.encryptedAesKeyBase64,
          signatureBase64:       envelope.signatureBase64,
          signingPublicKeyBase64: envelope.signingPublicKeyBase64,
        }),
      });
      const result = await res.json();

      if (result.success) {
        setEncryptProgress(100);
        setLastResult({ ok: true, msg: `✅ Envelope #${result.envelopeId} stored. Plaintext was never transmitted.` });
        appendCryptoLog({
          type:   'upload-ok',
          msg:    `Envelope #${result.envelopeId} stored`,
          detail: `fileName: ${envelope.fileName}`,
          params: {},
        });
        setSelectedFile(null);
      } else {
        throw new Error(result.error || 'Upload failed');
      }
    } catch (err) {
      setLastResult({ ok: false, msg: `❌ ${err.message}` });
      appendCryptoLog({ type: 'error', msg: 'Encryption/upload failed', detail: err.message, params: {} });
    } finally {
      setEncrypting(false);
      setTimeout(() => setEncryptProgress(0), 2000);
    }
  };

  // ── Decrypt ───────────────────────────────────────────────────────────────
  const handleDecrypt = async (envelope) => {
  setDecryptingId(envelope.id);
  setTamperAlert(null);

  try {
    const res  = await fetch(`${API}/decrypt/${envelope.id}`, { method: 'POST' });
    const data = await res.json();
    if (!data.success) throw new Error(data.error);

      appendCryptoLog({
        type:   'decrypt',
        msg:    `AES session key unwrapped by server`,
        detail: `Envelope #${envelope.id} | ${envelope.fileName} | Local AES-GCM decrypt starting...`,
        params: { aesKeyBits: data.aesKeyBits, tagBits: data.tagBits },
      });

      const { plaintext, fileName } = await hybridDecryptEnvelope(data);
      downloadDecryptedFile(plaintext, fileName);

      appendCryptoLog({
        type:   'decrypt-ok',
        msg:    `Decryption successful — file downloaded`,
        detail: `AES-256-GCM auth-tag verified. File: ${fileName}`,
        params: {},
      });
    } catch (err) {
      if (err.tampered) {
        setTamperAlert({ id: envelope.id, fileName: envelope.fileName });
        appendCryptoLog({
          type:   'tamper',
          msg:    '🚨 TAMPER DETECTED',
          detail: 'AES-GCM 128-bit authentication tag mismatch. Ciphertext was modified after encryption.',
          params: {},
        });
      } else {
        setLastResult({ ok: false, msg: `Decryption failed: ${err.message || err}` });
      }
    } finally {
      setDecryptingId(null);
    }
  };

  // ── Verify Integrity ──────────────────────────────────────────────────────
  const handleVerify = async (envelope) => {
    setVerifyingId(envelope.id);
    try {
      const res  = await fetch(`${API}/verify/${envelope.id}`, { method: 'POST' });
      const data = await res.json();
      setVerifyResult(prev => ({ ...prev, [envelope.id]: data.verified }));
      appendCryptoLog({
        type:   data.verified ? 'verify-ok' : 'verify-fail',
        msg:    data.verified ? '✅ Signature VALID' : '❌ Signature INVALID',
        detail: `${envelope.fileName} | ECDSA-P256-SHA256 | ${data.detail}`,
        params: {},
      });
    } finally {
      setVerifyingId(null);
    }
  };

  // ── Tamper Lab State Management ───────────────────────────────────────────
  const toggleTamperLab = (envelopeId) => {
    setTamperLabStates(prev => ({
      ...prev,
      [envelopeId]: prev[envelopeId] ? null : {
        target: 'ciphertext',
        attempts: 1,
        autoDecrypt: false,
        expanded: true,
      }
    }));
  };

  const updateTamperLabState = (envelopeId, updates) => {
    setTamperLabStates(prev => ({
      ...prev,
      [envelopeId]: { ...prev[envelopeId], ...updates }
    }));
  };

  // ── Execute Tamper Lab Attack ─────────────────────────────────────────────
  const handleExecuteTamperLab = async (envelope) => {
    const labState = tamperLabStates[envelope.id];
    if (!labState) return;

    const target = labState.target || 'ciphertext';
    const attempts = Math.min(5, Math.max(1, Number(labState.attempts) || 1));
    const { label: targetLabel, expectedSignal } = getTamperTargetMeta(target);

    setTamperingId(envelope.id);
    const steps = [];
    let verificationRuns = 0;
    let detectedCount = 0;

    try {
      for (let attempt = 1; attempt <= attempts; attempt++) {
        const stepResult = {
          attempt,
          stage: 'tamper',
          status: null,
          message: '',
          detail: '',
          timestamp: new Date().toLocaleTimeString(),
        };

        try {
          const res = await fetch(
            `${API}/tamper/${envelope.id}?target=${target}&attempt=${attempt}`,
            { method: 'POST' }
          );
          const data = await res.json();

          if (res.ok && data.success) {
            stepResult.status = 'success';
            const tamperedField = data.corruptedField || `${target} field`;
            stepResult.message = `Tampered ${targetLabel}`;
            const charMutation = data.mutatedBase64CharIndex >= 0
              ? `Base64 char[${data.mutatedBase64CharIndex}] '${data.beforeBase64Char}' -> '${data.afterBase64Char}'`
              : 'Base64 character delta not available';
            stepResult.detail = `${tamperedField} byte[${data.mutatedByteIndex}] ${data.beforeByteHex} -> ${data.afterByteHex} | ${charMutation}.`;
            appendCryptoLog({
              type:   'tamper-lab',
              msg:    `Tamper Lab attempt ${attempt}/${attempts}`,
              detail: `Target: ${targetLabel} | ${tamperedField} byte[${data.mutatedByteIndex}] ${data.beforeByteHex} -> ${data.afterByteHex}`,
              params: {
                target,
                corruptedField: tamperedField,
                expectedSignal,
                mutatedByteIndex: data.mutatedByteIndex,
                beforeByteHex: data.beforeByteHex,
                afterByteHex: data.afterByteHex,
                mutatedBase64CharIndex: data.mutatedBase64CharIndex,
                beforeBase64Char: data.beforeBase64Char,
                afterBase64Char: data.afterBase64Char,
              },
            });
          } else {
            stepResult.status = 'error';
            stepResult.message = data.error || 'Tamper failed';
          }
        } catch (err) {
          stepResult.status = 'error';
          stepResult.message = err.message;
        }

        steps.push(stepResult);

        if (labState.autoDecrypt) {
          verificationRuns += 1;
          const decryptStep = {
            attempt,
            stage: 'decrypt',
            status: null,
            message: '',
            detail: '',
            timestamp: new Date().toLocaleTimeString(),
          };

          try {
            const decRes = await fetch(`${API}/decrypt/${envelope.id}`, { method: 'POST' });
            const decData = await decRes.json();

            if (!decRes.ok || !decData.success) {
              throw new Error(decData.error || 'Server could not prepare decrypt response');
            }

            try {
              await hybridDecryptEnvelope(decData);
              decryptStep.status = 'undetected';
              decryptStep.message = 'Decrypt succeeded after tamper';
              decryptStep.detail = `No client-side tamper error was raised. Expected signal: ${expectedSignal}.`;
            } catch (decryptErr) {
              if (decryptErr?.tampered) {
                detectedCount += 1;
                decryptStep.status = 'detected';
                decryptStep.message = 'Tamper detected during decrypt';
                decryptStep.detail = `${expectedSignal} confirmed on attempt ${attempt}.`;
                appendCryptoLog({
                  type:   'tamper-detection',
                  msg:    `Detection confirmed on attempt ${attempt}`,
                  detail: `${targetLabel} tamper triggered ${expectedSignal}.`,
                  params: {},
                });
              } else {
                decryptStep.status = 'error';
                decryptStep.message = 'Decrypt failed for non-tamper reason';
                decryptStep.detail = decryptErr?.message || 'Unknown decrypt failure';
              }
            }
          } catch (err) {
            decryptStep.status = 'error';
            decryptStep.message = 'Decrypt check could not run';
            decryptStep.detail = err.message;
          }

          steps.push(decryptStep);
        }

        if (attempt < attempts) {
          await new Promise(resolve => setTimeout(resolve, 500));
        }
      }

      const summary = verificationRuns > 0
        ? `${detectedCount}/${verificationRuns} auto-decrypt checks raised tamper detection.`
        : 'Tamper injected. Run manual decrypt to verify client-side detection.';

      setTamperResults(prev => ({
        ...prev,
        [envelope.id]: {
          steps,
          target,
          targetLabel,
          detected: detectedCount > 0,
          summary,
        }
      }));

      setLastResult({
        ok: verificationRuns === 0 || detectedCount > 0,
        msg: `Tamper Lab complete on ${targetLabel}. ${summary}`,
      });
    } finally {
      setTamperingId(null);
    }
  };

  // ── Shred ─────────────────────────────────────────────────────────────────
  const handleShred = async (envelope) => {
    if (!window.confirm(`Securely shred "${envelope.fileName}"? This cannot be undone.`)) return;
    setShreddingId(envelope.id);
    try {
      const res  = await fetch(`${API}/shred/${envelope.id}`, { method: 'DELETE' });
      const data = await res.json();
      if (data.success) {
        appendCryptoLog({
          type:   'shred',
          msg:    `🗑️ Envelope #${envelope.id} shredded`,
          detail: `All ciphertext, wrapped key, and signature fields overwritten with random bytes.`,
          params: {},
        });
        await fetchEnvelopes();
      }
    } finally {
      setShreddingId(null);
    }
  };

  // ─────────────────────────────────────────────────────────────────────────
  // RENDER
  // ─────────────────────────────────────────────────────────────────────────

  return (
    <div className="app">
      {/* ── Header ─────────────────────────────────────────────────────── */}
      <header className="app-header">
        <div className="header-left">
          <div className="logo">🔐</div>
          <div>
            <h1 className="header-title">Hybrid Cryptosystem</h1>
            <p className="header-sub">RSA-4096-OAEP + AES-256-GCM · Zero-Knowledge Architecture</p>
          </div>
        </div>
        <div className="header-right">
          <StatusDot ok={serverReady} />
          <span className="server-status">{serverReady ? 'Server Ready' : 'Connecting...'}</span>
          {serverKeyInfo && (
            <span className="fingerprint" title={serverKeyInfo.publicKeyBase64?.slice(0, 40) + '...'}>
              🔑 {serverKeyInfo.fingerprint}
            </span>
          )}
        </div>
      </header>

      {/* ── Tamper Alert Banner ─────────────────────────────────────────── */}
      {tamperAlert && (
        <div className="tamper-banner">
          <span className="tamper-icon">🚨</span>
          <div>
            <strong>TAMPER DETECTED</strong>
            <p>AES-GCM 128-bit authentication tag mismatch on <em>{tamperAlert.fileName}</em>.<br />
            The ciphertext was modified after encryption. Decryption aborted.</p>
          </div>
          <button className="tamper-close" onClick={() => setTamperAlert(null)}>✕</button>
        </div>
      )}

      {/* ── Info Bar ───────────────────────────────────────────────────── */}
      {serverKeyInfo && (
        <div className="info-bar">
          <Badge label="Asymmetric"  value={`RSA-${serverKeyInfo.keyBits}-OAEP`} color="blue" />
          <Badge label="Symmetric"   value="AES-256-GCM"         color="green" />
          <Badge label="Signature"   value="ECDSA-P256"          color="purple" />
          <Badge label="IV"          value="96-bit"              color="cyan" />
          <Badge label="Auth Tag"    value="128-bit"             color="cyan" />
        </div>
      )}

      {/* ── Tabs ───────────────────────────────────────────────────────── */}
      <nav className="tabs">
        {[
          { id: 'encrypt', label: '🔒 Encrypt & Upload' },
          { id: 'files',   label: '📁 Stored Envelopes' },
          { id: 'audit',   label: '📋 Audit Log' },
        ].map(t => (
          <button
            key={t.id}
            className={`tab-btn ${activeTab === t.id ? 'active' : ''}`}
            onClick={() => setActiveTab(t.id)}
          >
            {t.label}
          </button>
        ))}
      </nav>

      <main className="main">
        {/* ── Left Panel ─────────────────────────────────────────────── */}
        <section className="panel panel-main">

          {/* ═══ ENCRYPT TAB ═════════════════════════════════════════ */}
          {activeTab === 'encrypt' && (
            <div className="tab-content">
              <h2 className="section-title">Encrypt & Upload File</h2>
              <p className="section-desc">
                Files are encrypted <strong>locally in your browser</strong> before upload.
                The server never sees the plaintext.
              </p>

              {/* Drop Zone */}
              <div
                className={`drop-zone ${dragOver ? 'drag-over' : ''} ${selectedFile ? 'has-file' : ''}`}
                onDragOver={(e) => { e.preventDefault(); setDragOver(true); }}
                onDragLeave={() => setDragOver(false)}
                onDrop={(e) => { e.preventDefault(); setDragOver(false); handleFileSelect(e.dataTransfer.files[0]); }}
                onClick={() => fileInputRef.current.click()}
              >
                <input
                  ref={fileInputRef}
                  type="file"
                  style={{ display: 'none' }}
                  onChange={(e) => handleFileSelect(e.target.files[0])}
                />
                {selectedFile ? (
                  <div className="file-info">
                    <div className="file-icon">📄</div>
                    <div>
                      <div className="file-name">{selectedFile.name}</div>
                      <div className="file-meta">
                        {(selectedFile.size / 1024).toFixed(1)} KB · {selectedFile.type || 'unknown type'}
                      </div>
                    </div>
                    <button className="clear-file" onClick={(e) => { e.stopPropagation(); setSelectedFile(null); }}>✕</button>
                  </div>
                ) : (
                  <div className="drop-hint">
                    <div className="drop-icon">⬆</div>
                    <div>Drop a file here or click to select</div>
                    <div className="drop-sub">Any file type · Max 50 MB</div>
                  </div>
                )}
              </div>

              {/* Encrypt Button */}
              <button
                className="btn-primary"
                disabled={!selectedFile || !serverReady || encrypting}
                onClick={handleEncryptAndUpload}
              >
                {encrypting ? (
                  <><span className="spinner" /> Encrypting...</>
                ) : (
                  '🔒 Encrypt & Upload'
                )}
              </button>

              {/* Progress */}
              {encryptProgress > 0 && (
                <div className="progress-bar">
                  <div className="progress-fill" style={{ width: `${Math.min(encryptProgress, 100)}%` }} />
                </div>
              )}

              {/* Result message */}
              {lastResult && (
                <div className={`result-msg ${lastResult.ok ? 'ok' : 'err'}`}>
                  {lastResult.msg}
                </div>
              )}

              {/* Algorithm info cards */}
              <div className="algo-cards">
                <AlgoCard
                  icon="🔑"
                  title="Key Encapsulation"
                  alg="RSA-4096-OAEP"
                  detail="SHA-256 · MGF1-SHA256 · 512-byte ciphertext"
                />
                <AlgoCard
                  icon="🔒"
                  title="File Encryption"
                  alg="AES-256-GCM"
                  detail="96-bit IV · 128-bit auth tag · AEAD"
                />
                <AlgoCard
                  icon="✍️"
                  title="Digital Signature"
                  alg="ECDSA P-256"
                  detail="SHA-256 · Non-repudiation · FIPS 186-4"
                />
              </div>
            </div>
          )}

          {/* ═══ FILES TAB ══════════════════════════════════════════ */}
          {activeTab === 'files' && (
            <div className="tab-content">
              <div className="section-header">
                <h2 className="section-title">Stored Digital Envelopes</h2>
                <button className="btn-sm" onClick={fetchEnvelopes}>↻ Refresh</button>
              </div>

              {envelopes.length === 0 ? (
                <div className="empty-state">No envelopes yet. Encrypt a file first.</div>
              ) : (
                <div className="envelope-list">
                  {envelopes.map(env => (
                    <div key={env.id} className={`envelope-card ${env.shredded ? 'shredded' : ''}`}>
                      <div className="env-header">
                        <div className="env-title">
                          <span className="env-icon">{env.shredded ? '🗑️' : '📦'}</span>
                          <div>
                            <div className="env-name">{env.fileName}</div>
                            <div className="env-meta">
                              #{env.id} · {(env.fileSizeBytes / 1024).toFixed(1)} KB ·{' '}
                              {new Date(env.uploadedAt).toLocaleString()}
                            </div>
                          </div>
                        </div>
                        <div className="env-badges">
                          {env.signed              && <span className="tag tag-purple">✍️ Signed</span>}
                          {env.shredded            && <span className="tag tag-red">🗑️ Shredded</span>}
                        </div>
                      </div>

                      <div className="env-params">
                        <span className="param">{env.symAlgorithm}</span>
                        <span className="param">{env.asymAlgorithm}</span>
                        <span className="param">IV: {env.ivBits}-bit</span>
                        <span className="param">Tag: {env.tagBits}-bit</span>
                        <span className="param">IV: <code>{env.ivBase64?.slice(0, 8)}…</code></span>
                      </div>

                      {/* Verify result */}
                      {verifyResult[env.id] !== undefined && (
                        <div className={`verify-result ${verifyResult[env.id] ? 'ok' : 'fail'}`}>
                          {verifyResult[env.id]
                            ? '✅ ECDSA signature valid — non-repudiation confirmed'
                            : '❌ ECDSA signature INVALID — possible tampering'}
                        </div>
                      )}

                      {/* Actions */}
                      {!env.shredded && (
                        <div className="env-actions">
                          <button
                            className="btn-action btn-decrypt"
                            disabled={decryptingId === env.id}
                            onClick={() => handleDecrypt(env)}
                          >
                            {decryptingId === env.id ? <><span className="spinner" /> Decrypting…</> : '🔓 Decrypt'}
                          </button>
                          <button
                            className="btn-action btn-verify"
                            disabled={verifyingId === env.id || !env.signed}
                            onClick={() => handleVerify(env)}
                            title={!env.signed ? 'No signature on this envelope' : 'Verify ECDSA signature'}
                          >
                            {verifyingId === env.id ? <><span className="spinner" /> Verifying…</> : '🔍 Verify Integrity'}
                          </button>
                          <button
                            className="btn-action btn-tamper"
                            disabled={tamperingId === env.id}
                            onClick={() => toggleTamperLab(env.id)}
                            title="Open Tamper Lab for configurable attacks"
                          >
                            🧪 Tamper Lab
                          </button>
                          <button
                            className="btn-action btn-shred"
                            disabled={shreddingId === env.id}
                            onClick={() => handleShred(env)}
                          >
                            {shreddingId === env.id ? <><span className="spinner" /> Shredding…</> : '🗑️ Shred'}
                          </button>
                        </div>
                      )}

                      {/* Tamper Lab Panel */}
                      {tamperLabStates[env.id] && (
                        <div className="tamper-lab-panel">
                          <div className="tamper-header">
                            <h4>🧪 Tamper Lab — Attack Simulator</h4>
                            <button
                              className="btn-close"
                              onClick={() => toggleTamperLab(env.id)}
                              title="Close Tamper Lab"
                            >
                              ✕
                            </button>
                          </div>

                          <div className="tamper-config">
                            <div className="config-row">
                              <div className="config-item">
                                <label>Attack Target:</label>
                                <select
                                  className="config-select"
                                  value={tamperLabStates[env.id]?.target || 'ciphertext'}
                                  onChange={(e) => updateTamperLabState(env.id, { target: e.target.value })}
                                  disabled={tamperingId === env.id}
                                >
                                  <option value="ciphertext">Ciphertext (AES-GCM)</option>
                                  <option value="iv">IV (Initialization Vector)</option>
                                  <option value="tag">Signature Tag (ECDSA)</option>
                                </select>
                              </div>

                              <div className="config-item">
                                <label>Attempts:</label>
                                <input
                                  type="number"
                                  className="config-input"
                                  min="1"
                                  max="5"
                                  value={tamperLabStates[env.id]?.attempts || 1}
                                  onChange={(e) => {
                                    const value = Math.min(5, Math.max(1, Number(e.target.value) || 1));
                                    updateTamperLabState(env.id, { attempts: value });
                                  }}
                                  disabled={tamperingId === env.id}
                                />
                              </div>

                              <div className="config-item checkbox">
                                <label>
                                  <input
                                    type="checkbox"
                                    checked={tamperLabStates[env.id]?.autoDecrypt || false}
                                    onChange={(e) => updateTamperLabState(env.id, { autoDecrypt: e.target.checked })}
                                    disabled={tamperingId === env.id}
                                  />
                                  Auto-Decrypt Check
                                </label>
                              </div>

                              <button
                                className="btn-tamper-execute"
                                disabled={tamperingId === env.id}
                                onClick={() => handleExecuteTamperLab(env)}
                              >
                                {tamperingId === env.id ? (
                                  <><span className="spinner" /> Executing…</>
                                ) : (
                                  '▶ Execute Attack'
                                )}
                              </button>
                            </div>
                            <div className="tamper-hint">
                              Selected target: <strong>{getTamperTargetMeta(tamperLabStates[env.id]?.target).label}</strong>
                              {' '}· Expected signal: {getTamperTargetMeta(tamperLabStates[env.id]?.target).expectedSignal}
                            </div>
                          </div>

                          {/* Tamper Results Timeline */}
                          {tamperResults[env.id] && (
                            <div className="tamper-results">
                              <div className="results-header">
                                <h5>📊 Attack Results</h5>
                                <span className={`detection-badge ${tamperResults[env.id].detected ? 'detected' : 'not-detected'}`}>
                                  {tamperResults[env.id].detected ? '🚨 Detected' : '⚠️ Simulated'}
                                </span>
                              </div>
                              <div className="timeline">
                                {tamperResults[env.id].steps.map((step, idx) => (
                                  <div key={idx} className={`timeline-item stage-${step.stage} status-${step.status}`}>
                                    <div className="timeline-marker">
                                      {step.stage === 'tamper' && '💉'}
                                      {step.stage === 'decrypt' && '🔓'}
                                    </div>
                                    <div className="timeline-content">
                                      <div className="timeline-title">
                                        Attempt {step.attempt} · {step.stage === 'tamper' ? 'Inject Attack' : 'Verify Detection'}
                                      </div>
                                      <div className="timeline-status">
                                        {step.status === 'success' && '✓ '}
                                        {step.status === 'detected' && '🚨 '}
                                        {step.status === 'undetected' && '⚠️ '}
                                        {step.status === 'error' && '✗ '}
                                        {step.message}
                                      </div>
                                      {step.detail && <div className="timeline-detail">{step.detail}</div>}
                                      <div className="timeline-time">{step.timestamp}</div>
                                    </div>
                                  </div>
                                ))}
                              </div>
                              <div className="results-summary">
                                <strong>Summary:</strong> {tamperResults[env.id].summary}
                                <span className="results-target">Target: {tamperResults[env.id].targetLabel || tamperResults[env.id].target}</span>
                              </div>
                            </div>
                          )}
                        </div>
                      )}
                    </div>
                  ))}
                </div>
              )}
            </div>
          )}

          {/* ═══ AUDIT TAB ══════════════════════════════════════════ */}
          {activeTab === 'audit' && (
            <div className="tab-content">
              <div className="section-header">
                <h2 className="section-title">Cryptographic Audit Log</h2>
                <button className="btn-sm" onClick={fetchAuditLog}>↻ Refresh</button>
              </div>
              <div className="audit-table-wrap">
                <table className="audit-table">
                  <thead>
                    <tr>
                      <th>#</th>
                      <th>Time</th>
                      <th>Event</th>
                      <th>File</th>
                      <th>Status</th>
                      <th>Details</th>
                    </tr>
                  </thead>
                  <tbody>
                    {auditLogs.map(log => (
                      <tr key={log.id} className={`audit-row ${log.status === 'FAILURE' ? 'row-fail' : ''}`}>
                        <td>{log.id}</td>
                        <td className="col-time">{new Date(log.timestamp).toLocaleTimeString()}</td>
                        <td><span className="event-badge">{log.eventType}</span></td>
                        <td className="col-file">{log.fileName}</td>
                        <td>
                          <span className={`status-badge ${log.status === 'SUCCESS' ? 'ok' : 'fail'}`}>
                            {log.status}
                          </span>
                        </td>
                        <td className="col-detail">{log.details}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </div>
          )}
        </section>

        {/* ── Right Panel: Crypto Variable Log ─────────────────────────── */}
        <aside className="panel panel-log">
          <div className="log-header">
            <h3>⚡ Crypto Variables Log</h3>
            <button className="btn-sm" onClick={() => setCryptoLog([])}>Clear</button>
          </div>
          <div className="log-list">
            {cryptoLog.length === 0
              ? <div className="log-empty">Crypto events will appear here in real-time.</div>
              : cryptoLog.map(entry => (
                <div key={entry.id} className={`log-entry log-${entry.type}`}>
                  <div className="log-time">{new Date(entry.ts).toLocaleTimeString()}</div>
                  <div className="log-msg">{entry.msg}</div>
                  {entry.detail && <div className="log-detail">{entry.detail}</div>}
                  {entry.params && Object.keys(entry.params).length > 0 && (
                    <div className="log-params">
                      {Object.entries(entry.params).map(([k, v]) => (
                        <span key={k} className="log-param">
                          <span className="lp-key">{k}</span>
                          <span className="lp-val">{String(v)}</span>
                        </span>
                      ))}
                    </div>
                  )}
                </div>
              ))
            }
          </div>

          {/* Architecture diagram */}
          <div className="arch-diagram">
            <div className="arch-title">Hybrid Architecture</div>
            <div className="arch-flow">
              <div className="arch-box browser">
                <strong>Browser (Zero-Knowledge)</strong>
                <div className="arch-items">
                  <div>📄 Plaintext File</div>
                  <div>↓ AES-256-GCM</div>
                  <div>🔒 Ciphertext</div>
                  <div>↓ RSA-4096-OAEP</div>
                  <div>🔑 Wrapped Key</div>
                  <div>↓ ECDSA-P256</div>
                  <div>✍️ Signature</div>
                </div>
              </div>
              <div className="arch-arrow">→ POST /upload</div>
              <div className="arch-box server">
                <strong>Server (Blind Storage)</strong>
                <div className="arch-items">
                  <div>🗄️ H2 Database</div>
                  <div>📦 Digital Envelope</div>
                  <div>🔑 RSA Private Key</div>
                  <div>📋 Audit Log</div>
                </div>
              </div>
            </div>
          </div>
        </aside>
      </main>
    </div>
  );
}

// ─── AlgoCard helper ─────────────────────────────────────────────────────────

function AlgoCard({ icon, title, alg, detail }) {
  return (
    <div className="algo-card">
      <div className="algo-icon">{icon}</div>
      <div>
        <div className="algo-title">{title}</div>
        <div className="algo-alg">{alg}</div>
        <div className="algo-detail">{detail}</div>
      </div>
    </div>
  );
}
