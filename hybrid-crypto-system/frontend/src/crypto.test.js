describe('crypto.js utilities and decrypt flow', () => {
  beforeEach(() => {
    jest.resetModules();

    Object.defineProperty(window, 'crypto', {
      configurable: true,
      value: {
        getRandomValues: (arr) => arr,
        subtle: {
          importKey: jest.fn(),
          decrypt: jest.fn(),
          unwrapKey: jest.fn(),
          deriveKey: jest.fn(),
        },
      },
    });
  });

  test('toBase64 and fromBase64 should round-trip bytes', async () => {
    const { toBase64, fromBase64 } = await import('./crypto');

    const input = new Uint8Array([1, 2, 3, 250, 255]).buffer;
    const encoded = toBase64(input);
    const decoded = new Uint8Array(fromBase64(encoded));

    expect(Array.from(decoded)).toEqual([1, 2, 3, 250, 255]);
  });

  test('hybridDecryptEnvelope should decrypt non-password envelope', async () => {
    const plaintext = new Uint8Array([10, 20, 30]).buffer;
    window.crypto.subtle.importKey.mockResolvedValue('aes-key');
    window.crypto.subtle.decrypt.mockResolvedValue(plaintext);

    const { hybridDecryptEnvelope } = await import('./crypto');

    const result = await hybridDecryptEnvelope({
      encryptedFileBase64: btoa('ciphertext'),
      ivBase64: btoa('iv-1234567890'),
      fileName: 'demo.txt',
      rawAesKeyBase64: btoa('raw-aes-key-32-bytes'),
      passwordProtected: false,
    });

    expect(result.fileName).toBe('demo.txt');
    expect(result.tampered).toBe(false);
    expect(result.plaintext).toBe(plaintext);
    expect(window.crypto.subtle.importKey).toHaveBeenCalledTimes(1);
    expect(window.crypto.subtle.decrypt).toHaveBeenCalledTimes(1);
  });

  test('hybridDecryptEnvelope should fail when password is missing', async () => {
    const { hybridDecryptEnvelope } = await import('./crypto');

    await expect(
      hybridDecryptEnvelope(
        {
          encryptedFileBase64: btoa('ciphertext'),
          ivBase64: btoa('iv-1234567890'),
          fileName: 'secure.txt',
          passwordProtected: true,
          pwWrappedAesKeyBase64: btoa('wrapped'),
          pwWrapIvBase64: btoa('pw-iv'),
          pbkdf2SaltBase64: btoa('salt'),
        },
        null
      )
    ).rejects.toThrow('Password required to decrypt this envelope.');
  });

  test('hybridDecryptEnvelope should raise tampered object when AES-GCM fails', async () => {
    window.crypto.subtle.importKey.mockResolvedValue('aes-key');
    window.crypto.subtle.decrypt.mockRejectedValue(new Error('auth tag mismatch'));

    const { hybridDecryptEnvelope } = await import('./crypto');

    await expect(
      hybridDecryptEnvelope({
        encryptedFileBase64: btoa('ciphertext'),
        ivBase64: btoa('iv-1234567890'),
        fileName: 'tampered.txt',
        rawAesKeyBase64: btoa('raw-aes-key-32-bytes'),
        passwordProtected: false,
      })
    ).rejects.toMatchObject({
      tampered: true,
      message: expect.stringContaining('authentication tag mismatch'),
    });
  });

  test('downloadDecryptedFile should create and revoke object URL', async () => {
    jest.useFakeTimers();

    const createObjectURL = jest.fn(() => 'blob:test-url');
    const revokeObjectURL = jest.fn();
    global.URL.createObjectURL = createObjectURL;
    global.URL.revokeObjectURL = revokeObjectURL;

    const click = jest.fn();
    const originalCreateElement = document.createElement.bind(document);
    jest.spyOn(document, 'createElement').mockImplementation((tagName) => {
      if (tagName === 'a') {
        return { href: '', download: '', click };
      }
      return originalCreateElement(tagName);
    });

    const { downloadDecryptedFile } = await import('./crypto');
    downloadDecryptedFile(new Uint8Array([1, 2, 3]).buffer, 'file.bin');

    expect(createObjectURL).toHaveBeenCalledTimes(1);
    expect(click).toHaveBeenCalledTimes(1);

    jest.advanceTimersByTime(10000);
    expect(revokeObjectURL).toHaveBeenCalledWith('blob:test-url');

    document.createElement.mockRestore();
    jest.useRealTimers();
  });
});
