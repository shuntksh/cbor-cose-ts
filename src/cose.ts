/**
 * RFC 8152: CBOR Object Signing and Encryption (COSE)
 *
 * This module provides functionality for encoding and decoding COSE structures:
 * - COSE_Sign1: Single signature with one signer (tag 18)
 * - COSE_Sign: Multiple signatures (tag 98)
 * - COSE_Mac0: Single MAC with one recipient (tag 17)
 * - COSE_Mac: Multiple MACs (tag 97)
 * - COSE_Encrypt0: Single recipient encrypted data (tag 16)
 * - COSE_Encrypt: Multiple recipient encrypted data (tag 96)
 *
 * Features:
 * - Full compliance with RFC 8152, including COSE tags and expanded header/algorithm support.
 * - Validation of mandatory header parameters (e.g., 'alg').
 * - No cryptographic operations implemented; this is a structural encoding/decoding library.
 */

import type { CBORValue } from "./cbor";
import { CBOR } from "./cbor";

// COSE Tags (RFC 8152 §2 - "Basic COSE Structure")
export enum COSETag {
	COSE_Encrypt = 96, // §2: Tag for multi-recipient encryption
	COSE_Encrypt0 = 16, // §2: Tag for single-recipient encryption
	COSE_Mac = 97, // §2: Tag for multi-recipient MAC
	COSE_Mac0 = 17, // §2: Tag for single-recipient MAC
	COSE_Sign = 98, // §2: Tag for multi-signature
	COSE_Sign1 = 18, // §2: Tag for single-signature
}

// COSE Header Parameters (RFC 8152 §3.1 - "Header Parameters")
export enum HeaderParameter {
	alg = 1, // §3.1: Algorithm identifier
	crit = 2, // §3.1: Critical headers to understand
	ctyp = 3, // §3.1: Content type
	kid = 4, // §3.1: Key identifier
	iv = 5, // §3.1: Initialization vector
	partial_iv = 6, // §3.1: Partial initialization vector
	counter_signature = 7, // §3.1: Counter signature
	salt = 8, // §3.1: Salt for key derivation
	counter_signature0 = 9, // §3.1: Counter signature (short form)
	x5chain = 33, // §3.1: Certificate chain
	x5t = 34, // §3.1: Certificate thumbprint
}

// COSE Algorithms (RFC 8152 §8.1 - "Algorithm Specification")
export enum Algorithm {
	// Signature Algorithms (§8.1)
	ES256 = -7, // §8.1: ECDSA w/ SHA-256
	ES384 = -35, // §8.1: ECDSA w/ SHA-384
	ES512 = -36, // §8.1: ECDSA w/ SHA-512
	EdDSA = -8, // §8.1: EdDSA
	RS256 = -257, // §8.1: RSA w/ SHA-256
	RS384 = -258, // §8.1: RSA w/ SHA-384
	RS512 = -259, // §8.1: RSA w/ SHA-512
	PS256 = -37, // §8.1: RSASSA-PSS w/ SHA-256
	PS384 = -38, // §8.1: RSASSA-PSS w/ SHA-384
	PS512 = -39, // §8.1: RSASSA-PSS w/ SHA-512

	// MAC Algorithms (§8.1)
	HMAC_256_64 = 4, // §8.1: HMAC w/ SHA-256 truncated to 64 bits
	HMAC_256_256 = 5, // §8.1: HMAC w/ SHA-256
	HMAC_384_384 = 6, // §8.1: HMAC w/ SHA-384
	HMAC_512_512 = 7, // §8.1: HMAC w/ SHA-512

	// AEAD Algorithms (§8.1)
	AES_CCM_16_64_128 = 10, // §8.1: AES-CCM mode 128-bit key
	AES_CCM_16_64_256 = 12, // §8.1: AES-CCM mode 256-bit key
	AES_CCM_64_64_128 = 13, // §8.1: AES-CCM mode 128-bit key
	AES_CCM_64_64_256 = 14, // §8.1: AES-CCM mode 256-bit key
	AES_CCM_16_128_128 = 30, // §8.1: AES-CCM mode 128-bit key
	AES_CCM_16_128_256 = 31, // §8.1: AES-CCM mode 256-bit key
	AES_CCM_64_128_128 = 32, // §8.1: AES-CCM mode 128-bit key
	AES_CCM_64_128_256 = 33, // §8.1: AES-CCM mode 256-bit key
	AES_GCM_128 = 1, // §8.1: AES-GCM mode 128-bit key
	AES_GCM_192 = 2, // §8.1: AES-GCM mode 192-bit key
	AES_GCM_256 = 3, // §8.1: AES-GCM mode 256-bit key
	ChaCha20_Poly1305 = 24, // §8.1: ChaCha20/Poly1305

	// Key Transport (§8.1)
	direct = -6, // §8.1: Direct key agreement
}

// COSE Header Map
export type HeaderMap = Record<number, CBORValue>;

// COSE_Sign1 Structure (RFC 8152 §4.2 - "Single Signer Data Object")
export interface COSESign1 {
	protected: HeaderMap; // §4.2: Protected header parameters
	unprotected: HeaderMap; // §4.2: Unprotected header parameters
	payload: ArrayBuffer | null; // §4.2: Payload (detached or included)
	signature: ArrayBuffer; // §4.2: Signature value
}

// COSE_Sign Structure (RFC 8152 §4.3 - "Signature with Multiple Signers")
export interface COSESign {
	protected: HeaderMap; // §4.3: Protected header parameters
	unprotected: HeaderMap; // §4.3: Unprotected header parameters
	payload: ArrayBuffer | null; // §4.3: Payload (detached or included)
	signatures: Array<{
		// §4.3: Array of signature objects
		protected: HeaderMap; // §4.3: Per-signer protected headers
		unprotected: HeaderMap; // §4.3: Per-signer unprotected headers
		signature: ArrayBuffer; // §4.3: Per-signer signature value
	}>;
}

// COSE_Mac0 Structure (RFC 8152 §4.4 - "MAC Objects with Single Recipient")
export interface COSEMac0 {
	protected: HeaderMap; // §4.4: Protected header parameters
	unprotected: HeaderMap; // §4.4: Unprotected header parameters
	payload: ArrayBuffer | null; // §4.4: Payload (detached or included)
	tag: ArrayBuffer; // §4.4: MAC tag value
}

// COSE_Mac Structure (RFC 8152 §4.5 - "MAC Objects with Multiple Recipients")
export interface COSEMac {
	protected: HeaderMap; // §4.5: Protected header parameters
	unprotected: HeaderMap; // §4.5: Unprotected header parameters
	payload: ArrayBuffer | null; // §4.5: Payload (detached or included)
	recipients: Array<{
		// §4.5: Array of recipient objects
		protected: HeaderMap; // §4.5: Per-recipient protected headers
		unprotected: HeaderMap; // §4.5: Per-recipient unprotected headers
		tag: ArrayBuffer; // §4.5: Per-recipient MAC tag
	}>;
}

// COSE_Encrypt0 Structure (RFC 8152 §4.6 - "Encryption with Single Recipient")
export interface COSEEncrypt0 {
	protected: HeaderMap; // §4.6: Protected header parameters
	unprotected: HeaderMap; // §4.6: Unprotected header parameters
	ciphertext: ArrayBuffer; // §4.6: Encrypted content
}

// COSE_Encrypt Structure (RFC 8152 §4.7 - "Encryption with Multiple Recipients")
export interface COSEEncrypt {
	protected: HeaderMap; // §4.7: Protected header parameters
	unprotected: HeaderMap; // §4.7: Unprotected header parameters
	ciphertext: ArrayBuffer; // §4.7: Encrypted content
	recipients: Array<{
		// §4.7: Array of recipient objects
		protected: HeaderMap; // §4.7: Per-recipient protected headers
		unprotected: HeaderMap; // §4.7: Per-recipient unprotected headers
		encrypted_key: ArrayBuffer; // §4.7: Per-recipient encrypted key
	}>;
}

export const COSE = {
	encodeSign1,
	decodeSign1,
	encodeSign,
	decodeSign,
	encodeMac0,
	decodeMac0,
	encodeMac,
	decodeMac,
	encodeEncrypt0,
	decodeEncrypt0,
	encodeEncrypt,
	decodeEncrypt,
} as const;

// --- Validation Helpers ---

/**
 * Validates that a header map contains mandatory parameters (e.g., 'alg').
 * @param header - The protected header map to validate.
 * @throws Error if mandatory parameters are missing or invalid.
 * RFC 8152 §3.1: Ensures 'alg' is present in protected headers
 */
function validateProtectedHeader(header: HeaderMap): void {
	if (!(HeaderParameter.alg in header)) {
		throw new Error("Protected header must contain 'alg' parameter");
	}
	const alg = header[HeaderParameter.alg];
	if (typeof alg !== "number" || !(alg in Algorithm)) {
		throw new Error("Invalid or unsupported algorithm in protected header");
	}
}

/**
 * Ensures a value is an ArrayBuffer.
 * @param value - The value to check.
 * @returns The value as an ArrayBuffer.
 * @throws Error if the value is not an ArrayBuffer.
 * RFC 8152 §4: Helper for type safety in COSE structures
 */
function ensureArrayBuffer(value: CBORValue): ArrayBuffer {
	if (!(value instanceof ArrayBuffer)) {
		throw new Error("Expected ArrayBuffer");
	}
	return value;
}

// --- Encoding Functions ---

/**
 * Encodes a COSE_Sign1 structure with tag 18.
 * @param sign1 - The COSE_Sign1 structure to encode.
 * @returns The encoded CBOR data with tag.
 * RFC 8152 §4.2: Implements COSE_Sign1 encoding
 */
function encodeSign1(sign1: COSESign1): ArrayBuffer {
	validateProtectedHeader(sign1.protected);
	const protectedHeader = CBOR.encode(sign1.protected);
	const value = [
		new Uint8Array(protectedHeader).buffer, // §4.2: Protected header as byte string
		sign1.unprotected, // §4.2: Unprotected header map
		sign1.payload, // §4.2: Payload (nil if detached)
		sign1.signature, // §4.2: Signature value
	];
	return CBOR.encode({ tag: COSETag.COSE_Sign1, value });
}

/**
 * Encodes a COSE_Sign structure with tag 98.
 * @param sign - The COSE_Sign structure to encode.
 * @returns The encoded CBOR data with tag.
 * RFC 8152 §4.3: Implements COSE_Sign encoding
 */
function encodeSign(sign: COSESign): ArrayBuffer {
	validateProtectedHeader(sign.protected);
	const protectedHeader = CBOR.encode(sign.protected);
	const value = [
		new Uint8Array(protectedHeader).buffer, // §4.3: Protected header as byte string
		sign.unprotected, // §4.3: Unprotected header map
		sign.payload, // §4.3: Payload (nil if detached)
		sign.signatures.map((sig) => {
			// §4.3: Array of signature structures
			validateProtectedHeader(sig.protected);
			return [
				new Uint8Array(CBOR.encode(sig.protected)).buffer, // §4.3: Per-signer protected header
				sig.unprotected, // §4.3: Per-signer unprotected header
				sig.signature, // §4.3: Per-signer signature
			];
		}),
	];
	return CBOR.encode({ tag: COSETag.COSE_Sign, value });
}

/**
 * Encodes a COSE_Mac0 structure with tag 17.
 * @param mac0 - The COSE_Mac0 structure to encode.
 * @returns The encoded CBOR data with tag.
 * RFC 8152 §4.4: Implements COSE_Mac0 encoding
 */
function encodeMac0(mac0: COSEMac0): ArrayBuffer {
	validateProtectedHeader(mac0.protected);
	const protectedHeader = CBOR.encode(mac0.protected);
	const value = [
		new Uint8Array(protectedHeader).buffer, // §4.4: Protected header as byte string
		mac0.unprotected, // §4.4: Unprotected header map
		mac0.payload, // §4.4: Payload (nil if detached)
		mac0.tag, // §4.4: MAC tag value
	];
	return CBOR.encode({ tag: COSETag.COSE_Mac0, value });
}

/**
 * Encodes a COSE_Mac structure with tag 97.
 * @param mac - The COSE_Mac structure to encode.
 * @returns The encoded CBOR data with tag.
 * RFC 8152 §4.5: Implements COSE_Mac encoding
 */
function encodeMac(mac: COSEMac): ArrayBuffer {
	validateProtectedHeader(mac.protected);
	const protectedHeader = CBOR.encode(mac.protected);
	const value = [
		new Uint8Array(protectedHeader).buffer, // §4.5: Protected header as byte string
		mac.unprotected, // §4.5: Unprotected header map
		mac.payload, // §4.5: Payload (nil if detached)
		mac.recipients.map((rec) => {
			// §4.5: Array of recipient structures
			validateProtectedHeader(rec.protected);
			return [
				new Uint8Array(CBOR.encode(rec.protected)).buffer, // §4.5: Per-recipient protected header
				rec.unprotected, // §4.5: Per-recipient unprotected header
				rec.tag, // §4.5: Per-recipient MAC tag
			];
		}),
	];
	return CBOR.encode({ tag: COSETag.COSE_Mac, value });
}

/**
 * Encodes a COSE_Encrypt0 structure with tag 16.
 * @param encrypt0 - The COSE_Encrypt0 structure to encode.
 * @returns The encoded CBOR data with tag.
 * RFC 8152 §4.6: Implements COSE_Encrypt0 encoding
 */
function encodeEncrypt0(encrypt0: COSEEncrypt0): ArrayBuffer {
	validateProtectedHeader(encrypt0.protected);
	const protectedHeader = CBOR.encode(encrypt0.protected);
	const value = [
		new Uint8Array(protectedHeader).buffer, // §4.6: Protected header as byte string
		encrypt0.unprotected, // §4.6: Unprotected header map
		encrypt0.ciphertext, // §4.6: Encrypted content
	];
	return CBOR.encode({ tag: COSETag.COSE_Encrypt0, value });
}

/**
 * Encodes a COSE_Encrypt structure with tag 96.
 * @param encrypt - The COSE_Encrypt structure to encode.
 * @returns The encoded CBOR data with tag.
 * RFC 8152 §4.7: Implements COSE_Encrypt encoding
 */
function encodeEncrypt(encrypt: COSEEncrypt): ArrayBuffer {
	validateProtectedHeader(encrypt.protected);
	const protectedHeader = CBOR.encode(encrypt.protected);
	const value = [
		new Uint8Array(protectedHeader).buffer, // §4.7: Protected header as byte string
		encrypt.unprotected, // §4.7: Unprotected header map
		encrypt.ciphertext, // §4.7: Encrypted content
		encrypt.recipients.map((rec) => {
			// §4.7: Array of recipient structures
			validateProtectedHeader(rec.protected);
			return [
				new Uint8Array(CBOR.encode(rec.protected)).buffer, // §4.7: Per-recipient protected header
				rec.unprotected, // §4.7: Per-recipient unprotected header
				rec.encrypted_key, // §4.7: Per-recipient encrypted key
			];
		}),
	];
	return CBOR.encode({ tag: COSETag.COSE_Encrypt, value });
}

// --- Decoding Functions ---

/**
 * Decodes a COSE_Sign1 structure (expects tag 18).
 * @param data - The CBOR-encoded data.
 * @returns The decoded COSE_Sign1 structure.
 * @throws Error if tag is incorrect or structure is invalid.
 * RFC 8152 §4.2: Implements COSE_Sign1 decoding
 */
function decodeSign1(data: ArrayBuffer): COSESign1 {
	const tagged = CBOR.decode(data) as { tag: number; value: CBORValue };
	if (tagged.tag !== COSETag.COSE_Sign1) {
		throw new Error(
			`Expected COSE_Sign1 tag ${COSETag.COSE_Sign1}, got ${tagged.tag}`,
		);
	}
	const decoded = tagged.value as [
		ArrayBuffer,
		HeaderMap,
		ArrayBuffer | null,
		ArrayBuffer,
	];
	const protectedHeader = CBOR.decode(decoded[0]) as HeaderMap; // §4.2: Decode protected header
	validateProtectedHeader(protectedHeader);
	return {
		protected: protectedHeader, // §4.2: Protected header
		unprotected: decoded[1], // §4.2: Unprotected header
		payload: decoded[2], // §4.2: Payload (nil if detached)
		signature: ensureArrayBuffer(decoded[3]), // §4.2: Signature value
	};
}

/**
 * Decodes a COSE_Sign structure (expects tag 98).
 * @param data - The CBOR-encoded data.
 * @returns The decoded COSE_Sign structure.
 * RFC 8152 §4.3: Implements COSE_Sign decoding
 */
function decodeSign(data: ArrayBuffer): COSESign {
	const tagged = CBOR.decode(data) as { tag: number; value: CBORValue };
	if (tagged.tag !== COSETag.COSE_Sign) {
		throw new Error(
			`Expected COSE_Sign tag ${COSETag.COSE_Sign}, got ${tagged.tag}`,
		);
	}
	const decoded = tagged.value as [
		ArrayBuffer,
		HeaderMap,
		ArrayBuffer | null,
		Array<[ArrayBuffer, HeaderMap, ArrayBuffer]>,
	];
	const protectedHeader = CBOR.decode(decoded[0]) as HeaderMap; // §4.3: Decode protected header
	validateProtectedHeader(protectedHeader);
	return {
		protected: protectedHeader, // §4.3: Protected header
		unprotected: decoded[1], // §4.3: Unprotected header
		payload: decoded[2], // §4.3: Payload (nil if detached)
		signatures: decoded[3].map((sig) => {
			// §4.3: Array of signature structures
			const sigProtected = CBOR.decode(sig[0]) as HeaderMap; // §4.3: Per-signer protected header
			validateProtectedHeader(sigProtected);
			return {
				protected: sigProtected, // §4.3: Per-signer protected header
				unprotected: sig[1], // §4.3: Per-signer unprotected header
				signature: ensureArrayBuffer(sig[2]), // §4.3: Per-signer signature
			};
		}),
	};
}

/**
 * Decodes a COSE_Mac0 structure (expects tag 17).
 * @param data - The CBOR-encoded data.
 * @returns The decoded COSE_Mac0 structure.
 * RFC 8152 §4.4: Implements COSE_Mac0 decoding
 */
function decodeMac0(data: ArrayBuffer): COSEMac0 {
	const tagged = CBOR.decode(data) as { tag: number; value: CBORValue };
	if (tagged.tag !== COSETag.COSE_Mac0) {
		throw new Error(
			`Expected COSE_Mac0 tag ${COSETag.COSE_Mac0}, got ${tagged.tag}`,
		);
	}
	const decoded = tagged.value as [
		ArrayBuffer,
		HeaderMap,
		ArrayBuffer | null,
		ArrayBuffer,
	];
	const protectedHeader = CBOR.decode(decoded[0]) as HeaderMap; // §4.4: Decode protected header
	validateProtectedHeader(protectedHeader);
	return {
		protected: protectedHeader, // §4.4: Protected header
		unprotected: decoded[1], // §4.4: Unprotected header
		payload: decoded[2], // §4.4: Payload (nil if detached)
		tag: ensureArrayBuffer(decoded[3]), // §4.4: MAC tag value
	};
}

/**
 * Decodes a COSE_Mac structure (expects tag 97).
 * @param data - The CBOR-encoded data.
 * @returns The decoded COSE_Mac structure.
 * RFC 8152 §4.5: Implements COSE_Mac decoding
 */
function decodeMac(data: ArrayBuffer): COSEMac {
	const tagged = CBOR.decode(data) as { tag: number; value: CBORValue };
	if (tagged.tag !== COSETag.COSE_Mac) {
		throw new Error(
			`Expected COSE_Mac tag ${COSETag.COSE_Mac}, got ${tagged.tag}`,
		);
	}
	const decoded = tagged.value as [
		ArrayBuffer,
		HeaderMap,
		ArrayBuffer | null,
		Array<[ArrayBuffer, HeaderMap, ArrayBuffer]>,
	];
	const protectedHeader = CBOR.decode(decoded[0]) as HeaderMap; // §4.5: Decode protected header
	validateProtectedHeader(protectedHeader);
	return {
		protected: protectedHeader, // §4.5: Protected header
		unprotected: decoded[1], // §4.5: Unprotected header
		payload: decoded[2], // §4.5: Payload (nil if detached)
		recipients: decoded[3].map((rec) => {
			// §4.5: Array of recipient structures
			const recProtected = CBOR.decode(rec[0]) as HeaderMap; // §4.5: Per-recipient protected header
			validateProtectedHeader(recProtected);
			return {
				protected: recProtected, // §4.5: Per-recipient protected header
				unprotected: rec[1], // §4.5: Per-recipient unprotected header
				tag: ensureArrayBuffer(rec[2]), // §4.5: Per-recipient MAC tag
			};
		}),
	};
}

/**
 * Decodes a COSE_Encrypt0 structure (expects tag 16).
 * @param data - The CBOR-encoded data.
 * @returns The decoded COSE_Encrypt0 structure.
 * RFC 8152 §4.6: Implements COSE_Encrypt0 decoding
 */
function decodeEncrypt0(data: ArrayBuffer): COSEEncrypt0 {
	const tagged = CBOR.decode(data) as { tag: number; value: CBORValue };
	if (tagged.tag !== COSETag.COSE_Encrypt0) {
		throw new Error(
			`Expected COSE_Encrypt0 tag ${COSETag.COSE_Encrypt0}, got ${tagged.tag}`,
		);
	}
	const decoded = tagged.value as [ArrayBuffer, HeaderMap, ArrayBuffer];
	const protectedHeader = CBOR.decode(decoded[0]) as HeaderMap; // §4.6: Decode protected header
	validateProtectedHeader(protectedHeader);
	return {
		protected: protectedHeader, // §4.6: Protected header
		unprotected: decoded[1], // §4.6: Unprotected header
		ciphertext: ensureArrayBuffer(decoded[2]), // §4.6: Encrypted content
	};
}

/**
 * Decodes a COSE_Encrypt structure (expects tag 96).
 * @param data - The CBOR-encoded data.
 * @returns The decoded COSE_Encrypt structure.
 * RFC 8152 §4.7: Implements COSE_Encrypt decoding
 */
function decodeEncrypt(data: ArrayBuffer): COSEEncrypt {
	const tagged = CBOR.decode(data) as { tag: number; value: CBORValue };
	if (tagged.tag !== COSETag.COSE_Encrypt) {
		throw new Error(
			`Expected COSE_Encrypt tag ${COSETag.COSE_Encrypt}, got ${tagged.tag}`,
		);
	}
	const decoded = tagged.value as [
		ArrayBuffer,
		HeaderMap,
		ArrayBuffer,
		Array<[ArrayBuffer, HeaderMap, ArrayBuffer]>,
	];
	const protectedHeader = CBOR.decode(decoded[0]) as HeaderMap; // §4.7: Decode protected header
	validateProtectedHeader(protectedHeader);
	return {
		protected: protectedHeader, // §4.7: Protected header
		unprotected: decoded[1], // §4.7: Unprotected header
		ciphertext: ensureArrayBuffer(decoded[2]), // §4.7: Encrypted content
		recipients: decoded[3].map((rec) => {
			// §4.7: Array of recipient structures
			const recProtected = CBOR.decode(rec[0]) as HeaderMap; // §4.7: Per-recipient protected header
			validateProtectedHeader(recProtected);
			return {
				protected: recProtected, // §4.7: Per-recipient protected header
				unprotected: rec[1], // §4.7: Per-recipient unprotected header
				encrypted_key: ensureArrayBuffer(rec[2]), // §4.7: Per-recipient encrypted key
			};
		}),
	};
}
