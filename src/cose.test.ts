import { describe, expect, test } from "bun:test";
import { fc } from "fast-check-bun-test";
import {
	Algorithm,
	COSE,
	HeaderParameter,
	type COSEEncrypt,
	type COSEEncrypt0,
	type COSEMac,
	type COSEMac0,
	type COSESign,
	type COSESign1,
} from "./cose";

describe("COSE", () => {
	describe("COSE_Sign1", () => {
		test("should encode and decode COSE_Sign1 with minimal fields", () => {
			const sign1: COSESign1 = {
				protected: {
					[HeaderParameter.alg]: Algorithm.ES256,
				},
				unprotected: {},
				payload: null,
				signature: new Uint8Array([1, 2, 3, 4]).buffer,
			};

			const encoded = COSE.encodeSign1(sign1);
			const decoded = COSE.decodeSign1(encoded);
			expect(decoded).toEqual(sign1);
		});

		test("should encode and decode COSE_Sign1 with all fields", () => {
			const sign1: COSESign1 = {
				protected: {
					[HeaderParameter.alg]: Algorithm.ES256,
					[HeaderParameter.crit]: [HeaderParameter.alg],
					[HeaderParameter.ctyp]: "application/cbor",
				},
				unprotected: {
					[HeaderParameter.kid]: new Uint8Array([1, 2, 3]).buffer,
				},
				payload: new Uint8Array([5, 6, 7, 8]).buffer,
				signature: new Uint8Array([9, 10, 11, 12]).buffer,
			};

			const encoded = COSE.encodeSign1(sign1);
			const decoded = COSE.decodeSign1(encoded);
			expect(decoded).toEqual(sign1);
		});

		test("should handle COSE_Sign1 with various payload types", () => {
			const sign1: COSESign1 = {
				protected: {
					[HeaderParameter.alg]: Algorithm.ES256,
				},
				unprotected: {},
				payload: new TextEncoder().encode("Hello, World!")
					.buffer as ArrayBuffer,
				signature: new Uint8Array([1, 2, 3, 4]).buffer,
			};

			const encoded = COSE.encodeSign1(sign1);
			const decoded = COSE.decodeSign1(encoded);
			expect(decoded).toEqual(sign1);
		});

		test("should throw error for missing algorithm", () => {
			const sign1: COSESign1 = {
				protected: {},
				unprotected: {},
				payload: null,
				signature: new Uint8Array([1, 2, 3, 4]).buffer,
			};

			expect(() => COSE.encodeSign1(sign1)).toThrow(
				"Protected header must contain 'alg' parameter",
			);
		});

		test("should throw error for invalid algorithm", () => {
			const sign1: COSESign1 = {
				protected: {
					[HeaderParameter.alg]: 999, // Invalid algorithm
				},
				unprotected: {},
				payload: null,
				signature: new Uint8Array([1, 2, 3, 4]).buffer,
			};

			expect(() => COSE.encodeSign1(sign1)).toThrow(
				"Invalid or unsupported algorithm in protected header",
			);
		});
	});

	describe("COSE_Sign", () => {
		test("should encode and decode COSE_Sign with minimal fields", () => {
			const sign: COSESign = {
				protected: {
					[HeaderParameter.alg]: Algorithm.ES256,
				},
				unprotected: {},
				payload: null,
				signatures: [
					{
						protected: {
							[HeaderParameter.alg]: Algorithm.ES256,
						},
						unprotected: {},
						signature: new Uint8Array([1, 2, 3, 4]).buffer,
					},
				],
			};

			const encoded = COSE.encodeSign(sign);
			const decoded = COSE.decodeSign(encoded);
			expect(decoded).toEqual(sign);
		});

		test("should encode and decode COSE_Sign with multiple signatures", () => {
			const sign: COSESign = {
				protected: {
					[HeaderParameter.alg]: Algorithm.ES256,
				},
				unprotected: {},
				payload: new Uint8Array([1, 2, 3]).buffer,
				signatures: [
					{
						protected: {
							[HeaderParameter.alg]: Algorithm.ES256,
						},
						unprotected: {
							[HeaderParameter.kid]: new Uint8Array([1]).buffer,
						},
						signature: new Uint8Array([2, 3, 4]).buffer,
					},
					{
						protected: {
							[HeaderParameter.alg]: Algorithm.ES384,
						},
						unprotected: {
							[HeaderParameter.kid]: new Uint8Array([2]).buffer,
						},
						signature: new Uint8Array([5, 6, 7]).buffer,
					},
				],
			};

			const encoded = COSE.encodeSign(sign);
			const decoded = COSE.decodeSign(encoded);
			expect(decoded).toEqual(sign);
		});
	});

	describe("COSE_Mac0", () => {
		test("should encode and decode COSE_Mac0 with minimal fields", () => {
			const mac0: COSEMac0 = {
				protected: {
					[HeaderParameter.alg]: Algorithm.HMAC_256_256,
				},
				unprotected: {},
				payload: null,
				tag: new Uint8Array([1, 2, 3, 4]).buffer,
			};

			const encoded = COSE.encodeMac0(mac0);
			const decoded = COSE.decodeMac0(encoded);
			expect(decoded).toEqual(mac0);
		});

		test("should encode and decode COSE_Mac0 with all fields", () => {
			const mac0: COSEMac0 = {
				protected: {
					[HeaderParameter.alg]: Algorithm.HMAC_256_256,
				},
				unprotected: {
					[HeaderParameter.kid]: new Uint8Array([1, 2, 3]).buffer,
				},
				payload: new Uint8Array([4, 5, 6]).buffer,
				tag: new Uint8Array([7, 8, 9]).buffer,
			};

			const encoded = COSE.encodeMac0(mac0);
			const decoded = COSE.decodeMac0(encoded);
			expect(decoded).toEqual(mac0);
		});
	});

	describe("COSE_Mac", () => {
		test("should encode and decode COSE_Mac with minimal fields", () => {
			const mac: COSEMac = {
				protected: {
					[HeaderParameter.alg]: Algorithm.HMAC_256_256,
				},
				unprotected: {},
				payload: null,
				recipients: [
					{
						protected: {
							[HeaderParameter.alg]: Algorithm.HMAC_256_256,
						},
						unprotected: {},
						tag: new Uint8Array([1, 2, 3, 4]).buffer,
					},
				],
			};

			const encoded = COSE.encodeMac(mac);
			const decoded = COSE.decodeMac(encoded);
			expect(decoded).toEqual(mac);
		});

		test("should encode and decode COSE_Mac with multiple recipients", () => {
			const mac: COSEMac = {
				protected: {
					[HeaderParameter.alg]: Algorithm.HMAC_256_256,
				},
				unprotected: {},
				payload: new Uint8Array([1, 2, 3]).buffer,
				recipients: [
					{
						protected: {
							[HeaderParameter.alg]: Algorithm.HMAC_256_256,
						},
						unprotected: {
							[HeaderParameter.kid]: new Uint8Array([1]).buffer,
						},
						tag: new Uint8Array([2, 3, 4]).buffer,
					},
					{
						protected: {
							[HeaderParameter.alg]: Algorithm.HMAC_384_384,
						},
						unprotected: {
							[HeaderParameter.kid]: new Uint8Array([2]).buffer,
						},
						tag: new Uint8Array([5, 6, 7]).buffer,
					},
				],
			};

			const encoded = COSE.encodeMac(mac);
			const decoded = COSE.decodeMac(encoded);
			expect(decoded).toEqual(mac);
		});
	});

	describe("COSE_Encrypt0", () => {
		test("should encode and decode COSE_Encrypt0 with minimal fields", () => {
			const encrypt0: COSEEncrypt0 = {
				protected: {
					[HeaderParameter.alg]: Algorithm.AES_GCM_128,
				},
				unprotected: {},
				ciphertext: new Uint8Array([1, 2, 3, 4]).buffer,
			};

			const encoded = COSE.encodeEncrypt0(encrypt0);
			const decoded = COSE.decodeEncrypt0(encoded);
			expect(decoded).toEqual(encrypt0);
		});

		test("should encode and decode COSE_Encrypt0 with all fields", () => {
			const encrypt0: COSEEncrypt0 = {
				protected: {
					[HeaderParameter.alg]: Algorithm.AES_GCM_128,
					[HeaderParameter.iv]: new Uint8Array([
						1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12,
					]).buffer,
				},
				unprotected: {
					[HeaderParameter.kid]: new Uint8Array([1, 2, 3]).buffer,
				},
				ciphertext: new Uint8Array([4, 5, 6]).buffer,
			};

			const encoded = COSE.encodeEncrypt0(encrypt0);
			const decoded = COSE.decodeEncrypt0(encoded);
			expect(decoded).toEqual(encrypt0);
		});
	});

	describe("COSE_Encrypt", () => {
		test("should encode and decode COSE_Encrypt with minimal fields", () => {
			const encrypt: COSEEncrypt = {
				protected: {
					[HeaderParameter.alg]: Algorithm.AES_GCM_128,
				},
				unprotected: {},
				ciphertext: new Uint8Array([1, 2, 3, 4]).buffer,
				recipients: [
					{
						protected: {
							[HeaderParameter.alg]: Algorithm.AES_GCM_128,
						},
						unprotected: {},
						encrypted_key: new Uint8Array([5, 6, 7, 8]).buffer,
					},
				],
			};

			const encoded = COSE.encodeEncrypt(encrypt);
			const decoded = COSE.decodeEncrypt(encoded);
			expect(decoded).toEqual(encrypt);
		});

		test("should encode and decode COSE_Encrypt with multiple recipients", () => {
			const encrypt: COSEEncrypt = {
				protected: {
					[HeaderParameter.alg]: Algorithm.AES_GCM_128,
					[HeaderParameter.iv]: new Uint8Array([
						1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12,
					]).buffer,
				},
				unprotected: {},
				ciphertext: new Uint8Array([1, 2, 3]).buffer,
				recipients: [
					{
						protected: {
							[HeaderParameter.alg]: Algorithm.AES_GCM_128,
						},
						unprotected: {
							[HeaderParameter.kid]: new Uint8Array([1]).buffer,
						},
						encrypted_key: new Uint8Array([2, 3, 4]).buffer,
					},
					{
						protected: {
							[HeaderParameter.alg]: Algorithm.AES_GCM_192,
						},
						unprotected: {
							[HeaderParameter.kid]: new Uint8Array([2]).buffer,
						},
						encrypted_key: new Uint8Array([5, 6, 7]).buffer,
					},
				],
			};

			const encoded = COSE.encodeEncrypt(encrypt);
			const decoded = COSE.decodeEncrypt(encoded);
			expect(decoded).toEqual(encrypt);
		});
	});

	describe("Property-based tests", () => {
		// Helper function to generate random header maps
		const headerMapArbitrary = fc.record({
			[HeaderParameter.alg]: fc.oneof(
				fc.constant(Algorithm.ES256),
				fc.constant(Algorithm.ES384),
				fc.constant(Algorithm.ES512),
				fc.constant(Algorithm.EdDSA),
				fc.constant(Algorithm.RS256),
				fc.constant(Algorithm.RS384),
				fc.constant(Algorithm.RS512),
				fc.constant(Algorithm.PS256),
				fc.constant(Algorithm.PS384),
				fc.constant(Algorithm.PS512),
				fc.constant(Algorithm.HMAC_256_256),
				fc.constant(Algorithm.HMAC_384_384),
				fc.constant(Algorithm.HMAC_512_512),
				fc.constant(Algorithm.AES_GCM_128),
				fc.constant(Algorithm.AES_GCM_192),
				fc.constant(Algorithm.AES_GCM_256),
				fc.constant(Algorithm.ChaCha20_Poly1305),
				fc.constant(Algorithm.direct),
			),
			[HeaderParameter.crit]: fc.oneof(
				fc.array(fc.integer()),
				fc.constant(undefined),
			),
			[HeaderParameter.ctyp]: fc.oneof(fc.string(), fc.constant(undefined)),
			[HeaderParameter.kid]: fc.oneof(
				fc.uint8Array().map((arr) => arr.buffer),
				fc.constant(undefined),
			),
			[HeaderParameter.iv]: fc.oneof(
				fc.uint8Array().map((arr) => arr.buffer),
				fc.constant(undefined),
			),
			[HeaderParameter.partial_iv]: fc.oneof(
				fc.uint8Array().map((arr) => arr.buffer),
				fc.constant(undefined),
			),
			[HeaderParameter.counter_signature]: fc.oneof(
				fc.uint8Array().map((arr) => arr.buffer),
				fc.constant(undefined),
			),
			[HeaderParameter.salt]: fc.oneof(
				fc.uint8Array().map((arr) => arr.buffer),
				fc.constant(undefined),
			),
			[HeaderParameter.x5chain]: fc.oneof(
				fc.uint8Array().map((arr) => arr.buffer),
				fc.constant(undefined),
			),
			[HeaderParameter.x5t]: fc.oneof(
				fc.uint8Array().map((arr) => arr.buffer),
				fc.constant(undefined),
			),
		});

		// Helper function to generate random binary data
		const binaryDataArbitrary = fc.oneof(
			fc.uint8Array().map((arr) => arr.buffer),
			fc.constant(null),
		);

		test("should handle any valid COSE_Sign1 structure", () => {
			fc.assert(
				fc.property(
					fc.record({
						protected: headerMapArbitrary,
						unprotected: headerMapArbitrary,
						payload: binaryDataArbitrary,
						signature: fc.uint8Array().map((arr) => arr.buffer),
					}),
					(sign1) => {
						const encoded = COSE.encodeSign1(sign1);
						const decoded = COSE.decodeSign1(encoded);
						expect(decoded).toEqual(sign1);
					},
				),
			);
		});

		test("should handle any valid COSE_Sign structure", () => {
			fc.assert(
				fc.property(
					fc.record({
						protected: headerMapArbitrary,
						unprotected: headerMapArbitrary,
						payload: binaryDataArbitrary,
						signatures: fc.array(
							fc.record({
								protected: headerMapArbitrary,
								unprotected: headerMapArbitrary,
								signature: fc.uint8Array().map((arr) => arr.buffer),
							}),
							{ minLength: 1, maxLength: 5 },
						),
					}),
					(sign) => {
						const encoded = COSE.encodeSign(sign);
						const decoded = COSE.decodeSign(encoded);
						expect(decoded).toEqual(sign);
					},
				),
			);
		});

		test("should handle any valid COSE_Mac0 structure", () => {
			fc.assert(
				fc.property(
					fc.record({
						protected: headerMapArbitrary,
						unprotected: headerMapArbitrary,
						payload: binaryDataArbitrary,
						tag: fc.uint8Array().map((arr) => arr.buffer),
					}),
					(mac0) => {
						const encoded = COSE.encodeMac0(mac0);
						const decoded = COSE.decodeMac0(encoded);
						expect(decoded).toEqual(mac0);
					},
				),
			);
		});

		test("should handle any valid COSE_Mac structure", () => {
			fc.assert(
				fc.property(
					fc.record({
						protected: headerMapArbitrary,
						unprotected: headerMapArbitrary,
						payload: binaryDataArbitrary,
						recipients: fc.array(
							fc.record({
								protected: headerMapArbitrary,
								unprotected: headerMapArbitrary,
								tag: fc.uint8Array().map((arr) => arr.buffer),
							}),
							{ minLength: 1, maxLength: 5 },
						),
					}),
					(mac) => {
						const encoded = COSE.encodeMac(mac);
						const decoded = COSE.decodeMac(encoded);
						expect(decoded).toEqual(mac);
					},
				),
			);
		});

		test("should handle any valid COSE_Encrypt0 structure", () => {
			fc.assert(
				fc.property(
					fc.record({
						protected: headerMapArbitrary,
						unprotected: headerMapArbitrary,
						ciphertext: fc.uint8Array().map((arr) => arr.buffer),
					}),
					(encrypt0) => {
						const encoded = COSE.encodeEncrypt0(encrypt0);
						const decoded = COSE.decodeEncrypt0(encoded);
						expect(decoded).toEqual(encrypt0);
					},
				),
			);
		});

		test("should handle any valid COSE_Encrypt structure", () => {
			fc.assert(
				fc.property(
					fc.record({
						protected: headerMapArbitrary,
						unprotected: headerMapArbitrary,
						ciphertext: fc.uint8Array().map((arr) => arr.buffer),
						recipients: fc.array(
							fc.record({
								protected: headerMapArbitrary,
								unprotected: headerMapArbitrary,
								encrypted_key: fc.uint8Array().map((arr) => arr.buffer),
							}),
							{ minLength: 1, maxLength: 5 },
						),
					}),
					(encrypt) => {
						const encoded = COSE.encodeEncrypt(encrypt);
						const decoded = COSE.decodeEncrypt(encoded);
						expect(decoded).toEqual(encrypt);
					},
				),
			);
		});

		test("should handle edge cases for header maps", () => {
			fc.assert(
				fc.property(
					fc.record({
						protected: fc.record({
							[HeaderParameter.alg]: fc.constant(Algorithm.ES256),
							[HeaderParameter.crit]: fc.array(fc.integer()),
							[HeaderParameter.ctyp]: fc.string(),
							[HeaderParameter.kid]: fc.uint8Array().map((arr) => arr.buffer),
							[HeaderParameter.iv]: fc.uint8Array().map((arr) => arr.buffer),
						}),
						unprotected: fc.record({
							[HeaderParameter.alg]: fc.integer(),
							[HeaderParameter.crit]: fc.array(fc.integer()),
							[HeaderParameter.ctyp]: fc.string(),
							[HeaderParameter.kid]: fc.uint8Array().map((arr) => arr.buffer),
							[HeaderParameter.iv]: fc.uint8Array().map((arr) => arr.buffer),
						}),
						payload: binaryDataArbitrary,
						signature: fc.uint8Array().map((arr) => arr.buffer),
					}),
					(sign1) => {
						const encoded = COSE.encodeSign1(sign1);
						const decoded = COSE.decodeSign1(encoded);
						expect(decoded).toEqual(sign1);
					},
				),
			);
		});

		test("should handle edge cases for binary data", () => {
			fc.assert(
				fc.property(
					fc.record({
						protected: headerMapArbitrary,
						unprotected: headerMapArbitrary,
						payload: fc.oneof(
							fc.constant(null),
							fc.constant(new Uint8Array().buffer),
							fc.constant(new Uint8Array([0]).buffer),
							fc.constant(new Uint8Array([255]).buffer),
							fc.constant(new Uint8Array(1000).fill(255).buffer),
						),
						signature: fc.uint8Array().map((arr) => arr.buffer),
					}),
					(sign1) => {
						const encoded = COSE.encodeSign1(sign1);
						const decoded = COSE.decodeSign1(encoded);
						expect(decoded).toEqual(sign1);
					},
				),
			);
		});
	});
});
