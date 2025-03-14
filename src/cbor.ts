/**
 * A reusable CBOR (Concise Binary Object Representation) encoder and decoder.
 * Supports maps, arrays, byte strings, text strings, unsigned integers, negative integers,
 * tags (major type 6), floating-point numbers, and special values (false, true, null, undefined).
 * Based on RFC 8949 with deterministic encoding (shortest lengths, sorted map keys).
 *
 * Limitations:
 * - Maximum input size limited to 16MB to prevent memory exhaustion.
 * - Streaming not supported; all data is processed in memory.
 */

/**
 * Represents all possible CBOR value types as defined in RFC 8949.
 *
 * Major types:
 * - 0: Unsigned integers and simple values (false, true, null, undefined)
 * - 1: Negative integers
 * - 2: Byte strings (ArrayBuffer)
 * - 3: Text strings
 * - 4: Arrays (recursive)
 * - 5: Maps (recursive)
 * - 6: Tagged values (used by COSE)
 * - 7: Floating-point numbers and simple values
 */
export type CBORValue =
	| number // Major types 0, 1, 7: integers and floats
	| ArrayBuffer // Major type 2: byte strings
	| string // Major type 3: text strings
	| CBORValue[] // Major type 4: arrays (recursive)
	| { [key: string | number]: CBORValue } // Major type 5: maps (recursive)
	| { tag: number; value: CBORValue } // Major type 6: tagged values (used by COSE)
	| boolean // Major type 7: simple values
	| null // Major type 7: simple values
	| undefined; // Major type 7: simple values

export const CBOR = {
	encode,
	decode,
} as const;

// Maximum buffer size (16MB) to prevent DoS via memory exhaustion
const MAX_BUFFER_SIZE = 16 * 1024 * 1024;

/**
 * Decodes a CBOR-encoded ArrayBuffer into a JavaScript value.
 * @param buffer - The CBOR-encoded data as an ArrayBuffer.
 * @returns The decoded JavaScript value.
 * @throws Error if decoding fails, buffer is malformed, or exceeds size limit.
 * RFC 8949 §3: Basic decoding of CBOR data items
 */
function decode(buffer: ArrayBuffer): CBORValue {
	if (buffer.byteLength > MAX_BUFFER_SIZE) {
		throw new Error(`Buffer exceeds maximum size of ${MAX_BUFFER_SIZE} bytes`);
	}
	const [value] = decodeFirstItem(buffer, 0);
	return value;
}

/**
 * Encodes a JavaScript value into a CBOR-encoded ArrayBuffer.
 * @param value - The value to encode (object, string, ArrayBuffer, number, array, tagged value).
 * @returns The CBOR-encoded data as an ArrayBuffer.
 * @throws Error if the value cannot be encoded or exceeds size limits.
 * RFC 8949 §3: Basic encoding of CBOR data items
 */
function encode(value: CBORValue): ArrayBuffer {
	const buffers: Uint8Array[] = [];
	encodeValue(value, buffers);
	const totalLength = buffers.reduce((sum, buf) => sum + buf.byteLength, 0);
	if (totalLength > MAX_BUFFER_SIZE) {
		throw new Error(
			`Encoded data exceeds maximum size of ${MAX_BUFFER_SIZE} bytes`,
		);
	}
	return concatenateBuffers(buffers);
}

// --- Decoding Helpers ---

/**
 * RFC 8949 §3.2: Decode a single CBOR item based on its major type
 */
function decodeFirstItem(
	buffer: ArrayBuffer,
	startOffset: number,
): [CBORValue, number] {
	const dataView = new DataView(buffer);
	if (startOffset >= buffer.byteLength) {
		throw new Error("Buffer too short for CBOR decoding");
	}

	const firstByte = dataView.getUint8(startOffset);
	const majorType = firstByte >> 5; // §3.1: Major type in high 3 bits
	const additionalInfo = firstByte & 0x1f; // §3.1: Additional info in low 5 bits
	const offset = startOffset + 1;

	switch (majorType) {
		case 0: // §3.2.1: Unsigned integer
			return decodeUnsignedInteger(dataView, offset, additionalInfo);
		case 1: // §3.2.2: Negative integer
			return decodeNegativeInteger(dataView, offset, additionalInfo);
		case 2: // §3.2.3: Byte string
			return decodeByteString(buffer, dataView, offset, additionalInfo);
		case 3: // §3.2.4: Text string
			return decodeTextString(buffer, dataView, offset, additionalInfo);
		case 4: // §3.2.5: Array
			return decodeArray(buffer, dataView, offset, additionalInfo);
		case 5: // §3.2.6: Map
			return decodeMap(buffer, dataView, offset, additionalInfo);
		case 6: // §3.2.7: Tag
			return decodeTag(buffer, dataView, offset, additionalInfo);
		case 7: // §3.2.8: Simple values and floating-point numbers
			return decodeSpecial(dataView, offset, additionalInfo);
		default:
			throw new Error(`Unsupported CBOR major type: ${majorType}`);
	}
}

/**
 * RFC 8949 §3.2.1: Decode unsigned integers
 */
function decodeUnsignedInteger(
	dataView: DataView,
	offset: number,
	additionalInfo: number,
): [number, number] {
	if (additionalInfo <= 23) return [additionalInfo, offset];
	if (additionalInfo === 24) {
		ensureBytes(dataView, offset, 1);
		return [dataView.getUint8(offset), offset + 1];
	}
	if (additionalInfo === 25) {
		ensureBytes(dataView, offset, 2);
		return [dataView.getUint16(offset, false), offset + 2];
	}
	if (additionalInfo === 26) {
		ensureBytes(dataView, offset, 4);
		return [dataView.getUint32(offset, false), offset + 4];
	}
	if (additionalInfo === 27) {
		ensureBytes(dataView, offset, 8);
		return [Number(dataView.getBigUint64(offset, false)), offset + 8];
	}
	throw new Error("Invalid additional info for unsigned integer");
}

/**
 * RFC 8949 §3.2.2: Decode negative integers
 */
function decodeNegativeInteger(
	dataView: DataView,
	offset: number,
	additionalInfo: number,
): [number, number] {
	if (additionalInfo <= 23) return [-1 - additionalInfo, offset];
	if (additionalInfo === 24) {
		ensureBytes(dataView, offset, 1);
		return [-1 - dataView.getUint8(offset), offset + 1];
	}
	if (additionalInfo === 25) {
		ensureBytes(dataView, offset, 2);
		return [-1 - dataView.getUint16(offset, false), offset + 2];
	}
	if (additionalInfo === 26) {
		ensureBytes(dataView, offset, 4);
		return [-1 - dataView.getUint32(offset, false), offset + 4];
	}
	if (additionalInfo === 27) {
		ensureBytes(dataView, offset, 8);
		return [-1 - Number(dataView.getBigUint64(offset, false)), offset + 8];
	}
	throw new Error("Invalid additional info for negative integer");
}

/**
 * RFC 8949 §3.2.3: Decode byte strings
 */
function decodeByteString(
	buffer: ArrayBuffer,
	dataView: DataView,
	offset: number,
	additionalInfo: number,
): [ArrayBuffer, number] {
	const [length, newOffset] = readLength(dataView, offset, additionalInfo);
	ensureBytes(dataView, newOffset, length);
	return [buffer.slice(newOffset, newOffset + length), newOffset + length];
}

/**
 * RFC 8949 §3.2.4: Decode text strings (UTF-8 encoded)
 */
function decodeTextString(
	buffer: ArrayBuffer,
	dataView: DataView,
	offset: number,
	additionalInfo: number,
): [string, number] {
	const [length, newOffset] = readLength(dataView, offset, additionalInfo);
	ensureBytes(dataView, newOffset, length);
	const bytes = new Uint8Array(buffer.slice(newOffset, newOffset + length));
	try {
		return [
			new TextDecoder("utf-8", { fatal: true }).decode(bytes),
			newOffset + length,
		];
	} catch (e) {
		throw new Error("Invalid UTF-8 sequence in text string");
	}
}

/**
 * RFC 8949 §3.2.5: Decode arrays
 */
function decodeArray(
	buffer: ArrayBuffer,
	dataView: DataView,
	offset: number,
	additionalInfo: number,
): [CBORValue[], number] {
	const [length, newOffset] = readLength(dataView, offset, additionalInfo);
	if (length > 10000) throw new Error("Array length exceeds reasonable limit");
	const array: CBORValue[] = [];
	let currentOffset = newOffset;
	for (let i = 0; i < length; i++) {
		const [item, nextOffset] = decodeFirstItem(buffer, currentOffset);
		array.push(item);
		currentOffset = nextOffset;
	}
	return [array, currentOffset];
}

/**
 * RFC 8949 §3.2.6: Decode maps
 */
function decodeMap(
	buffer: ArrayBuffer,
	dataView: DataView,
	offset: number,
	additionalInfo: number,
): [{ [key: string | number]: CBORValue }, number] {
	const [numPairs, newOffset] = readLength(dataView, offset, additionalInfo);
	if (numPairs > 10000) throw new Error("Map size exceeds reasonable limit");
	const map: { [key: string | number]: CBORValue } = {};
	let currentOffset = newOffset;
	for (let i = 0; i < numPairs; i++) {
		const [key, keyOffset] = decodeFirstItem(buffer, currentOffset);
		if (typeof key !== "string" && typeof key !== "number") {
			throw new Error("CBOR map keys must be strings or numbers");
		}
		const [value, valueOffset] = decodeFirstItem(buffer, keyOffset);
		map[key] = value;
		currentOffset = valueOffset;
	}
	return [map, currentOffset];
}

/**
 * RFC 8949 §3.2.7: Decode tagged values (major type 6)
 */
function decodeTag(
	buffer: ArrayBuffer,
	dataView: DataView,
	offset: number,
	additionalInfo: number,
): [{ tag: number; value: CBORValue }, number] {
	const [tag, newOffset] = readLength(dataView, offset, additionalInfo);
	const [value, finalOffset] = decodeFirstItem(buffer, newOffset);
	return [{ tag, value }, finalOffset];
}

/**
 * RFC 8949 §3.2.8: Decode simple values and floating-point numbers (major type 7)
 */
function decodeSpecial(
	dataView: DataView,
	offset: number,
	additionalInfo: number,
): [CBORValue, number] {
	switch (additionalInfo) {
		case 20:
			return [false, offset]; // §3.3: Simple value false
		case 21:
			return [true, offset]; // §3.3: Simple value true
		case 22:
			return [null, offset]; // §3.3: Simple value null
		case 23:
			return [undefined, offset]; // §3.3: Simple value undefined
		case 25: // §3.2.8: 16-bit float (half-precision)
			ensureBytes(dataView, offset, 2);
			return [dataView.getFloat32(offset, false), offset + 2];
		case 26: // §3.2.8: 32-bit float (single-precision)
			ensureBytes(dataView, offset, 4);
			return [dataView.getFloat32(offset, false), offset + 4];
		case 27: // §3.2.8: 64-bit float (double-precision)
			ensureBytes(dataView, offset, 8);
			return [dataView.getFloat64(offset, false), offset + 8];
		default:
			throw new Error(`Unsupported special value: ${additionalInfo}`);
	}
}

/**
 * RFC 8949 §3.1: Read length from additional information
 */
function readLength(
	dataView: DataView,
	offset: number,
	additionalInfo: number,
): [number, number] {
	if (additionalInfo <= 23) return [additionalInfo, offset];
	if (additionalInfo === 24) {
		ensureBytes(dataView, offset, 1);
		return [dataView.getUint8(offset), offset + 1];
	}
	if (additionalInfo === 25) {
		ensureBytes(dataView, offset, 2);
		return [dataView.getUint16(offset, false), offset + 2];
	}
	if (additionalInfo === 26) {
		ensureBytes(dataView, offset, 4);
		return [dataView.getUint32(offset, false), offset + 4];
	}
	if (additionalInfo === 27) {
		ensureBytes(dataView, offset, 8);
		return [Number(dataView.getBigUint64(offset, false)), offset + 8];
	}
	throw new Error("Unsupported CBOR length encoding");
}

/**
 * Helper to ensure sufficient bytes in buffer (RFC 8949 §3)
 */
function ensureBytes(dataView: DataView, offset: number, length: number): void {
	if (offset + length > dataView.byteLength) {
		throw new Error("Buffer too short for CBOR data");
	}
}

// --- Encoding Helpers ---

/**
 * RFC 8949 §3: Encode a CBOR value based on its type
 */
function encodeValue(value: CBORValue, buffers: Uint8Array[]): void {
	if (typeof value === "number") {
		if (Number.isInteger(value)) {
			if (value >= 0)
				encodeUnsignedInteger(value, buffers); // §3.2.1
			else encodeNegativeInteger(value, buffers); // §3.2.2
		} else {
			encodeFloat(value, buffers); // §3.2.8
		}
	} else if (value instanceof ArrayBuffer) {
		encodeByteString(value, buffers); // §3.2.3
	} else if (typeof value === "string") {
		encodeTextString(value, buffers); // §3.2.4
	} else if (Array.isArray(value)) {
		encodeArray(value, buffers); // §3.2.5
	} else if (typeof value === "object" && value !== null) {
		if ("tag" in value && "value" in value && typeof value.tag === "number") {
			encodeTag(value.tag, value.value, buffers); // §3.2.7
		} else {
			encodeMap(value, buffers); // §3.2.6
		}
	} else if (typeof value === "boolean") {
		encodeBoolean(value, buffers); // §3.3
	} else if (value === null) {
		encodeNull(buffers); // §3.3
	} else if (value === undefined) {
		encodeUndefined(buffers); // §3.3
	} else {
		throw new Error(
			`Unsupported value type for CBOR encoding: ${typeof value}`,
		);
	}
}

/**
 * RFC 8949 §3.2.1: Encode unsigned integers
 */
function encodeUnsignedInteger(value: number, buffers: Uint8Array[]): void {
	if (value < 0 || !Number.isInteger(value)) {
		throw new Error("Only unsigned integers are supported");
	}
	if (value <= 23) {
		buffers.push(new Uint8Array([value]));
	} else if (value <= 0xff) {
		buffers.push(new Uint8Array([0x18, value]));
	} else if (value <= 0xffff) {
		const buffer = new Uint8Array(3);
		buffer[0] = 0x19;
		new DataView(buffer.buffer).setUint16(1, value, false);
		buffers.push(buffer);
	} else if (value <= 0xffffffff) {
		const buffer = new Uint8Array(5);
		buffer[0] = 0x1a;
		new DataView(buffer.buffer).setUint32(1, value, false);
		buffers.push(buffer);
	} else if (value <= Number.MAX_SAFE_INTEGER) {
		const buffer = new Uint8Array(9);
		buffer[0] = 0x1b;
		new DataView(buffer.buffer).setBigUint64(1, BigInt(value), false);
		buffers.push(buffer);
	} else {
		throw new Error("Integer value too large for CBOR encoding");
	}
}

/**
 * RFC 8949 §3.2.2: Encode negative integers
 */
function encodeNegativeInteger(value: number, buffers: Uint8Array[]): void {
	if (!Number.isInteger(value) || value >= 0) {
		throw new Error("Only negative integers are supported");
	}
	const absValue = Math.abs(value) - 1;
	if (absValue <= 23) {
		buffers.push(new Uint8Array([0x20 | absValue]));
	} else if (absValue <= 0xff) {
		buffers.push(new Uint8Array([0x38, absValue]));
	} else if (absValue <= 0xffff) {
		const buffer = new Uint8Array(3);
		buffer[0] = 0x39;
		new DataView(buffer.buffer).setUint16(1, absValue, false);
		buffers.push(buffer);
	} else if (absValue <= 0xffffffff) {
		const buffer = new Uint8Array(5);
		buffer[0] = 0x3a;
		new DataView(buffer.buffer).setUint32(1, absValue, false);
		buffers.push(buffer);
	} else if (absValue <= Number.MAX_SAFE_INTEGER) {
		const buffer = new Uint8Array(9);
		buffer[0] = 0x3b;
		new DataView(buffer.buffer).setBigUint64(1, BigInt(absValue), false);
		buffers.push(buffer);
	} else {
		throw new Error("Integer value too large for CBOR encoding");
	}
}

/**
 * RFC 8949 §3.2.3: Encode byte strings
 */
function encodeByteString(value: ArrayBuffer, buffers: Uint8Array[]): void {
	const length = value.byteLength;
	const header = encodeLength(2, length); // Major type 2
	buffers.push(header);
	buffers.push(new Uint8Array(value));
}

/**
 * RFC 8949 §3.2.4: Encode text strings (UTF-8 encoded)
 */
function encodeTextString(value: string, buffers: Uint8Array[]): void {
	const bytes = new TextEncoder().encode(value);
	const header = encodeLength(3, bytes.length); // Major type 3
	buffers.push(header);
	buffers.push(bytes);
}

/**
 * RFC 8949 §3.2.5: Encode arrays
 */
function encodeArray(value: CBORValue[], buffers: Uint8Array[]): void {
	if (value.length > 10000)
		throw new Error("Array length exceeds reasonable limit");
	const header = encodeLength(4, value.length); // Major type 4
	buffers.push(header);
	for (const item of value) {
		encodeValue(item, buffers);
	}
}

/**
 * RFC 8949 §3.2.6 & §4.2: Encode maps with deterministic key sorting
 */
function encodeMap(
	value: { [key: string | number]: CBORValue },
	buffers: Uint8Array[],
): void {
	const entries = Object.entries(value);
	if (entries.length > 10000)
		throw new Error("Map size exceeds reasonable limit");
	// §4.2: Sort keys for deterministic encoding
	entries.sort(([a], [b]) => (a < b ? -1 : a > b ? 1 : 0));
	const header = encodeLength(5, entries.length); // Major type 5
	buffers.push(header);
	for (const [key, val] of entries) {
		const numKey = Number(key);
		if (!Number.isNaN(numKey)) {
			encodeValue(numKey, buffers);
		} else {
			encodeTextString(key, buffers);
		}
		encodeValue(val, buffers);
	}
}

/**
 * RFC 8949 §3.2.7: Encode tagged values (major type 6)
 */
function encodeTag(tag: number, value: CBORValue, buffers: Uint8Array[]): void {
	if (!Number.isInteger(tag) || tag < 0) {
		throw new Error("Tag must be a non-negative integer");
	}
	const header = encodeLength(6, tag); // Major type 6
	buffers.push(header);
	encodeValue(value, buffers);
}

/**
 * RFC 8949 §3.2.8: Encode floating-point numbers (64-bit default)
 */
function encodeFloat(value: number, buffers: Uint8Array[]): void {
	const buffer = new Uint8Array(9);
	buffer[0] = 0xfb; // Major type 7, 64-bit float (most precise)
	new DataView(buffer.buffer).setFloat64(1, value, false);
	buffers.push(buffer.slice(0, 9));
}

/**
 * RFC 8949 §3.1: Encode length for major types
 */
function encodeLength(majorType: number, length: number): Uint8Array {
	const mt = majorType << 5;
	if (length <= 23) return new Uint8Array([mt | length]);
	if (length <= 0xff) return new Uint8Array([mt | 24, length]);
	if (length <= 0xffff) {
		const buffer = new Uint8Array(3);
		buffer[0] = mt | 25;
		new DataView(buffer.buffer).setUint16(1, length, false);
		return buffer;
	}
	if (length <= 0xffffffff) {
		const buffer = new Uint8Array(5);
		buffer[0] = mt | 26;
		new DataView(buffer.buffer).setUint32(1, length, false);
		return buffer;
	}
	throw new Error("Length too large for CBOR encoding");
}

/**
 * RFC 8949 §3.3: Encode boolean values (true/false)
 */
function encodeBoolean(value: boolean, buffers: Uint8Array[]): void {
	buffers.push(new Uint8Array([value ? 0xf5 : 0xf4]));
}

/**
 * RFC 8949 §3.3: Encode null value
 */
function encodeNull(buffers: Uint8Array[]): void {
	buffers.push(new Uint8Array([0xf6]));
}

/**
 * RFC 8949 §3.3: Encode undefined value
 */
function encodeUndefined(buffers: Uint8Array[]): void {
	buffers.push(new Uint8Array([0xf7]));
}

/**
 * Helper to concatenate buffers (not explicitly in RFC 8949, implementation detail)
 */
function concatenateBuffers(buffers: Uint8Array[]): ArrayBuffer {
	const totalLength = buffers.reduce(
		(sum, buffer) => sum + buffer.byteLength,
		0,
	);
	const result = new Uint8Array(totalLength);
	let offset = 0;
	for (const buffer of buffers) {
		result.set(buffer, offset);
		offset += buffer.byteLength;
	}
	return result.buffer;
}
