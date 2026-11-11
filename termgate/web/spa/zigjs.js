// zig-js, the JavaScript side (vendor/zig-js): JS values for Zig in WASM.
// mitchellh/zig-js js/src/zigjs.ts (MIT), written as plain JavaScript.

// The prefix of every NaN-boxed reference
const NAN_PREFIX = 0x7FF80000;

// References with fixed ids
const predefined = { nan: 0, null: 1, true: 2, false: 3, undefined: 4, globalThis: 5, runtime: 6 };
const PREDEFINED_ID_MAX = 6;

const encoder = new TextEncoder();
const decoder = new TextDecoder("utf-8");

class ZigJS {
  constructor() {
    // The WASM memory; set before the first call into the WASM
    this.memory = null;
    // Values by id; duplicates are separate references
    this.values = [NaN, null, true, false, undefined, globalThis, this];
    // Freed ids, used again first
    this.idPool = [];
  }

  // The imports the WASM needs, under "zig-js"
  importObject() {
    return {
      "zig-js": {
        valueGet: this.valueGet.bind(this),
        valueSet: this.valueSet.bind(this),
        valueDeinit: this.valueDeinit.bind(this),
        valueObjectCreate: this.valueObjectCreate.bind(this),
        valueStringCreate: this.valueStringCreate.bind(this),
        valueStringLen: this.valueStringLen.bind(this),
        valueStringCopy: this.valueStringCopy.bind(this),
        valueNew: this.valueNew.bind(this),
        funcApply: this.funcApply.bind(this),
      },
    };
  }

  valueGet(out, id, ptr, len) {
    this.storeValue(out, Reflect.get(this.loadValue(id), this.loadString(ptr, len)));
  }

  valueSet(id, ptr, len, refAddr) {
    Reflect.set(this.loadValue(id), this.loadString(ptr, len), this.loadRef(refAddr));
  }

  valueDeinit(id) {
    if (id > PREDEFINED_ID_MAX) {
      this.values[id] = null;
      this.idPool.push(id);
    }
  }

  valueObjectCreate(out) {
    this.storeValue(out, new Object());
  }

  valueStringCreate(out, ptr, len) {
    this.storeValue(out, this.loadString(ptr, len));
  }

  valueStringLen(id) {
    return encoder.encode(this.loadValue(id)).byteLength;
  }

  valueStringCopy(id, ptr, max) {
    if (this.memory == null) return;
    const bytes = encoder.encode(this.loadValue(id));
    if (bytes.byteLength > max) return;
    new Uint8Array(this.memory.buffer, ptr, bytes.length).set(bytes);
  }

  valueNew(out, id, argsAddr, argsLen) {
    const args = [];
    for (let i = 0; i < argsLen; i++) args.push(this.loadRef(argsAddr + i * 8));
    this.storeValue(out, Reflect.construct(this.loadValue(id), args));
  }

  funcApply(out, id, thisRefAddr, argsAddr, argsLen) {
    const fn = this.loadValue(id);
    const thisVal = this.loadRef(thisRefAddr);
    const args = [];
    for (let i = 0; i < argsLen; i++) args.push(this.loadRef(argsAddr + i * 8));
    this.storeValue(out, Reflect.apply(fn, thisVal, args));
  }

  loadValue(id) {
    return this.values[id];
  }

  deleteValue(id) {
    const val = this.values[id];
    this.valueDeinit(id);
    return val;
  }

  loadRef(refAddr) {
    if (this.memory == null) return;
    const view = new DataView(this.memory.buffer);
    // Not a NaN: the number itself
    const floatVal = view.getFloat64(refAddr, true);
    if (!isNaN(floatVal)) return floatVal;
    return this.values[this.loadRefId(refAddr)];
  }

  loadRefId(refAddr) {
    if (this.memory == null) return 0;
    return new DataView(this.memory.buffer).getUint32(refAddr, true);
  }

  storeValue(out, val) {
    if (this.memory == null) return;
    const view = new DataView(this.memory.buffer);
    if (typeof val === "number") {
      // One encoding for every NaN
      if (isNaN(val)) {
        view.setUint32(out, predefined.nan, true);
        view.setUint32(out + 4, NAN_PREFIX, true);
      } else {
        view.setFloat64(out, val, true);
      }
      return;
    }
    if (val === null) {
      view.setUint32(out, predefined.null, true);
      view.setUint32(out + 4, NAN_PREFIX, true);
      return;
    }
    if (val === undefined) {
      view.setUint32(out, predefined.undefined, true);
      view.setUint32(out + 4, NAN_PREFIX, true);
      return;
    }
    let id = this.idPool.pop();
    if (id === undefined) id = this.values.length;
    this.values[id] = val;
    let typeId = 0;
    switch (typeof val) {
      case "object": typeId = 1; break;
      case "string": typeId = 2; break;
      case "symbol": typeId = 3; break;
      case "function": typeId = 4; break;
    }
    view.setUint32(out, Number(id), true);
    view.setUint32(out + 4, NAN_PREFIX | typeId, true);
  }

  loadString(ptr, len) {
    if (this.memory == null) return "";
    // A copy, so that a shared buffer works too
    return decoder.decode(new Uint8ClampedArray(this.memory.buffer, ptr, Number(len)).slice());
  }
}
