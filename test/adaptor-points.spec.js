/* global describe, it, beforeEach */
const assert = require('assert');
const Buffer = require('safe-buffer').Buffer;
const BigInteger = require('bigi');
const schnorr = require('bip-schnorr');
const { math, convert } = require('bip-schnorr');
const adaptor = require('../src/adaptor')
const ecurve = require('ecurve');

const curve = ecurve.getCurveByName('secp256k1');
const concat = Buffer.concat;
const G = curve.G;
const n = curve.n;

const testVectors = require('./test-vectors-schnorr.json');

function assertError(error, expectedMessage) {
  assert.strictEqual(error.message, expectedMessage);
}

describe('adaptor points', () => {
  const positiveTestVectors = testVectors.filter(vec => vec.result);
  const privKeys = [], pubKeys = [], messages = [], rValues = [], kValues = [], secrets = []
  for (let i = 0; i < 4; i++) {
    const vec = positiveTestVectors[i];
    const privKey = BigInteger.fromHex(vec.d);
    const pubKey = Buffer.from(vec.pk, 'hex');
    const m = Buffer.from(vec.m, 'hex');
    const sig = Buffer.from(vec.sig, 'hex');
    const r = sig.slice(0, 32);
    const s = sig.slice(32, 64);
    const aux = Buffer.from(vec.aux, 'hex');
    const P = G.multiply(privKey);
    const Px = convert.intToBuffer(P.affineX);
    const d = math.getEvenKey(P, privKey);
    const t = convert.intToBuffer(d.xor(convert.bufferToInt(math.taggedHash('BIP0340/aux', aux))));
    const rand = math.taggedHash('BIP0340/nonce', concat([t, Px, m]))
    const kPrime = convert.bufferToInt(rand).mod(n);
    privKeys.push(privKey)
    pubKeys.push(pubKey);
    messages.push(m);
    rValues.push(r);
    secrets.push(s);
    kValues.push(kPrime)
  }

  describe('createAdaptorPoint', () => {
    it('can check adaptor point params', () => {
      try { adaptor.createAdaptorPoint([Buffer.from([])], messages, rValues); } catch(e) { assertError(e, 'pubKey[0] must be 32 bytes long'); }
      try { adaptor.createAdaptorPoint(pubKeys, [Buffer.from([])], rValues); } catch(e) { assertError(e, 'message[0] must be 32 bytes long'); }
      try { adaptor.createAdaptorPoint(pubKeys, messages, [Buffer.from([])]); } catch(e) { assertError(e, 'nonce[0] must be 32 bytes long'); }
      try { adaptor.createAdaptorPoint('foo', messages, rValues); } catch(e) { assertError(e, 'pubKey[0] must be a Buffer'); }
      try { adaptor.createAdaptorPoint(pubKeys, 'foo', rValues); } catch(e) { assertError(e, 'message[0] must be a Buffer'); }
      try { adaptor.createAdaptorPoint(pubKeys, messages, 'foo'); } catch(e) { assertError(e, 'nonce[0] must be a Buffer'); }
      try { adaptor.createAdaptorPoint('', messages, rValues); } catch(e) { assertError(e, 'pubKeys must be an array with one or more elements'); }
      try { adaptor.createAdaptorPoint(pubKeys, '', rValues); } catch(e) { assertError(e, 'messages must be an array with one or more elements'); }
      try { adaptor.createAdaptorPoint(pubKeys, messages, ''); } catch(e) { assertError(e, 'nonces must be an array with one or more elements'); }
    })
    it('can create adaptor point for single params', () => {
      const adaptorPoint = adaptor.createAdaptorPoint([pubKeys[0]], [messages[0]], [rValues[0]])
      const sG = convert.intToBuffer(G.multiply(convert.bufferToInt(secrets[0])).affineX)

      assert.strictEqual(adaptorPoint.toString('hex'), sG.toString('hex'))
    })
    it('can create adaptor point for multiple params', () => {
      const adaptorPoint = adaptor.createAdaptorPoint(pubKeys, messages, rValues)
      const combinedSecrets = adaptor.combineSecrets(secrets)
      const sG = convert.intToBuffer(G.multiply(convert.bufferToInt(combinedSecrets)).affineX)

      assert.strictEqual(adaptorPoint.toString('hex'), sG.toString('hex'))
    })
    it('can create adaptor point that matches adaptor secret', () => {
      const adaptorPoint = adaptor.createAdaptorPoint(pubKeys, messages, rValues)
      const adaptorSecret = adaptor.createAdaptorSecret(privKeys, messages, kValues)
      const sG = convert.intToBuffer(G.multiply(convert.bufferToInt(adaptorSecret)).affineX)

      assert.strictEqual(adaptorPoint.toString('hex'), sG.toString('hex'))
    })
  })

  describe('createAdaptorSecret', () => {
    it('can check create adaptor secret params', () => {
      try { adaptor.createAdaptorSecret('foo', messages, kValues); } catch(e) { assertError(e, 'privateKey must be a BigInteger'); }
      try { adaptor.createAdaptorSecret(privKeys, 'foo', kValues); } catch(e) { assertError(e, 'message[0] must be a Buffer'); }
      try { adaptor.createAdaptorSecret(privKeys, messages, 'foo'); } catch(e) { assertError(e, 'kValue must be a BigInteger'); }
      try { adaptor.createAdaptorSecret('', messages, kValues); } catch(e) { assertError(e, 'privateKeys must be an array with one or more elements'); }
      try { adaptor.createAdaptorSecret(privKeys, '', kValues); } catch(e) { assertError(e, 'messages must be an array with one or more elements'); }
      try { adaptor.createAdaptorSecret(privKeys, messages, ''); } catch(e) { assertError(e, 'KValues must be an array with one or more elements'); }
      try { adaptor.createAdaptorSecret([BigInteger.valueOf(0)], messages, kValues); } catch(e) { assertError(e, 'privateKey must be an integer in the range 1..n-1'); }
      try { adaptor.createAdaptorSecret(privKeys, [Buffer.from([])], kValues); } catch(e) { assertError(e, 'message[0] must be 32 bytes long'); }
      try { adaptor.createAdaptorSecret(privKeys, messages, [BigInteger.valueOf(0)]); } catch(e) { assertError(e, 'kValue must be an integer in the range 1..n-1'); }
    })
    it('can create adaptor secret for single params', () => {
      const adaptorSecret = adaptor.createAdaptorSecret([privKeys[0]], [messages[0]], [kValues[0]])

      assert.strictEqual(adaptorSecret.toString('hex'), secrets[0].toString('hex'))
    })
    it('can create adaptor secret for multiple params', () => {
      const adaptorSecret = adaptor.createAdaptorSecret(privKeys, messages, kValues)
      const combinedSecrets = adaptor.combineSecrets(secrets)

      assert.strictEqual(adaptorSecret.toString('hex'), combinedSecrets.toString('hex'))
    })
  })

  describe('combineSecrets', () => {
    it('can check combine secrets', () => {
      try { adaptor.combineSecrets('foo', messages, kValues); } catch(e) { assertError(e, 'secrets[0] must be a Buffer'); }
    })
    it('can combine secrets', () => {
      const s1 = convert.bufferToInt(secrets[0])
      const s2 = convert.bufferToInt(secrets[1])
      const s = convert.intToBuffer(s1.add(s2).mod(n))
      const combinedSecrets = adaptor.combineSecrets([secrets[0], secrets[1]])

      assert.strictEqual(s.toString('hex'), combinedSecrets.toString('hex'))
    })
  })
});
