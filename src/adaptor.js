const BigInteger = require('bigi');
const Buffer = require('safe-buffer').Buffer;
const ecurve = require('ecurve');
const curve = ecurve.getCurveByName('secp256k1');
const { math, convert } = require('bip-schnorr');
const check = require('./check')

const concat = Buffer.concat;
const G = curve.G;
const p = curve.p;
const n = curve.n;
const zero = BigInteger.ZERO;

function createAdaptorPoint(pubKeys, messages, rValues) {
  // https://github.com/discreetlogcontracts/dlcspecs/blob/c4fb12d95a4255eabb873611437d05b740bbeccc/CETCompression.md#adaptor-points-with-multiple-signatures
  // s * G = (s1 + s2 + ... + sn) * G = (R1 + R2 + ... + Rn) + H(R1, m1) * P + ... + H(Rn, mn) * P
  check.checkCreateAdaptorPointParams(pubKeys, messages, rValues)

  let sG = null;
  for (let i = 0; i < pubKeys.length; i++) {
    const P = math.liftX(pubKeys[i]);
    const Px = convert.intToBuffer(P.affineX);
    const r = convert.bufferToInt(rValues[i]);
    const e = math.getE(convert.intToBuffer(r), Px, messages[i]);
    const R = math.liftX(rValues[i]);

    if (i === 0) {
      sG = R;
    } else {
      sG = sG.add(R);
    }
    sG = sG.add(P.multiply(e));
  }

  return convert.intToBuffer(sG.affineX)
}

function createAdaptorSecret(privKeys, messages, kValues) {
  check.checkCreateAdaptorSecretParams(privKeys, messages, kValues)

  let s = null
  for (let i = 0; i < kValues.length; i++) {
    const privateKey = privKeys[i]
    const P = G.multiply(privateKey);
    const Px = convert.intToBuffer(P.affineX);

    const d = math.getEvenKey(P, privateKey);

    const message = messages[i]
    const kPrime = kValues[i]

    const R = G.multiply(kPrime);
    const k = math.getEvenKey(R, kPrime);
    const Rx = convert.intToBuffer(R.affineX);
    const e = math.getE(Rx, Px, message);

    if (s === null) {
      s = k
    } else {
      s = s.add(k)
    }
    s = s.add(e.multiply(d))
  }

  return convert.intToBuffer(s.mod(n))
}

function combineSecrets(secrets) {
  check.checkSecretArr(secrets)

  let s = convert.bufferToInt(secrets[0])
  for (let i = 1; i < secrets.length; i++) {
    s = s.add(convert.bufferToInt(secrets[i])).mod(n)
  }
  return convert.intToBuffer(s)
}

module.exports = {
  createAdaptorPoint,
  createAdaptorSecret,
  combineSecrets,
};
