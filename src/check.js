const { check } = require('bip-schnorr')


const BigInteger = require('bigi');
const Buffer = require('safe-buffer').Buffer;
const ecurve = require('ecurve');
const curve = ecurve.getCurveByName('secp256k1');

const one = BigInteger.ONE;
const n = curve.n;
const p = curve.p;

function checkBuffer(name, buf, len, idx) {
  const idxStr = (idx !== undefined ? '[' + idx + ']' : '');
  if (!Buffer.isBuffer(buf)) {
    throw new Error(name + idxStr + ' must be a Buffer');
  }
  if (buf.length !== len) {
    throw new Error(name + idxStr + ' must be ' + len + ' bytes long');
  }
}

function checkSecretArr(secrets) {
  check.checkArray('secrets', secrets);
  for (let i = 0; i < secrets.length; i++) {
    checkBuffer('secrets', secrets[i], 32, i);
  }
}

function checkMessageArr(messages) {
  check.checkArray('messages', messages);
  for (let i = 0; i < messages.length; i++) {
    checkBuffer('message', messages[i], 32, i);
  }
}

function checkPrivateKey(privateKey, idx) {
  const idxStr = (idx !== undefined ? '[' + idx + ']' : '');
  if (!BigInteger.isBigInteger(privateKey)) {
    throw new Error('privateKey' + idxStr + ' must be a BigInteger');
  }
  check.checkRange('privateKey', privateKey);
}

function checkPrivateKeyArr(privateKeys) {
  check.checkArray('privateKeys', privateKeys)
  for (let i = 0; i < privateKeys.length; i++) {
    checkPrivateKey(privateKeys[i])
  }
}

function checkBigInteger(value, idx) {
  const idxStr = (idx !== undefined ? '[' + idx + ']' : '');
  if (!BigInteger.isBigInteger(value)) {
    throw new Error(idxStr + ' must be a BigInteger');
  }
}

function checkBigIntegerArr(values, idx) {
  const idxStr = (idx !== undefined ? '[' + idx + ']' : '');
  check.checkArray(idx, values)
  for (let i = 0; i < values.length; i++) {
    checkBigInteger(values[i])
  }
}

function checkKValue(privateKey, idx) {
  const idxStr = (idx !== undefined ? '[' + idx + ']' : '');
  if (!BigInteger.isBigInteger(privateKey)) {
    throw new Error('kValue' + idxStr + ' must be a BigInteger');
  }
  check.checkRange('kValue', privateKey);
}

function checkKValueArr(kValues) {
  check.checkArray('KValues', kValues)
  for (let i = 0; i < kValues.length; i++) {
    checkKValue(kValues[i])
  }
}

function checkCreateAdaptorPointParams(pubKeys, messages, rValues) {
  check.checkPubKeyArr(pubKeys)
  checkMessageArr(messages)
  check.checkNonceArr(rValues)

  if (pubKeys.length !== messages.length || messages.length !== rValues.length) {
    throw new Error('all parameters must be an array with the same length')
  }
}

function checkCreateAdaptorSecretParams(privKeys, messages, kValues) {
  checkPrivateKeyArr(privKeys);
  checkMessageArr(messages);
  checkKValueArr(kValues);

  if (privKeys.length !== messages.length || messages.length !== kValues.length) {
    throw new Error('all parameters must be an array with the same length')
  }
}

module.exports = {
  checkCreateAdaptorPointParams,
  checkCreateAdaptorSecretParams,
  checkSecretArr
};
