# Javascript implementation of Adaptor Point and Adaptor Secret computation

This is a pure javascript implementation of adaptor point and adaptor secret computation over the elliptic curve secp256k1 using multiple signatures

The code is based on [BIP Schnorr](https://github.com/guggero/bip-schnorr/) and utilizes similar methods for constructing adaptor points as signing schnorr signatures

This implementation can be used for providing adaptor points for [DLC](https://github.com/discreetlogcontracts/dlcspecs) construction enabling [CET Compression](https://github.com/discreetlogcontracts/dlcspecs/blob/c4fb12d95a4255eabb873611437d05b740bbeccc/CETCompression.md#adaptor-points-with-multiple-signatures), [Numeric Outcomes](https://github.com/discreetlogcontracts/dlcspecs/blob/c4fb12d95a4255eabb873611437d05b740bbeccc/NumericOutcome.md), and [Multi Oracle Support](https://github.com/discreetlogcontracts/dlcspecs/blob/4fb01bc4e15865fa8323caf7e9cebb403b8116a5/MultiOracle.md)

## Install

**NPM**:
```bash
npm install --save schnorr-adaptor-points
```

**yarn**:
```bash
yarn add schnorr-adaptor-points
```
