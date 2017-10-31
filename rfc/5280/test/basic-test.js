'use strict';
/* global describe it */

const assert = require('assert');
const fs = require('fs');
const asn1 = require('../../../');
const rfc5280 = require('..');

const Buffer = require('buffer').Buffer;

describe('asn1.js RFC5280', function() {

  it('should decode Certificate', function() {
    const data = fs.readFileSync(__dirname + '/fixtures/cert1.crt');
    const res = rfc5280.Certificate.decode(data, 'der');

    const tbs = res.tbsCertificate;
    assert.equal(tbs.version, 'v3');
    assert.deepEqual(tbs.serialNumber,
      new asn1.bignum('462e4256bb1194dc', 16));
    assert.equal(tbs.signature.algorithm.join('.'),
      '1.2.840.113549.1.1.5');
    assert.equal(tbs.signature.parameters.toString('hex'), '0500');
  });

  it('should decode ECC Certificate', function() {
    // Symantec Class 3 ECC 256 bit Extended Validation CA from
    // https://knowledge.symantec.com/support/ssl-certificates-support/index?page=content&actp=CROSSLINK&id=AR1908
    const data = fs.readFileSync(__dirname + '/fixtures/cert2.crt');
    const res = rfc5280.Certificate.decode(data, 'der');

    const tbs = res.tbsCertificate;
    assert.equal(tbs.version, 'v3');
    assert.deepEqual(tbs.serialNumber,
      new asn1.bignum('4d955d20af85c49f6925fbab7c665f89', 16));
    assert.equal(tbs.signature.algorithm.join('.'),
      '1.2.840.10045.4.3.3');  // RFC5754
    const spki = rfc5280.SubjectPublicKeyInfo.encode(tbs.subjectPublicKeyInfo,
      'der');
    // spki check to the output of
    // openssl x509 -in ecc_cert.pem -pubkey -noout |
    // openssl pkey -pubin  -outform der | openssl base64
    assert.equal(spki.toString('base64'),
      'MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE3QQ9svKQk5fG6bu8kdtR8KO' +
                 'G7fvG04WTMgVJ4ASDYZZR/1chrgvaDucEoX/bKhy9ypg1xXFzQM3oaqtUhE' +
                 'Mm4g=='
    );
  });

  it('should decode AuthorityInfoAccess', function() {
    const data = new Buffer('305a302b06082b06010505073002861f687474703a2f2f70' +
                          '6b692e676f6f676c652e636f6d2f47494147322e63727430' +
                          '2b06082b06010505073001861f687474703a2f2f636c6965' +
                          '6e7473312e676f6f676c652e636f6d2f6f637370',
    'hex');

    const info = rfc5280.AuthorityInfoAccessSyntax.decode(data, 'der');

    assert(info[0].accessMethod);
  });

  it('should decode directoryName in GeneralName', function() {
    const data = new Buffer('a411300f310d300b06022a03160568656c6c6f', 'hex');

    const name = rfc5280.GeneralName.decode(data, 'der');
    assert.equal(name.type, 'directoryName');
  });

  it('should decode Certificate Extensions', function() {
    let data;
    let cert;

    let extensions = {};
    data = fs.readFileSync(__dirname + '/fixtures/cert3.crt');
    cert = rfc5280.Certificate.decode(data, 'der');
    cert.tbsCertificate.extensions.forEach(function(e) {
      extensions[e.extnID] = e;
    });
    assert.equal(extensions.basicConstraints.extnValue.cA, false);
    assert.equal(extensions.extendedKeyUsage.extnValue.length, 2);

    extensions = {};
    data = fs.readFileSync(__dirname + '/fixtures/cert4.crt');
    cert = rfc5280.Certificate.decode(data, 'der');
    cert.tbsCertificate.extensions.forEach(function(e) {
      extensions[e.extnID] = e;
    });
    assert.equal(extensions.basicConstraints.extnValue.cA, true);
    assert.equal(extensions.authorityInformationAccess.extnValue[0]
      .accessLocation.value, 'http://ocsp.godaddy.com/');

    extensions = {};
    data = fs.readFileSync(__dirname + '/fixtures/cert5.crt');
    cert = rfc5280.Certificate.decode(data, 'der');
    cert.tbsCertificate.extensions.forEach(function(e) {
      extensions[e.extnID] = e;
    });
    assert.equal(extensions.basicConstraints.extnValue.cA, true);

    extensions = {};
    data = fs.readFileSync(__dirname + '/fixtures/cert6.crt');
    cert = rfc5280.Certificate.decode(data, 'der');
    cert.tbsCertificate.extensions.forEach(function(e) {
      extensions[e.extnID] = e;
    });
    assert.equal(extensions.basicConstraints.extnValue.cA, true);
  });

  it('should encode/decode IssuingDistributionPoint', function() {
    let input = {
      onlyContainsUserCerts: true,
      onlyContainsCACerts: false,
      indirectCRL: true,
      onlyContainsAttributeCerts: false
    };

    let data = rfc5280.IssuingDistributionPoint.encode(input);

    let decoded = rfc5280.IssuingDistributionPoint.decode(data);
    assert.deepEqual(decoded, input);

    input = {
      onlyContainsUserCerts: true,
      onlyContainsCACerts: false,
      indirectCRL: true,
      onlyContainsAttributeCerts: false,
      onlySomeReasons: { unused: 0, data: new Buffer('asdf') }
    };

    data = rfc5280.IssuingDistributionPoint.encode(input);

    decoded = rfc5280.IssuingDistributionPoint.decode(data);
    assert.deepEqual(decoded, input);
  });

  it('should decode Revoked Certificates', function() {
    let data;
    let crl;

    // Downloadable CRL (containing two certificates) from distribution point available on cert1.crt
    data = fs.readFileSync(__dirname + '/fixtures/cert1.crl');

    crl = rfc5280.CertificateList.decode(data, 'der');
    assert.equal(crl.tbsCertList.revokedCertificates.length, 2);
    assert.deepEqual(crl.tbsCertList.revokedCertificates[0].userCertificate,
      new asn1.bignum('764bedd38afd51f7', 16));

    const cert1 = crl.tbsCertList.revokedCertificates[1];
    assert.deepEqual(cert1.userCertificate,
      new asn1.bignum('31da3380182af9b2', 16));
    assert.equal(cert1.crlEntryExtensions.length, 1);

    const ext1 = cert1.crlEntryExtensions[0];
    assert.equal(ext1.extnID, 'reasonCode');
    assert.equal(ext1.extnValue, 'affiliationChanged');

    // Downloadable CRL (empty) from distribution point available on cert4.crt
    data = fs.readFileSync(__dirname + '/fixtures/cert4.crl');

    crl = rfc5280.CertificateList.decode(data, 'der');
    assert.equal(crl.tbsCertList.revokedCertificates, undefined);
  });
});
