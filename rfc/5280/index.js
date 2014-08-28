try {
  var asn1 = require('asn1.js');
  var rfc3280 = require('asn1.js/rfc/3280');
} catch (e) {
  var asn1 = require('../..');
  var rfc3280 = require('../3280');
}

/**
 * RFC5280 X509 Extension Definitions
 */

var rfc5280 = exports;

/**
 * Extensions
 */

rfc5280.extensions = {
  standard: {
    // Standard Extensions (id-ce)
    prefix: [2, 5, 29],
    35: 'Authority Key Identifier',
    14: 'Subject Key Identifier',
    15: {
      name: 'Key Usage',
      parse: function(decoded, cert, ext, edata) {
        // For bitstr: KeyUsage
        // NOTE: nonRepudiation was renamed to contentCommitment:
        var data = decoded.data[0];
        return {
          digitalSignature: !!((data >> 0) & 1),
          nonRepudiation: !!((data >> 1) & 1),
          contentCommitment: !!((data >> 1) & 1),
          keyEncipherment: !!((data >> 2) & 1),
          dataEncipherment: !!((data >> 3) & 1),
          keyAgreement: !!((data >> 4) & 1),
          keyCertSign: !!((data >> 5) & 1),
          cRLSign: !!((data >> 6) & 1),
          encipherOnly: !!((data >> 7) & 1),
          decipherOnly: !!((data >> 8) & 1)
        };
      },
      execute: function(cert) {
        return cert;
      }
    },
    32: 'Certificate Policies',
    33: 'Policy Mappings',
    17: 'Subject Alternative Name',
    18: 'Issuer Alternative Name',
     9: 'Subject Directory Attributes',
    19: 'Basic Constraints',
    30: 'Name Constraints',
    36: 'Policy Constraints',
    37: 'Extended Key Usage',
    31: {
      name: 'CRL Distribution Points',
      parse: function(decoded, cert, ext, edata) {
        return decoded;
      },
      execute: function(cert) {
        return cert;
      }
    },
    54: 'Inhibit anyPolicy',
    46: 'Freshest CRL'
  },

  // Private Internet Extensions (id-pe)
  priv: {
    // Unknown extension: 1.3.6.1.5.5.7.1.1
    prefix: [1, 3, 6, 1, 5, 5, 7],
          1: 'Authority Information Access',
         11: 'Subject Information Access',
      // Unknown Extension (not documented anywhere, probably non-standard)
      '1.1': 'Unknown Extension'
  },

  // CRL Extensions (id-ce)
  crl: {
    prefix: [2, 5, 29],
    20: 'CRL Number',
    27: 'Delta CRL Indicator',
    28: 'Issuing Distribution Point',
    21: 'Reason Code',
    24: 'Invalidity Date',
    29: 'Certificate Issuer'
  }
};

/**
 * Standard Extensions
 */

/**
 * 1
 * # Authority Key Identifier
 */

var AuthorityKeyIdentifier =
rfc5280.AuthorityKeyIdentifier = asn1.define('AuthorityKeyIdentifier', function() {
  this.seq().obj(
    // XXX Workaround parser error:
    this.key('_unknown').any(),
    this.key('keyIdentifier').optional().use(KeyIdentifier),
    this.key('authorityCertIssuer').optional().use(GeneralNames),
    this.key('authorityCertSerialNumber').optional().use(CertificateSerialNumber)
  );
});

/**
 * ## KeyIdentifier
 */

var KeyIdentifier =
rfc5280.KeyIdentifier = asn1.define('KeyIdentifier', function() {
  this.octstr();
});

/**
 * ## CertificateSerialNumber
 */

var CertificateSerialNumber =
rfc5280.CertificateSerialNumber = asn1.define('CertificateSerialNumber', function() {
  this.int();
});

/**
 * ## GeneralNames
 */

var GeneralNames =
rfc5280.GeneralNames = asn1.define('GeneralNames', function() {
  this.seqof(GeneralName);
});

/**
 * ### GeneralName
 */

var GeneralName =
rfc5280.GeneralName = asn1.define('GeneralName', function() {
  this.choice({
    // XXX Workaround parser error:
    _unknown: this.int(),
    otherName: this.use(AnotherName),
    rfc822Name: this.ia5str(),
    dNSName: this.ia5str(),
    x400Address: this.use(ORAddress),
    directoryName: this.use(rfc3280.Name),
    ediPartyName: this.use(EDIPartyName),
    uniformResourceIdentifier: this.ia5str(),
    iPAddress: this.octstr(),
    registeredID: this.objid()
  });
});

/**
 * #### AnotherName
 * Also referenced as "OtherName"
 */

var AnotherName =
rfc5280.AnotherName = asn1.define('AnotherName', function() {
  this.seq().obj(
    this.key('typeId').objid(),
    this.key('value').explicit(0).any()
  );
});

/**
 * #### ORAddress
 */

var ORAddress =
rfc5280.ORAddress = asn1.define('ORAddress', function() {
  this.seq().obj(
    this.key('builtInStandardAttributes').use(BuiltInStandardAttributes),
    this.key('builtInDomainDefinedAttributes').optional().use(BuiltInDomainDefinedAttributes),
    this.key('extensionAttributes').optional().use(ExtensionAttributes)
  );
});

/**
 * ##### BuiltInStandardAttributes
 */

var BuiltInStandardAttributes =
rfc5280.BuiltInStandardAttributes = asn1.define('BuiltInStandardAttributes', function() {
  this.seq().obj(
    this.key('countryName').optional().use(CountryName),
    this.key('administrationDomainName').optional().use(AdministrationDomainName),
    this.key('networkAddress').optional().use(NetworkAddress),
    this.key('terminalIdentifier').optional().use(TerminalIdentifier),
    this.key('privateDomainName').optional().use(PrivateDomainName),
    this.key('organizationName').optional().use(OrganizationName),
    this.key('numericUserIdentifier').optional().use(NumericUserIdentifier),
    this.key('personalName').optional().use(PersonalName),
    this.key('organizationalUnitNames').optional().use(OrganizationalUnitNames)
  );
});

/**
 * ###### CountryName
 */

var CountryName =
rfc5280.CountryName = asn1.define('CountryName', function() {
  this.choice({
    x121DccCode: this.numstr(),
    iso3166Alpha2Code: this.printstr()
  });
});

/**
 * ###### AdministrationDomainName
 */

var AdministrationDomainName =
rfc5280.AdministrationDomainName = asn1.define('AdministrationDomainName', function() {
  this.choice({
    numeric: this.numstr(),
    printable: this.printstr()
  });
});

/**
 * ###### NetworkAddress
 */

var NetworkAddress =
rfc5280.NetworkAddress = asn1.define('NetworkAddress', function() {
  this.use(X121Address);
});

/**
 * ###### X121Address
 */

var X121Address =
rfc5280.X121Address = asn1.define('X121Address', function() {
  this.numstr();
});

/**
 * ###### TerminalIdentifier
 */

var TerminalIdentifier =
rfc5280.TerminalIdentifier = asn1.define('TerminalIdentifier', function() {
  this.printstr();
});

/**
 * ###### PrivateDomainName
 */

var PrivateDomainName =
rfc5280.PrivateDomainName = asn1.define('PrivateDomainName', function() {
  this.choice({
    numeric: this.numstr(),
    printable: this.printstr()
  });
});

/**
 * ###### OrganizationName
 */

var OrganizationName =
rfc5280.OrganizationName = asn1.define('OrganizationName', function() {
  this.printstr();
});

/**
 * ###### NumericUserIdentifier
 */

var NumericUserIdentifier =
rfc5280.NumericUserIdentifier = asn1.define('NumericUserIdentifier', function() {
  this.numstr();
});

/**
 * ###### PersonalName
 */

var PersonalName =
rfc5280.PersonalName = asn1.define('PersonalName', function() {
  this.set().obj(
    this.key('surname').implicit().printstr(),
    this.key('givenName').implicit().printstr(),
    this.key('initials').implicit().printstr(),
    this.key('generationQualifier').implicit().printstr()
  );
});

/**
 * ###### OrganizationalUnitNames
 */

var OrganizationalUnitNames =
rfc5280.OrganizationalUnitNames = asn1.define('OrganizationalUnitNames', function() {
  this.seqof(OrganizationalUnitName);
});

/**
 * ####### OrganizationalUnitName
 */

var OrganizationalUnitName =
rfc5280.OrganizationalUnitName = asn1.define('OrganizationalUnitName', function() {
  this.printstr();
});

/**
 * ##### BuiltInDomainDefinedAttributes
 */

var BuiltInDomainDefinedAttributes =
rfc5280.BuiltInDomainDefinedAttributes = asn1.define('BuiltInDomainDefinedAttributes', function() {
  this.seqof(BuiltInDomainDefinedAttribute);
});

/**
 * ###### BuiltInDomainDefinedAttribute
 */

var BuiltInDomainDefinedAttribute =
rfc5280.BuiltInDomainDefinedAttribute = asn1.define('BuiltInDomainDefinedAttribute', function() {
  this.seq().obj(
    this.key('type').printstr(),
    this.key('value').printstr()
  );
});

/**
 * ## ExtensionAttributes
 */

var ExtensionAttributes =
rfc5280.ExtensionAttributes = asn1.define('ExtensionAttributes', function() {
  this.seqof(ExtensionAttribute);
});

/**
 * ### ExtensionAttribute
 */

var ExtensionAttribute =
rfc5280.ExtensionAttribute = asn1.define('ExtensionAttribute', function() {
  this.seq().obj(
    this.key('extensionAttributeType').implicit().int(),
    this.key('extensionAttributeValue').any().implicit().int()
  );
});

/**
 * #### EDIPartyName
 */

var EDIPartyName =
rfc5280.EDIPartyName = asn1.define('EDIPartyName', function() {
  this.seq().obj(
    this.key('nameAssigner').optional().use(DirectoryString),
    this.key('partyName').use(DirectoryString)
  );
});

/**
 * ##### DirectoryString
 */

var DirectoryString =
rfc5280.DirectoryString = asn1.define('DirectoryString', function() {
  this.choice({
    teletexString: this.t61str(),
    printableString: this.printstr(),
    universalString: this.unistr(),
    utf8String: this.utf8str(),
    bmpString: this.bmpstr()
  });
});

/**
 * 2
 * # Subject Key Identifier
 */

var SubjectKeyIdentifier =
rfc5280.SubjectKeyIdentifier = asn1.define('SubjectKeyIdentifier', function() {
  this.use(KeyIdentifier);
});

/**
 * 3
 * # Key Usage
 */

var KeyUsage =
rfc5280.KeyUsage = asn1.define('KeyUsage', function() {
  this.bitstr();
});

/**
 * 4
 * # Certificate Policies
 */

var CertificatePolicies =
rfc5280.CertificatePolicies = asn1.define('CertificatePolicies', function() {
  this.seqof(PolicyInformation);
});

/**
 * ## Policy Information
 */

var PolicyInformation =
rfc5280.PolicyInformation = asn1.define('PolicyInformation', function() {
  this.seq().obj(
    this.key('policyIdentifier').use(CertPolicyId),
    this.key('policyQualifiers').use(PolicyQualifiers)
  );
});

/**
 * ## Cert Policy Id
 */

var CertPolicyId =
rfc5280.CertPolicyId = asn1.define('CertPolicyId', function() {
  this.objid();
});


/**
 * ### Policy Qualifiers
 */

var PolicyQualifiers =
rfc5280.PolicyQualifiers = asn1.define('PolicyQualifiers', function() {
  this.seqof(PolicyQualifierInfo);
});

/**
 * #### Policy Qualifier Info
 */

var PolicyQualifierInfo =
rfc5280.PolicyQualifierInfo = asn1.define('PolicyQualifierInfo', function() {
  this.seq().obj(
    this.key('policyQualifierId').use(PolicyQualifierId),
    this.key('qualifier').any().use(PolicyQualifierId)
  );
});

/**
 * ##### Policy Qualifier Id
 */

var PolicyQualifierId =
rfc5280.PolicyQualifierId = asn1.define('PolicyQualifierId', function() {
  this.objid();
});

/**
 * 5
 * # Policy Mappings
 */

var PolicyMappings =
rfc5280.PolicyMappings = asn1.define('PolicyMappings', function() {
  this.seqof(PolicyMapping);
});

/**
 * ## Policy Mapping
 */

var PolicyMapping =
rfc5280.PolicyMapping = asn1.define('PolicyMapping', function() {
  this.seq().obj(
    this.key('issuerDomainPolicy').use(CertPolicyId),
    this.key('subjectDomainPolicy').use(CertPolicyId)
  );
});

/**
 * 6
 * # Subject Alternative Name
 */

var SubjectAlternativeName =
rfc5280.SubjectAlternativeName = asn1.define('SubjectAlternativeName', function() {
  this.use(GeneralNames);
});

/**
 * 7
 * # Issuer Alternative Name
 */

var IssuerAlternativeName =
rfc5280.IssuerAlternativeName = asn1.define('IssuerAlternativeName', function() {
  this.use(GeneralNames);
});

/**
 * 8
 * # Subject Directory Attributes
 */

var SubjectDirectoryAttributes =
rfc5280.SubjectDirectoryAttributes = asn1.define('SubjectDirectoryAttributes', function() {
  this.seqof(Attribute);
});

/**
 * ## Attribute
 */

var AttributeTypeAndValue = rfc5280.AttributeTypeAndValue = rfc3280.AttributeTypeAndValue;
var Attribute = rfc5280.AttributeTypeAndValue = AttributeTypeAndValue;

/**
 * 9
 * # Basic Constraints
 */

var BasicConstraints =
rfc5280.BasicConstraints = asn1.define('BasicConstraints', function() {
  this.seq().obj(
    this.key('cA').bool().def(false),
    this.key('pathLenConstraint').optional().int()
  );
});

/**
 * 10
 * # Name Constraints
 */

var NameConstraints =
rfc5280.NameConstraints = asn1.define('NameConstraints', function() {
  this.seq().obj(
    this.key('permittedSubtrees').optiona().use(GeneralSubtrees),
    this.key('excludedSubtrees').optional().use(GeneralSubtrees)
  );
});

/**
 * ## General Subtrees
 */

var GeneralSubtrees =
rfc5280.GeneralSubtrees = asn1.define('GeneralSubtrees', function() {
  this.seqof(GeneralSubtree);
});

/**
 * ### General Subtree
 */

var GeneralSubtree =
rfc5280.GeneralSubtree = asn1.define('GeneralSubtree', function() {
  this.seq().obj(
    this.key('base').use(GeneralName),
    this.key('minimum').default(0).use(BaseDistance),
    this.key('maximum').optional().use(BaseDistance)
  );
});

/**
 * #### Base Distance
 */

var BaseDistance =
rfc5280.BaseDistance = asn1.define('BaseDistance', function() {
  this.int();
});

/**
 * 11
 * # Policy Constraints
 */

var PolicyConstraints =
rfc5280.PolicyConstraints = asn1.define('PolicyConstraints', function() {
  this.seq().obj(
    this.key('requireExplicitPolicy').optional().use(SkipCerts),
    this.key('inhibitPolicyMapping').optional().use(SkipCerts)
  );
});

/**
 * ## Skip Certs
 */

var SkipCerts =
rfc5280.SkipCerts = asn1.define('SkipCerts', function() {
  this.int();
});

/**
 * 12
 * # Extended Key Usage
 */

var ExtendedKeyUsage =
rfc5280.ExtendedKeyUsage = asn1.define('ExtendedKeyUsage', function() {
  this.seqof(KeyPurposeId);
});

/**
 * ## Key Purpose Id
 */

var KeyPurposeId =
rfc5280.KeyPurposeId = asn1.define('KeyPurposeId', function() {
  this.objid();
});

/**
 * 13
 * # CRL Distribution Points
 */

var CRLDistributionPoints =
rfc5280.CRLDistributionPoints = asn1.define('CRLDistributionPoints', function() {
  this.seqof(DistributionPoint);
});

/**
 * ## Distribution Point
 */

var DistributionPoint =
rfc5280.DistributionPoint = asn1.define('DistributionPoint', function() {
  this.seq().obj(
    this.key('distributionPoint').optional().use(DistributionPointName),
    this.key('reasons').optional().use(ReasonFlags),
    this.key('cRLIssuer').optional().use(GeneralNames)
  );
});

/**
 * ### Distribution Point Name
 */

var DistributionPointName =
rfc5280.DistributionPointName = asn1.define('DistributionPointName', function() {
  this.choice({
    // XXX Workaround parser error:
    _unknown: this.any(),
    fullName: this.use(GeneralNames),
    nameRelativeToCRLIssuer: this.use(RelativeDistinguishedName)
  });
});

/**
 * #### Relative Distinguished Name
 */

var RelativeDistinguishedName =
rfc5280.RelativeDistinguishedName = rfc3280.RelativeDistinguishedName;

var RelativeDistinguishedName =
rfc5280.RelativeDistinguishedName = asn1.define('RelativeDistinguishedName', function() {
  this.setof(AttributeTypeAndValue);
});

/**
 * ### Reason Flags
 */

var ReasonFlags =
rfc5280.ReasonFlags = asn1.define('ReasonFlags', function() {
  this.bitstr();
});

/**
 * 14
 * # Inhibit anyPolicy
 */

var InhibitAnyPolicy =
rfc5280.InhibitAnyPolicy = asn1.define('InhibitAnyPolicy', function() {
  this.use(SkipCerts);
});

/**
 * 15
 * # Freshest CRL
 */

var FreshestCRL =
rfc5280.FreshestCRL = asn1.define('FreshestCRL', function() {
  this.use(CRLDistributionPoints);
});

/**
 * Private Internet Extensions
 */

/**
 * 16
 * # Authority Information Access
 */

var AuthorityInformationAccess =
rfc5280.AuthorityInformationAccess = asn1.define('AuthorityInformationAccess', function() {
  this.seqof(AccessDescription);
});

/**
 * ## Access Description
 */

var AccessDescription =
rfc5280.AccessDescription = asn1.define('AccessDescription', function() {
  this.seq().obj(
    this.key('accessMethod').objid(),
    this.key('accessLocation').use(GeneralName)
  );
});

/**
 * 17
 * # Subject Information Access
 */

var SubjectInformationAccess =
rfc5280.SubjectInformationAccess = asn1.define('SubjectInformationAccess', function() {
  this.seqof(AccessDescription);
});

/**
 * XXX
 * # Unknown Extension
 */

var UnknownExtension =
rfc5280.UnknownExtension = asn1.define('UnknownExtension', function() {
  this.any();
});

/**
 * CRL Extensions
 */

/**
 * 1
 * # CRL Number
 */

var CRLNumber =
rfc5280.CRLNumber = asn1.define('CRLNumber', function() {
  this.int();
});

/**
 * 2
 * # Delta CRL Indicator
 */

var DeltaCRLIndicator =
rfc5280.DeltaCRLIndicator = asn1.define('DeltaCRLIndicator', function() {
  this.use(CRLNumber);
});

/**
 * 3
 * # Issuing Distribution Point
 */

var IssuingDistributionPoint =
rfc5280.IssuingDistributionPoint = asn1.define('IssuingDistributionPoint', function() {
  this.seq().obj(
    this.key('distributionPoint').use(DistributionPointName),
    this.key('onlyContainsUserCerts').def(false).bool(),
    this.key('onlyContainsCACerts').def(false).bool(),
    this.key('onlySomeReasons').use(ReasonFlags),
    this.key('indirectCRL').def(false).bool(),
    this.key('onlyContainsAttributeCerts').def(false).bool()
  );
});

/**
 * 4
 * # Reason Code
 */

var ReasonCode =
rfc5280.ReasonCode = asn1.define('ReasonCode', function() {
  this.enum();
});

/**
 * 5
 * # Invalidity Date
 */

var InvalidityDate =
rfc5280.InvalidityDate = asn1.define('InvalidityDate', function() {
  this.gentime();
});

/**
 * 6
 * # Certificate Issuer
 */

var CertificateIssuer =
rfc5280.CertificateIssuer = asn1.define('CertificateIssuer', function() {
  this.use(GeneralNames);
});

/**
 * Create Extension Decoders
 */

Object.keys(rfc5280.extensions).forEach(function(typeName) {
  var type = rfc5280.extensions[typeName];
  Object.keys(type).forEach(function(suffix) {
    var id, prop, schemaName, schema, parse, execute;

    if (suffix === 'prefix')
      return;

    var prefix = type.prefix;
    var name = type[suffix];

    if (typeof name === 'object') {
      var obj = name;
      name = obj.name;
      parse = obj.parse;
      execute = obj.execute;
    }

    id = prefix.concat(suffix).join('.');

    if (/^[A-Z]+ /.test(name)) {
      // CRL Distribution Points - > CRLDistributionPoints
      prop = name.replace(/ /g, '');
    } else {
      prop = (name[0].toLowerCase()) + name.substring(1).replace(/ /g, '');
    }

    schemaName = name.replace(/ /g, '');
    schema = rfc5280[schemaName];

    rfc5280.extensions[id] = {
      typeName: typeName,
      prefix: prefix,
      suffix: suffix,
      id: id,
      name: name,
      prop: prop,
      schemaName: schemaName,
      schema: schema,
      parse: parse,
      execute: execute
    };
  });
});

/**
 * Parse all TBSCertificate's extensions
 */

rfc5280.decodeExtensions = function(cert, format, options) {
  var tbsCertificate = cert.tbsCertificate;

  if (format && typeof format === 'object') {
    options = format;
    format = null;
  }

  format = format || 'der';

  if (!tbsCertificate) {
    tbsCertificate = cert;
    cert = null;
  }

  var edata, eid, ext, decoded, errors, data;

  var output = {};
  output.unknown = [];

  for (var i = 0; i < tbsCertificate.extensions.length; i++) {
    edata = tbsCertificate.extensions[i];
    eid = edata.extnID.join('.');

    if (ext = rfc5280.extensions[eid]) {
      // Parse Extension
      decoded = ext.schema.decode(edata.extnValue, format, options);

      // partial: true throws everything onto: { result: ..., errors: ... }
      if (options.partial && decoded.result) {
        errors = decoded.errors;
        if (Array.isArray(decoded.result)) {
          decoded = decoded.result.map(function(decoded) {
            decoded.errors.forEach(function(error) {
              errors.push(error);
            });
            return decoded.result;
          });
        } else {
          decoded = decoded.result;
        }
      }

      // If the Extension needs extra parsing (i.e. bitstrs)
      data = {
        decoded: ext.parse
          ? ext.parse(decoded, cert, ext, edata)
          : decoded,
        raw: edata.extnValue
      };

      // Tack on some useful info

      // Comment for debugging:
      // data.edata = edata;
      // data.ext = ext;

      // Execute Behavior for Cert
      if (ext.execute) {
        data.execute = ext.execute;
      }

      // Add errors for partial: true
      if (options.partial && errors) {
        data.errors = errors;
      }

      // Add our decoded extension to the output
      output[ext.prop] = data;
    } else {
      // Add unknown extension:
      output.unknown.push(edata);
    }
  }

  output.verified = !output.unknown.filter(function(ext) {
    return ext.critical;
  }).length;

  return output;
};
