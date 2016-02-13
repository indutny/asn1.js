var assert = require('assert');
var asn1 = require('../../../');
var rfc5280 = require('..');

var Buffer = require('buffer').Buffer;

describe('asn1.js RFC5280', function() {

  it('should decode Certificate', function() {
    var data = new Buffer(
      '308204763082035ea0030201020208462e4256bb1194dc300d06092a864886f70d0101' +
      '0505003049310b300906035504061302555331133011060355040a130a476f6f676c65' +
      '20496e63312530230603550403131c476f6f676c6520496e7465726e65742041757468' +
      '6f72697479204732301e170d3134303733303132303434305a170d3134313032383030' +
      '303030305a3068310b30090603550406130255533113301106035504080c0a43616c69' +
      '666f726e69613116301406035504070c0d4d6f756e7461696e20566965773113301106' +
      '0355040a0c0a476f6f676c6520496e633117301506035504030c0e7777772e676f6f67' +
      '6c652e636f6d30820122300d06092a864886f70d01010105000382010f003082010a02' +
      '82010100b7894e02f9ba01e07889d670fd3618d6022efc96c9d9deae2e800aa19f4b17' +
      '20c371b9996b2efc12fa191b60a92afe76e80e5d9d47280cbc46a4cd9cf454503fefcf' +
      'cd2e1c8b113a89bcd1f1427ae793bbd0d1e077bc963ff2ceb2b0c9ab68196fce1b2f40' +
      '0dc77d6294a7c0d50ff104cf92ee837d5c484a3ba0ce76b9c018cf96545f7e27518232' +
      '57874945f87b69bac902ce4b378746953c619db909e73fd2f5e2dd009c5c748ec22fcb' +
      'd6648fe60a5805e98ab8cd65ab0eb0772d7a19aefdc24c9a3933692ca695e7b493f8ac' +
      '7aab8e5d1229f071cf08ac0b6c641704a74747faacfb857b68359fc1a98c777fb5eb3e' +
      '9c90d6a13b78f42d6d797fd74f03c30203010001a38201413082013d301d0603551d25' +
      '0416301406082b0601050507030106082b0601050507030230190603551d1104123010' +
      '820e7777772e676f6f676c652e636f6d306806082b06010505070101045c305a302b06' +
      '082b06010505073002861f687474703a2f2f706b692e676f6f676c652e636f6d2f4749' +
      '4147322e637274302b06082b06010505073001861f687474703a2f2f636c69656e7473' +
      '312e676f6f676c652e636f6d2f6f637370301d0603551d0e04160414e43d6cc20c12e9' +
      '7c1920533676ef287737d8884a300c0603551d130101ff04023000301f0603551d2304' +
      '18301680144add06161bbcf668b576f581b6bb621aba5a812f30170603551d20041030' +
      '0e300c060a2b06010401d67902050130300603551d1f042930273025a023a021861f68' +
      '7474703a2f2f706b692e676f6f676c652e636f6d2f47494147322e63726c300d06092a' +
      '864886f70d010105050003820101002d5501bd33f7b6e06117e53ccf21703565f29ab7' +
      '8642a771effa4369f32938b45f04208d88a1046ba0a726622e864143c8dac38392430d' +
      'fbea1b7d41c1e27dd43438a47d36c4a048de318be442abed5f60373687d01b7fefc43e' +
      '0aacf620b11a69fb237aaa4dc33b97bc0eb39b1abe6902b1518253addda25037389c26' +
      '0ef2808be7f702f47a6466d6f3b35764f088c94e0a2b9ee403602ae21cbad3fd8e873e' +
      '9e817945a3d23fd2b35579cce19ea7f8815d166f3e46d53eed25ef391a912bb715af64' +
      'e43e124f98be487f9d222954a5bebc8d5ca384c7128c6dabffb11150a7d2a62ce565b8' +
      'a02a6c4c8ecfc7ac7065c1979cb8d50eabd5d36c72a5396e712e',
      'hex');

    var res = rfc5280.Certificate.decode(data, 'der');

    var tbs = res.tbsCertificate;
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
    var data = new Buffer(
      '308203e33082036aa00302010202104d955d20af85c49f6925fbab7c665f89300a0608' +
      '2a8648ce3d0403033081ca310b300906035504061302555331173015060355040a130e' +
      '566572695369676e2c20496e632e311f301d060355040b1316566572695369676e2054' +
      '72757374204e6574776f726b313a3038060355040b1331286329203230303720566572' +
      '695369676e2c20496e632e202d20466f7220617574686f72697a656420757365206f6e' +
      '6c79314530430603550403133c566572695369676e20436c6173732033205075626c69' +
      '63205072696d6172792043657274696669636174696f6e20417574686f72697479202d' +
      '204734301e170d3132313232303030303030305a170d3232313231393233353935395a' +
      '30818b310b3009060355040613025553311d301b060355040a131453796d616e746563' +
      '20436f72706f726174696f6e311f301d060355040b131653796d616e74656320547275' +
      '7374204e6574776f726b313c303a0603550403133353796d616e74656320436c617373' +
      '203320454343203235362062697420457874656e6465642056616c69646174696f6e20' +
      '43413059301306072a8648ce3d020106082a8648ce3d03010703420004dd043db2f290' +
      '9397c6e9bbbc91db51f0a386edfbc6d38593320549e00483619651ff5721ae0bda0ee7' +
      '04a17fdb2a1cbdca9835c5717340cde86aab54844326e2a382016d3082016930120603' +
      '551d130101ff040830060101ff02010030370603551d1f0430302e302ca02aa0288626' +
      '687474703a2f2f63726c2e77732e73796d616e7465632e636f6d2f706361332d67342e' +
      '63726c300e0603551d0f0101ff040403020106303706082b06010505070101042b3029' +
      '302706082b06010505073001861b687474703a2f2f6f6373702e77732e73796d616e74' +
      '65632e636f6d30650603551d20045e305c305a0604551d20003052302606082b060105' +
      '05070201161a687474703a2f2f7777772e73796d617574682e636f6d2f637073302806' +
      '082b06010505070202301c1a1a687474703a2f2f7777772e73796d617574682e636f6d' +
      '2f727061302a0603551d1104233021a41f301d311b30190603550403131253594d432d' +
      '4543432d43412d703235362d33301d0603551d0e041604144813651794ec9e162a2a74' +
      '5ce8532db4fb83eb8e301f0603551d23041830168014b31691fdeea66ee4b52e498f87' +
      '788180ece5b1b5300a06082a8648ce3d040303036700306402305c9bee83a3764d8c2d' +
      '054c8234bab3bece8fe8c33481fb4077e8346c5b172b3badd5a7a3d2f366c24fb2b0c8' +
      '76988fbf02304fc22fce92c5a9bdce7d4ed41b3b6624ea4ecd82af544a88efe3bf3a93' +
      '6354217d1230d232cdabc981b0a711437b4566',
      'hex');
    var res = rfc5280.Certificate.decode(data, 'der');

    var tbs = res.tbsCertificate;
    assert.equal(tbs.version, 'v3');
    assert.deepEqual(tbs.serialNumber,
                     new asn1.bignum('4d955d20af85c49f6925fbab7c665f89', 16));
    assert.equal(tbs.signature.algorithm.join('.'),
                 '1.2.840.10045.4.3.3');  // RFC5754
    var spki = rfc5280.SubjectPublicKeyInfo.encode(tbs.subjectPublicKeyInfo,
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
    var data = new Buffer('305a302b06082b06010505073002861f687474703a2f2f70' +
                          '6b692e676f6f676c652e636f6d2f47494147322e63727430' +
                          '2b06082b06010505073001861f687474703a2f2f636c6965' +
                          '6e7473312e676f6f676c652e636f6d2f6f637370',
                          'hex');

    var info = rfc5280.AuthorityInfoAccessSyntax.decode(data, 'der');

    assert(info[0].accessMethod);
  });

  it('should decode directoryName in GeneralName', function() {
    var data = new Buffer('a411300f310d300b06022a03160568656c6c6f', 'hex');

    var name = rfc5280.GeneralName.decode(data, 'der');
    assert.equal(name.type, 'directoryName');
  });

  it('should decode Certificate Extensions', function() {
    var chain = [];
    var cert;
    var extensions = {}

    chain[0] = new Buffer(
      '3082052030820408a003020102020727a49d05046d62300d06092a864886f70d01010b' +
      '05003081b4310b30090603550406130255533110300e060355040813074172697a6f6e' +
      '61311330110603550407130a53636f74747364616c65311a3018060355040a1311476f' +
      '44616464792e636f6d2c20496e632e312d302b060355040b1324687474703a2f2f6365' +
      '7274732e676f64616464792e636f6d2f7265706f7369746f72792f3133303106035504' +
      '03132a476f204461646479205365637572652043657274696669636174652041757468' +
      '6f72697479202d204732301e170d3134303432363132333532365a170d313630343236' +
      '3132333532365a303a3121301f060355040b1318446f6d61696e20436f6e74726f6c20' +
      '56616c6964617465643115301306035504030c0c2a2e6269747061792e636f6d308201' +
      '22300d06092a864886f70d01010105000382010f003082010a0282010100e2a5dd4aea' +
      '959c1d0fb016e6e05bb7011e741cdc61918c61f9625a2f682f485f0e862ea63db61cc9' +
      '161753127504de800604df36b10f46cb17ab6cb99dba8aa45a36adfb901a2fc380c89e' +
      '234bce18de6639b883e9339801673efaee1f2df77eeb82f7c39c96a2f8ef4572b634c2' +
      '03d9be8fd1e0036d32fb38b6b9b5ecd5a0684345c7e9ffc5d26bc6fd69aa6619f77bad' +
      'aa4bfb989478fb2f41aa92782e40b34ba9ac4549a4e6fda76b5fc4a581853bd0de5fb5' +
      'a2c6dfdc12cdfadb54e9636a6d1223705924b8be566b81ac7921078cf590a146ae397a' +
      '84908ef4fc83ff5715a44ab59e9258674d90113bb607b8d81eb268e4c6ce849497c765' +
      '21795b0873950203010001a38201ae308201aa300f0603551d130101ff040530030101' +
      '00301d0603551d250416301406082b0601050507030106082b06010505070302300e06' +
      '03551d0f0101ff0404030205a030360603551d1f042f302d302ba029a0278625687474' +
      '703a2f2f63726c2e676f64616464792e636f6d2f676469673273312d34392e63726c30' +
      '530603551d20044c304a3048060b6086480186fd6d010717013039303706082b060105' +
      '05070201162b687474703a2f2f6365727469666963617465732e676f64616464792e63' +
      '6f6d2f7265706f7369746f72792f307606082b06010505070101046a3068302406082b' +
      '060105050730018618687474703a2f2f6f6373702e676f64616464792e636f6d2f3040' +
      '06082b060105050730028634687474703a2f2f6365727469666963617465732e676f64' +
      '616464792e636f6d2f7265706f7369746f72792f67646967322e637274301f0603551d' +
      '2304183016801440c2bd278ecc348330a233d7fb6cb3f0b42c80ce30230603551d1104' +
      '1c301a820c2a2e6269747061792e636f6d820a6269747061792e636f6d301d0603551d' +
      '0e0416041485454e3b4072e2f58e377438988b5229387e967a300d06092a864886f70d' +
      '01010b050003820101002d0a7ef97f988905ebbbad4e9ffb690352535211d679251611' +
      '9838b55f24ff9fa4e93b6187b8517cbb0477457d3378078ef66057abe41bcafeb142ec' +
      '52443a94b88114fa069f725c6198581d97af16352727f4f35e7f2110faa41a0511bcfd' +
      'f8e3f4a3a310278c150b10f32a962c81e8f3d5374d9cb56d893027ff4fa4e3c3e6384c' +
      '1f1557ceea6fca9cbc0c110748c08b82d8f0ed9a579637ee43a2d8fec3b5b04d1f3c8f' +
      '1a3e2088da2274b6bc60948bbe744a7f8b942b41f0ae9b4afaeefbb7e0f04a0587b52e' +
      'fb6ebfa2d970b9de56a068575e4bf0cf824618dc17bbeaa2cdd25d65970a9f1a06fc9f' +
      'ffb466a10c9568cd651795bc2c7996975027bdbaba',
    'hex');

    chain[1] = new Buffer(
      '308204d0308203b8a003020102020107300d06092a864886f70d01010b050030818331' +
      '0b30090603550406130255533110300e060355040813074172697a6f6e613113301106' +
      '03550407130a53636f74747364616c65311a3018060355040a1311476f44616464792e' +
      '636f6d2c20496e632e3131302f06035504031328476f20446164647920526f6f742043' +
      '6572746966696361746520417574686f72697479202d204732301e170d313130353033' +
      '3037303030305a170d3331303530333037303030305a3081b4310b3009060355040613' +
      '0255533110300e060355040813074172697a6f6e61311330110603550407130a53636f' +
      '74747364616c65311a3018060355040a1311476f44616464792e636f6d2c20496e632e' +
      '312d302b060355040b1324687474703a2f2f63657274732e676f64616464792e636f6d' +
      '2f7265706f7369746f72792f313330310603550403132a476f20446164647920536563' +
      '75726520436572746966696361746520417574686f72697479202d2047323082012230' +
      '0d06092a864886f70d01010105000382010f003082010a0282010100b9e0cb10d4af76' +
      'bdd49362eb3064b881086cc304d962178e2fff3e65cf8fce62e63c521cda16454b55ab' +
      '786b63836290ce0f696c99c81a148b4ccc4533ea88dc9ea3af2bfe80619d7957c4cf2e' +
      'f43f303c5d47fc9a16bcc3379641518e114b54f828bed08cbef030381ef3b026f86647' +
      '636dde7126478f384753d1461db4e3dc00ea45acbdbc71d9aa6f00dbdbcd303a794f5f' +
      '4c47f81def5bc2c49d603bb1b24391d8a4334eeab3d6274fad258aa5c6f4d5d0a6ae74' +
      '05645788b54455d42d2a3a3ef8b8bde9320a029464c4163a50f14aaee77933af0c2007' +
      '7fe8df0439c269026c6352fa77c11bc87487c8b993185054354b694ebc3bd3492e1fdc' +
      'c1d252fb0203010001a382011a30820116300f0603551d130101ff040530030101ff30' +
      '0e0603551d0f0101ff040403020106301d0603551d0e0416041440c2bd278ecc348330' +
      'a233d7fb6cb3f0b42c80ce301f0603551d230418301680143a9a8507106728b6eff6bd' +
      '05416e20c194da0fde303406082b0601050507010104283026302406082b0601050507' +
      '30018618687474703a2f2f6f6373702e676f64616464792e636f6d2f30350603551d1f' +
      '042e302c302aa028a0268624687474703a2f2f63726c2e676f64616464792e636f6d2f' +
      '6764726f6f742d67322e63726c30460603551d20043f303d303b0604551d2000303330' +
      '3106082b06010505070201162568747470733a2f2f63657274732e676f64616464792e' +
      '636f6d2f7265706f7369746f72792f300d06092a864886f70d01010b05000382010100' +
      '087e6c9310c838b896a9904bffa15f4f04ef6c3e9c8806c9508fa673f757311bbebce4' +
      '2fdbf8bad35be0b4e7e679620e0ca2d76a637331b5f5a848a43b082da25d90d7b47c25' +
      '4f115630c4b6449d7b2c9de55ee6ef0c61aabfe42a1bee849eb8837dc143ce44a71370' +
      '0d911ff4c813ad8360d9d872a873241eb5ac220eca17896258441bab892501000fcdc4' +
      '1b62db51b4d30f512a9bf4bc73fc76ce36a4cdd9d82ceaae9bf52ab290d14d75188a3f' +
      '8a4190237d5b4bfea403589b46b2c3606083f87d5041cec2a190c3bbef022fd21554ee' +
      '4415d90aaea78a33edb12d763626dc04eb9ff7611f15dc876fee469628ada1267d0a09' +
      'a72e04a38dbcf8bc043001',
      'hex');

    chain[2] = new Buffer(
      '3082047d30820365a00302010202031be715300d06092a864886f70d01010b05003063' +
      '310b30090603550406130255533121301f060355040a131854686520476f2044616464' +
      '792047726f75702c20496e632e3131302f060355040b1328476f20446164647920436c' +
      '61737320322043657274696669636174696f6e20417574686f72697479301e170d3134' +
      '303130313037303030305a170d3331303533303037303030305a308183310b30090603' +
      '550406130255533110300e060355040813074172697a6f6e6131133011060355040713' +
      '0a53636f74747364616c65311a3018060355040a1311476f44616464792e636f6d2c20' +
      '496e632e3131302f06035504031328476f20446164647920526f6f7420436572746966' +
      '696361746520417574686f72697479202d20473230820122300d06092a864886f70d01' +
      '010105000382010f003082010a0282010100bf716208f1fa5934f71bc918a3f7804958' +
      'e9228313a6c52043013b84f1e685499f27eaf6841b4ea0b4db7098c73201b1053e074e' +
      'eef4fa4f2f593022e7ab19566be28007fcf316758039517be5f935b6744ea98d8213e4' +
      'b63fa90383faa2be8a156a7fde0bc3b6191405caeac3a804943b467c320df3006622c8' +
      '8d696d368c1118b7d3b21c60b438fa028cced3dd4607de0a3eeb5d7cc87cfbb02b53a4' +
      '926269512505611a44818c2ca9439623dfac3a819a0e29c51ca9e95d1eb69e9e300a39' +
      'cef18880fb4b5dcc32ec85624325340256270191b43b702a3f6eb1e89c88017d9fd4f9' +
      'db536d609dbf2ce758abb85f46fccec41b033c09eb49315c6946b3e0470203010001a3' +
      '82011730820113300f0603551d130101ff040530030101ff300e0603551d0f0101ff04' +
      '0403020106301d0603551d0e041604143a9a8507106728b6eff6bd05416e20c194da0f' +
      'de301f0603551d23041830168014d2c4b0d291d44c1171b361cb3da1fedda86ad4e330' +
      '3406082b0601050507010104283026302406082b060105050730018618687474703a2f' +
      '2f6f6373702e676f64616464792e636f6d2f30320603551d1f042b30293027a025a023' +
      '8621687474703a2f2f63726c2e676f64616464792e636f6d2f6764726f6f742e63726c' +
      '30460603551d20043f303d303b0604551d20003033303106082b060105050702011625' +
      '68747470733a2f2f63657274732e676f64616464792e636f6d2f7265706f7369746f72' +
      '792f300d06092a864886f70d01010b05000382010100590b53bd928611a7247bed5b31' +
      'cf1d1f6c70c5b86ebe4ebbf6be9750e1307fba285c6294c2e37e33f7fb427685db951c' +
      '8c225875090c886567390a1609c5a03897a4c523933fb418a601064491e3a76927b45a' +
      '257f3ab732cddd84ff2a382933a4dd67b285fea188201c5089c8dc2af64203374ce688' +
      'dfd5af24f2b1c3dfccb5ece0995eb74954203c94180cc71c521849a46de1b3580bc9d8' +
      'ecd9ae1c328e28700de2fea6179e840fbd5770b35ae91fa08653bbef7cff690be048c3' +
      'b7930bc80a54c4ac5d1467376ccaa52f310837aa6e6f8cbc9be2575d2481af97979c84' +
      'ad6cac374c66f361911120e4be309f7aa42909b0e1345f6477184051df8c30a6af',
      'hex');

    chain[3] = new Buffer(
      '30820400308202e8a003020102020100300d06092a864886f70d01010505003063310b' +
      '30090603550406130255533121301f060355040a131854686520476f20446164647920' +
      '47726f75702c20496e632e3131302f060355040b1328476f20446164647920436c6173' +
      '7320322043657274696669636174696f6e20417574686f72697479301e170d30343036' +
      '32393137303632305a170d3334303632393137303632305a3063310b30090603550406' +
      '130255533121301f060355040a131854686520476f2044616464792047726f75702c20' +
      '496e632e3131302f060355040b1328476f20446164647920436c617373203220436572' +
      '74696669636174696f6e20417574686f7269747930820120300d06092a864886f70d01' +
      '010105000382010d00308201080282010100de9dd7ea571849a15bebd75f4886eabedd' +
      'ffe4ef671cf46568b35771a05e77bbed9b49e970803d561863086fdaf2ccd03f7f0254' +
      '225410d8b281d4c0753d4b7fc777c33e78ab1a03b5206b2f6a2bb1c5887ec4bb1eb0c1' +
      'd845276faa3758f78726d7d82df6a917b71f72364ea6173f659892db2a6e5da2fe88e0' +
      '0bde7fe58d15e1ebcb3ad5e212a2132dd88eaf5f123da0080508b65ca565380445991e' +
      'a3606074c541a572621b62c51f6f5f1a42be025165a8ae23186afc7803a94d7f80c3fa' +
      'ab5afca140a4ca1916feb2c8ef5e730dee77bd9af67998bcb10767a2150ddda058c644' +
      '7b0a3e62285fba41075358cf117e3874c5f8ffb569908f8474ea971baf020103a381c0' +
      '3081bd301d0603551d0e04160414d2c4b0d291d44c1171b361cb3da1fedda86ad4e330' +
      '818d0603551d230481853081828014d2c4b0d291d44c1171b361cb3da1fedda86ad4e3' +
      'a167a4653063310b30090603550406130255533121301f060355040a13185468652047' +
      '6f2044616464792047726f75702c20496e632e3131302f060355040b1328476f204461' +
      '64647920436c61737320322043657274696669636174696f6e20417574686f72697479' +
      '820100300c0603551d13040530030101ff300d06092a864886f70d0101050500038201' +
      '0100324bf3b2ca3e91fc12c6a1078c8e77a03306145c901e18f708a63d0a19f9878011' +
      '6e69e4961730ff3491637238eecc1c01a31d9428a431f67ac454d7f6e5315803a2ccce' +
      '62db944573b5bf45c924b5d58202ad2379698db8b64dcecf4cca3323e81c88aa9d8b41' +
      '6e16c920e5899ecd3bda70f77e992620145425ab6e7385e69b219d0a6c820ea8f8c20c' +
      'fa101e6c96ef870dc40f618badee832b95f88e92847239eb20ea83ed83cd976e08bceb' +
      '4e26b6732be4d3f64cfe2671e26111744aff571a870f75482ecf516917a002126195d5' +
      'd140b2104ceec4ac1043a6a59e0ad595629a0dcf8882c5320ce42b9f45e60d9f289cb1' +
      'b92a5a57ad370faf1d7fdbbd9f',
      'hex');

    cert = rfc5280.Certificate.decode(chain[0], 'der');
    cert.tbsCertificate.extensions.forEach(function(e) {
      extensions[e.extnID] = e
    });
    assert.equal(extensions.basicConstraints.extnValue.cA, false);
    assert.equal(extensions.extendedKeyUsage.extnValue.length, 2);

    extensions = {}
    cert = rfc5280.Certificate.decode(chain[1], 'der');
    cert.tbsCertificate.extensions.forEach(function(e) {
      extensions[e.extnID] = e
    });
    assert.equal(extensions.basicConstraints.extnValue.cA, true);
    assert.equal(extensions.authorityInformationAccess.extnValue[0]
                 .accessLocation.value, 'http://ocsp.godaddy.com/')

    extensions = {}
    cert = rfc5280.Certificate.decode(chain[2], 'der');
    cert.tbsCertificate.extensions.forEach(function(e) {
      extensions[e.extnID] = e
    });
    assert.equal(extensions.basicConstraints.extnValue.cA, true);

    extensions = {}
    cert = rfc5280.Certificate.decode(chain[3], 'der');
    cert.tbsCertificate.extensions.forEach(function(e) {
      extensions[e.extnID] = e
    });
    assert.equal(extensions.basicConstraints.extnValue.cA, true);
  });
});
