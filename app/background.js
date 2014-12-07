var pki = forge.pki;

var hex2a = function(hexx) {
  var hex = hexx.toString();
  var str = '';
  for (var i = 0; i < hex.length; i += 2)
    str += String.fromCharCode(parseInt(hex.substr(i, 2), 16));
  return str;
};

var getPOSIXTimestampUTC = function() {
  var date = new Date();
  return date.getTimezoneOffset() * 60 + Math.round(date/1000);
} 

var getHostRecentCertificate = function (host, callback) {
  chrome.storage.local.get([host, ], callback);
};

var saveHostCertificateRecord = function(host, certChain, verification) {
  var stored = {};
  stored[host] = certChain;
  chrome.storage.local.set(stored, function() {});
};

var createSocket = function(hostname, port, callback) {
  var socketProps = {
    "persistent": false,
    "name": hostname + ":" + port
  };
  chrome.sockets.tcp.create(socketProps, function(createInfo) {
    var socketId = createInfo.socketId;
    chrome.sockets.tcp.connect(socketId, hostname, port, function(result) {
      if (result < 0) {
        // console.log("connect(" + socketProps.name + "): failed with code " + result);
        chrome.sockets.tcp.close(socketId);
        callback(null);
      }
      else {
        // console.log("connect(" + socketProps.name + "): socketId " + socketId);
        callback(socketId);
      }
    });
  });
};

var socketReadCallbacksById = {};
var socketReadCallback = function(info) {
  var socketId = info.socketId;
  var data = info.data;
  if (socketReadCallbacksById[socketId]) {
    // console.log("read: " + data.byteLength + " bytes for socket " + socketId);
    socketReadCallbacksById[socketId](data);
  }
  else {
    // console.log("read: " + data.byteLength + " bytes for socket " + socketId +
    //            "; no handler!");
  }
};

var closeSocket = function(socketId) {
  if (socketReadCallbacksById[socketId])
    delete socketReadCallbacksById[socketId];
  chrome.sockets.tcp.close(socketId);
}

var registerReadCallback = function(socketId, callback) {
  socketReadCallbacksById[socketId] = callback;
};

chrome.sockets.tcp.onReceive.addListener(socketReadCallback);

var constructTLSClientHello = function(hostname) {
  // Only RSA ciphers allowed
  //   http://tools.ietf.org/html/rfc5246#appendix-A.5
  var ciphers = [0x00, 0x01,
                 0x00, 0x02,
                 0x00, 0x3B,
                 0x00, 0x04,
                 0x00, 0x05,
                 0x00, 0x0A,
                 0x00, 0x2F,
                 0x00, 0x35,
                 0x00, 0x3C,
                 0x00, 0x3D];
  var ciphersLength = ciphers.length;

  var hostnameLength = hostname.length;
  var hostnameExtStruct = restruct.int16bu('extType').int16bu('extLength')
                            .int16bu('listLength').int8bu('nameType')
                            .int16bu('nameLength').string('name', hostnameLength)
  var hostnameExt = hostnameExtStruct.pack({
    "extType": 0x0000,
    "extLength": hostnameLength + 5,
    "listLength": hostnameLength + 3,
    "nameType": 0x00,
    "nameLength": hostnameLength,
    "name": hostname
  });
  var hostnameExtLength = hostnameExt.length;

  // var extraExt = (hex2a("000a00080006001700180019") +
  //                 hex2a("000b00020100") +
  //                 hex2a("000d000c000a05010401020104030203"))
  var extraExt = "";
  var extraExtLength = extraExt.length;

  var helloStruct = restruct.int8bu('type').int16bu('version')
                            .int16bu('length').int8bu('handshakeType')
                            .int8bu('zero').int16bu('handshakeLength')
                            .int16bu('handshakeVersion')
                            .int32bu('timestamp').string('rand', 28)
                            .int8bu('sessionIdLength').int16bu('ciphersLength')
                            .array('ciphers', ciphersLength)
                            .int8bu('compressionLength')
                            .int8bu('compressionMethod')
                            .int16bu('extensionsLength')
                            .array('hostnameExt', hostnameExtLength)
                            .string('extraExt', extraExtLength);

  var hello = helloStruct.pack({
    "type": 0x16,
    "version": 0x0301,
    "length": helloStruct.size - 5,
    "handshakeType": 0x01,
    "zero": 0x00,
    "handshakeLength": helloStruct.size - 5 - 4,
    "handshakeVersion": 0x0303,
    "timestamp": getPOSIXTimestampUTC(),
    "rand": hex2a("d13c975d36a4f242b0137bea65f04cc80428301d2cd77d663437c2d3"),
    "sessionIdLength": 0,
    "ciphersLength": ciphersLength,
    "ciphers": ciphers,
    "compressionLength": 1,
    "compressionMethod": 0,
    "extensionsLength": extraExtLength + hostnameExtLength,
    "hostnameExt": hostnameExt,
    "extraExt": extraExt
  });

  return hello;
}

var getHostCertificate = function(hostname, port, callback) {
  var tlsTimeout = 30 * 1000;

  createSocket(hostname, port, function(socketId) {
    if (socketId != null) {
      var failedOrTimeout = function() {
        closeSocket(socketId);
        callback(null);
      };
      var timeoutHandle = setTimeout(failedOrTimeout, tlsTimeout);

      var reader = {
        "state": "read_header", "buf": []
      };
      var tlsHeaderStruct = restruct.int8bu('type').int16bu('version').int16bu('length');
      var messageHeaderStruct = restruct.int8bu('type').int8bu('zero')
                                        .int16bu('length');

      registerReadCallback(socketId, function(data) {
        reader.buf = reader.buf.concat(
          Array.prototype.slice.call((new Uint8Array(data))));

        while (1) {
          if (reader.state == "read_header") {
            if (reader.buf.length > tlsHeaderStruct.size) {
              reader.header = tlsHeaderStruct.unpack(reader.buf.slice(0, tlsHeaderStruct.size));
              reader.buf = reader.buf.slice(tlsHeaderStruct.size, reader.buf.length);
              reader.state = "reader_message"
              // console.log("read_header: " + JSON.stringify(reader.header));
            }
            else
              break;
          }
          else if (reader.state == "reader_message") {
            if (reader.buf.length > reader.header.length) {
              var message = reader.buf.slice(0, reader.header.length);
              if (reader.header.type == 0x15) { // ALERT
                // console.log("reader_message: alert");
              }
              else if (reader.header.type == 0x16) { // HANDSHAKE
                var handshake = messageHeaderStruct.unpack(
                  message.slice(0, messageHeaderStruct.size));
                // console.log("reader_message: handshake: " + JSON.stringify(handshake));

                if (handshake.type == 0x0e) {
                  // console.log("reader_message: handshake: server hello done!")
                }
                else if (handshake.type == 0x0b) {
                  // console.log("reader_message: handshake: certificate")
                  var message = message.slice(messageHeaderStruct.size, message.length);
                  var certsLength = message[1] * 0x100 + message[2];
                  var message = message.slice(3, message.length);
                  var certChain = [], i = 0;
                  while (message.length > i) {
                    var certLength = message[i+1] * 0x100 + message[i+2];
                    var rawCert = message.slice(i+3, i+certLength+3);
                    var b64encoded = btoa(String.fromCharCode.apply(null, rawCert));
                    var chunks = b64encoded.match(/[\s\S]{1,64}/g);
                    var pemCert = "-----BEGIN CERTIFICATE-----\n" + chunks.join("\n") + "\n-----END CERTIFICATE-----\n"
                    certChain.push(pemCert);
                    var i = i + certLength + 3;
                  }
                  clearTimeout(timeoutHandle);
                  _.defer(_.partial(callback, certChain));
                  closeSocket(socketId);
                  break;
                }
              }
              reader.buf = reader.buf.slice(reader.header.length, reader.buf.length);
              reader.state = "read_header";
            }
            else
              break;
          }
        }
      });

      var hello = constructTLSClientHello(hostname);
      var helloBuf = new Uint8Array(hello);
      chrome.sockets.tcp.send(socketId, helloBuf.buffer, function() {});
    }
  });
};

var parseHostCertificate = function(pems) {
  var certChain = [];
  _.each(pems, function(p) {
    certChain.push(pki.certificateFromPem(p))
  });
  return certChain;
};

var verifyCertChain = function(certChain, callback) {
  pki.verifyCertificateChain(window.caStore, certChain, callback);
};

var compareCertChain = function(host, previousCertChain, certChain) {
  var anomaly = false;
  if (previousCertChain === undefined) {
    console.info(host + ": first time access.");
    return;
  }
  if (previousCertChain[0].signature != certChain[0].signature) {
    var anomaly = true;
    console.info(host + ": Signature mismatch! " + previousCertChain[0].signature + "!=" + certChain[0].signature);
  }
  var issuerName = certChain[0].issuer.getField("CN").value;
  if (previousCertChain[0].issuer.hash != certChain[0].issuer.hash) {
     var anomaly = true;
     console.info(host + ": Issuer mismatch! " + previousCertChain[0].issuer.hash + "!=" + certChain[0].issuer.hash);

     var previousIssuerName = previousCertChain[0].issuer.getField("CN").value;
     if (previousIssuerName != issuerName) {
       console.info(host + ": Issuer changed from " + previousIssuerName + " to " + issuerName);
     }
  }
  if (previousCertChain[0].subject.getField("CN").value != certChain[0].subject.getField("CN").value) {
    console.info(host + ": Subject name changed from " + previousCertChain[0].subject.getField("CN").value +
      " to " + certChain[0].subject.getField("CN").value);
  }
  if (! anomaly)
    console.log(host + ": issued by " + issuerName + ", check ok.");
}

window.certs = {};
chrome.runtime.onMessageExternal.addListener(
  function(request, sender, sendResponse) {
    var host = request.hostname + ":" + request.port;
    console.log("message: " + host);
    getHostCertificate(request.hostname, request.port, function(cert) {
      console.log("getHostCertificate(" + host + "): " + "Done!");
      if (cert != null) {
        var certChain = parseHostCertificate(cert);
        window.certs[host] = certChain;
        getHostRecentCertificate(host, function(previousCert) {
          saveHostCertificateRecord(host, cert, getPOSIXTimestampUTC(), false);
          var previousCertChain = parseHostCertificate(previousCert);
          var result = compareCertChain(host, previousCertChain, certChain);
        });
      }
    });
    // sendResponse({"validation": true})
  }
);

var updateCABundle = function(callback) {
  var url = "https://raw.githubusercontent.com/bagder/ca-bundle/master/ca-bundle.crt";  // extracted from Mozzila
  var xhr = new XMLHttpRequest();
  xhr.open('GET', url, true);
  xhr.responseType = 'text';
  xhr.onload = function(e) {
    var caBundlePEM = this.responseText;
    var stored = {
      "ca-bundle": {
          "pem": caBundlePEM,
          "source": url,
          "timestamp": getPOSIXTimestampUTC()
        }
      };
    chrome.storage.local.set(stored, function() {});
    callback(caBundlePEM);
  };
  xhr.send();
}

var loadCAStorage = function(bundle) {
  var regex = /\s*-----BEGIN ([A-Z0-9- ]+)-----\r?\n?([\x21-\x7e\s]+?(?:\r?\n\r?\n))?([:A-Za-z0-9+\/=\s]+?)-----END \1-----/g;
  var pems = bundle.match(regex);
  var failed = 0;
  var certs = []
  _.each(pems, function(p) {
    try {
      certs.push(pki.certificateFromPem(p));
    }
    catch(err) {
    }
  });
  window.caStore = pki.createCaStore(certs);
  console.log("Loaded " + (certs.length) + " Certificate Authorities.");
}

chrome.runtime.onInstalled.addListener(function(details) {
  chrome.storage.local.get(["ca-bundle", ], function(caBundle) {
    if (_.has(caBundle["ca-bundle"], "pem")) {
      var caBundle = caBundle["ca-bundle"];
      loadCAStorage(caBundle.pem);
      if ((getPOSIXTimestampUTC() - caBundle.timestamp) > 3600 * 24) // update everyday
        updateCABundle(loadCAStorage);
    }
    else
      updateCABundle(loadCAStorage);
  });
});
