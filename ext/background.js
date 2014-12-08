chrome.runtime.onInstalled.addListener(function(details) {
  var runtime = {};
  var sentHostnameTimestamp = {};
  var refreshRate = 300 * 1000;  // 300s
  // var refreshRate = 1000;
  var validatedHostnames = {};

  var getPOSIXTimestampUTC = function() {
    var date = new Date();
    return date.getTimezoneOffset() * 60 + Math.round(date/1000);
  };

  chrome.management.getAll(function (exts) {
    _.each(exts, function(ext) {
      if (ext.name == "CertMonitor Background App") {
        runtime.app = {};
        runtime.app.id = ext.id;
      }
    });
  });

  var sendHostname = function(hostname, port, timestamp, callback) {
    var appId = runtime.app.id;
    chrome.runtime.sendMessage(appId, {
      hostname: hostname,
      port: port,
      timestamp: timestamp,
    }, callback);
  };

  var throttledSendHostname = function(hostname, port, timestamp, callback) {
    host = hostname + ":" + port;
    if (_.has(sentHostnameTimestamp, host)) {
      var ts = sentHostnameTimestamp[host];
      if (timestamp - ts < refreshRate) {
        callback(null);
        return false;
      }
    }
    sendHostname(hostname, port, timestamp, callback);
    return true;
  };

  var webRequestCallback = function(details) {
    // console.log(details);
    var uri = new URI(details.url);
    var ts = new Date().getTime();
    var redirect = "http://127.0.0.1:58271/validate?url="

    var hostname = uri.hostname();
    var port = parseInt(uri.port()) | 443;
    var host = hostname + ":" + port;

    if (_.has(validatedHostnames, host) == false ||
              getPOSIXTimestampUTC() - validatedHostnames[host] > refreshRate) {
      sendHostname(hostname, port, ts, function(r) {
        if (r.validation) {
          validatedHostnames[r.host] = getPOSIXTimestampUTC();
        }
        else {
          validatedHostnames[r.host] = 0;
        }
      });
      if (["GET",].indexOf(details.method) >= 0 && details.type == "main_frame") {
        return {
          "redirectUrl": redirect + encodeURIComponent(uri)
        }
      }
      else {
        return {
          "cancel": true
        }
      }
    }
    else {
      return {
        "cancel": false
      }
    }
  };
  chrome.webRequest.onBeforeRequest.addListener(webRequestCallback,
    {urls: ["https://*/*"]}, ["blocking"]);
})