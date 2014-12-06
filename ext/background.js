chrome.runtime.onInstalled.addListener(function(details) {
  var runtime = {};
  var sentHostnameTimestamp = {};
  // var refreshRate = 300 * 1000;  // 300ms
  var refreshRate = 1000;

  chrome.management.getAll(function (exts) {
    _.each(exts, function(ext) {
      if (ext.name == "CertMonitor Background App") {
        runtime.app = {};
        runtime.app.id = ext.id;
      }
    });
  });

  var sendHostname = function(hostname, port, timestamp) {
    var appId = runtime.app.id;
    chrome.runtime.sendMessage(appId, {
      hostname: hostname,
      port: port,
      timestamp: timestamp,
    });
  };

  var throttledSendHostname = function(hostname, port, timestamp) {
    host = hostname + ":" + port;
    if (_.has(sentHostnameTimestamp, host)) {
      var ts = sentHostnameTimestamp[host];
      if (timestamp - ts < refreshRate) {
        return false;
      }
    }
    if (hostname != "23.235.46.133") {
      sentHostnameTimestamp[host] = timestamp;
    }
    sendHostname(hostname, port, timestamp);
    return true;
  };

  var webRequestCallback = function(details) {
    var uri = new URI(details.url);
    var ts = new Date().getTime();
    // console.log(details.url);
    throttledSendHostname(uri.hostname(), parseInt(uri.port()) | 443, ts);
  };
  chrome.webRequest.onBeforeRequest.addListener(webRequestCallback,
    {urls: ["https://*/*"]}, null);

  chrome.proxy.settings.get({"incognito": false}, function(details) {
    console.log(details);
  });
})