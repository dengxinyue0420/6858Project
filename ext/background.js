window.tabs = {};

chrome.runtime.onInstalled.addListener(function(details) {
  var runtime = {};
  var sentHostnameTimestamp = {};
  var refreshRate = 30;  // 300s
  // var refreshRate = 1000;
  var validatedHostnames = {};
  var hostnameIssuers = {};

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

  chrome.tabs.onCreated.addListener(function(tab) {
    window.tabs[tab.id] = {};
  });

  chrome.tabs.onUpdated.addListener(function(tabId, changeInfo, tab) {
    if (changeInfo.status == "loading")
      window.tabs[tabId] = {};
  });

  chrome.tabs.onRemoved.addListener(function(tabId, removeInfo) {
    delete window.tabs[tabId];
  });

  var resetCounter = function() {
    console.log("resetCounter: " + window.currentTabId);
    if (_.has(window.tabs, window.currentTabId)) {
      var c = _.countBy(window.tabs[window.currentTabId], function(v) {
        if (v.status == "pending")
          return "true";
        if (v.verification)
          return "true";
        return "false";
      });
      console.log(c);
      chrome.browserAction.setBadgeText({text: "" + (c["false"] | 0)});
    }
  };
  chrome.tabs.onActivated.addListener(function(activeInfo) {
    window.currentTabId = activeInfo.tabId;
    console.log("active tab: " + window.currentTabId);
    resetCounter();
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
      if (_.has(window.tabs, details.tabId) && ! _.has(window.tabs[details.tabId], host)) {
        window.tabs[details.tabId][host] = {
          "status": "pending"
        }
      }
      sendHostname(hostname, port, ts, function(r) {
        if (r.validation) {
          validatedHostnames[r.host] = getPOSIXTimestampUTC();
          if (_.has(window.tabs, details.tabId)) {
            window.tabs[details.tabId][r.host] = {
              "status": "done",
              "verification": true,
              "lastVerification": validatedHostnames[r.host],
              "issuer": r.issuer || "N/A"
            }
          }
          hostnameIssuers[r.host] = r.issuer || "N/A"
        }
        else {
          if (_.has(window.tabs, details.tabId)) {
            window.tabs[details.tabId][r.host] = {
              "status": "done",
              "verification": false,
              "lastVerification": getPOSIXTimestampUTC(),
              "message": r.message,
              "issuer": r.issuer || "N/A"
            }
          }
          validatedHostnames[r.host] = 0;
          delete hostnameIssuers[r.host];
        }
        resetCounter();
      });
      // if (["GET",].indexOf(details.method) >= 0 && details.type == "main_frame") {
      //   return {
      //     "redirectUrl": redirect + encodeURIComponent(uri)
      //   }
      // }
      // else {
      //   return {
      //     "cancel": true
      //   }
      // }
    }
    else {
      if (_.has(window.tabs, details.tabId)) {
        window.tabs[details.tabId][host] = {
          "status": "done",
          "verification": true,
          "lastVerification": validatedHostnames[host],
          "issuer": hostnameIssuers[host]
        }
      }
    }
  };
  chrome.webRequest.onBeforeRequest.addListener(webRequestCallback,
    {urls: ["https://*/*"]}, []);

  chrome.runtime.onMessage.addListener(
    function(request, sender, sendResponse) {
      console.log("tab requested: " + request.tabId);
      sendResponse(window.tabs[request.tabId]);
    }
  );

  var query = {active: true, currentWindow: true};
  chrome.tabs.query(query, function(tabs) {
    window.currentTabId = tabs[0].id;
  });
})
