var tabCallback = function (tabs) {
  var currentTab = tabs[0];
  console.log("current tab: " + currentTab.id);
  chrome.runtime.sendMessage({"tabId": currentTab.id}, 
    function(r) {
      var date = new Date();
      console.log(r);
      _.each(r, function(v, host) {
        if (v.status == "done" && v.verification == true) {
          var t = moment.utc((v.lastVerification - date.getTimezoneOffset() * 60) * 1000);
          v.message = "Verified " + t.fromNow();
        }
        else if (v.status == "pending") {
          v.message = "Pending...";
        }
      });
      var template = document.getElementById("popup-template").innerHTML;
      var output = _.template(template)({"result": r});
      document.body.innerHTML = output;
    }
  );
}
var query = {active: true, currentWindow: true};
chrome.tabs.query(query, tabCallback);
