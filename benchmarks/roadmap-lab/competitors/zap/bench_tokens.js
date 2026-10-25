// ZAP httpsender script: gives each Access Control scanner user its benchmark
// token, and removes Authorization from the unauthenticated replay (ZAP would
// otherwise resend the seeded request's own header). Other traffic is untouched.
// Tokens are read per request from the bind-mounted results directory, so a new
// pass only rewrites the file.

var HttpSender = Java.type("org.parosproxy.paros.network.HttpSender");
var Files = Java.type("java.nio.file.Files");
var Paths = Java.type("java.nio.file.Paths");
var TOKENS = "/zap/wrk/tokens.local.json";

function sendingRequest(msg, initiator, helper) {
    if (initiator != HttpSender.ACCESS_CONTROL_SCANNER_INITIATOR) {
        return;
    }
    var tokens = JSON.parse(String(Files.readString(Paths.get(TOKENS))));
    var header = msg.getRequestHeader();
    header.setHeader("Authorization", null);
    var user = msg.getRequestingUser();
    if (user != null) {
        var token = tokens[user.getName()];
        if (!token) {
            throw "no benchmark token for ZAP user " + user.getName();
        }
        header.setHeader("Authorization", "Bearer " + token);
    }
}

function responseReceived(msg, initiator, helper) {}
