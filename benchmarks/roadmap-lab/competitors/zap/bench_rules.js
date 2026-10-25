// ZAP standalone script: sets the pre-registered Access Control rules for one
// case on every node of its context. The Access Control API can start scans but
// cannot set rules, so this is the only headless way to configure them.
// Input /zap/wrk/case.json: {"contextId": n, "rules": {"<userId>": "ALLOWED"|"DENIED"}},
// where userId -1 is ZAP's unauthenticated user. Writes the rules it set to
// /zap/wrk/rules-applied.json.

var Control = Java.type("org.parosproxy.paros.control.Control");
var Model = Java.type("org.parosproxy.paros.model.Model");
var Files = Java.type("java.nio.file.Files");
var Paths = Java.type("java.nio.file.Paths");
var JEnum = Java.type("java.lang.Enum");

var spec = JSON.parse(String(Files.readString(Paths.get("/zap/wrk/case.json"))));
var ext = Control.getSingleton().getExtensionLoader().getExtension("ExtensionAccessControl");
var ruleType = ext.getClass().getClassLoader()
    .loadClass("org.zaproxy.zap.extension.accessControl.AccessRule");
var manager = ext.getContextAccessRulesManager(spec.contextId);
manager.reloadContextSiteTree(Model.getSingleton().getSession());

var nodes = [];
function walk(node) {
    for (var i = 0; i < node.getChildCount(); i++) {
        var child = node.getChildAt(i);
        nodes.push(child);
        walk(child);
    }
}
walk(manager.getContextSiteTree().getRoot());

var applied = [];
for (var userId in spec.rules) {
    var rule = JEnum.valueOf(ruleType, spec.rules[userId]);
    for (var n = 0; n < nodes.length; n++) {
        manager.addRule(parseInt(userId, 10), nodes[n], rule);
        applied.push({userId: parseInt(userId, 10), node: String(nodes[n].getNodeName()), rule: String(rule)});
    }
}
Files.writeString(Paths.get("/zap/wrk/rules-applied.json"), JSON.stringify(applied));
print("bench_rules: " + applied.length + " rules on " + nodes.length + " nodes");
