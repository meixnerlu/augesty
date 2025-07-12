"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
var core_1 = require("@actions/core");
try {
    var service_account = core_1.default.getInput('service_account');
    var url = core_1.default.getInput('service_url');
    var gh_token = process.env.GITHUB_TOKEN;
    if (!gh_token) {
        core_1.default.setFailed('GITHUB_TOKEN is not set');
    }
    console.log("Fetching accesstoken for ".concat(service_account, "!"));
    var res = await fetch("${url}/api/v1/auth/accesstoken", { method: 'POST', headers: {
            'Authorization': "Bearer ".concat(gh_token),
            'Content-Type': 'application/json',
        }, body: JSON.stringify({ 'service_account': service_account }) });
    if (res.status !== 200) {
        core_1.default.setFailed("Failed to fetch access token: ".concat(res.statusText));
    }
    core_1.default.setOutput('accesstoken', res.json().then(function (data) { return data.accesstoken; }));
}
catch (err) {
    core_1.default.setFailed(err.message);
}
