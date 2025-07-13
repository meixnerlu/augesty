import core, { getIDToken } from '@actions/core';

try {
  const serviceAccount = core.getInput('service_account');
  const serviceUrl = core.getInput('service_url');
  const oidcToken = await getIDToken(serviceUrl);

  console.log(`Fetching accesstoken for ${serviceAccount}!`);

  let res = await fetch(`${serviceUrl}/api/identify`, {method: 'POST', headers: { 
    'Authorization': `Bearer ${oidcToken}`,
    'Content-Type': 'application/json',
  }, body: JSON.stringify({ 'service_account': serviceAccount }) })

  if (res.status !== 200) {
    core.setFailed(`Failed to fetch access token: ${res.statusText}`);
  }

  const { accesstoken } = await res.json();

  core.setOutput("accesstoken", accesstoken);
} catch (err) {
  core.setFailed(err.message);
}