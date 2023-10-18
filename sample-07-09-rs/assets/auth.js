const SERVER_URL = "http://localhost:8080";

function register() {
  const username = document.getElementById("username").value;
  if (username === "") {
    alert("Please enter a username");
    return;
  }
  const flash_message = document.getElementById("flash_message");
  flash_message.innerHTML = "Registration was initiated...";

  fetch(`${SERVER_URL}/register_start/` + encodeURIComponent(username), {
    method: "POST",
  }).then(async (response) => {
    if (!response.ok) {
      flash_message.innerHTML = "Error whilst registering!";
    }

    const credentialCreationOptions = await response.json();
    flash_message.innerHTML = "Created credentialCreationOptions from server response:";
    flash_message.innerHTML +=
      "<br/><pre><code>" + JSON.stringify(credentialCreationOptions, undefined, 2) + "</code></pre>";

    credentialCreationOptions.publicKey.challenge = Base64.toUint8Array(credentialCreationOptions.publicKey.challenge);
    credentialCreationOptions.publicKey.user.id = Base64.toUint8Array(credentialCreationOptions.publicKey.user.id);
    credentialCreationOptions.publicKey.excludeCredentials?.forEach((listItem) => {
      listItem.id = Base64.toUint8Array(listItem.id);
    });

    const authRes = await navigator.credentials.create({
      publicKey: credentialCreationOptions.publicKey,
    });

    const attRes = authRes.response;
    const credential = {
      id: authRes.id,
      rawId: Base64.fromUint8Array(new Uint8Array(authRes.rawId), true),
      type: authRes.type,
      response: {
        attestationObject: Base64.fromUint8Array(new Uint8Array(attRes.attestationObject), true),
        clientDataJSON: Base64.fromUint8Array(new Uint8Array(attRes.clientDataJSON), true),
      },
    };

    flash_message.innerHTML += "<br/>Created PublicKeyCredential from authenticator response:";
    flash_message.innerHTML += "<br/><pre><code>" + JSON.stringify(credential, undefined, 2) + "</code></pre>";

    const parsedAttRes = fido2testlib.parseAuthenticatorResponse(attRes);
    flash_message.innerHTML += "<br/>Content of AuthenticatorAttestationResponse:";
    flash_message.innerHTML +=
      "<pre><code>clientDataJson\n" + JSON.stringify(parsedAttRes.clientDataJSON, undefined, 2) + "</code></pre>";
    flash_message.innerHTML +=
      "<pre><code>attestationObject\n" +
      JSON.stringify(
        parsedAttRes.attestationObject,
        (key, val) => (val instanceof Array && key === "data" ? Base64.fromUint8Array(new Uint8Array(val)) : val),
        2
      );
    +"</code></pre>";

    const res = await fetch(`${SERVER_URL}/register_finish`, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
      },
      body: JSON.stringify(credential),
    });

    if (!res.ok) {
      flash_message.innerHTML += "Error whilst registering!";
      return;
    }
    flash_message.innerHTML += "Successfully registered!";

    const createChallenge = credentialCreationOptions.publicKey.challenge;
    const verifyAttestationResult = await fido2testlib.verifyAttestation(authRes, createChallenge);
    flash_message.innerHTML += "<br/>Attested Credential Public Key:";
    flash_message.innerHTML += "<pre><code>" + verifyAttestationResult.credentialPublicKey + "</code></pre>";
    flash_message.innerHTML += "<br/>Attestation Certificate:";
    flash_message.innerHTML += "<pre><code>" + verifyAttestationResult.attestationCertificate + "</code></pre>";
  });
}

function login() {
  const username = document.getElementById("username").value;
  if (username === "") {
    alert("Please enter a username");
    return;
  }
  const flash_message = document.getElementById("flash_message");
  flash_message.innerHTML = "Authentication was initiated...";

  fetch(`${SERVER_URL}/login_start/` + encodeURIComponent(username), {
    method: "POST",
  }).then(async (response) => {
    if (!response.ok) {
      flash_message.innerHTML = "Error whilst authentication!";
    }

    const credentialRequestOptions = await response.json();
    flash_message.innerHTML = "Created credentialRequestOptions from server response:";
    flash_message.innerHTML +=
      "<br/><pre><code>" + JSON.stringify(credentialRequestOptions, undefined, 2) + "</code></pre>";

    credentialRequestOptions.publicKey.challenge = Base64.toUint8Array(credentialRequestOptions.publicKey.challenge);
    credentialRequestOptions.publicKey.allowCredentials?.forEach((listItem) => {
      listItem.id = Base64.toUint8Array(listItem.id);
    });

    const authRes = await navigator.credentials.get({
      publicKey: credentialRequestOptions.publicKey,
    });
    const assRes = authRes.response;
    const credential = {
      id: authRes.id,
      rawId: Base64.fromUint8Array(new Uint8Array(authRes.rawId), true),
      type: authRes.type,
      response: {
        authenticatorData: Base64.fromUint8Array(new Uint8Array(assRes.authenticatorData), true),
        clientDataJSON: Base64.fromUint8Array(new Uint8Array(assRes.clientDataJSON), true),
        signature: Base64.fromUint8Array(new Uint8Array(assRes.signature), true),
        userHandle: Base64.fromUint8Array(new Uint8Array(assRes.userHandle), true),
      },
    };

    flash_message.innerHTML += "<br/>Created Credential from authenticator response:";
    flash_message.innerHTML += "<br/><pre><code>" + JSON.stringify(credential, undefined, 2) + "</code></pre>";

    const parsedAssRes = fido2testlib.parseAuthenticatorResponse(assRes);
    flash_message.innerHTML += "<br/>Content of AuthenticatorAssertionResponse:";
    flash_message.innerHTML +=
      "<pre><code>clientDataJson\n" + JSON.stringify(parsedAssRes.clientDataJSON, undefined, 2) + "</code></pre>";
    flash_message.innerHTML +=
      "<pre><code>authenticatorData\n" +
      Base64.fromUint8Array(new Uint8Array(parsedAssRes.authenticatorData)) +
      "</code></pre>";
    flash_message.innerHTML +=
      "<pre><code>signature\n" + Base64.fromUint8Array(new Uint8Array(parsedAssRes.signature)) + "</code></pre>";

    const res = await fetch(`${SERVER_URL}/login_finish`, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
      },
      body: JSON.stringify(credential),
    });

    if (!res.ok) {
      flash_message.innerHTML += "Error whilst authentication!";
      return;
    }
    flash_message.innerHTML += "Successfully authenticated!";
  });
}
