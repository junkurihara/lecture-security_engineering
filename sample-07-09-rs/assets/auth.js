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
    flash_message.innerHTML += "<br/>Content of AuthenticatoAttestationResponse:";
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

    if (res.ok) {
      flash_message.innerHTML += "Successfully registered!";
    } else {
      flash_message.innerHTML += "Error whilst registering!";
    }
  });
}
