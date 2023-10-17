function register() {
  const username = document.getElementById("username").value;
  if (username === "") {
    alert("Please enter a username");
    return;
  }

  fetch("http://localhost:8080/register_start/" + encodeURIComponent(username), {
    method: "POST",
  }).then((r) => console.log(r.json()));

  //   .then((response) => response.json())
  //   .then((credentialCreationOptions) => {
  //     credentialCreationOptions.publicKey.challenge = Base64.toUint8Array(
  //       credentialCreationOptions.publicKey.challenge
  //     );
  //     credentialCreationOptions.publicKey.user.id = Base64.toUint8Array(credentialCreationOptions.publicKey.user.id);
  //     credentialCreationOptions.publicKey.excludeCredentials?.forEach(function (listItem) {
  //       listItem.id = Base64.toUint8Array(listItem.id);
  //     });

  //     return navigator.credentials.create({
  //       publicKey: credentialCreationOptions.publicKey,
  //     });
  //   })
  //   .then((credential) => {
  //     fetch("http://localhost:8080/register_finish", {
  //       method: "POST",
  //       headers: {
  //         "Content-Type": "application/json",
  //       },
  //       body: JSON.stringify({
  //         id: credential.id,
  //         rawId: Base64.fromUint8Array(new Uint8Array(credential.rawId), true),
  //         type: credential.type,
  //         response: {
  //           attestationObject: Base64.fromUint8Array(new Uint8Array(credential.response.attestationObject), true),
  //           clientDataJSON: Base64.fromUint8Array(new Uint8Array(credential.response.clientDataJSON), true),
  //         },
  //       }),
  //     }).then((response) => {
  //       const flash_message = document.getElementById("flash_message");
  //       if (response.ok) {
  //         flash_message.innerHTML = "Successfully registered!";
  //       } else {
  //         flash_message.innerHTML = "Error whilst registering!";
  //       }
  //     });
  //   });
}
