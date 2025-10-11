
// PKCS #7 Padding, RFC 5652
export const pkcs7Padding = (paddingLength, blockLength) => {
  const pad = (paddingLength) ? new Uint8Array(paddingLength) : new Uint8Array(blockLength);
  const filling = (paddingLength) ? paddingLength : blockLength;
  return pad.map( () => filling);
};
