// Client token types shared between the issuer and relay1.
// Token wire format (x-shine-token header value):
//   base64url(nonce + "." + exp_decimal) + "." + base64url(HMAC-SHA256(secret, nonce + "." + exp_decimal))

export interface TokenPayload {
  nonce: string; // base64url 16 random bytes — ensures uniqueness
  exp: number;   // unix seconds (not ms)
}
