{
 "@context": "https://www.w3.org/ns/did/v1",
 "id": "did:example:12345abcde",
 "type": ["DecentralizedIdentifier","UserProfileIdentity"],
 "issuer":"did:example:ebfeb1bc6f1c276e12ec21",
 "issuanceDate":"2021-08-18T14:15:26Z",
 "publicKey": [{
    "id": "did:example:12345abcde#keys-1",
    "type": "Ed25519VerificationKey2020",
    "publicKeyMultibase":"QjztzfDAm26/l04BvnSyxePee2kmOVC+flqF1zK7uQM="
 }],
 "claim":{
    "id": "did:example:8vFBbPrhbfsQKXQKPLskBCu",
    "fullName": "Merlec M.",
    "email": "abc@exampl.com",
    "profileURL": "https://myprofileurl.org",
      "studentOf": {
      "id": "did:example:c276e12ec21ebfeb1f712ebc6f1",
      "institution": [{
        "name": "Example University",
        "department": " Department of x"
      }]
    }
  },  
 "authentication": [{
    "type": "Ed25519VerificationKey2020",
    "publicKey" : "QjztzfDAm26/l04BvnSyxePee2kmOVC+flqF1zK7uQM="
 }],
 "proof":{
    "type":"Ed25519Signature2020",
    "created": "2021-08-18T14:12:19Z",
    "creator":"did:example:12345abcde",
    "verificationMethod": "did:example/issuer#z6MkjLrk3gKS2nnkeWcmcxi",
    "signatureValue": "sITJX1CxPCT8yAV...PAYuNzVBAh4vGHSrQyHUdBBPM"
 }
}