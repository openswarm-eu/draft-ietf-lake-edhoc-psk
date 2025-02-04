---
title: "EDHOC PSK authentication"
abbrev: "TODO - Abbreviation"
category: info

docname: draft-ietf-lake-edhoc-psk-latest
submissiontype: IETF  # also: "independent", "editorial", "IAB", or "IRTF"
number:
date:
consensus: true
v: 3
area: Security
workgroup: LAKE Working Group
keyword:
venue:
  group: LAKE
  type: Working Group
  mail: lake@ietf.org
  arch: https://example.com/WG
  github: ElsaLopez133/draft-lopez-lake-psk
  latest: https://elsalopez133.github.io/draft-lopez-lake-edhoc-psk/#go.draft-lopez-lake-edhoc-psk.html

author:
 -
    fullname: Elsa Lopez-Perez
    organization: Inria
    email: elsa.lopez-perez@inria.fr
 -
    fullname: Göran Selander
    organization: Ericsson
    email: goran.selander@ericsson.com
 -
    fullname: John Preuß Mattsson
    organization: Ericsson
    email: john.mattsson@ericsson.com
 -
    fullname: Rafael Marin-Lopez
    organization: University of Murcia
    email: rafa@um.es

normative:

  RFC9528:
  RFC9052:
  RFC9053:
  RFC8742:
  RFC8949:
  RFC8610:
  RFC8392:
  RFC4279:

informative:

--- abstract

This document specifies the Pre-Shared Key (PSK) authentication method for the Ephemeral Diffie-Hellman Over COSE (EDHOC) key exchange protocol. It describes the authentication processes, message flows, and security considerations of this authentication method.

--- middle

# Introduction

## Motivation

The growth of IoT environemnts has led to a renwed effort to expand the current authentication mechanisms of EDHOC to inlcude Pre-Shared Keys (PSK), making this draft an update to the {{RFC9528}}. In fact, this authentication method was proposed in the first I-Ds of Ephemeral Diffie-Hellman Over COSE (EDHOC) {{RFC9528}}, and was ruled out to speed out the development process. The prevalence of PSK-based authentication is a main reason for its support. Even protocols taht are not oriented towards IoT devices, such as TLS 1.3, have included PSK as an authentication method {{RFC4279}}.

EDHOC with PSK authentication could be beneficial for existing systems where two nodes have been provided with a PSK from other parties out of band. This allows the nodes to perform ephemeral Diffie-Hellman to achieve Perfect Forward Secrecy (PFS), ensuring that past communications remain secure even if the PSK is compromised. The authentication provided by EDHOC prevents eavesdropping by on-path attackers, as they would need to be active participants in the communication to intercept and potentially tamper with the session. Examples could be Generic Bootstrapping Architecture (GBA) and Authenticated Key Management Architecture (AKMA) in mobile systems, or Peer and Authenticator in EAP.

Another prominent use case of PSK authentication in the EDHOC protocol is session resumption. This allows previously connected parties to quickly reestablish secure communication using pre-shared keys from their earlier session, reducing the overhead of full key exchange. This efficiency is beneficial in scenarios where frequent key updates are needed, such in resource-constrained environments or applications requiring high-frequency secure communications. The use of PSK authentication in EDHOC ensures that session key can be refreshed without heavy computational overhead, typically associated with public key operations, thus optimizing both performance and security.


# Conventions and Definitions

{::boilerplate bcp14-tagged}

Readers are expected to be familiar with the terms and concepts described in CBOR {{RFC8949}}, CBOR Sequences {{RFC8742}}, COSE Structures and Processing {{RFC9052}}, COSE Algorithms {{RFC9053}}, CWT and CCS {{RFC8392}}, and the Concise Data Definition Language (CDDL) {{RFC8610}}, which is used to express CBOR data structures.

# Protocol

In this method, the Pre-Shared Key identifier (ID_CRED_PSK) is sent in message_3. The ID_CRED_PSK allows retrieval of CRED_PSK, a COSE_Key compatible authentication credential that contains the PSK. Through this document we will refer to the Pre-Shared Key authentication method as EDHOC-PSK.

## Credentials

Initiator and Responder are assumed to have a PSK with good amount of randomness and the requirements that:

- Only the Initiator and the Responder have access to the PSK.
- The Responder is able to retrieve the PSK using ID_CRED_PSK.

where:

- ID_CRED_PSK is a COSE header map containing header parameters that can identify a pre-shared key. For example:

~~~~~~~~~~~~
ID_CRED_PSK = {4 : h'lf' }
~~~~~~~~~~~~

- CRED_PSK is a COSE_Key compatible authentication credential, i.e., a CBOR Web Token (CWT) or CWT Claims Set (CCS) {{RFC8392}} whose 'cnf' claim uses the confirmation method 'COSE_Key' encoding the PSK. For example:

~~~~~~~~~~~~
{                                               /CCS/
  2 : "mydotbot",                               /sub/
  8 : {                                         /cnf/
    1 : {                                       /COSE_Key/
       1 : 4,                                   /kty/
       2 : h'32',                               /kid/
      -1 : h'50930FF462A77A3540CF546325DEA214'  /k/
    }
  }
}
~~~~~~~~~~~~

The purpose of ID_CRED_PSK is to facilitate the retrieval of the PSK.
It is RECOMMENDED that it uniquely identifies the CRED_PSK as the recipient might otherwise have to try several keys.
If ID_CRED_PSK contains a single 'kid' parameter, then the compact encoding is applied; see [Section 3.5.3.2 of RFC9528](https://www.rfc-editor.org/rfc/rfc9528.html#section-3.5.3.2).
The authentication credential CRED_PSK substitutes CRED_I and CRED_R specified in {{RFC9528}}, and, when applicable, MUST follow the same guidelines described in  [Section 3.5.2](https://www.rfc-editor.org/rfc/rfc9528.html#section-3.5.2) and [Section 3.5.3 of RFC9528](https://www.rfc-editor.org/rfc/rfc9528.html#section-3.5.3).

## Message flow of PSK

The ID_CRED_PSK is sent in message_3, encrypted using a key derived from the ephemeral shared secret, G_XY. The Responder authenticates the Initiator first.
{{fig-variant2}} shows the message flow of PSK authentication method.

~~~~~~~~~~~~ aasvg
Initiator                                                   Responder
|                  METHOD, SUITES_I, G_X, C_I, EAD_1                |
+------------------------------------------------------------------>|
|                             message_1                             |
|                                                                   |
|                      G_Y, Enc( C_R, EAD_2 )                       |
|<------------------------------------------------------------------+
|                             message_2                             |
|                                                                   |
|                   Enc( ID_CRED_PSK ), AEAD( EAD_3 )               |
+------------------------------------------------------------------>|
|                             message_3                             |
|                                                                   |
|                           AEAD( EAD_4 )                           |
|<------------------------------------------------------------------+
|                             message_4                             |
~~~~~~~~~~~~
{: #fig-variant2 title="Overview of message flow of PSK." artwork-align="center"}

This approach provides protection against passive attackers for both Initiator and Responder.
message_4 remains optional, but is needed to authenticate the Responder and achieve mutual authentication in EDHOC if not relaying on external applications, such as OSCORE. With this fourth message, the protocol achieves both explicit key confirmation and mutual authentication.

# Key derivation

The pseudorandom keys (PRKs) used for PSK authentication method in EDHOC are derived using EDHOC_Extract, as done in {{RFC9528}}.

~~~~~~~~~~~~
PRK  = EDHOC_Extract( salt, IKM )
~~~~~~~~~~~~

where the salt and input keying material (IKM) are defined for each key.
The definition of EDHOC_Extract depends on the EDHOC hash algorithm selected in the cipher suite.

{{fig-variant2key}} lists the key derivations that differ from those specified in [Section 4.1.2 of RFC9528](https://www.rfc-editor.org/rfc/rfc9528.html#section-4.1.2).

~~~~~~~~~~~~
PRK_3e2m      = PRK_2e
PRK_4e3m      = EDHOC_Extract( SALT_4e3m, CRED_PSK )
KEYSTREAM_3   = EDHOC_KDF( PRK_3e2m,    TBD, TH_3,  ID_CRED_PSK length )
K_3           = EDHOC_KDF( PRK_4e3m,    TBD, TH_3,  key_length )
IV_3          = EDHOC_KDF( PRK_4e3m,    TBD, TH_3,  iv_length  )
~~~~~~~~~~~~
{: #fig-variant2key title="Key derivation of EDHOC PSK authentication method." artwork-align="center"}

where:

- KEYSTREAM_3 is used to encrypt the ID_CRED_PSK in message_3.
- TH_3 = H( TH_2, PLAINTEXT_2, CRED_PSK )

Additionally, the definition of the transcript hash TH_4 is modified as:

- TH_4 = H( TH_3, ID_CRED_PSK, ? EAD_3, CRED_PSK )

# Message formatting and processing

This section specifies the differences on the message formatting compared to {{RFC9528}}.

## Message 1

Same as message_1 of EDHOC, described in [Section 5.2.1 of RFC9528](https://www.rfc-editor.org/rfc/rfc9528.html#section-5.2.1).

## Message 2

message_2 SHALL be a CBOR sequence, defined as:

~~~~~~~~~~~~
message_2 = (
  G_Y_CIPHERTEXT_2 : bstr,
)
~~~~~~~~~~~~

where:

- G_Y_CIPHERTEXT_2 is the concatenation of G_Y (i.e., the ephemeral public key of the Responder) and CIPHERTEXT_2.
- CIPHERTEXT_2 is calculated with a binary additive stream cipher, using KEYSTREAM_2 and the following plaintext:

  - PLAINTEXT_2 = ( C_R, / bstr / -24..23, ? EAD_2 )
  - CIPHERTEXT_2 = PLAINTEXT_2 XOR KEYSTREAM_2

Contrary to {{RFC9528}}, MAC_2 is not used.

## Message 3

message_3 SHALL be a CBOR sequence, as defined below:

~~~~~~~~~~~~
message_3 = (
  CIPHERTEXT_3A: bstr,
  CIPHERTEXT_3B: bstr,
)
~~~~~~~~~~~~

where:

- CIPHERTEXT_3A is CBOR byte string, with value calculated by means of a binary additive stream cipher, XORing a KESYSTREAM_3 generated with EDHOC_Expand and the following plaintext:

  - PLAINTEXT_3A = ( ID_CRED_PSK )

- CIPHERTEXT_3B is the 'ciphertext' of COSE_Encrypt0 object as defined in [Section 5.2](https://www.rfc-editor.org/rfc/rfc9528.html#section-5.2) and [Section 5.3 of RFC9528](https://www.rfc-editor.org/rfc/rfc9528.html#section-5.3), with the EDHOC AEAD algorithm of the selected cipher suite, using the encryption key K_3, the initialization vector IV_3 (if used by the AEAD algorithm), the parameters described in [Section 5.2](https://www.rfc-editor.org/rfc/rfc9528.html#section-5.2), plaintext PLAINTEXT_3B and the following parameters as input:

  - protected = h''
  - external_aad = << Enc(ID_CRED_PSK), TH_3 >>
  - K_3 and IV_3 as defined in [Section 5.2](#message-2)
  - PLAINTEXT_3B = ( ? EAD_3 )

The Initiator computes TH_4 = H( TH_3, ID_CRED_PSK, PLAINTEXT_3B, CRED_PSK ), defined in [Section 5.2](#message-2).

## Message 4

message_4 is optional and is a CBOR sequence, defined as:

~~~~~~~~~~~~
message_4 = (
  CIPHERTEXT_4 : bstr,
)
~~~~~~~~~~~~

To authenticate the Responder and achieve mutual authentication, a fourth message is mandatory.
The Initiator MUST NOT persistently store PRK_out or application keys until the Initiator has verified message_4 or a message protected with a derived application key, such as an OSCORE message, from the Responder and the application has authenticated the Responder.

# Security Considerations

When evaluating the security considerations, it is important to differentiate between the initial handshake and session resumption phases.

  1. **Initial Handshake**: a fresh CRED_PSK is used to establish a secure connection.
  2. **Session Resumption**: the same PSK identifier (ID_CRED_PSK) is reused each time EDHOC is executed.
    While this enhances efficiency and reduces the overhead of key exchanges, it presents privacy risks if not managed properly.
    Over multiple resumption sessions, initiating a full EDHOC session changes the resumption PSK, resulting in a new ID_CRED_PSK.
    The periodic renewal of the CRED_PSK and ID_CRED_PSK helps mitigate long-term privacy risks associated with static key identifiers.

PSK authentication method introduces changes with respect to the current specification of EDHOC {{RFC9528}}. The protocol differs from EDHOC in the following ways:

  - ID_CRED_PSK is encrypted and sent in message 3, XOR encrypted with a keystream derived from the ephemeral shared secret G_XY. As a consequence, contrary totThe current EDHOC methods that protect the Initiator’s identity against active attackers and the Responder’s identity against passive attackers (See [Section 9.1 of RFC9528](https://www.rfc-editor.org/rfc/rfc9528.html#section-9.1)), EDHOC-PSK provides identity protection for both the Initator and the Responder against passive attackers.
  -  Mutual authentication depends on the security of the session key, i.e., the protocol's confidentiality. Both properties hold as long as the PSK remains secret.
  - Both the ephemeral components and the PSK are used as inputs of Key Derivation Function (KDF) to derive intermedaite keys (PRK). This hybrid approach guarantees as well post-quantum security, as defined in [Section 6.1](#post-quantum-considerations).
  - The current EDHOC protocol consists of three mandatory messages and an optional fourth message. In the case of EDHOC-PSK authentication method, message_4 remains optional, but mutual authentication is not guaranteed without it, or an OSCORE message or any application data that confirms that the Responder owns the PSK. Additionally, with this fourth message the protocol achieves explicit key confirmation in addition to mutual authentication.
  - Similarly to {{RFC9528}}, EDHOC-PSK provides external authorization data protection.

## Post Quantum Considerations

Recent achievements in developing quantum computers demonstrate that it is probably feasible to build one that is cryptographically significant. If such a computer is implemented, many of the cryptographic algorithms and protocols currently in use would be insecure. A quantum computer would be able to solve Diffie-Hellman (DH) and Elliptic Curve Diffie-Hellman (ECDH) problems in polynomial time.

EDCHOC with pre-shared keys would not be vulnerable to quantum attacks because those keys are used as inputs to the key derivation function. The use of intermediate keys derived through key derivation functions ensure that the message is not immediately compromised if the symmetrically distributed key (PSK) is compromised, or if the algorithm used to distribute keys asymmetrically (DH) is broken. If the pre-shared key has sufficient entropy and the Key Derivation Function (KDF), encryption, and authentication transforms are quantum secure, then the resulting system is believed to be quantum secure.
Therefore, provided that the PSK remains secret, EDHOC-PSK provides confidentiality, mutual authentication and Perfect Forward Secrecy (PFS) even in the presence of quantum attacks. What is more, the key exchange is still a key agreement where both parties contribute with randomness.

# Unified Approach and Recommendations

For use cases involving the transmission of application data, application data can be sent concurrently with message_3, maintaining the protocol's efficiency.
In applications such as EAP-EDHOC, where application data is not sent, message_4 is mandatory. Thus, EDHOC-PSK authentication method does not include any extra messages.
Other implementations may continue using OSCORE in place of EDHOC message_4, with a required change in the protocol's language to:
      The Initiator SHALL NOT persistently store PRK_out or application keys until the Initiator has verified message_4 or a message protected with a derived application key, such as an OSCORE message.

This change ensures that key materials are only stored once their integrity and authenticity are confirmed, thereby enhancing privacy by preventing early storage of potentially compromised keys.

Lastly, whether the Initiator or Responder authenticates first is not relevant when using symmetric keys.
This consideration was important for the privacy properties when using asymmetric authentication but is not significant in the context of symmetric key usage.

# IANA Considerations

This document has no IANA actions.

--- back

# Acknowledgments
{:numbered="false"}

TODO acknowledge.
