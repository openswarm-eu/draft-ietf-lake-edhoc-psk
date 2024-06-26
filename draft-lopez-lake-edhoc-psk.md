---
title: "EDHOC PSK authentication"
abbrev: "TODO - Abbreviation"
category: info

docname: draft-lopez-lake-edhoc-psk-latest
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
    fullname: Elsa Lopez Perez
    organization: Inria
    email: elsa.lopez-perez@inria.fr

normative:

  RFC9528:
  RFC9529:
  RFC9052:

informative:

--- abstract

TODO Abstract

--- middle

# Introduction

## Motivation

Pre-shared key (PSK) authentication method provides a balance between security and computational efficiency.
This authentication method was proposed in the first drafts of Ephemeral Diffie-Hellman Over COSE (EDHOC), and was ruled out to speed out the development process.
However, there is now a renewed effort to reintroduce PSK authentication, making this draft an update to the {{RFC9528}}.

One prominent use case of PSK authentication in the EDHOC protocol is the update of session keys.
This method aims to reduce the computational cost that comes with re-running the protocol with public authentication keys.
This efficiency is beneficial in scenarios where frequent key updates are needed, such in resource-constrained environments or applications requiring high-frequency secure communications.
The use of PSK authentication in EDHOC ensures that session key can be refreshed without heavy computational overhead, typically associated with public key operations, thus optimizing both performance and security.

The resumption capability in Extensible Authentication Protocol (EAP) leveraging EDHOC can benefit from this method.
EAP-EDHOC resumption aims to provide a streamlined process for re-establishing secure sessions, reducing latency and resource consumption.
By employing PSK authentication for key updates, EAP-EDHOC resumption can achieve  secure session resumption, enhancing overall efficiency and user experience.

EDHOC with PSK authentication is also beneficial for existing systems where two nodes have been provided with a PSK from other parties.
This allows the nodes to perform ephemeral Diffie-Hellman to achieve Perfect Forward Secrecy (PFS), ensuring that past communications remain secure even if the PSK is compromised.
The authentication provided by EDHOC prevents eavesdropping by on-path attackers, as they would need to be active participants in the communication to intercept and potentially tamper with the session.
Examples could be Generic Bootstrapping Architecture (GBA) and Authenticated Key Management Architecture (AKMA) in mobile systems, or Peer and Authenticator in EAP.

## Assumptions

# Conventions and Definitions

{::boilerplate bcp14-tagged}

# Protocol

There are currently two proposed versions of the authentication method, depending on where the pre-shared key identifier (ID_CRED_PSK) is sent.
ID_CRED_PSK allows retrieval of CRED_PSK, a COSE object that contains the PSK.

In both cases, Initiator and Responder are assumed to have a PSK with good amount of randomness and the requirements that:

- Only the Initiator and the Responder have access to the PSK.
- The Responder is able to retrieve the PSK using ID_CRED_PSK.

where:

- ID_CRED_PSK is a COSE header map containing header parameters that can identify a pre-shared key. For example:

~~~~~~~~~~~~
ID_CRED_PSK = {4 : h'lf' }
~~~~~~~~~~~~

- CRED_PSK is a COSE_Key compatible credential, encoded as a CCS or CWT. For example:

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
If ID_CRED_PSK contains a single 'kid' parameter, then the compact encoding is applied; see Section 3.5.3.2 of {{RFC9528}}.
The authentication credential CRED_PSK substitutes CRED_I and CRED_R specified in {{RFC9529}}, and, when applicable, MUST follow the same guidelines described in Sections 3.5.2 and 3.5.3 of {{RFC9528}}.

# Variant 1

In the first variant of the method the ID_CRED_PSK is sent in the clear in the first message.
{{fig-variant1}} shows the message flow of Variant 1.

~~~~~~~~~~~~ aasvg
Initiator                                                   Responder
|          METHOD, SUITES_I, G_X, C_I, ID_CRED_PSK, EAD_1           |
+------------------------------------------------------------------>|
|                             message_1                             |
|                                                                   |
|                    G_Y, Enc( C_R, MAC_2, EAD_2 )                  |
|<------------------------------------------------------------------+
|                             message_2                             |
|                                                                   |
|                           AEAD( EAD_3 )                           |
+------------------------------------------------------------------>|
|                             message_3                             |
|                                                                   |
|                           AEAD( EAD_4 )                           |
|<- - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - +
|                             message_4                             |
~~~~~~~~~~~~
{: #fig-variant1 title="Overview of message flow of Variant 1." artwork-align="center"}

This variant incurs minimal modifications with respect to the current methods described in {{RFC9528}} and the fourth message remains optional.
MAC_3 is removed in message_3 and replaced by AEAD.
This approach is similar to TLS 1.3, and, consequently, has similar privacy issues. For example:

- **Identity Leakage**: neither the identity of the Initiator nor the Responder are protected against active or passive attackers.
By sending the ID_CRED_PSK in the clear, the initiator reveals its identity to any eavesdropper on the network.
This allows passive observers to learn which client is attempting to connect to the server.
- **Tracking and correlation**: An attacker can use the plaintext ID_CRED_PSK to track the client across multiple connections, even if those connections are made from different networks or at different times.
This enables long-term tracking of clients.
- **Information leakage about relationships**: ID_CRED_PSK also reveals information about the relationship between the client and the server.
An observer can infer that the two parties have a pre-existing relationship and have previously agreed on a shared secret.
- **Replay and preplay attacks**: ID_CRED_PSK can facilitate replay attacks.
An attacker might use the observed ID_CRED_PSK to initiate their own connection attempts, potentially leading to denial-of-service or other attacks.
- **Downgrade attacks**: If multiple PSKs are available (e.g., of varying strengths or for different purposes), an attacker might attempt to force the use of a weaker or less privacy-preserving PSK by manipulating the ID_CRED_PSK field.

## Variant 2

The ID_CRED_PSK is sent in message_3, encrypted using a key derived from the ephemeral shared secret, G_XY.
In this case, the Responder will authenticate the Initiator first, contrary to Variant 1.
{{fig-variant2}} shows the message flow of Variant 2.

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
{: #fig-variant2 title="Overview of message flow of Variant 2." artwork-align="center"}

Contrary to Variant 1, this approach provides protection against passive attackers for both Initiator and Responder.
message_4 remains optional, but is needed to achieve mutual authentication if not relaying on external applications, such as OSCORE.

# Key derivation

The pseudorandom keys (PRKs) used for PSK authentication method in EDHOC are derived using EDHOC_Extract, as done in {{RFC9528}}.

~~~~~~~~~~~~
PRK  = EDHOC_Extract( salt, IKM )
~~~~~~~~~~~~

where the salt and input keying material (IKM) are defined for each key.
The definition of EDHOC_Extract depends on the EDHOC hash algorithm selected in the cipher suite.

## Variant 1

{{fig-variant1key}} lists the key derivations that differ from those specified in Section 4.1.2 of {{RFC9528}}.

~~~~~~~~~~~~
PRK_3e2m      = EDHOC_Extract( salt3e_2m, CRED_PSK )
PRK_4e3m      = PRK_3e2m
MAC_2         = EDHOC_KDF( PRK_3e2m,      2,  context_2,  mac_length_2 )
K_3           = EDHOC_KDF( PRK_4e3m,    TBD,  context_3,  key_length   )
IV_3          = EDHOC_KDF( PRK_4e3m,    TBD,  context_3,  iv_length    )
~~~~~~~~~~~~
{: #fig-variant1key title="Key derivation of variant 1 of EDHOC PSK authentication method." artwork-align="center"}

where:

- context_2 = <<C_R, ID_CRED_PSK, TH_2, CRED_PSK, ? EAD_2>>
- context_3 = <<ID_CRED_PSK, TH_3, CRED_PSK, ? EAD_3>>

## Variant 2

{{fig-variant2key}} lists the key derivations that differ from those specified in Section 4.1.2 of {{RFC9528}}.

~~~~~~~~~~~~
PRK_4e3m      = EDHOC_Extract( SALT_4e3m, CRED_PSK )
KEYSTREAM_3   = EDHOC_KDF( PRK_3e2m,    TBD,  TH_3,       key_length )
K_3           = EDHOC_KDF( PRK_4e3m,    TBD,  context_3,  key_length )
IV_3          = EDHOC_KDF( PRK_4e3m,    TBD,  context_3,  iv_length  )
~~~~~~~~~~~~
{: #fig-variant2key title="Key derivation of variant 2 of EDHOC PSK authentication method." artwork-align="center"}

where:

- KEYSTREAM_3 is used to encrypt the ID_CRED_PSK in message_3.
- context_3 <<ID_CRED_PSK, TH_3, CRED_PSK, ? EAD_3>>
- TH_3 = H( TH_2, PLAINTEXT_2)
- TH_4 = H( TH_3, ID_CRED_PSK, ? EAD_3, CRED_PSK )

# Message formatting and processing. Differences with respect to {{RFC9528}}

This section specifies the differences on the message formatting compared to {{RFC9528}}.

## Variant 1

### Message 1

message_1 contains the ID_CRED_PSK.
The composition of message_1 SHALL be a CBOR sequence, as defined below:

~~~~~~~~~~~~
message_1 = (
  METHOD : int,
  SUITES_I : suites,
  G_X : bstr,
  C_I : bstr / -24..23,
  ID_CRED_PSK : header map // kid_value : bstr,
  ? EAD_1,
)

suites =  [ 2* int ] / int
EAD_1 = 1* ead
~~~~~~~~~~~~

where:

- ID_CRED_PSK is an identifier used to facilitate retrieval of the PSK.

The Initiator includes ID_CRED_PSK in message_1 and encodes the full message as a sequence of CBOR-encoded data items as specified in Section 5.2.1. of {{RFC9528}}

The Responder SHALL process message_1 as follows:

- Decode message_1.
- Retrieve CRED_PSK using ID_CRED_PSK.
- Process message_1 as specified in Section 5.2.3. of {{RFC9528}}.

### Message 2

message_2 SHALL be a CBOR sequence, defined as:

~~~~~~~~~~~~
message_2 = (
  G_Y_CIPHERTEXT_2 : bstr,
)
~~~~~~~~~~~~

where:

- G_Y_CIPHERTEXT_2 is the concatenation of G_Y (i.e., the ephemeral public key of the Responder) and CIPHERTEXT_2.
- CIPHERTEXT_2 is calculated with a binary additive stream cipher, using KEYSTREAM_2 and the following plaintext:

  - PLAINTEXT_2 = (C_R, / bstr / -24..23, MAC_2, ? EAD_2)
  - CIPHERTEXT_2 = PLAINTEXT_2 XOR KEYSTREAM_2

The Responder uses MAC instead of Signature. Hence, COSE_Sign1 is not used.
The Responder computes MAC_2 as described in Section 4.1.2 of {{RFC9528}}, with context_2 <<C_R, ID_CRED_PSK, TH_2, CRED_PSK, ? EAD_2>>

### Message 3

message_3 SHALL be a CBOR sequence, defined as:

~~~~~~~~~~~~
message_3 = (
  CIPHERTEXT_3 : bstr,
)
~~~~~~~~~~~~

The Initiator computes a COSE_Encrypt0 object as defined in Section 5.2 and 5.3 of {{RFC9052}} with the EDHOC AEAD algorithm of the selected cipher suite and the following parameters:

- K_3 and IV_3 as defined in Section 4.1.2 of {{RFC9528}}
- PLAINTEXT_3 = ( ID_CRED_PSK / bstr / -24..2, ? EAD_3 )

The Initiator computes TH_4 = H( TH_3, ID_CRED_PSK, PLAINTEXT_3, CRED_PSK )

### Message 4

message_4 SHALL be a CBOR sequence, defined as:

~~~~~~~~~~~~
message_4 = (
  CIPHERTEXT_4 : bstr,
)
~~~~~~~~~~~~

message_4 is optional.

## Variant 2

### Message 1

Same as message_1 of EDHOC, described in Section 5.2.1 of {{RFC9528}}.

### Message 2

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

Contrary to {{RFC9528}} and Variant 1, MAC_2 is not needed.

### Message 3

message_3 SHALL be a CBOR Sequence, as defined below:

~~~~~~~~~~~~
message_3 = (
  CIPHERTEXT_3
)
~~~~~~~~~~~~

where:

- CIPHERTEXT_3 is a concatenation of two different ciphertexts:

  - CIPHERTEXT_3A is calculated with a binary additive stream cipher, using a KESYSTREAM_3 generated with EDHOC_Expand and the following plaintext:

    - PLAINTEXT_3A = ( ID_CRED_PSK )

  - CIPHERTEXT_3B is a COSE_Encrypt0 object as defined in Sections 5.2 and 5.3 of {{RFC9052}}, with the EDHOC AEAD algorithm of the selected cipher suite, using the encryption key K_3, the initialization vector IV_3 (if used by the AEAD algorithm), the parameters described in Section 5.2 of {{RFC9528}}, plaintext PLAINTEXT_3B and the following parameters as input:

    - protected = h''
    - external_aad = context_3, defined in Section 5.2
    - K_3 and IV_3 as defined in Section 5.2
    - PLAINTEXT_3B = ( ? EAD_3 )

The Initiator computes TH_4 = H( TH_3, ID_CRED_PSK, PLAINTEXT_3, CRED_PSK ), defined in Section 5.2.

### Message 4

message_4 SHALL be a CBOR sequence, defined as:

~~~~~~~~~~~~
message_4 = (
  CIPHERTEXT_4 : bstr,
)
~~~~~~~~~~~~

A fourth message is mandatory.
The Initiator MUST NOT persistently store PRK_out or application keys until the Initiator has verified message_4 or a message protected with a derived application key, such as an OSCORE message, from the Responder and the application has authenticated the Responder.

# Security Considerations

When evaluating the security considerations, it is important to differentiate between the initial handshake and session resumption phases.

  1. **Initial Handshake**: a fresh CRED_PSK is used to establish a secure connection.
  2. **Session Resumption**: the same PSK identifier (ID_CRED_PSK) is reused each time EDHOC is executed.
    While this enhances efficiency and reduces the overhead of key exchanges, it presents privacy risks if not managed properly.
    Over multiple resumption sessions, initiating a full EDHOC session changes the resumption PSK, resulting in a new ID_CRED_PSK.
    The periodic renewal of the CRED_PSK and ID_CRED_PSK helps mitigate long-term privacy risks associated with static key identifiers.

## Identity protection

The current EDHOC methods protect the Initiator’s identity against active attackers and the Responder’s identity against passive attackers.
However, there are differences between the two variants described in this draft:

  1. **Variant 1**: neither the Initiator's identity nor the Responder's identity are protected against active or passive attackers.
  2. **Variant 2**: both the Initiator's and Responder's identities are protected against passive attackers.

## Number of messages

The current EDHOC protocol consists of three mandatory messages and an optional fourth message.
The PSK authentication method might require a compulsory message depending on which variant is employed:

  1. **Variant 1**: message_4 is optional since both identities are authenticated after message_3.
  2. **Variant 2**: message_4 remains optional, but mutual authentication is not guaranteed without it, or an OSCORE message.

## External Authorization Data

In both variants, the Initiator and Responder can send information in EAD_3 and EAD_4 or in OSCORE messages in parallel with message_3 and message_4.
This is possible because the Initiator knows that only the entity with access to the CRED_PSK can decrypt the information.

## Optimization

1. **Variant 1**: ID_CRED_PSK is sent without encryption, saving computational resources at the cost of privacy.
The exposure of ID_CRED_PSK in message_1 allows for earlier key derivation on the responder's side, potentially speeding up the process.
2. **Variant 2**: It requires encryption of ID_CRED_PSK in message_3, which implies higher computational cost.

## Mutual Authentication

Mutual authentication is achieved at earlier stages in Variant 1, which might be important in certain applications, as well as increasing security against Denial of Service attacks or oracle attacks.

## Attacks

1. **Variant 1**: it allows for earlier authentication, potentially improving resistance to some active attacks, but at the cost of reduced privacy and increased vulnerability to passive attacks and traffic analysis.-
2. **Variant 2**: it  offers better privacy and resistance to passive attacks but might be more vulnerable to certain active attacks due to delayed authentication.

## Comparison

| Aspect | Variant 1 (Clear ID_CRED_PSK) | Variant 2 (Encrypted ID_CRED_PSK) |
|--------|-----------------------------------|--------------------------------------|
| Privacy | Lower: ID_CRED_PSK sent in clear in message_1 | Higher: ID_CRED_PSK encrypted in message_3 |
|---|---|---|
| Initiator Identity Protection | Exposed from message_1 | Protected until message_3 |
|---|---|---|
| Authentication Timing | Earlier, possible from message_1 | Delayed until message_3 |
|---|---|---|
| Computational Efficiency | Slightly higher (no encryption of ID_CRED_PSK) | Slightly lower (encryption of ID_CRED_PSK) |
|---|---|---|
| Resistance to Passive Attacks | Lower due to exposed identity | Higher due to identity protection |
|---|---|---|
| Early Access Control | Possible from message_1 | Limited, delayed until message_3 |
|---|---|---|
| DoS Attack Vulnerability | Lower due to early authentication | Potentially higher due to delayed authentication |
|---|---|---|
| Resource Allocation | Fewer resources allocated before authentication | More resources allocated before authentication |
|---|---|---|
| Compatibility with Systems Expecting Early ID | Higher | Lower |
|---|---|---|
| Flexibility for Identity Protection | Lower | Higher |
|---|---|---|
| Key Derivation Timing | Potentially earlier | Potentially delayed |
|---|---|---|
| Completeness | Complete with optional message_4 | Complete with optional message_4 |
|---|---|---|
| Suitability for Quick Identification Scenarios | Higher | Lower |
{: #comparison-table title="Comparison between Variant 1 and Variant 2." cols="r l l"}

# Privacy Considerations

# Unified Approach and Recommendations

To improve privacy during both initial handshake and session resumption, a single unified method for handling PSKs could be beneficial.
Variant 2 is particularly suitable for this purpose as it streamlines key management and usage across different phases.

For use cases involving the transmission of application data, application data can be sent concurrently with message_3, maintaining the protocol's efficiency.
In scenarios such as EAP-EDHOC, where application data is not sent, message_4 is mandatory.
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
