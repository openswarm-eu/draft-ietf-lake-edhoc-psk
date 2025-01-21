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
  RFC9529:
  RFC9052:

informative:

--- abstract

This document specifies the Pre-Shared Key (PSK) authentication method for the Ephemeral Diffie-Hellman Over COSE (EDHOC) key exchange protocol. It describes the authentication processes, message flows, and security considerations of this authentication method.

--- middle

# Introduction

## Motivation

Pre-shared key (PSK) authentication method provides a balance between security and computational efficiency.
This authentication method was proposed in the first I-Ds of Ephemeral Diffie-Hellman Over COSE (EDHOC) {{RFC9528}}, and was ruled out to speed out the development process.
However, there is now a renewed effort to reintroduce PSK authentication, making this draft an update to the {{RFC9528}}.

EDHOC with PSK authentication could be beneficial for existing systems where two nodes have been provided with a PSK from other parties out of band.
This allows the nodes to perform ephemeral Diffie-Hellman to achieve Perfect Forward Secrecy (PFS), ensuring that past communications remain secure even if the PSK is compromised.
The authentication provided by EDHOC prevents eavesdropping by on-path attackers, as they would need to be active participants in the communication to intercept and potentially tamper with the session.
Examples could be Generic Bootstrapping Architecture (GBA) and Authenticated Key Management Architecture (AKMA) in mobile systems, or Peer and Authenticator in EAP.

Another prominent use case of PSK authentication in the EDHOC protocol is session resumption.
This allows previously connected parties to quickly reestablish secure communication using pre-shared keys from their earlier session, reducing the overhead of full key exchange.
This efficiency is beneficial in scenarios where frequent key updates are needed, such in resource-constrained environments or applications requiring high-frequency secure communications.
The use of PSK authentication in EDHOC ensures that session key can be refreshed without heavy computational overhead, typically associated with public key operations, thus optimizing both performance and security.



## Assumptions

# Conventions and Definitions

{::boilerplate bcp14-tagged}

# Protocol

In this method, the Pre-Shared Key identifier (ID_CRED_PSK) is sent in message_3. The ID_CRED_PSK allows retrieval of CRED_PSK, a COSE object that contains the PSK. Through this document we will refer to the Pre-Shared Key authentication method as EDHOC-PSK.

## Credentials

Initiator and Responder are assumed to have a PSK with good amount of randomness and the requirements that:

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
message_4 remains optional, but is needed to to authenticate the Responder and achieve mutual authentication in EDHOC if not relaying on external applications, such as OSCORE. With this fourth message, the protocol achieves both explicit key confirmation and mutual authentication.

# Key derivation

The pseudorandom keys (PRKs) used for PSK authentication method in EDHOC are derived using EDHOC_Extract, as done in {{RFC9528}}.

~~~~~~~~~~~~
PRK  = EDHOC_Extract( salt, IKM )
~~~~~~~~~~~~

where the salt and input keying material (IKM) are defined for each key.
The definition of EDHOC_Extract depends on the EDHOC hash algorithm selected in the cipher suite.

{{fig-variant2key}} lists the key derivations that differ from those specified in Section 4.1.2 of {{RFC9528}}.

~~~~~~~~~~~~
PRK_3e2m      = PRK_2e
PRK_4e3m      = EDHOC_Extract( SALT_4e3m, CRED_PSK )
KEYSTREAM_3   = EDHOC_KDF( PRK_3e2m,    TBD,  TH_3,       key_length )
K_3           = EDHOC_KDF( PRK_4e3m,    TBD,  TH_3,  key_length )
IV_3          = EDHOC_KDF( PRK_4e3m,    TBD,  TH_3,  iv_length  )
~~~~~~~~~~~~
{: #fig-variant2key title="Key derivation of EDHOC PSK authentication method." artwork-align="center"}

where:

- KEYSTREAM_3 is used to encrypt the ID_CRED_PSK in message_3.
- TH_3 = H( TH_2, PLAINTEXT_2, CRED_PSK )
- TH_4 = H( TH_3, ID_CRED_PSK, ? EAD_3, CRED_PSK )

# Message formatting and processing. Differences with respect to {{RFC9528}}

This section specifies the differences on the message formatting compared to {{RFC9528}}.

## Message 1

Same as message_1 of EDHOC, described in Section 5.2.1 of {{RFC9528}}.

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

message_3 SHALL be a bit string, as defined below:

~~~~~~~~~~~~
message_3 = (
  CIPHERTEXT_3: bstr,
)
~~~~~~~~~~~~

where:

- CIPHERTEXT_3 is a concatenation of two different ciphertexts, each of it a CBOR Sequence:

  - CIPHERTEXT_3A is CBOR Sequence calculated with a binary additive stream cipher, using a KESYSTREAM_3 generated with EDHOC_Expand and the following plaintext:

    - PLAINTEXT_3A = ( ID_CRED_PSK )

  - CIPHERTEXT_3B is a COSE_Encrypt0 object as defined in Sections 5.2 and 5.3 of {{RFC9052}}, with the EDHOC AEAD algorithm of the selected cipher suite, using the encryption key K_3, the initialization vector IV_3 (if used by the AEAD algorithm), the parameters described in Section 5.2 of {{RFC9528}}, plaintext PLAINTEXT_3B and the following parameters as input:

    - protected = h''
    - external_aad = << Enc(ID_CRED_PSK), TH_3 >>
    - K_3 and IV_3 as defined in Section 5.2
    - PLAINTEXT_3B = ( ? EAD_3 )

The Initiator computes TH_4 = H( TH_3, ID_CRED_PSK, PLAINTEXT_3, CRED_PSK ), defined in Section 5.2.

## Message 4

message_4 is mandatory and is a CBOR sequence, defined as:

~~~~~~~~~~~~
message_4 = (
  CIPHERTEXT_4 : bstr,
)
~~~~~~~~~~~~

A fourth message is mandatory for Responder's authentication.
The Initiator MUST NOT persistently store PRK_out or application keys until the Initiator has verified message_4 or a message protected with a derived application key, such as an OSCORE message, from the Responder and the application has authenticated the Responder.

# Security Considerations

When evaluating the security considerations, it is important to differentiate between the initial handshake and session resumption phases.

  1. **Initial Handshake**: a fresh CRED_PSK is used to establish a secure connection.
  2. **Session Resumption**: the same PSK identifier (ID_CRED_PSK) is reused each time EDHOC is executed.
    While this enhances efficiency and reduces the overhead of key exchanges, it presents privacy risks if not managed properly.
    Over multiple resumption sessions, initiating a full EDHOC session changes the resumption PSK, resulting in a new ID_CRED_PSK.
    The periodic renewal of the CRED_PSK and ID_CRED_PSK helps mitigate long-term privacy risks associated with static key identifiers.

## Identity protection

The current EDHOC methods protect the Initiator’s identity against active attackers and the Responder’s identity against passive attackers (See Section 9.1 of {{RFC9528}}).
With EDHOC-PSK authentication method, both the Initiator's and Responder's identities are protected against passive attackers, but not against active attackers.

## Number of messages

The current EDHOC protocol consists of three mandatory messages and an optional fourth message.
In the case of EDHOC-PSK authentication method, message_4 remains optional, but mutual authentication is not guaranteed without it, or an OSCORE message or any application data that confirms that the Responder owns the PSK. Additionally, with this fourth message the protocol achieves explicit key confirmation in addition to mutual authentication.

## External Authorization Data

The Initiator and Responder can send information in EAD_3 and EAD_4 or in OSCORE messages in parallel with message_3 and message_4.
This is possible because the Initiator knows that only the Responder with access to the CRED_PSK can decrypt the information.

## Attacks

EDHOC-PSK authentication method offers privacy and resistance to passive attacks but might be vulnerable to certain active attacks due to delayed authentication.

# Privacy Considerations

# Unified Approach and Recommendations

For use cases involving the transmission of application data, application data can be sent concurrently with message_3, maintaining the protocol's efficiency.
In applications such as EAP-EDHOC, where application data is not sent, message_4 is mandatory. Thus, EDHOC-PSK authentication method doe snot include any extra messages.
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
