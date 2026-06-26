
context 
using ../tools/secret_manager
using ../tools/shared_secrets
as templates when things are unclear/incomplete

using libs: 
../simple-ui
../simple-network
../rust-secure-memory-public

we will design a system of secret managers

constraint #1:
- use PQC for auth
- be paranoid for encryption
- use VDF style KDF (it takes time to try something else!)

what can be done:
- save secrets
- reload secrets, to pipe,env etc. 
- load secrets to temporary in RAM only managers 
- pair with another secret manager
- share secret to others, using assymetric encryption,
as well as network connection with KEM etc. [proper pairing]

MULTI SIGNATURE STYLE
extra app: phone/tablet, that can be used for multifactor validation
key point: some secrets will be stored as a k in n form [for instance, with retrieval formula "HASH(secret1, secret2) XOR magic" or something else so that it is technically/practically impossible to retrieve the secret with one part only ]
secret sharing of this type can be with edge devices as well as regular desktop

scenarios
- retrieve secret locally
- send secret via binary/ascii blob
- load secret
- send secret to paired device
- multiple/MPC style secret retrieval [n of k style]
- multisig [ PQC multi sig would be nice => websearch ]
- temporory transfer of secret to remote secret manager 
- integration as lib, with plugable RNG/Entropy source 
- multifactor factor for auth 

all WELL DOCUMENTED
by default, the storage is locked by a LOCAL pasword 
the default is to propose a password as a passphrase: 20, 40 words a la winter solider/BTC wallet/etc.

network: local netwrok + Tor/I2P
[ look at ../service-network for examples, in case ]

PLAN.
PROPOSE IMPROVEMENT REQUESTS TO DEPS [simple-ui, simple-network, rust-secure-memory-public], only if really needed
model key security properties in lean4

many phases, many steps
CI vi a local ci.sh script, linux + mac 