# xsig: eXtended signatures

**xsig** (eXtended signatures) is a library for specifying an authorization policy together with an evaluation engine. Something like "signatures on steroids" -- cryptographic signatures with finer-grained authorization conditions. Let's see some examples:

- "run this software only if at least two signatures are valid out of a set of 5 public keys" *(quorum-based authorization)*

- "run this software only on the HSM with serial number 12345 and if it is earlier than Jan 1st, 2042" *(per-device signing, time-bound authorization)*

- "accept this command if it's been signed by [two engineers and one manager] or [two vice-presidents]" *(slightly more complex access structure)*

## Components
**xsig** consists of two separate parts:

1. A minimalistic **domain-specific language** to express policy conditions, along with tooling to write and serialize these conditions. Using this language you can express an elaborate condition based on AND/OR combination of subconditions based off quora, time, etc.

2. An **evaluation engine** based on a simple interpreter. This interpreter is compact and suitable for embedding in bootloaders or other constrained environments like HSMs.

Using **xsig** saves you from writing the scary code that does policy enforcement and at the same time gives you a way to express / update / change policy conditions.

## Interface

The current version of **xsig** basically implements the following function:

```
func Eval(xpublickey, xsignature, msg) -> {0,1}
```

Let's look at the arguments:
 * `xpublickey` is actually a policy (called "locking script" elsewhere), you can think of it as an "extended public key". In the simplest form, it _is_ just a public key.
 * `xsignature` is a statement that should satisfy the policy. This generalizes the idea of "signature" (also called "unlocking script").

The function returns 1 if `xsignature` is a valid "extended" signature for `msg` under `xpublickey`.

## Design

Under the hood, **xsig** embeds a simple interpreter in the spirit of Forth / inspired by Bitcoin script. We keep things very simple to make it easy to extend and reason about the security and correctness of the interpreter.
This is the order of execution for the function above:

1. Evaluate `xsignature`. This typically prepares the stack
1. Copy the data stack to a fresh new machine
1. Evaluate `xpublickey`
1. Succeed if the stack is exactly `[1]`, fail otherwise

To reason about correctness, consider `xsignature` completely untrusted and `xpublickey` trusted. Then, convince yourself there's no way to trick `xpublickey` to return a `[1]` other than by using the legitimate `xsignature`.


**Other machines**. A future machine could introduce some minimal I/O mechanisms to run interactive protocols (think challenge-response for FA unlock, or absolute time synchronization, etc).


**WARNING**: Experimental research code.
Big bugs will bite.
Written by a single person with zero peer review.

## Future work

- [ ] C interpreter
- [ ] Multisignatures
- [ ] miniscript-like compiler
- [ ] semi-formal security argument / security verification
- [ ] delegation certs
- [ ] serial numbers / device unique string

## Contact

https://github.com/oreparaz/xsig
