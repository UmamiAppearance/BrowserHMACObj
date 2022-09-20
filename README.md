# BrowserHMACObj

[![License](https://img.shields.io/github/license/UmamiAppearance/BrowserHMACObj?color=009911&style=for-the-badge)](./LICENSE)
[![npm](https://img.shields.io/npm/v/browser-hmac-obj?color=%23009911&style=for-the-badge)](https://www.npmjs.com/package/browser-hmac-obj)


**BrowserHMACObj** creates a HMAC-SHA-(1/256/384/512) object. It is related to [pythons hmac libary](https://docs.python.org/3/library/hmac.html) in its methods and features but with many extras. It provides an easy access to the browsers ``Crypto.subtle`` method, and also makes it possible to get multiple different digest methods with a little help of [BaseEx](https://github.com/UmamiAppearance/BaseExJS).

## Installation

### GitHub
```sh
git clone https://github.com/UmamiAppearance/BrowserHMACObj.git
```

### npm
```sh
nmp install browser-hmac-obj
```

## Builds
You can find builds in [dist](https://github.com/UmamiAppearance/BrowserHMACObj/tree/main/dist). If you want to build by yourself run:

```sh
npm run build
``` 

Two types are available ([esm](https://developer.mozilla.org/en-US/docs/Web/JavaScript/Guide/Modules) and [iife](https://developer.mozilla.org/en-US/docs/Glossary/IIFE)), plus a minified version of each. 
* ``BrowserHMACObj.esm.js``
* ``BrowserHMACObj.esm.min.js``
* ``BrowserHMACObj.iife.js``
* ``BrowserHMACObj.iife.min.js``


## Usage

### Importing
BrowserHMACObj is a ESM module and exported as _default_. Importing works as follows:
```js
// esm
import BrowserHMACObj from "./path/BrowserHMACObj.esm.min.js";

// esm from CDN (jsdelivr)
import BrowseHMACObj from "https://cdn.jsdelivr.net/npm/browser-hmac-obj@latest/dist/BrowserHMACObj.esm.min.js"
```

```html
<!-- script tag -->
<script src="./path/BrowserHMACObj.iife.min.js"></script>

<!-- script tag from CDN (jsdelivr)-->
<script src="https://cdn.jsdelivr.net/npm/browser-hmac-obj@latest/dist/BrowserHMACObj.iife.min.js"></script>
```

### Creating an instance    
The constructor takes one argument for the ``digestmod``. Available options are:
* ``SHA-1``
* ``SHA-256``
* ``SHA-384``
* ``SHA-512``

There a two possible methods available to create an instance:

#### new operator
```js
const hmacSHA256 = new BrowserHMACObj("SHA-256");
```

#### new method
This method is asynchronous to allow you to associate a message in one go.
```js
const hmacSHA512 = await HMACObj.new("super_secret_key", "Hello World!", "SHA-512");
```


### Methods and Properties


#### Static

##### ``BrowserHMACObj.digestmodsAvailable()``
A set containing the names of the hash algorithms that are available.

##### ``BrowserHMACObj.keyFormats()``
Static method to receive a set of the available key formats.

##### ``BrowserHMACObj.new(key=null, msg=null, digestmod="", keyFormat="raw", permitExports=false)``
Asynchronously creates a new instance. In contrast to the regular [new operator](#new-operator) a message and key can  be provided. If a message is set, a key must also be handed over or a crypto key gets generated automatically.  
  
A message gets passed to the [``update``](#updateinput-replacefalse) method.

##### ``BrowserHMACObj.generateKey()``
Static asynchronous method to generate a crypto key for the HMAC algorithm.

##### ``BrowserHMACObj.compareDigest(a, b)``
Return ``a === b``. This function uses an approach designed to prevent timing analysis by avoiding content-based short circuiting behavior, making it appropriate for cryptography.  

``a`` and ``b`` (or more precisely their byte representation) must both be of the same type.

##### ``BrowserHMACObj.baseEx``
A [BaseEx Instance](https://github.com/UmamiAppearance/BaseExJS#available-converterscharsets) for the possibility to manually convert (byte) representations.

#### Instance

##### ``digestSize`` _(property)_
The size of the resulting HMAC in bytes.

##### ``blockSize`` _(property)_
The internal block size of the hash algorithm in bytes.

##### ``name`` _(property)_
The canonical name of this HMAC, always uppercase and always suitable as a parameter to create another HMAC of this type.

##### ``update(input[, replace=false])``
Update the HMAC object with almost any input. The input gets converted to a ``Uint8Array``. Unless ``replace`` is set to true, repeated calls are equivalent to a single call with the concatenation of all the arguments:  
``hmacObj.update(a)``; ``hmacObj.update(b)`` is in many occasions equivalent to ``hmacObj.update(a+b)``.  
  
_(Note: The process is a concatenation of bytes. Take as an exception for instance ``hmacObj.update(1)``; ``hmacObj.update(2)``, which is not the same as ``hmacObj.update(1+2)``)_

##### ``replace(input)``
Replace the the HMAC object with fresh input (the same as ``update(input, true)``).

##### ``sign(msg, base=null)``
Signs a single message independent from the current instance message. If a base is provided, the key gets returned in the corresponding [base representation](https://umamiappearance.github.io/BrowserHMACObj/examples/live-examples.html#base-representations).

##### ``verify(msg, signature)``
A given message (``msg``) and ``signature`` can be tested if it is signed with the current instance crypto key.

##### ``setKey(cryptoKey)``
Method to set or replace the associated crypto key. The key must be as provided of the [Web Crypto API](https://developer.mozilla.org/en-US/docs/Web/API/CryptoKey).

##### ``generateKey(permitExports=true)``
Like the [static method](#browserhmacobjgeneratekey), with the difference, that the key is not returned but assigned to the instance. By default the key is exportable.

##### ``importKey(key, format="raw", permitExports=false)
Import a Crypto Key from almost any input or a pre existing key.

##### ``exportKey(format="raw")``
Exports the Crypto Key assigned to the instance, if it is an exportable key.

##### ``digest()``
Return the digest of the data passed to the [``update``](#updateinput-replacefalse) method so far. This is an ``ArrayBuffer`` of size [``digestSize``](#digestsize-property).

##### ``hexdigest()``
Like [``digest``](#digest) except the digest is returned as a string of double length, containing only hexadecimal digits. This may be used (as one of many options) to exchange the value safely in non-binary environments.

##### ``basedigest`` _(object)_
Provides many different methods to convert the digest into different base representations. Take a look at the [live-examples](https://umamiappearance.github.io/BrowserHMACObj/examples/live-examples.html#base-representations), to see it in action.  
Every ``basedigest`` optionally takes additional [BaseEx Parameters](https://github.com/UmamiAppearance/BaseExJS#options).

##### ``copy()``
Async method to return a copy/clone of the HMAC object. This can be used to efficiently compute the digests of data hmacring a common initial substring.


## Examples
[Here](https://umamiappearance.github.io/BrowserHMACObj/examples/live-examples.html) you can find many live-examples. To get a better idea of a possible use case, take a look at the [Online HMAC Generator](https://umamiappearance.github.io/BrowserHMACObj/examples/generator.html).


## License
This work is licensed under [GPL-3.0](https://opensource.org/licenses/GPL-3.0).
