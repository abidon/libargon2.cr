# libargon2.cr
A Crystal binding to the Argon2 C library

### Requirements

- libargon2 (compiled and installed by yourself)

### Usage

* Add the following to your `shards.yml` file:

```yaml
dependencies:
  argon2:
    github: abidon/libargon2.cr
    branch: master
```

* Call the `libargon2` functions

```crystal
require "argon2"

# Create an hasher with specific time cost, memory cost and parallelism level
hasher = Argon2.new 20, 2_u32, 1_u32

# Hash a password with a given salt and hash length
# $argon2i$v=19$m=131072,t=20,p=1$c2FsdHNhbHQ$Y48PG/x+21lkne8mNNKddcIY5X0kLr1CaYjo0toGU6k
hash = hasher.hash_encoded_i("password", "saltsalt", 32_u32)
print hash

# Verifying doesn't require an instance, as all costs are in the encoded hash string
Argon2.verify_i(hash, "password")
```

You can also access the C binding through the `LibArgon2` namespace.

### License

Copyright 2017 Aurélien Bidon (abidon@protonmail.com)

Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the "Software"), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
