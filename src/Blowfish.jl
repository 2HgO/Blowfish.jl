"""
Copyright 2020 Oghogho Odemwingie <odemwingieog@gmail.com>. All rights reserved.
Use of this source code is governed by an MIT
license that can be found in the LICENSE file.

Package blowfish implements Bruce Schneier's Blowfish encryption algorithm.

Blowfish is a legacy cipher and its short block size makes it vulnerable to
birthday bound attacks (see https://sweet32.info). It should only be used
where compatibility with legacy systems, not security, is the goal.
"""

module Blowfish

export Blocksize, Cipher, KeySizeError, NewCipher, NewSaltedCipher, Encrypt!, Decrypt!, ExpandKey!

# The code is a port of Bruce Schneier's C implementation.
# See https://www.schneier.com/blowfish.html.

const Blocksize = 8

"""
	A KeySizeError is an Exception which indicates that the length of a given cipher key does not conform to the bounds key -> 1 < key < 56
"""
struct KeySizeError <: Exception
	size::Int
end
Base.show(kErr::KeySizeError) = "Blowfish.jl: invalid key size ($(kErr.size))"

"""
	A Cipher is an instance of Blowfish encryption using a particular key.
"""
mutable struct Cipher
	p::Array{UInt32, 1}
	s0::Array{UInt32, 1}
	s1::Array{UInt32, 1}
	s2::Array{UInt32, 1}
	s3::Array{UInt32, 1}

	Cipher() = new(collect(p), collect(s0), collect(s1), collect(s2), collect(s3))
end

include("Block.jl")
include("Const.jl")

"""
	NewCipher(key::Array{UInt8, 1})

Generates a new instance of a blowfish cipher from a given cipher key

# Examples
```julia-repl
julia> NewCipher(UInt8['a', 'e', 'i', 'o', 'u'])
Cipher(UInt32[0x7a48b0ec, 0xb7c5649b, 0xfee9c8a4, 0x985e8a2a, 0xd6a5938e, 0x145c1599, 0x51b0c8db, 0x91b92643, 0x53c0affc, 0x3642f567, 0x8100d42b, 0x49179092, 0x7d3bec7b, 0x3ba790e3, 0xc3e03bcd, 0x85640a20, 0xdeb3c3dc, 0xa49501f5], UInt32[0xde18af37, 0xd5438974, 0x461bbb53, 0x392f99c3, 0xfb69ec53, 0x049fe21a, 0xd4489b31, 0xc73d87f2, 0xfdb21b2e, 0xb78761e0  …  0x458175a4, 0xc13c6dd7, 0x1fa5ee57, 0x38925136, 0x29f87d84, 0x36c2ce5c, 0x76ec4eb0, 0x7b4a5c7c, 0x8fb372ec, 0xc775630f], UInt32[0x703686bc, 0xd1acb9d6, 0x2832c1f9, 0xecb4b1f3, 0xecb60b8d, 0xc22e7889, 0x79fb10f0, 0xb7230280, 0xbd6772e9, 0xb320259b  …  0x18610527, 0xb6e95540, 0xdd5a53b3, 0x6c144d00, 0x8254f230, 0xcc9cd03b, 0xda916333, 0x64818319, 0x4d123b0e, 0x17c4af84], UInt32[0xe1919f40, 0x50b5ebc1, 0x8673f868, 0x2e7e8c6d, 0xc4e0bf50, 0x4769fa9f, 0x7e55db03, 0x21e58059, 0xc4d0c578, 0x8239570e  …  0xaffbcc32, 0x480e8087, 0x0a41bc51, 0xb4571997, 0xc01ecce2, 0x32d89616, 0xc671c03e, 0xaf2f65a2, 0x2f073414, 0xa780d378], UInt32[0x5f19d24e, 0x335b6476, 0x9fb61c67, 0x17e3c8f5, 0x98aab626, 0x7c4c102f, 0x03bbf3a2, 0xade7d94a, 0x6f0bc1d2, 0x9a6da0e8  …  0xc85d33cf, 0x73a34514, 0x30600f9e, 0x5afc4493, 0x64fbb2ff, 0x1d0dacce, 0x9468581e, 0xd3ea966a, 0x10a864b3, 0xc4d48364])
```
"""
function NewCipher(key::AbstractArray{UInt8, 1}) :: Cipher
	(length(key) < 1 || length(key) > 56) && throw(KeySizeError(length(key)))
	res = Cipher()
	ExpandKey!(key, res)
	return res
end

"""
	NewSaltedCipher(key::Array{UInt8, 1})

Generates a Cipher that folds a salt into its key schedule. For most purposes, NewCipher, instead of NewSaltedCipher, is sufficient and desirable. For bcrypt compatibility, the key can be over 56 bytes.

# Examples
```julia-repl
julia> NewSaltedCipher(UInt8['s', 'a', 'l', 't'],UInt8['a', 'e', 'i', 'o', 'u'])
Cipher(UInt32[0xab5a9c73, 0xa49c2d2a, 0xc87e8ec8, 0xaa432b79, 0x1d0b7db7, 0x21cbb7fe, 0x2f36fc0f, 0x2871116d, 0xe7f0000b, 0x10264298, 0x545b2686, 0x3eb8dcde, 0xf6e314ab, 0x7d4f6dd5, 0x2e89833f, 0xe16df037, 0x61e28e24, 0xc5409a31], UInt32[0xc53c53e7, 0xfb819947, 0x23c33744, 0x795a4bf1, 0xdd4183b4, 0xae68d5c4, 0x9eb3ed52, 0x7b3e0314, 0x16e20c08, 0x779e49a0  …  0x1bceff46, 0x50a2f67b, 0x30c5d692, 0xb6aa33c1, 0x201dd700, 0x640abd32, 0x123498f4, 0x84383581, 0x6e6b9f74, 0x8ae4ae80], UInt32[0xe6f14e74, 0x2072fdce, 0x3318cee1, 0xb31f5a86, 0x33ad0de5, 0xab1423b6, 0x661392ad, 0x437999f9, 0x6b2e4675, 0xd72bb28c  …  0xba487480, 0x2f82dfcb, 0xff1c012d, 0x56705613, 0xe21b7f92, 0xf4a3ee42, 0x1f9c5542, 0x01e8f0ac, 0x000e41eb, 0x8ec4511b], UInt32[0xebbd88cb, 0xde0bc3b4, 0x23c31968, 0xa25fd135, 0xec8689f8, 0x70fcb881, 0xc74964a3, 0xe59851c2, 0x3cdb369f, 0xc2c4f08a  …  0x464ba53e, 0xef69b586, 0x196b4813, 0x1ec8abc6, 0x8ab71719, 0x34a15e09, 0x7675589d, 0x9d7f2a78, 0x92540a14, 0x1452cb64], UInt32[0x62053d78, 0xcc13a352, 0xb4b0d494, 0x92d66e7f, 0x2db90c93, 0xf5243558, 0xe0831a00, 0xca5f77b7, 0x99f6388a, 0x45906ae3  …  0xdd979889, 0x961e8abd, 0x5c821e51, 0x8a2fbfcc, 0x292c2a3c, 0xdbc24193, 0xdfdcd502, 0x22868810, 0x2d0a2a98, 0xa5fc3e68])
```
"""
function NewSaltedCipher(key::AbstractArray{UInt8, 1}, salt::AbstractArray{UInt8, 1}) :: Cipher
	isempty(salt) && return NewCipher(key)
	length(key) < 1 && throw(KeySizeError(length(key)))
	res = Cipher()
	expand_key_with_salt!(key, salt, res)
	return res
end

"""
	Encrypt!(c::Cipher, dst::Array{UInt8, 1}, src::Array{UInt8, 1})

Encrypt encrypts the 8-byte buffer src using the key k and stores the result in dst.
Note that for amounts of data larger than a block, it is not safe to just call Encrypt on successive blocks.
"""
function Encrypt!(c::Cipher, dst::AbstractArray{UInt8, 1}, src::AbstractArray{UInt8, 1})
	l = UInt32(src[1])<<24 | UInt32(src[2])<<16 | UInt32(src[3])<<8 | UInt32(src[4])
	r = UInt32(src[5])<<24 | UInt32(src[6])<<16 | UInt32(src[7])<<8 | UInt32(src[8])
	l, r = encrypt_block(l, r, c)
	dst[1], dst[2], dst[3], dst[4] = UInt8(l>>24 & 0xff), UInt8(l>>16 & 0xff), UInt8(l>>8 & 0xff), UInt8(l & 0xff)
	dst[5], dst[6], dst[7], dst[8] = UInt8(r>>24 & 0xff), UInt8(r>>16 & 0xff), UInt8(r>>8 & 0xff), UInt8(r & 0xff)
end

"""
	Decrypt!(c::Cipher, dst::Array{UInt8, 1}, src::Array{UInt8, 1})

Decrypt decrypts the 8-byte buffer src using the key k and stores the result in dst.
"""
function Decrypt!(c::Cipher, dst::AbstractArray{UInt8, 1}, src::AbstractArray{UInt8, 1})
	l = UInt32(src[1])<<24 | UInt32(src[2])<<16 | UInt32(src[3])<<8 | UInt32(src[4])
	r = UInt32(src[5])<<24 | UInt32(src[6])<<16 | UInt32(src[7])<<8 | UInt32(src[8])
	l, r = decrypt_block(l, r, c)
	dst[1], dst[2], dst[3], dst[4] = UInt8(l>>24 & 0xff), UInt8(l>>16 & 0xff), UInt8(l>>8 & 0xff), UInt8(l & 0xff)
	dst[5], dst[6], dst[7], dst[8] = UInt8(r>>24 & 0xff), UInt8(r>>16 & 0xff), UInt8(r>>8 & 0xff), UInt8(r & 0xff)
end

end # module
