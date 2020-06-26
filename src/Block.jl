mutable struct Num <: Integer
	val::Int
end
Num() = Num(0)

function get_next_word!(b::Array{UInt8, 1}, pos::Num) :: UInt32
	w = Int32(0)
	j = pos.val
	for i in 1:4
		w = w<<8 | UInt32(b[j+1])
		j += 1
		if j >= length(b)
			j = 0
		end
	end
	pos.val = j
	return w
end

function ExpandKey!(key::Array{UInt8, 1}, c::Cipher)
	j = Int(0)
	for i in 1:18
		d = UInt32(0)
		for k in 1:4
			d = d<<8 | UInt32(key[j+1])
			j += 1
			if (j >= length(key))
				j = 0
			end
		end
		c.p[i] ⊻= d
	end

	l, r = UInt32(0), UInt32(0)
	for i in 1:2:18
		l, r = encrypt_block(l, r, c)
		c.p[i], c.p[i+1] = l, r
	end
	for i in 1:2:256
		l, r = encrypt_block(l, r, c)
		c.s0[i], c.s0[i+1] = l, r
	end
	for i in 1:2:256
		l, r = encrypt_block(l, r, c)
		c.s1[i], c.s1[i+1] = l, r
	end
	for i in 1:2:256
		l, r = encrypt_block(l, r, c)
		c.s2[i], c.s2[i+1] = l, r
	end
	for i in 1:2:256
		l, r = encrypt_block(l, r, c)
		c.s3[i], c.s3[i+1] = l, r
	end
end

function expand_key_with_salt!(key::Array{UInt8, 1}, salt::Array{UInt8, 1}, c::Cipher)
	j = Num()
	for i in 1:18
		c.p[i] ⊻= get_next_word!(key, j)
	end

	j = Num()
	l, r = UInt32(0), UInt32(0)
	for i in 1:2:18
		l ⊻= get_next_word!(salt, j)
		r ⊻= get_next_word!(salt, j)
		l, r = encrypt_block(l, r, c)
		c.p[i], c.p[i+1] = l, r
	end
	for i in 1:2:256
		l ⊻= get_next_word!(salt, j)
		r ⊻= get_next_word!(salt, j)
		l, r = encrypt_block(l, r, c)
		c.s0[i], c.s0[i+1] = l, r
	end
	for i in 1:2:256
		l ⊻= get_next_word!(salt, j)
		r ⊻= get_next_word!(salt, j)
		l, r = encrypt_block(l, r, c)
		c.s1[i], c.s1[i+1] = l, r
	end
	for i in 1:2:256
		l ⊻= get_next_word!(salt, j)
		r ⊻= get_next_word!(salt, j)
		l, r = encrypt_block(l, r, c)
		c.s2[i], c.s2[i+1] = l, r
	end
	for i in 1:2:256
		l ⊻= get_next_word!(salt, j)
		r ⊻= get_next_word!(salt, j)
		l, r = encrypt_block(l, r, c)
		c.s3[i], c.s3[i+1] = l, r
	end
end

function encrypt_block(l::UInt32, r::UInt32, c::Cipher) :: Tuple{UInt32, UInt32}
	xl, xr = l, r
	xl ⊻= c.p[1]
	xr ⊻= ((c.s0[xl>>24 & 0xff + 1] + c.s1[xl>>16 & 0xff + 1]) ⊻ c.s2[xl>>8 & 0xff + 1]) + c.s3[xl & 0xff + 1] ⊻ c.p[2]
	xl ⊻= ((c.s0[xr>>24 & 0xff + 1] + c.s1[xr>>16 & 0xff + 1]) ⊻ c.s2[xr>>8 & 0xff + 1]) + c.s3[xr & 0xff + 1] ⊻ c.p[3]
	xr ⊻= ((c.s0[xl>>24 & 0xff + 1] + c.s1[xl>>16 & 0xff + 1]) ⊻ c.s2[xl>>8 & 0xff + 1]) + c.s3[xl & 0xff + 1] ⊻ c.p[4]
	xl ⊻= ((c.s0[xr>>24 & 0xff + 1] + c.s1[xr>>16 & 0xff + 1]) ⊻ c.s2[xr>>8 & 0xff + 1]) + c.s3[xr & 0xff + 1] ⊻ c.p[5]
	xr ⊻= ((c.s0[xl>>24 & 0xff + 1] + c.s1[xl>>16 & 0xff + 1]) ⊻ c.s2[xl>>8 & 0xff + 1]) + c.s3[xl & 0xff + 1] ⊻ c.p[6]
	xl ⊻= ((c.s0[xr>>24 & 0xff + 1] + c.s1[xr>>16 & 0xff + 1]) ⊻ c.s2[xr>>8 & 0xff + 1]) + c.s3[xr & 0xff + 1] ⊻ c.p[7]
	xr ⊻= ((c.s0[xl>>24 & 0xff + 1] + c.s1[xl>>16 & 0xff + 1]) ⊻ c.s2[xl>>8 & 0xff + 1]) + c.s3[xl & 0xff + 1] ⊻ c.p[8]
	xl ⊻= ((c.s0[xr>>24 & 0xff + 1] + c.s1[xr>>16 & 0xff + 1]) ⊻ c.s2[xr>>8 & 0xff + 1]) + c.s3[xr & 0xff + 1] ⊻ c.p[9]
	xr ⊻= ((c.s0[xl>>24 & 0xff + 1] + c.s1[xl>>16 & 0xff + 1]) ⊻ c.s2[xl>>8 & 0xff + 1]) + c.s3[xl & 0xff + 1] ⊻ c.p[10]
	xl ⊻= ((c.s0[xr>>24 & 0xff + 1] + c.s1[xr>>16 & 0xff + 1]) ⊻ c.s2[xr>>8 & 0xff + 1]) + c.s3[xr & 0xff + 1] ⊻ c.p[11]
	xr ⊻= ((c.s0[xl>>24 & 0xff + 1] + c.s1[xl>>16 & 0xff + 1]) ⊻ c.s2[xl>>8 & 0xff + 1]) + c.s3[xl & 0xff + 1] ⊻ c.p[12]
	xl ⊻= ((c.s0[xr>>24 & 0xff + 1] + c.s1[xr>>16 & 0xff + 1]) ⊻ c.s2[xr>>8 & 0xff + 1]) + c.s3[xr & 0xff + 1] ⊻ c.p[13]
	xr ⊻= ((c.s0[xl>>24 & 0xff + 1] + c.s1[xl>>16 & 0xff + 1]) ⊻ c.s2[xl>>8 & 0xff + 1]) + c.s3[xl & 0xff + 1] ⊻ c.p[14]
	xl ⊻= ((c.s0[xr>>24 & 0xff + 1] + c.s1[xr>>16 & 0xff + 1]) ⊻ c.s2[xr>>8 & 0xff + 1]) + c.s3[xr & 0xff + 1] ⊻ c.p[15]
	xr ⊻= ((c.s0[xl>>24 & 0xff + 1] + c.s1[xl>>16 & 0xff + 1]) ⊻ c.s2[xl>>8 & 0xff + 1]) + c.s3[xl & 0xff + 1] ⊻ c.p[16]
	xl ⊻= ((c.s0[xr>>24 & 0xff + 1] + c.s1[xr>>16 & 0xff + 1]) ⊻ c.s2[xr>>8 & 0xff + 1]) + c.s3[xr & 0xff + 1] ⊻ c.p[17]
	xr ⊻= c.p[18]
	return xr, xl
end

function decrypt_block(l::UInt32, r::UInt32, c::Cipher) :: Tuple{UInt32, UInt32}
	xl, xr = l, r
	xl ⊻= c.p[18]
	xr ⊻= ((c.s0[xl>>24 & 0xff + 1] + c.s1[xl>>16 & 0xff + 1]) ⊻ c.s2[xl>>8 & 0xff + 1]) + c.s3[xl & 0xff + 1] ⊻ c.p[17]
	xl ⊻= ((c.s0[xr>>24 & 0xff + 1] + c.s1[xr>>16 & 0xff + 1]) ⊻ c.s2[xr>>8 & 0xff + 1]) + c.s3[xr & 0xff + 1] ⊻ c.p[16]
	xr ⊻= ((c.s0[xl>>24 & 0xff + 1] + c.s1[xl>>16 & 0xff + 1]) ⊻ c.s2[xl>>8 & 0xff + 1]) + c.s3[xl & 0xff + 1] ⊻ c.p[15]
	xl ⊻= ((c.s0[xr>>24 & 0xff + 1] + c.s1[xr>>16 & 0xff + 1]) ⊻ c.s2[xr>>8 & 0xff + 1]) + c.s3[xr & 0xff + 1] ⊻ c.p[14]
	xr ⊻= ((c.s0[xl>>24 & 0xff + 1] + c.s1[xl>>16 & 0xff + 1]) ⊻ c.s2[xl>>8 & 0xff + 1]) + c.s3[xl & 0xff + 1] ⊻ c.p[13]
	xl ⊻= ((c.s0[xr>>24 & 0xff + 1] + c.s1[xr>>16 & 0xff + 1]) ⊻ c.s2[xr>>8 & 0xff + 1]) + c.s3[xr & 0xff + 1] ⊻ c.p[12]
	xr ⊻= ((c.s0[xl>>24 & 0xff + 1] + c.s1[xl>>16 & 0xff + 1]) ⊻ c.s2[xl>>8 & 0xff + 1]) + c.s3[xl & 0xff + 1] ⊻ c.p[11]
	xl ⊻= ((c.s0[xr>>24 & 0xff + 1] + c.s1[xr>>16 & 0xff + 1]) ⊻ c.s2[xr>>8 & 0xff + 1]) + c.s3[xr & 0xff + 1] ⊻ c.p[10]
	xr ⊻= ((c.s0[xl>>24 & 0xff + 1] + c.s1[xl>>16 & 0xff + 1]) ⊻ c.s2[xl>>8 & 0xff + 1]) + c.s3[xl & 0xff + 1] ⊻ c.p[9]
	xl ⊻= ((c.s0[xr>>24 & 0xff + 1] + c.s1[xr>>16 & 0xff + 1]) ⊻ c.s2[xr>>8 & 0xff + 1]) + c.s3[xr & 0xff + 1] ⊻ c.p[8]
	xr ⊻= ((c.s0[xl>>24 & 0xff + 1] + c.s1[xl>>16 & 0xff + 1]) ⊻ c.s2[xl>>8 & 0xff + 1]) + c.s3[xl & 0xff + 1] ⊻ c.p[7]
	xl ⊻= ((c.s0[xr>>24 & 0xff + 1] + c.s1[xr>>16 & 0xff + 1]) ⊻ c.s2[xr>>8 & 0xff + 1]) + c.s3[xr & 0xff + 1] ⊻ c.p[6]
	xr ⊻= ((c.s0[xl>>24 & 0xff + 1] + c.s1[xl>>16 & 0xff + 1]) ⊻ c.s2[xl>>8 & 0xff + 1]) + c.s3[xl & 0xff + 1] ⊻ c.p[5]
	xl ⊻= ((c.s0[xr>>24 & 0xff + 1] + c.s1[xr>>16 & 0xff + 1]) ⊻ c.s2[xr>>8 & 0xff + 1]) + c.s3[xr & 0xff + 1] ⊻ c.p[4]
	xr ⊻= ((c.s0[xl>>24 & 0xff + 1] + c.s1[xl>>16 & 0xff + 1]) ⊻ c.s2[xl>>8 & 0xff + 1]) + c.s3[xl & 0xff + 1] ⊻ c.p[3]
	xl ⊻= ((c.s0[xr>>24 & 0xff + 1] + c.s1[xr>>16 & 0xff + 1]) ⊻ c.s2[xr>>8 & 0xff + 1]) + c.s3[xr & 0xff + 1] ⊻ c.p[2]
	xr ⊻= c.p[1]
	return xr, xl
end