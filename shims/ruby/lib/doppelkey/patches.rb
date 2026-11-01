# frozen_string_literal: true

# Patches for OpenSSL::HMAC, OpenSSL::PKCS5, OpenSSL::KDF and OpenSSL::Cipher. A call made with
# a doppelkey handle goes to the keeper; every other call runs unchanged. Derivations return a
# new handle, so derived keys (e.g. Rails' KeyGenerator output) stay in the keeper.
require "openssl"
require "base64"
require_relative "handle"
require_relative "keeper"

module Doppelkey
  HASHES = %w[sha1 sha256 sha384 sha512].freeze

  module_function

  def hash_name(digest)
    name = case digest
           when String then digest
           when OpenSSL::Digest then digest.name
           when Class then digest.new.name
           else digest.respond_to?(:name) ? digest.name : digest.to_s
           end
    n = name.downcase.delete("-")
    unless HASHES.include?(n)
      raise Doppelkey::Error.new("bad_request", "hash \"#{name}\" is not supported with a doppelkey handle (supported: SHA-1, SHA-256, SHA-384, SHA-512)")
    end
    n
  end

  def b64(s)
    Base64.strict_encode64(s.to_s.b)
  end

  def handle_bytes(result, length)
    out = result.fetch("handle").b
    raise Doppelkey::Error.new("bad_reply", "keeper returned a #{out.bytesize}-byte handle, expected #{length}", "doppelkey doctor") if length && out.bytesize != length
    out
  end

  def unsupported(what)
    raise Doppelkey::Error.new("unsupported", "#{what} is not supported with a doppelkey handle yet, so the call was refused instead of computing with the handle text", "If you need it, open an issue: https://github.com/KaiHongTan/dopplekey/issues")
  end

  def remote_hmac(ref, alg, data)
    r = Keeper.call("hmac", ref.fields.merge("alg" => alg, "data" => b64(data)))
    r.key?("handle") ? r["handle"].b : Base64.strict_decode64(r["digest"])
  end

  # Stands in for an OpenSSL::HMAC instance whose key is a handle.
  class RemoteHMAC
    def initialize(ref, alg)
      @ref, @alg, @buf = ref, alg, +"".b
    end

    def update(data)
      @buf << data.to_s.b
      self
    end
    alias << update

    def digest = Doppelkey.remote_hmac(@ref, @alg, @buf)
    def hexdigest = digest.unpack1("H*")
    def base64digest = Base64.strict_encode64(digest)

    def reset
      @buf = +"".b
      self
    end
  end

  module HMACClass
    def new(key, digest = nil)
      ref = Handle.recognise(key)
      return super unless ref
      RemoteHMAC.new(ref, Doppelkey.hash_name(digest))
    end

    def digest(digest, key, data)
      ref = Handle.recognise(key)
      ref ? Doppelkey.remote_hmac(ref, Doppelkey.hash_name(digest), data) : super
    end

    def hexdigest(digest, key, data)
      ref = Handle.recognise(key)
      ref ? Doppelkey.remote_hmac(ref, Doppelkey.hash_name(digest), data).unpack1("H*") : super
    end

    def base64digest(digest, key, data)
      ref = Handle.recognise(key)
      ref ? Base64.strict_encode64(Doppelkey.remote_hmac(ref, Doppelkey.hash_name(digest), data)) : super
    end
  end

  module PKCS5Patch
    def pbkdf2_hmac(pass, salt, iter, keylen, digest)
      ref = Handle.recognise(pass)
      return super unless ref
      r = Keeper.call("pbkdf2", ref.fields.merge("hash" => Doppelkey.hash_name(digest), "salt" => Doppelkey.b64(salt), "iterations" => iter.to_i, "length" => keylen.to_i))
      Doppelkey.handle_bytes(r, keylen.to_i)
    end

    def pbkdf2_hmac_sha1(pass, salt, iter, keylen)
      Handle.recognise(pass) ? pbkdf2_hmac(pass, salt, iter, keylen, "sha1") : super
    end
  end

  module KDFPatch
    def hkdf(ikm, salt:, info:, length:, hash:)
      ref = Handle.recognise(ikm)
      return super unless ref
      r = Keeper.call("hkdf", ref.fields.merge("hash" => Doppelkey.hash_name(hash), "salt" => Doppelkey.b64(salt), "info" => Doppelkey.b64(info), "length" => length.to_i))
      Doppelkey.handle_bytes(r, length.to_i)
    end

    def pbkdf2_hmac(pass, salt:, iterations:, length:, hash:)
      ref = Handle.recognise(pass)
      return super unless ref
      r = Keeper.call("pbkdf2", ref.fields.merge("hash" => Doppelkey.hash_name(hash), "salt" => Doppelkey.b64(salt), "iterations" => iterations.to_i, "length" => length.to_i))
      Doppelkey.handle_bytes(r, length.to_i)
    end

    def scrypt(pass, **kw)
      Doppelkey.unsupported("scrypt") if Handle.recognise(pass)
      super
    end
  end

  # OpenSSL::Cipher with a handle as its key: output is computed by the keeper. Like OpenSSL,
  # update returns output as soon as it is determined (GCM is counter mode; CBC chains blocks),
  # computed over everything so far; final checks the tag (GCM) or padding (CBC).
  module CipherPatch
    AES = /\A(?:id-)?aes-?(128|192|256)-(gcm|cbc)\z/i

    def encrypt(*)
      @dk_mode = "encrypt"
      super
    end

    def decrypt(*)
      @dk_mode = "decrypt"
      super
    end

    def key=(key)
      ref = Handle.recognise(key)
      unless ref
        @dk_ref = nil
        return super
      end
      m = AES.match(name)
      Doppelkey.unsupported("cipher \"#{name}\"") unless m
      raise ArgumentError, "key must be #{m[1].to_i / 8} bytes" unless ref.key_encoding || key.bytesize * 8 == m[1].to_i
      @dk_ref, @dk_bits, @dk_kind = ref, m[1].to_i, m[2].downcase
      @dk_mode ||= "encrypt"
      @dk_buf, @dk_emitted, @dk_aad, @dk_padding = +"".b, 0, +"".b, true
      super(OpenSSL::Random.random_bytes(key.bytesize)) # decoy: keeps OpenSSL's own state valid
    end

    def iv=(iv)
      @dk_iv = iv.b if @dk_ref
      super
    end

    def random_iv
      iv = super
      @dk_iv = iv.b if @dk_ref
      iv
    end

    def auth_data=(aad)
      return super unless @dk_ref
      @dk_aad = aad.to_s.b
      super
    end

    def auth_tag=(tag)
      return super unless @dk_ref
      Doppelkey.unsupported("AES-GCM with a #{tag.bytesize}-byte tag (only 16-byte tags)") unless tag.bytesize == 16
      @dk_tag = tag.b
    end

    def auth_tag(len = 16)
      return super unless @dk_ref
      raise OpenSSL::Cipher::CipherError, "retrieving the authentication tag failed" unless @dk_out_tag
      @dk_out_tag[0, len]
    end

    def padding=(on)
      @dk_padding = on != 0 && on != false if @dk_ref
      super
    end

    def update(data, *rest)
      return super unless @dk_ref
      @dk_buf << data.to_s.b
      out = dk_emit(dk_partial)
      rest.first ? rest.first.replace(out) : out
    end

    def final
      return super unless @dk_ref
      args = { "iv" => Doppelkey.b64(@dk_iv), "key_bits" => (@dk_ref.key_encoding ? nil : @dk_bits) }.compact
      begin
        out = if @dk_kind == "gcm"
                if @dk_mode == "encrypt"
                  r = dk_call("aes_gcm", args.merge("mode" => "encrypt", "data" => Doppelkey.b64(@dk_buf), "aad" => Doppelkey.b64(@dk_aad)))
                  @dk_out_tag = r[-16..]
                  r[0...-16]
                else
                  raise OpenSSL::Cipher::CipherError, "" unless @dk_tag
                  dk_call("aes_gcm", args.merge("mode" => "decrypt", "data" => Doppelkey.b64(@dk_buf + @dk_tag), "aad" => Doppelkey.b64(@dk_aad)))
                end
              else
                dk_call("aes_cbc", args.merge("mode" => @dk_mode, "data" => Doppelkey.b64(@dk_buf), "padding" => @dk_padding))
              end
      rescue Doppelkey::Error => e
        raise OpenSSL::Cipher::CipherError, (@dk_kind == "gcm" ? "" : "bad decrypt") if e.code == "crypto_error"
        raise
      end
      dk_emit(out)
    end

    private

    def dk_call(op, params)
      Base64.strict_decode64(Keeper.call(op, @dk_ref.fields.merge(params))["out"])
    end

    def dk_emit(full)
      out = full.byteslice(@dk_emitted..) || +"".b
      @dk_emitted = [@dk_emitted, full.bytesize].max
      out
    end

    def dk_partial
      return +"".b if @dk_iv.nil?
      args = { "iv" => Doppelkey.b64(@dk_iv), "key_bits" => (@dk_ref.key_encoding ? nil : @dk_bits) }.compact
      if @dk_kind == "gcm"
        return +"".b if @dk_buf.empty?
        # Counter mode: "encrypting" ciphertext yields plaintext, so decrypt uses encrypt too.
        dk_call("aes_gcm", args.merge("mode" => "encrypt", "data" => Doppelkey.b64(@dk_buf)))[0...-16]
      else
        n = @dk_buf.bytesize - (@dk_buf.bytesize % 16)
        n -= 16 if @dk_mode == "decrypt" && @dk_padding && n == @dk_buf.bytesize
        return +"".b if n <= 0
        dk_call("aes_cbc", args.merge("mode" => @dk_mode, "data" => Doppelkey.b64(@dk_buf.byteslice(0, n)), "padding" => false))
      end
    end
  end

  def install!
    return if @installed
    @installed = true
    OpenSSL::HMAC.singleton_class.prepend(HMACClass)
    OpenSSL::PKCS5.singleton_class.prepend(PKCS5Patch)
    OpenSSL::KDF.singleton_class.prepend(KDFPatch) if defined?(OpenSSL::KDF)
    OpenSSL::Cipher.prepend(CipherPatch)
  end
end
