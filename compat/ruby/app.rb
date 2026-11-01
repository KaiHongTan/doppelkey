# Unmodified uses of OpenSSL and popular gems with handles in ENV. Writes results, then waits so
# the oracle can scan this process's memory.
require "json"
require "openssl"
require "base64"

results = { "errors" => {} }
def attempt(results, name)
  results[name] = yield
rescue StandardError => e
  results["errors"][name] = "#{e.class}: #{e.message}"
end

env = ENV
attempt(results, "hmac_hexdigest") { OpenSSL::HMAC.hexdigest("SHA256", env["JWT_SECRET"], "hello") }
attempt(results, "hmac_stream") { h = OpenSSL::HMAC.new(env["JWT_SECRET"], OpenSSL::Digest.new("SHA512")); h << "hel"; h.update("lo"); h.hexdigest }
attempt(results, "hmac_plain") { OpenSSL::HMAC.hexdigest("SHA256", "not-a-handle", "hello") }
attempt(results, "md5_refused") { OpenSSL::HMAC.hexdigest("MD5", env["JWT_SECRET"], "x") }
attempt(results, "jwt") do
  require "jwt"
  t = JWT.encode({ "sub" => "user1" }, env["JWT_SECRET"], "HS256")
  { "token" => t, "verify" => JWT.decode(t, env["JWT_SECRET"], true, algorithm: "HS256")[0]["sub"] }
end
attempt(results, "rails") do
  require "active_support"
  require "active_support/key_generator"
  require "active_support/message_verifier"
  require "active_support/message_encryptor"
  kg = ActiveSupport::KeyGenerator.new(env["SECRET_KEY_BASE"], iterations: 1000, hash_digest_class: OpenSSL::Digest::SHA256)
  verifier = ActiveSupport::MessageVerifier.new(kg.generate_key("signed cookie"), digest: "SHA256", serializer: JSON)
  signed = verifier.generate({ "user" => "alice" })
  enc = ActiveSupport::MessageEncryptor.new(kg.generate_key("authenticated encrypted cookie", 32), serializer: JSON)
  sealed = enc.encrypt_and_sign({ "user" => "alice" })
  { "signed" => signed, "verified" => verifier.verify(signed)["user"], "sealed" => sealed, "opened" => enc.decrypt_and_verify(sealed)["user"],
    "tampered" => (verifier.verified(signed.sub(/.\z/) { |c| c == "a" ? "b" : "a" }) || "rejected") }
end
attempt(results, "hkdf") { k = OpenSSL::KDF.hkdf(env["AUTH_SECRET"], salt: "salt", info: "info", length: 32, hash: "SHA256"); OpenSSL::HMAC.hexdigest("SHA256", k, "hello") }
attempt(results, "cbc") do
  c = OpenSSL::Cipher.new("aes-256-cbc").encrypt
  c.key = [env["ENCRYPTION_KEY_HEX"]].pack("H*")
  c.iv = "\x09".b * 16
  ct = c.update("ruby cbc ") + c.update("stream") + c.final
  d = OpenSSL::Cipher.new("aes-256-cbc").decrypt
  d.key = [env["ENCRYPTION_KEY_HEX"]].pack("H*")
  d.iv = "\x09".b * 16
  { "ct" => Base64.strict_encode64(ct), "back" => d.update(ct) + d.final }
end
attempt(results, "chacha_refused") { c = OpenSSL::Cipher.new("chacha20-poly1305").encrypt; c.key = env["ENCRYPTION_KEY"] }
results["env_jwt"] = env["JWT_SECRET"]
results["shim_loaded"] = defined?(Doppelkey::RemoteHMAC) ? true : false
File.write(env.fetch("DOPPELKEY_RESULTS"), JSON.pretty_generate(results))
puts "READY #{Process.pid}"
$stdout.flush
sleep((env["DOPPELKEY_WAIT"] || "0").to_f)
