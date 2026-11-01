# Oracle-pattern tests for the Ruby shim. The app runs with handles and the shim preloaded
# (RUBYOPT=-r .../doppelkey/register); this process holds the real keys and never loads the
# shim. Gems: gem install --install-dir .gems activesupport jwt
#   ruby test_compat.rb        (DOPPELKEY_KEEPER_CMD selects doppelkeyd)
GEMS = File.join(__dir__, ".gems")
ENV["GEM_PATH"] = [GEMS, ENV["GEM_PATH"]].compact.join(":")
Gem.paths = ENV
require "minitest/autorun"
require "json"
require "open3"
require "openssl"
require "base64"
require "tmpdir"

HERE = __dir__
ROOT = File.expand_path("../..", HERE)
VAULT_FILE = File.join(ROOT, "compat/fixtures/vault.json")
VAULT = JSON.parse(File.read(VAULT_FILE))
LABEL = "NOT-A-SECRET-load-doppelkey-shim"

def real(name)
  e = VAULT["keys"][name]
  e["value_b64"] ? Base64.strict_decode64(e["value_b64"]) : e["value"].b
end

def env_value(e)
  crc = OpenSSL::Digest::SHA256.hexdigest("dk1:#{e["id"]}")[0, 4]
  prefix, form = e["prefix"] || "", e["form"] || "long"
  len = e["value_b64"] ? Base64.strict_decode64(e["value_b64"]).bytesize : e["value"].bytesize
  return "#{prefix}dk1:#{LABEL}:#{e["id"]}:#{crc}" if form == "long"
  n = %w[hex base64].include?(form) ? len : len - prefix.bytesize
  padded = "dk1:#{e["id"]}#{crc}".ljust(n, ".")
  return prefix + padded if form == "compact"
  form == "hex" ? prefix + padded.unpack1("H*") : prefix + Base64.strict_encode64(padded)
end

def forms(n)
  [n, n.unpack1("H*"), Base64.strict_encode64(n).delete("="), Base64.urlsafe_encode64(n).delete("=")].select { |f| f.bytesize >= 16 }
end

def scan(pid, needles)
  maps = File.readlines("/proc/#{pid}/maps")
  found = {}
  File.open("/proc/#{pid}/mem", "rb") do |mem|
    maps.each do |line|
      addr, perms = line.split[0, 2]
      next unless perms.start_with?("r") && !line.include?("[vvar") && !line.include?("[vsyscall")
      lo, hi = addr.split("-").map { |x| x.to_i(16) }
      chunk = begin
        mem.seek(lo)
        mem.read(hi - lo)
      rescue StandardError
        next
      end
      next unless chunk
      needles.each { |name, n| found[name] = true if !found[name] && forms(n).any? { |f| chunk.include?(f) } }
    end
  end
  found.keys.sort
end

class RubyShimTest < Minitest::Test
  def self.run_once
    @run ||= begin
      dir = Dir.mktmpdir("dk-rbkeeper-")
      sock = File.join(dir, "k.sock")
      cmd = (ENV["DOPPELKEY_KEEPER_CMD"] || "node #{File.join(ROOT, "compat/test-keeper/keeper.mjs")}").split
      # Like the real service, no code-injection variables (doppelkeyd refuses them).
      clean = %w[LD_PRELOAD LD_LIBRARY_PATH LD_AUDIT DYLD_INSERT_LIBRARIES DYLD_LIBRARY_PATH DYLD_FRAMEWORK_PATH].to_h { |v| [v, nil] }
      keeper = IO.popen(clean, cmd + ["--vault", VAULT_FILE, "--socket", sock, "--audit", File.join(dir, "audit.jsonl")])
      raise "keeper did not start" unless keeper.gets.to_s.include?("listening")
      out = File.join(dir, "results.json")
      env = VAULT["keys"].to_h { |n, e| [n, env_value(e)] }.merge(
        "DOPPELKEY_SOCK" => sock, "DOPPELKEY_RESULTS" => out, "DOPPELKEY_WAIT" => "60",
        "RUBYOPT" => "-r#{File.join(ROOT, "shims/ruby/lib/doppelkey/register.rb")}", "GEM_PATH" => ENV["GEM_PATH"]
      )
      stdin, stdout, stderr, wait = Open3.popen3(env, "ruby", File.join(HERE, "app.rb"))
      line = stdout.gets.to_s
      raise "app failed: #{line}#{stderr.read}" unless line.start_with?("READY")
      results = JSON.parse(File.read(out))
      kg = ->(salt, len) { OpenSSL::PKCS5.pbkdf2_hmac(real("SECRET_KEY_BASE").unpack1("H*"), salt, 1000, len, OpenSSL::Digest::SHA256.new) }
      needles = VAULT["keys"].keys.to_h { |k| [k, real(k)] }.merge(
        "rails signing key" => kg.("signed cookie", 64), "rails encryption key" => kg.("authenticated encrypted cookie", 32)
      )
      found = RUBY_PLATFORM.include?("linux") ? scan(wait.pid, needles) : nil
      Process.kill("KILL", wait.pid)
      [stdin, stdout, stderr].each(&:close)
      Process.kill("TERM", keeper.pid)
      { results: results, found: found }
    end
  end

  def r = self.class.run_once[:results]
  def hx(key, msg, alg = "SHA256") = OpenSSL::HMAC.hexdigest(alg, key, msg)

  def test_no_unexpected_errors
    assert_equal({}, r["errors"].reject { |k, _| %w[md5_refused chacha_refused].include?(k) })
    assert r["shim_loaded"]
    assert r["env_jwt"].start_with?("dk1:NOT-A-SECRET")
  end

  def test_openssl_hmac
    assert_equal hx(real("JWT_SECRET"), "hello"), r["hmac_hexdigest"]
    assert_equal hx(real("JWT_SECRET"), "hello", "SHA512"), r["hmac_stream"]
    assert_equal hx("not-a-handle", "hello"), r["hmac_plain"]
    assert_match(/hash "MD5" is not supported with a doppelkey handle/, r["errors"]["md5_refused"])
    assert_match(/cipher "ChaCha20-Poly1305" is not supported/i, r["errors"]["chacha_refused"])
  end

  def test_jwt_gem
    require "jwt"
    assert_equal "user1", JWT.decode(r["jwt"]["token"], real("JWT_SECRET"), true, algorithm: "HS256")[0]["sub"]
    assert_equal "user1", r["jwt"]["verify"]
  end

  def test_rails_message_verifier_and_encryptor_from_secret_key_base
    require "active_support"
    require "active_support/key_generator"
    require "active_support/message_verifier"
    require "active_support/message_encryptor"
    kg = ActiveSupport::KeyGenerator.new(real("SECRET_KEY_BASE").unpack1("H*"), iterations: 1000, hash_digest_class: OpenSSL::Digest::SHA256)
    v = ActiveSupport::MessageVerifier.new(kg.generate_key("signed cookie"), digest: "SHA256", serializer: JSON)
    e = ActiveSupport::MessageEncryptor.new(kg.generate_key("authenticated encrypted cookie", 32), serializer: JSON)
    assert_equal "alice", v.verify(r["rails"]["signed"])["user"]
    assert_equal "alice", e.decrypt_and_verify(r["rails"]["sealed"])["user"]
    assert_equal "alice", r["rails"]["verified"]
    assert_equal "alice", r["rails"]["opened"]
    assert_equal "rejected", r["rails"]["tampered"]
  end

  def test_kdf_hkdf
    k = OpenSSL::KDF.hkdf(real("AUTH_SECRET"), salt: "salt", info: "info", length: 32, hash: "SHA256")
    assert_equal hx(k, "hello"), r["hkdf"]
  end

  def test_cipher_cbc_with_hex_encoded_handle
    d = OpenSSL::Cipher.new("aes-256-cbc").decrypt
    d.key = real("ENCRYPTION_KEY_HEX")
    d.iv = "\x09".b * 16
    assert_equal "ruby cbc stream", d.update(Base64.strict_decode64(r["cbc"]["ct"])) + d.final
    assert_equal "ruby cbc stream", r["cbc"]["back"]
  end

  def test_memory_holds_no_real_or_derived_keys
    skip "Linux only" unless RUBY_PLATFORM.include?("linux")
    assert_equal [], self.class.run_once[:found]
  end
end
