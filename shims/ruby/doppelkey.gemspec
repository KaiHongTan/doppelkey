Gem::Specification.new do |s|
  s.name = "doppelkey"
  s.version = "0.1.0"
  s.summary = "ssh-agent for app secrets: keep signing and encryption keys out of your Ruby process"
  s.description = "Ruby shim for doppelkey: OpenSSL::HMAC, PKCS5, KDF and Cipher calls made with a doppelkey handle are performed by the doppelkey keeper. Zero dependencies."
  s.authors = ["doppelkey contributors"]
  s.license = "Apache-2.0"
  s.homepage = "https://github.com/KaiHongTan/doppelkey"
  s.files = Dir["lib/**/*.rb"] + ["LICENSE", "README.md"]
  s.required_ruby_version = ">= 3.0"
end
