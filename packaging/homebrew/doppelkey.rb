# Homebrew formula template for a tap (KaiHongTan/homebrew-tap). Take the checksums from the
# release's SHA256SUMS; packaging/set-version.sh updates `version`. See docs/releasing.md.
class Doppelkey < Formula
  desc "ssh-agent for app secrets: keep signing and encryption keys out of your app"
  homepage "https://github.com/KaiHongTan/doppelkey"
  version "0.1.0"
  license "Apache-2.0"

  on_macos do
    on_arm do
      url "https://github.com/KaiHongTan/doppelkey/releases/download/v#{version}/doppelkey-#{version}-aarch64-apple-darwin.tar.gz"
      sha256 "REPLACE_WITH_SHA256"
    end
    on_intel do
      url "https://github.com/KaiHongTan/doppelkey/releases/download/v#{version}/doppelkey-#{version}-x86_64-apple-darwin.tar.gz"
      sha256 "REPLACE_WITH_SHA256"
    end
  end
  on_linux do
    on_arm do
      url "https://github.com/KaiHongTan/doppelkey/releases/download/v#{version}/doppelkey-#{version}-aarch64-unknown-linux-gnu.tar.gz"
      sha256 "REPLACE_WITH_SHA256"
    end
    on_intel do
      url "https://github.com/KaiHongTan/doppelkey/releases/download/v#{version}/doppelkey-#{version}-x86_64-unknown-linux-gnu.tar.gz"
      sha256 "REPLACE_WITH_SHA256"
    end
  end

  def install
    bin.install "bin/doppelkey", "bin/doppelkeyd"
    (share/"doppelkey").install Dir["share/doppelkey/*"]
  end

  service do
    run [opt_bin/"doppelkeyd", "serve"]
    keep_alive true
  end

  test do
    assert_match "doppelkey", shell_output("#{bin}/doppelkey --version")
  end
end
