class Loglens < Formula
  desc "Local, privacy-first log anomaly detection (with neural mode built in)"
  homepage "https://github.com/LoglensAI/LogLens-AI"
  version "0.12.0"
  license "MIT"

  on_macos do
    on_arm do
      url "https://github.com/LoglensAI/LogLens-AI/releases/download/v0.12.0/loglens-macos-arm64.tar.gz"
      sha256 "REPLACED_BY_CI_ARM64"
    end
    on_intel do
      odie "Prebuilt LogLens binaries are Apple Silicon only. On Intel Macs, install with: pip install loglensai"
    end
  end

  on_linux do
    url "https://github.com/LoglensAI/LogLens-AI/releases/download/v0.12.0/loglens-linux-x86_64.tar.gz"
    sha256 "REPLACED_BY_CI_LINUX"
  end

  def install
    # The tarball contains the onedir directory `loglens/`.
    libexec.install Dir["*"]
    (bin/"loglens").write <<~SH
      #!/bin/sh
      exec "#{libexec}/loglens/loglens" "$@"
    SH
    chmod 0755, bin/"loglens"
  end

  service do
    run [opt_bin/"loglens", "daemon", "start", "--foreground", "--idle-timeout", "0"]
    keep_alive true
    log_path var/"log/loglens.log"
    error_log_path var/"log/loglens.log"
  end

  test do
    assert_match version.to_s, shell_output("#{bin}/loglens version")
  end
end