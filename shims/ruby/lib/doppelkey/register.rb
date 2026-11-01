# frozen_string_literal: true

# Preload: RUBYOPT="-r/path/to/doppelkey/register" (doppelkey run and `doppelkey env` set this),
# or `require "doppelkey/register"` first thing in config/boot.rb.
require_relative "patches"
Doppelkey.install! unless ENV["DOPPELKEY_SHIM"] == "off"
