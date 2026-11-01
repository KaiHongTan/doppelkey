# frozen_string_literal: true

# Blocking wire-protocol v1 client: 4-byte big-endian length + JSON over a Unix socket.
require "json"
require "socket"
require "tmpdir"

module Doppelkey
  class Error < StandardError
    attr_reader :code, :hint

    def initialize(code, message, hint = nil)
      @code, @hint = code, hint
      advice = if hint.nil? then ""
               elsif hint.start_with?("doppelkey ") then " Run \"#{hint}\"."
               else " #{hint}"
               end
      super("doppelkey: #{message.sub(/[.\s]+\z/, "")}.#{advice}")
    end
  end

  module Keeper
    @lock = Mutex.new
    @conn = nil
    @pid = nil
    @seq = 0

    module_function

    def socket_path
      return ENV["DOPPELKEY_SOCK"] if ENV["DOPPELKEY_SOCK"] && !ENV["DOPPELKEY_SOCK"].empty?
      return File.join(ENV["XDG_RUNTIME_DIR"], "doppelkey", "doppelkeyd.sock") if ENV["XDG_RUNTIME_DIR"]
      File.join(ENV["TMPDIR"] || "/tmp", "doppelkey-#{Process.uid}", "doppelkeyd.sock")
    end

    def connect
      path = socket_path
      @conn = UNIXSocket.new(path)
      @pid = Process.pid
    rescue SystemCallError
      raise Doppelkey::Error.new("keeper_unreachable", "keeper not running (no keeper at #{path})", "doppelkey doctor")
    end

    def read_exact(n)
      buf = +""
      while buf.bytesize < n
        chunk = @conn.read(n - buf.bytesize)
        raise IOError, "keeper closed the connection" if chunk.nil? || chunk.empty?
        buf << chunk
      end
      buf
    end

    # Send one request; return its result Hash. Raises Doppelkey::Error.
    def call(op, params)
      msg = @lock.synchronize do
        connect if @conn.nil? || @pid != Process.pid # reconnect after fork
        @seq += 1
        body = JSON.generate(params.merge("v" => 1, "id" => @seq, "op" => op))
        begin
          @conn.write([body.bytesize].pack("N") + body)
          loop do
            n = read_exact(4).unpack1("N")
            m = JSON.parse(read_exact(n))
            break m if m["id"] == @seq
          end
        rescue IOError, SystemCallError => e
          @conn&.close
          @conn = nil
          raise Doppelkey::Error.new("keeper_unreachable", "keeper connection failed: #{e.message}", "doppelkey doctor")
        end
      end
      return msg["result"] || {} if msg["ok"]
      e = msg["error"] || {}
      code = e["code"] || "error"
      hint = e["hint"] || (%w[unknown_handle version_mismatch].include?(code) ? "doppelkey doctor" : nil)
      raise Doppelkey::Error.new(code, e["message"] || "keeper error", hint)
    end
  end
end
