# frozen_string_literal: true

# Handle format v1 (docs/protocol.md). Mirrors shims/node/src/handle.ts.
require "digest"
require "base64"

module Doppelkey
  module Handle
    LABEL = "NOT-A-SECRET-load-doppelkey-shim"
    MAX_PREFIX = 8
    CORE = "dk1:(?:#{LABEL}:[0-9a-f]{12}:|[0-9a-f]{12})[0-9a-f]{4}"
    KEY_RE = /\A([\s\S]{0,#{MAX_PREFIX}}?)((?:#{CORE}\.*)+)\z/n
    CORE_RE = /dk1:(?:#{LABEL}:([0-9a-f]{12}):|([0-9a-f]{12}))([0-9a-f]{4})/n
    HEX_MARK = "646b313a"
    B64_MARK = "ZGsxO"

    # A key that is (or encodes) a handle.
    Ref = Struct.new(:handle, :prefix, :key_encoding, :length) do
      def fields
        f = { "handle" => handle }
        f["prefix"] = Base64.strict_encode64(prefix) unless prefix.empty?
        f["key_encoding"] = key_encoding if key_encoding
        f
      end
    end

    module_function

    def crc(id)
      @crc ||= {}
      @crc[id] ||= ::Digest::SHA256.hexdigest("dk1:#{id}")[0, 4]
    end

    def parse(bytes)
      m = KEY_RE.match(bytes)
      return nil unless m
      m[2].scan(CORE_RE) { |a, b, c| return nil unless crc(a || b) == c }
      [m[1], m[2]]
    end

    # Ref if `key` is a doppelkey handle (raw, prefixed, or hex/base64-encoded), else nil.
    def recognise(key)
      return nil unless key.is_a?(String) && key.bytesize >= 20
      b = key.b
      if b.include?("dk1:")
        p = parse(b)
        return p && Ref.new(p[1], p[0], nil, b.bytesize)
      end
      starts = [b.index(HEX_MARK), b.index(B64_MARK)].compact.select { |i| i <= MAX_PREFIX }
      return nil if starts.empty?
      start = starts.min
      body = b[start..]
      if body.start_with?(HEX_MARK) && body.match?(/\A[0-9a-f]+\z/) && body.bytesize.even?
        enc, decoded = "hex", [body].pack("H*")
      elsif body.start_with?(B64_MARK) && body.match?(%r{\A[A-Za-z0-9+/]+={0,2}\z})
        enc = "base64"
        decoded = begin
          Base64.strict_decode64(body)
        rescue ArgumentError
          return nil
        end
      else
        return nil
      end
      p = parse(decoded.b)
      return nil unless p && p[0].empty?
      Ref.new(p[1], b[0, start], enc, b.bytesize)
    end
  end
end
