#!/usr/bin/env ruby
# frozen_string_literal: true

# Certificate Inspector Extension for Marshall Browser
# Deep SSL/TLS certificate analysis and chain verification
# Written in Ruby for flexibility
# Part of Marshall Extensions Collection

require 'openssl'
require 'socket'
require 'json'
require 'date'

module Marshall
  module Extensions
    # Certificate analysis and verification
    class CertInspector
      VERSION = '1.0.0'

      # Certificate grade levels
      GRADES = {
        'A+' => { min_score: 95, color: '#00ff00' },
        'A'  => { min_score: 85, color: '#44ff00' },
        'B'  => { min_score: 70, color: '#88ff00' },
        'C'  => { min_score: 55, color: '#ffff00' },
        'D'  => { min_score: 40, color: '#ff8800' },
        'F'  => { min_score: 0,  color: '#ff0000' }
      }.freeze

      # Weak cipher suites to flag
      WEAK_CIPHERS = %w[
        DES RC4 MD5 NULL EXPORT ANON
        3DES CBC
      ].freeze

      # Modern secure protocols
      SECURE_PROTOCOLS = %i[TLSv1_2 TLSv1_3].freeze

      attr_reader :host, :port, :certificate, :chain, :analysis

      def initialize(host, port = 443)
        @host = host
        @port = port
        @certificate = nil
        @chain = []
        @analysis = {}
      end

      # Fetch certificate from server
      def fetch_certificate
        context = OpenSSL::SSL::SSLContext.new
        context.verify_mode = OpenSSL::SSL::VERIFY_NONE

        tcp = TCPSocket.new(@host, @port)
        ssl = OpenSSL::SSL::SSLSocket.new(tcp, context)
        ssl.hostname = @host
        ssl.connect

        @certificate = ssl.peer_cert
        @chain = ssl.peer_cert_chain || []
        @protocol = ssl.ssl_version
        @cipher = ssl.cipher

        ssl.close
        tcp.close

        true
      rescue StandardError => e
        @analysis[:error] = e.message
        false
      end

      # Analyze certificate security
      def analyze
        return @analysis if @certificate.nil?

        @analysis = {
          subject: parse_subject,
          issuer: parse_issuer,
          validity: analyze_validity,
          key: analyze_key,
          signature: analyze_signature,
          extensions: analyze_extensions,
          chain: analyze_chain,
          protocol: analyze_protocol,
          cipher: analyze_cipher,
          score: 0,
          grade: 'F',
          issues: [],
          recommendations: []
        }

        calculate_score
        @analysis
      end

      private

      # Parse subject details
      def parse_subject
        subject = @certificate.subject.to_a
        {
          common_name: extract_field(subject, 'CN'),
          organization: extract_field(subject, 'O'),
          org_unit: extract_field(subject, 'OU'),
          country: extract_field(subject, 'C'),
          state: extract_field(subject, 'ST'),
          locality: extract_field(subject, 'L')
        }
      end

      # Parse issuer details
      def parse_issuer
        issuer = @certificate.issuer.to_a
        {
          common_name: extract_field(issuer, 'CN'),
          organization: extract_field(issuer, 'O'),
          country: extract_field(issuer, 'C')
        }
      end

      def extract_field(array, field)
        entry = array.find { |e| e[0] == field }
        entry ? entry[1] : nil
      end

      # Analyze validity period
      def analyze_validity
        not_before = @certificate.not_before
        not_after = @certificate.not_after
        now = Time.now

        days_remaining = ((not_after - now) / 86400).to_i
        total_validity = ((not_after - not_before) / 86400).to_i

        validity = {
          not_before: not_before.iso8601,
          not_after: not_after.iso8601,
          days_remaining: days_remaining,
          total_validity_days: total_validity,
          is_valid: now >= not_before && now <= not_after,
          is_expired: now > not_after,
          is_not_yet_valid: now < not_before
        }

        # Check issues
        if validity[:is_expired]
          @analysis[:issues] << 'Certificate has expired!'
        elsif days_remaining < 30
          @analysis[:issues] << "Certificate expires in #{days_remaining} days"
          @analysis[:recommendations] << 'Renew certificate soon'
        end

        if total_validity > 398 # 13 months
          @analysis[:issues] << 'Certificate validity exceeds 398 days (CA/B Forum limit)'
        end

        validity
      end

      # Analyze public key
      def analyze_key
        pub_key = @certificate.public_key
        key_info = {
          type: pub_key.class.name.split('::').last,
          size: nil,
          secure: false
        }

        case pub_key
        when OpenSSL::PKey::RSA
          key_info[:size] = pub_key.n.num_bits
          key_info[:secure] = key_info[:size] >= 2048
          
          if key_info[:size] < 2048
            @analysis[:issues] << "RSA key size (#{key_info[:size]} bits) is weak"
            @analysis[:recommendations] << 'Use RSA 2048+ or ECDSA 256+'
          end
        when OpenSSL::PKey::EC
          key_info[:size] = pub_key.group.degree
          key_info[:curve] = pub_key.group.curve_name
          key_info[:secure] = key_info[:size] >= 256
        when OpenSSL::PKey::DSA
          key_info[:size] = pub_key.p.num_bits
          @analysis[:issues] << 'DSA keys are deprecated'
        end

        key_info
      end

      # Analyze signature algorithm
      def analyze_signature
        sig_alg = @certificate.signature_algorithm

        sig_info = {
          algorithm: sig_alg,
          secure: true
        }

        if sig_alg.include?('sha1') || sig_alg.include?('md5')
          sig_info[:secure] = false
          @analysis[:issues] << "Weak signature algorithm: #{sig_alg}"
          @analysis[:recommendations] << 'Use SHA-256 or stronger'
        end

        sig_info
      end

      # Analyze certificate extensions
      def analyze_extensions
        extensions = {}

        @certificate.extensions.each do |ext|
          ext_name = ext.oid
          ext_value = ext.value
          ext_critical = ext.critical?

          extensions[ext_name] = {
            value: ext_value.length > 200 ? "#{ext_value[0..200]}..." : ext_value,
            critical: ext_critical
          }

          # Analyze specific extensions
          case ext_name
          when 'subjectAltName'
            extensions[:san] = parse_san(ext_value)
          when 'keyUsage'
            extensions[:key_usage] = ext_value.split(', ')
          when 'extendedKeyUsage'
            extensions[:extended_key_usage] = ext_value.split(', ')
          when 'certificatePolicies'
            if ext_value.include?('EV') || ext_value.include?('Organization Validation')
              extensions[:validation_type] = 'EV'
            elsif ext_value.include?('Organization')
              extensions[:validation_type] = 'OV'
            else
              extensions[:validation_type] = 'DV'
            end
          when 'crlDistributionPoints'
            extensions[:crl_urls] = ext_value.scan(/URI:([^\s,]+)/).flatten
          when 'authorityInfoAccess'
            extensions[:ocsp_urls] = ext_value.scan(/OCSP - URI:([^\s,]+)/).flatten
            extensions[:ca_issuers] = ext_value.scan(/CA Issuers - URI:([^\s,]+)/).flatten
          end
        end

        # Check for missing extensions
        unless extensions['subjectAltName']
          @analysis[:issues] << 'Missing Subject Alternative Name (SAN)'
        end

        extensions
      end

      # Parse Subject Alternative Names
      def parse_san(value)
        names = value.split(', ').map do |entry|
          type, name = entry.split(':', 2)
          { type: type, value: name }
        end

        {
          dns_names: names.select { |n| n[:type] == 'DNS' }.map { |n| n[:value] },
          ip_addresses: names.select { |n| n[:type] == 'IP Address' }.map { |n| n[:value] },
          emails: names.select { |n| n[:type] == 'email' }.map { |n| n[:value] }
        }
      end

      # Analyze certificate chain
      def analyze_chain
        chain_info = {
          length: @chain.length,
          certificates: [],
          valid: true
        }

        @chain.each_with_index do |cert, index|
          cert_info = {
            subject: cert.subject.to_s,
            issuer: cert.issuer.to_s,
            self_signed: cert.subject == cert.issuer,
            is_ca: false
          }

          # Check basicConstraints for CA
          cert.extensions.each do |ext|
            if ext.oid == 'basicConstraints' && ext.value.include?('CA:TRUE')
              cert_info[:is_ca] = true
            end
          end

          chain_info[:certificates] << cert_info
        end

        # Verify chain
        if @chain.length == 1 && @chain[0].subject == @chain[0].issuer
          @analysis[:issues] << 'Self-signed certificate'
          chain_info[:valid] = false
        end

        chain_info
      end

      # Analyze protocol version
      def analyze_protocol
        protocol_info = {
          version: @protocol,
          secure: SECURE_PROTOCOLS.map(&:to_s).include?(@protocol)
        }

        unless protocol_info[:secure]
          @analysis[:issues] << "Insecure protocol: #{@protocol}"
          @analysis[:recommendations] << 'Enable TLS 1.2+ and disable older versions'
        end

        protocol_info
      end

      # Analyze cipher suite
      def analyze_cipher
        return nil unless @cipher

        cipher_info = {
          name: @cipher[0],
          version: @cipher[1],
          bits: @cipher[2],
          secure: true
        }

        # Check for weak ciphers
        WEAK_CIPHERS.each do |weak|
          if @cipher[0].include?(weak)
            cipher_info[:secure] = false
            @analysis[:issues] << "Weak cipher component: #{weak}"
          end
        end

        if @cipher[2] < 128
          cipher_info[:secure] = false
          @analysis[:issues] << "Weak cipher strength: #{@cipher[2]} bits"
        end

        cipher_info
      end

      # Calculate overall security score
      def calculate_score
        score = 100

        # Deduct for issues
        @analysis[:issues].each do |issue|
          case issue
          when /expired/i
            score -= 50
          when /weak/i
            score -= 20
          when /insecure/i
            score -= 25
          when /missing/i
            score -= 10
          when /self-signed/i
            score -= 30
          else
            score -= 5
          end
        end

        # Bonus for good practices
        score += 5 if @analysis.dig(:key, :type) == 'EC'
        score += 5 if @analysis.dig(:extensions, :validation_type) == 'EV'
        score += 5 if @analysis.dig(:protocol, :version) == 'TLSv1.3'

        score = [[score, 0].max, 100].min
        @analysis[:score] = score
        @analysis[:grade] = calculate_grade(score)
      end

      def calculate_grade(score)
        GRADES.each do |grade, config|
          return grade if score >= config[:min_score]
        end
        'F'
      end
    end

    # Extension interface for Marshall browser
    class CertInspectorExtension
      def initialize
        @inspector = nil
      end

      def analyze_current_page(url)
        uri = URI.parse(url)
        return { error: 'Not HTTPS' } unless uri.scheme == 'https'

        @inspector = CertInspector.new(uri.host, uri.port || 443)
        return { error: @inspector.analysis[:error] } unless @inspector.fetch_certificate

        @inspector.analyze
      end

      def to_json
        @inspector&.analysis&.to_json
      end

      def to_html
        return '<p>No analysis available</p>' unless @inspector&.analysis

        a = @inspector.analysis
        grade_color = CertInspector::GRADES[a[:grade]][:color]

        <<~HTML
          <div class="cert-analysis">
            <div class="cert-header">
              <h2>#{a.dig(:subject, :common_name)}</h2>
              <div class="grade-badge" style="background: #{grade_color}">
                <span class="grade">#{a[:grade]}</span>
                <span class="score">#{a[:score]}/100</span>
              </div>
            </div>

            <div class="cert-section">
              <h3>📜 Certificate Details</h3>
              <table>
                <tr><td>Subject</td><td>#{a.dig(:subject, :common_name)}</td></tr>
                <tr><td>Organization</td><td>#{a.dig(:subject, :organization) || 'N/A'}</td></tr>
                <tr><td>Issuer</td><td>#{a.dig(:issuer, :common_name)}</td></tr>
                <tr><td>Valid From</td><td>#{a.dig(:validity, :not_before)}</td></tr>
                <tr><td>Valid Until</td><td>#{a.dig(:validity, :not_after)}</td></tr>
                <tr><td>Days Remaining</td><td>#{a.dig(:validity, :days_remaining)}</td></tr>
              </table>
            </div>

            <div class="cert-section">
              <h3>🔐 Security</h3>
              <table>
                <tr><td>Key Type</td><td>#{a.dig(:key, :type)} #{a.dig(:key, :size)} bits</td></tr>
                <tr><td>Signature</td><td>#{a.dig(:signature, :algorithm)}</td></tr>
                <tr><td>Protocol</td><td>#{a.dig(:protocol, :version)}</td></tr>
                <tr><td>Cipher</td><td>#{a.dig(:cipher, :name)}</td></tr>
              </table>
            </div>

            #{issues_html(a[:issues])}
            #{recommendations_html(a[:recommendations])}
          </div>
        HTML
      end

      private

      def issues_html(issues)
        return '' if issues.empty?

        items = issues.map { |i| "<li>⚠️ #{i}</li>" }.join
        "<div class='cert-section issues'><h3>⚠️ Issues</h3><ul>#{items}</ul></div>"
      end

      def recommendations_html(recs)
        return '' if recs.empty?

        items = recs.map { |r| "<li>💡 #{r}</li>" }.join
        "<div class='cert-section recommendations'><h3>💡 Recommendations</h3><ul>#{items}</ul></div>"
      end
    end
  end
end

# Entry point when run directly
if __FILE__ == $PROGRAM_NAME
  if ARGV.empty?
    puts 'Usage: ruby cert_inspector.rb <hostname>'
    exit 1
  end

  inspector = Marshall::Extensions::CertInspector.new(ARGV[0])
  if inspector.fetch_certificate
    analysis = inspector.analyze
    puts JSON.pretty_generate(analysis)
  else
    puts "Error: #{inspector.analysis[:error]}"
  end
end
