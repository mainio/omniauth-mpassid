# frozen_string_literal: true

module OmniAuth
  module MPASSid
    module Test
      class Utility
        def self.inflate_xml(encoded_deflated_xml)
          deflated_xml = Base64.decode64(encoded_deflated_xml)
          Zlib::Inflate.new(-Zlib::MAX_WBITS).inflate(deflated_xml)
        end

        def self.signed_xml(raw_xml_file, opts)
          raw_xml = File.read(raw_xml_file)
          signed_xml_from_string(raw_xml, opts)
        end

        def self.signed_xml_from_string(raw_xml, opts)
          sign_xml_element(
            raw_xml,
            opts[:sign_certificate],
            opts[:sign_private_key]
          )
        end

        def self.sign_xml_element(element, sign_certificate, sign_key)
          doc = XMLSecurity::Document.new(element)
          doc.sign_document(
            sign_key,
            sign_certificate,
            XMLSecurity::Document::RSA_SHA256,
            XMLSecurity::Document::SHA256
          )
          # Move the signature to the correct position, otherwise schema
          # validation does not work because the internal logic of ruby-saml
          # cannot handle custom element names (saml2:Issuer instead of
          # saml:Issuer).
          signature = doc.delete_element('//ds:Signature')
          issuer = doc.elements['//saml2:Issuer']
          doc.root.insert_after(issuer, signature)

          doc.to_s
        end
      end
    end
  end
end
