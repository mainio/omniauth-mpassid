# frozen_string_literal: true

require 'omniauth-saml'

module OmniAuth
  module Strategies
    class MPASSid < SAML
      # Mode:
      # :production - MPASSid production environment
      # :test - MPASSid test environment
      option :mode, :production

      # The request attributes for MPASSid
      option :request_attributes, [
        # The unique identifier of the authenticated user. Currently recommended
        # identifier for identifying the user. NOTE: will change if the user
        # moves to another user registry.
        # (single value)
        {
          name: 'urn:mpass.id:uid',
          name_format: 'urn:oasis:names:tc:SAML:2.0:attrname-format:uri'
        },
        # Funet EDU person learner ID
        # (single value)
        {
          name: 'urn:oid:1.3.6.1.4.1.16161.1.1.27',
          name_format: 'urn:oasis:names:tc:SAML:2.0:attrname-format:uri'
        },
        # The first/given name of the user.
        # (single value)
        {
          name: 'urn:oid:2.5.4.42',
          name_format: 'urn:oasis:names:tc:SAML:2.0:attrname-format:uri',
          friendly_name: 'givenName'
        },
        # All the first/given names of the user.
        # (single value)
        {
          name: 'http://eidas.europa.eu/attributes/naturalperson/CurrentGivenName',
          name_format: 'urn:oasis:names:tc:SAML:2.0:attrname-format:uri',
          friendly_name: 'firstName'
        },
        # The last/family name of the user.
        # (single value)
        {
          name: 'urn:oid:2.5.4.4',
          name_format: 'urn:oasis:names:tc:SAML:2.0:attrname-format:uri',
          friendly_name: 'sn'
        },
        # The municipality code of the authenticated user. See
        # http://tilastokeskus.fi/meta/luokitukset/kunta/001-2017/index.html
        # for mappings in Finland.
        # (multi value)
        {
          name: 'urn:mpass.id:municipalityCode',
          name_format: 'urn:oasis:names:tc:SAML:2.0:attrname-format:uri',
          friendly_name: 'municipalityCode'
        },
        # The human-readable name of the municipality of the authenticated user.
        # (multi value)
        {
          name: 'urn:mpass.id:municipality',
          name_format: 'urn:oasis:names:tc:SAML:2.0:attrname-format:uri'
        },
        {
          name: 'urn:educloudalliance.org:municipality',
          name_format: 'urn:oasis:names:tc:SAML:2.0:attrname-format:uri',
          friendly_name: 'ecaMunicipality'
        },
        # The school code of the authenticated user. See
        # https://virkailija.opintopolku.fi/koodisto-service/rest/json/oppilaitosnumero/koodi
        # (JSON format)
        # https://virkailija.opintopolku.fi/koodisto-service/rest/oppilaitosnumero/koodi
        # (XML format)
        # for the mappings in Finland. For example,
        # https://virkailija.opintopolku.fi/koodisto-service/rest/codeelement/oppilaitosnumero_04647
        # for school code 04647.
        # (multi value)
        {
          name: 'urn:mpass.id:schoolCode',
          name_format: 'urn:oasis:names:tc:SAML:2.0:attrname-format:uri'
        },
        # The human-readable name of the school of the authenticated user.
        # (multi value)
        {
          name: 'urn:mpass.id:school',
          name_format: 'urn:oasis:names:tc:SAML:2.0:attrname-format:uri',
          friendly_name: 'school'
        },
        # The class/group-information of the authenticated user.
        # For instance: 8A or 3B.
        # (multi value)
        {
          name: 'urn:mpass.id:class',
          name_format: 'urn:oasis:names:tc:SAML:2.0:attrname-format:uri'
        },
        {
          name: 'urn:educloudalliance.org:group',
          name_format: 'urn:oasis:names:tc:SAML:2.0:attrname-format:uri',
          friendly_name: 'ecaGroup'
        },
        # The class/level-information of the authenticated user.
        # For instance 8 or 3.
        # (multi value)
        {
          name: 'urn:mpass.id:classLevel',
          name_format: 'urn:oasis:names:tc:SAML:2.0:attrname-format:uri'
        },
        # The role name of the user.
        # For instance Oppilas.
        # (multi value)
        {
          name: 'urn:educloudalliance.org:role',
          name_format: 'urn:oasis:names:tc:SAML:2.0:attrname-format:uri',
          friendly_name: 'ecaRole'
        },
        # The role of the user in four parts, divided with a semicolon (;)
        # character. First municipality, followed by school code, group and role
        # in the group.
        # For instance Helsinki;32132;9A;Oppilas.
        # (multi value)
        {
          name: 'urn:mpass.id:role',
          name_format: 'urn:oasis:names:tc:SAML:2.0:attrname-format:uri'
        },
        {
          name: 'urn:educloudalliance.org:structuredRole',
          name_format: 'urn:oasis:names:tc:SAML:2.0:attrname-format:uri',
          friendly_name: 'ecaStructuredRole'
        }
      ]

      # Maps the SAML attributes to OmniAuth info schema:
      # https://github.com/omniauth/omniauth/wiki/Auth-Hash-Schema#schema-10-and-later
      option(
        :attribute_statements,
        # Given name or all first names (in case given name is not found)
        first_name: ['urn:oid:2.5.4.42', 'http://eidas.europa.eu/attributes/naturalperson/CurrentGivenName'],
        last_name: ['urn:oid:2.5.4.4'],
        # The municipality of the person (literal format in Finnish)
        location: ['urn:mpass.id:municipality', 'urn:educloudalliance.org:municipality']
      )

      info do
        # Generate the full name to the info hash
        first_name = find_attribute_by(
          [
            'urn:oid:2.5.4.42',
            'http://eidas.europa.eu/attributes/naturalperson/CurrentGivenName'
          ]
        )
        last_name = find_attribute_by(['urn:oid:2.5.4.4'])
        display_name = "#{first_name} #{last_name}".strip
        display_name = nil if display_name.length.zero?

        found_attributes = [[:name, display_name]]

        # Default functionality from omniauth-saml
        found_attributes += options.attribute_statements.map do |key, values|
          attribute = find_attribute_by(values)
          [key, attribute]
        end

        Hash[found_attributes]
      end

      option(
        :security_settings,
        digest_method: XMLSecurity::Document::SHA256,
        signature_method: XMLSecurity::Document::RSA_SHA256
      )

      # The attribute key maps to the SAML URIs so that we have more descriptive
      # attribute keys available for use. These will be mapped to the OmniAuth
      # `extra` information hash under the `:saml_attributes` key.
      option(
        :saml_attributes_map,
        given_name: ['urn:oid:2.5.4.42'],
        first_names: ['http://eidas.europa.eu/attributes/naturalperson/CurrentGivenName'],
        last_name: ['urn:oid:2.5.4.4'],
        municipality_code: {
          name: ['urn:mpass.id:municipalityCode'],
          type: :multi
        },
        municipality_name: {
          name: ['urn:mpass.id:municipality', 'urn:educloudalliance.org:municipality'],
          type: :multi
        },
        school_code: {
          name: ['urn:mpass.id:schoolCode'],
          type: :multi
        },
        school_name: {
          name: ['urn:mpass.id:school'],
          type: :multi
        },
        class: {
          name: ['urn:mpass.id:class', 'urn:educloudalliance.org:group'],
          type: :multi
        },
        class_level: {
          name: ['urn:mpass.id:classLevel'],
          type: :multi
        },
        role: {
          name: ['urn:mpass.id:role', 'urn:educloudalliance.org:structuredRole'],
          type: :multi
        },
        role_name: {
          name: ['urn:educloudalliance.org:role'],
          type: :multi
        },
        # Extra (undocumented)
        funet_person_learner_id: ['urn:oid:1.3.6.1.4.1.16161.1.1.27']
      )

      # Defines the SAML attribute from which to determine the OmniAuth `uid`.
      # NOTE:
      # In case the user moves to another user registry, this will change.
      # However, there is no other unique identifier passed along the SAML
      # attributes that we could rely on, so this is the best bet.
      option :uid_attribute, 'urn:mpass.id:uid'

      # Add the SAML attributes to the extra hash for easier access.
      extra { {saml_attributes: saml_attributes} }

      def initialize(app, *args, &block)
        super

        # Add the MPASSid options to the local options, most of which are
        # fetched from the metadata. The options array is the one that gets
        # priority in case it overrides some of the metadata or locally defined
        # option values.
        @options = OmniAuth::Strategy::Options.new(
          mpassid_options.merge(options)
        )
      end

      # This method can be used externally to fetch information about the
      # response, e.g. in case of failures.
      def response_object
        return nil unless request.params['SAMLResponse']

        with_settings do |settings|
          response = OneLogin::RubySaml::Response.new(
            request.params['SAMLResponse'],
            options_for_response_object.merge(settings: settings)
          )
          response.attributes['fingerprint'] = settings.idp_cert_fingerprint
          response
        end
      end

    private

      def idp_metadata_url
        case options.mode
        when :test
          'https://mpass-proxy-test.csc.fi/idp/shibboleth'
        else
          'https://mpass-proxy.csc.fi/idp/shibboleth'
        end
      end

      def mpassid_options
        idp_metadata_parser = OneLogin::RubySaml::IdpMetadataParser.new

        # Returns OneLogin::RubySaml::Settings prepopulated with idp metadata
        # We are using the redirect binding for the SSO and SLO URLs as these
        # are the ones expected by omniauth-saml. Otherwise the default would be
        # the first one defined in the IdP metadata, which would be the
        # HTTP-POST binding.
        settings = idp_metadata_parser.parse_remote_to_hash(
          idp_metadata_url,
          true,
          sso_binding: ['urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect']
        )

        # Define the security settings as there are some defaults that need to be
        # modified
        security_defaults = OneLogin::RubySaml::Settings::DEFAULTS[:security]
        settings[:security] = security_defaults.merge(options.security_settings)

        settings
      end

      def saml_attributes
        {}.tap do |attrs|
          options.saml_attributes_map.each do |target, definition|
            unless definition.is_a?(Hash)
              definition = {
                name: definition,
                type: :single
              }
            end

            value = definition[:name].map do |key|
              @attributes.public_send(definition[:type], key)
            end.reject(&:nil?).first

            attrs[target] = value
          end
        end
      end
    end
  end
end

OmniAuth.config.add_camelization 'mpassid', 'MPASSid'
