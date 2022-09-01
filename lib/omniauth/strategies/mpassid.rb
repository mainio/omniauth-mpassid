# frozen_string_literal: true

require 'omniauth-saml'

module OmniAuth
  module Strategies
    class MPASSid < SAML
      # Mode:
      # :production - MPASSid production environment
      # :test - MPASSid test environment
      option :mode, :production

      # Defines the lang parameters to check from the request phase request
      # parameters. A valid language will be added to the IdP sign in redirect
      # URL as the last parameter (with the name `lang` as expected by
      # MPASSid).
      #
      # MPASSid generally accepts `fi` or `sv` in this parameter but it can
      # depend on the underlying service. The language can be parsed from the
      # following kind of strings:
      # - fi
      # - sv-SE
      # - fi_FI
      #
      # In case a valid language cannot be parsed from the parameter, the lang
      # parameter will default to `:idp_sso_service_url_default_lang`.
      option :idp_sso_service_url_lang_params, %w[locale language lang]

      # This is the default language to be passed to IdP sign in redirect URL as
      # defined above. In case a valid language is not found from the request
      # parameters, this will be used instead.
      option :idp_sso_service_url_default_lang, 'fi'

      # The request attributes for MPASSid
      option :request_attributes, [
        # The unique identifier of the authenticated user. Currently recommended
        # identifier for identifying the user. NOTE: will change if the user
        # moves to another user registry.
        # (single value)
        {
          name: 'urn:mpass.id:uid',
          name_format: 'urn:oasis:names:tc:SAML:2.0:attrname-format:uri',
          friendly_name: 'mpassUsername'
        },
        # Funet EDU person learner ID
        # (single value)
        {
          name: 'urn:oid:1.3.6.1.4.1.16161.1.1.27',
          name_format: 'urn:oasis:names:tc:SAML:2.0:attrname-format:uri',
          friendly_name: 'learnerId'
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
          name_format: 'urn:oasis:names:tc:SAML:2.0:attrname-format:uri',
          friendly_name: 'mpassSchoolCode'
        },
        # The human-readable name of the school of the authenticated user.
        # (multi value)
        {
          name: 'urn:mpass.id:school',
          name_format: 'urn:oasis:names:tc:SAML:2.0:attrname-format:uri',
          friendly_name: 'school'
        },
        # Combination of the school code and official name of the educational
        # institution separated with semicolon.
        # For instance: 00000;Tuntematon
        {
          name: 'urn:mpass.id:schoolInfo',
          name_format: 'urn:oasis:names:tc:SAML:2.0:attrname-format:uri',
          friendly_name: 'mpassSchoolInfo'
        },
        # The class/group-information of the authenticated user.
        # For instance: 8A or 3B.
        # (multi value)
        {
          name: 'urn:mpass.id:class',
          name_format: 'urn:oasis:names:tc:SAML:2.0:attrname-format:uri',
          friendly_name: 'mpassClass'
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
          name_format: 'urn:oasis:names:tc:SAML:2.0:attrname-format:uri',
          friendly_name: 'mpassClassLevel'
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
        # character. First educational provider's organization OID, followed by
        # school code, group and role in the group.
        # For instance 1.2.246.562.10.12345678907;99900;7B;Oppilas.
        # (multi value)
        #
        # The educational providers' organization OIDs can be found from:
        # https://github.com/Opetushallitus/aitu/blob/master/ttk-db/resources/db/migration/V11_2__koulutustoimijat.sql
        {
          name: 'urn:mpass.id:role',
          name_format: 'urn:oasis:names:tc:SAML:2.0:attrname-format:uri',
          friendly_name: 'mpassRole'
        },
        # The educational provider's permanent organization OID.
        # (multi value)
        #
        # The educational providers' organization OIDs can be found from:
        # https://github.com/Opetushallitus/aitu/blob/master/ttk-db/resources/db/migration/V11_2__koulutustoimijat.sql
        {
          name: 'urn:mpass.id:educationProviderId',
          name_format: 'urn:oasis:names:tc:SAML:2.0:attrname-format:uri',
          friendly_name: 'mpassEducationProviderOid'
        },
        # The educational provider's human-readable name.
        # (multi value)
        {
          name: 'urn:mpass.id:educationProvider',
          name_format: 'urn:oasis:names:tc:SAML:2.0:attrname-format:uri',
          friendly_name: 'mpassEducationProviderName'
        },
        # Combination of the education provider's organisation-OID and official
        # name. Separated by semicolon.
        # For instance: 1.2.246.562.10.494695390410;Virallinen nimi
        # (multi value)
        {
          name: 'urn:mpass.id:educationProviderInfo',
          name_format: 'urn:oasis:names:tc:SAML:2.0:attrname-format:uri',
          friendly_name: 'mpassEducationProviderInfo'
        }
      ]

      # Maps the SAML attributes to OmniAuth info schema:
      # https://github.com/omniauth/omniauth/wiki/Auth-Hash-Schema#schema-10-and-later
      option(
        :attribute_statements,
        # Given name or all first names (in case given name is not found)
        first_name: ['urn:oid:2.5.4.42', 'http://eidas.europa.eu/attributes/naturalperson/CurrentGivenName'],
        last_name: ['urn:oid:2.5.4.4'],
        # The education provider (e.g. municipality) of the person (literal format in Finnish)
        location: ['urn:mpass.id:educationProvider']
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

        found_attributes.to_h
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
        first_names: ['urn:oid:2.5.4.42'],
        last_name: ['urn:oid:2.5.4.4'],
        provider_id: {
          name: ['urn:mpass.id:educationProviderId'],
          type: :multi
        },
        provider_name: {
          name: ['urn:mpass.id:educationProvider'],
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
        # Extra
        # Unique learner ID
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

      # Override the request phase to be able to pass the lang parameter to
      # the redirect URL. Note that this needs to be the last parameter to
      # be passed to the redirect URL.
      def request_phase
        authn_request = OneLogin::RubySaml::Authrequest.new
        lang = lang_for_authn_request

        with_settings do |settings|
          url = authn_request.create(settings, additional_params_for_authn_request)
          url += "&lang=#{CGI.escape(lang)}" unless lang.nil?
          redirect(url)
        end
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

      # Override the callback URL so that it always matches the one expected by
      # MPASSid. No additional query string parameters can be included in the
      # string.
      def callback_url
        full_host + script_name + callback_path
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
            end.compact.first

            attrs[target] = value
          end
        end
      end

      def lang_for_authn_request
        if options.idp_sso_service_url_lang_params.is_a?(Array)
          options.idp_sso_service_url_lang_params.each do |param|
            next unless request.params.key?(param.to_s)

            lang = parse_language_value(request.params[param.to_s])
            return lang unless lang.nil?
          end
        end

        options.idp_sso_service_url_default_lang
      end

      def parse_language_value(string)
        language = string.sub('_', '-').split('-').first

        language if language =~ /^(fi|sv)$/
      end
    end
  end
end

OmniAuth.config.add_camelization 'mpassid', 'MPASSid'
