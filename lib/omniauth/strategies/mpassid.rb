# frozen_string_literal: true

require 'omniauth-saml'

module OmniAuth
  module Strategies
    class MPASSid < SAML
      # Mode:
      # :production - MPASSid production environment
      # :test - MPASSid test environment
      option :mode, :production

      # The certificate file to define the certificate.
      option :certificate_file, nil

      # The private key file to define the private key.
      option :private_key_file, nil

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
        # The last/family name of the user.
        # (single value)
        {
          name: 'urn:oid:2.5.4.4',
          name_format: 'urn:oasis:names:tc:SAML:2.0:attrname-format:uri',
          friendly_name: 'sn'
        },
        # The given name of the user.
        # (single value)
        {
          name: 'urn:oid:2.5.4.42',
          name_format: 'urn:oasis:names:tc:SAML:2.0:attrname-format:uri',
          friendly_name: 'givenName'
        },
        # The first name/nickname of the user (calling name / kutsumanimi).
        # (single value)
        {
          name: 'urn:mpass.id:nickname',
          name_format: 'urn:oasis:names:tc:SAML:2.0:attrname-format:uri',
          friendly_name: 'nickname'
        },
        # The unique identifier of the authenticated user. Currently recommended
        # identifier for identifying the user. NOTE: will change if the user
        # moves to another user registry.
        # (single value)
        {
          name: 'urn:mpass.id:uid',
          name_format: 'urn:oasis:names:tc:SAML:2.0:attrname-format:uri',
          friendly_name: 'mpassUsername'
        },
        # Combination of the school code and official name of the educational
        # institution separated with semicolon.
        # For instance: 30076;Mansikkalan testi peruskoulu AND 1.2.246.562.99.00000000002;Mansikkalan testi peruskoulu
        #
        # Contains the school code of the authenticated user. See
        # https://virkailija.opintopolku.fi/koodisto-service/rest/json/oppilaitosnumero/koodi
        # (JSON format)
        # https://virkailija.opintopolku.fi/koodisto-service/rest/oppilaitosnumero/koodi
        # (XML format)
        # for the mappings in Finland. For example,
        # https://virkailija.opintopolku.fi/koodisto-service/rest/codeelement/oppilaitosnumero_04647
        # for school code 04647.
        # (multi value)
        #
        # The OIDs for educational institution (`OPPILAITOS`) can be found from:
        # https://virkailija.opintopolku.fi/organisaatio-service/swagger-ui/index.html
        {
          name: 'urn:mpass.id:schoolInfo',
          name_format: 'urn:oasis:names:tc:SAML:2.0:attrname-format:uri',
          friendly_name: 'mpassSchoolInfo'
        },
        # The class/level-information of the authenticated user.
        # For instance 8 or 3.
        # (single value)
        {
          name: 'urn:mpass.id:classLevel',
          name_format: 'urn:oasis:names:tc:SAML:2.0:attrname-format:uri',
          friendly_name: 'mpassClassLevel'
        },
        # The learning material charge.
        # For instance 0;00000 AND 0;1.2.246.562.99.00000000003.
        # (multi value)
        {
          name: 'urn:mpass.id:learningMaterialsCharge',
          name_format: 'urn:oasis:names:tc:SAML:2.0:attrname-format:uri',
          friendly_name: 'mpassLearningMaterialsCharge'
        },
        # The role of the user in four parts, divided with a semicolon (;)
        # character. First educational provider's organization OID, followed by
        # school code, group (e.g. the class), role in the group (e.g.
        # "Oppilas"), the role code (e.g. "1"), the educational institution's
        # OID and finally the office OID (can be undefined).
        # For instance 1.2.246.562.99.00000000001;00000;1A;Oppilas;1;1.2.246.562.99.00000000003;
        # (multi value)
        #
        # The OIDs for educational providers (`KOULUTUSTOIMIJA`), educational
        # institutions (`OPPILAITOS`) and offices/branches (`TOIMIPISTE`) can be
        # found from:
        # https://virkailija.opintopolku.fi/organisaatio-service/swagger-ui/index.html
        #
        # The test entries are in:
        # https://github.com/Opetushallitus/aitu/blob/master/ttk-db/resources/db/migration/V12_0__oppilaitosten_puuttuvat_koulutustoimijat.sql
        {
          name: 'urn:mpass.id:role',
          name_format: 'urn:oasis:names:tc:SAML:2.0:attrname-format:uri',
          friendly_name: 'mpassRole'
        },
        # Funet EDU person learner ID
        # (single value)
        {
          name: 'urn:oid:1.3.6.1.4.1.16161.1.1.27',
          name_format: 'urn:oasis:names:tc:SAML:2.0:attrname-format:uri',
          friendly_name: 'learnerId'
        },
        # Combination of the education provider's organisation-OID and official
        # name. Separated by semicolon.
        # For instance: 1.2.246.562.10.494695390410;Virallinen nimi
        # (multi value)
        #
        # The OIDs for educational providers (`KOULUTUSTOIMIJA`) can be found
        # from:
        # https://virkailija.opintopolku.fi/organisaatio-service/swagger-ui/index.html
        {
          name: 'urn:mpass.id:educationProviderInfo',
          name_format: 'urn:oasis:names:tc:SAML:2.0:attrname-format:uri',
          friendly_name: 'mpassEducationProviderInfo'
        },
        # The relaying organization for the information.
        # For instance: 1.2.246.562.10.00000000000
        # (single value)
        {
          name: 'urn:mpass.id:originalIssuer',
          name_format: 'urn:oasis:names:tc:SAML:2.0:attrname-format:uri',
          friendly_name: 'originalIssuer'
        }
      ]

      # Maps the SAML attributes to OmniAuth info schema:
      # https://github.com/omniauth/omniauth/wiki/Auth-Hash-Schema#schema-10-and-later
      option(
        :attribute_statements,
        # First name/calling name or given name (in case first name/calling name is not found)
        first_name: ['urn:mpass.id:nickname', 'urn:oid:2.5.4.42'],
        last_name: ['urn:oid:2.5.4.4']
      )

      info do
        # Generate the full name to the info hash
        first_name = find_attribute_by(
          [
            'urn:mpass.id:nickname',
            'urn:oid:2.5.4.42'
          ]
        )
        last_name = find_attribute_by(['urn:oid:2.5.4.4'])
        display_name = "#{first_name} #{last_name}".strip
        display_name = nil if display_name.length.zero? # rubocop:disable Style/ZeroLengthPredicate

        found_attributes = [[:name, display_name]]

        provider = find_attribute_by(['urn:mpass.id:educationProviderInfo'])
        if provider
          provider_parts = provider.split(';')
          found_attributes << [:location, provider_parts[1]] if provider_parts[1]
        end

        # Default functionality from omniauth-saml
        found_attributes += options.attribute_statements.map do |key, values|
          attribute = find_attribute_by(values)
          [key.to_sym, attribute]
        end

        found_attributes.to_h
      end

      option(
        :security_settings,
        authn_requests_signed: true,
        digest_method: XMLSecurity::Document::SHA256,
        signature_method: XMLSecurity::Document::RSA_SHA256
      )

      # The attribute key maps to the SAML URIs so that we have more descriptive
      # attribute keys available for use. These will be mapped to the OmniAuth
      # `extra` information hash under the `:saml_attributes` key.
      option(
        :saml_attributes_map,
        given_name: ['urn:oid:2.5.4.42'],
        first_name: ['urn:mpass.id:nickname'],
        last_name: ['urn:oid:2.5.4.4'],
        provider_info: {
          name: ['urn:mpass.id:educationProviderInfo'],
          type: :multi
        },
        school_info: {
          name: ['urn:mpass.id:schoolInfo'],
          type: :multi
        },
        class_level: ['urn:mpass.id:classLevel'],
        learning_materials_charge: {
          name: ['urn:mpass.id:learningMaterialsCharge'],
          type: :multi
        },
        role: {
          name: ['urn:mpass.id:role'],
          type: :multi
        },
        learner_id: ['urn:oid:1.3.6.1.4.1.16161.1.1.27'],
        original_issuer: ['urn:mpass.id:originalIssuer']
      )

      # Defines the SAML attribute from which to determine the OmniAuth `uid`.
      # NOTE:
      # In case the user moves to another user registry, this will change.
      # However, there is no other unique identifier passed along the SAML
      # attributes that we could rely on, so this is the best bet.
      option :uid_attribute, 'urn:mpass.id:uid'

      # Add the SAML attributes to the extra hash for easier access.
      extra { {saml_attributes: saml_attributes} }

      attr_accessor :options
      attr_reader :mpassid_thread

      def initialize(app, *args, &block)
        super

        # Add the MPASSid options to the local options, most of which are
        # fetched from the metadata. The options array is the one that gets
        # priority in case it overrides some of the metadata or locally defined
        # option values.
        @mpassid_thread = Thread.new do
          @options = OmniAuth::Strategy::Options.new(
            mpassid_options.merge(options)
          )
          options[:security][:authn_requests_signed] = false unless options[:certificate] && options[:private_key]
        end
      end

      # Override the request phase to be able to pass the lang parameter to
      # the redirect URL. Note that this needs to be the last parameter to
      # be passed to the redirect URL.
      def request_phase
        mpassid_thread.join if mpassid_thread.alive?
        authn_request = OneLogin::RubySaml::Authrequest.new
        lang = lang_for_authn_request

        session['saml_redirect_url'] = request.params['redirect_url']

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

      def certificate
        File.read(options.certificate_file) if options.certificate_file
      end

      def private_key
        File.read(options.private_key_file) if options.private_key_file
      end

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

        # Local certificate and private key to decrypt the responses
        settings[:certificate] = certificate
        settings[:private_key] = private_key

        # Define the security settings as there are some defaults that need to be
        # modified
        security_defaults = OneLogin::RubySaml::Settings::DEFAULTS[:security]
        settings[:security] = security_defaults.merge(
          options.security_settings.to_h.transform_keys(&:to_sym)
        )

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
