# frozen_string_literal: true

require 'spec_helper'

RSpec::Matchers.define :fail_with do |message|
  match do |actual|
    actual.redirect? && actual.location == /\?.*message=#{message}/
  end
end

describe OmniAuth::Strategies::MPASSid, type: :strategy do
  include OmniAuth::Test::StrategyTestCase

  let(:auth_hash) { last_request.env['omniauth.auth'] }
  let(:saml_options) do
    {
      mode: mode,
      sp_entity_id: sp_entity_id,
      certificate_file: certificate_file,
      private_key_file: private_key_file
    }
  end
  let(:mode) { :test }
  let(:sp_entity_id) { 'https://www.service.fi/auth/mpassid/metadata' }
  let(:certificate_file) { support_filepath('sp_cert.crt') }
  let(:private_key_file) { support_filepath('sp_cert.key') }
  let(:strategy) { [OmniAuth::Strategies::MPASSid, saml_options] }

  before do
    # Stub the metadata to return the locally stored metadata for easier
    # testing. Otherwise an external HTTP request would be made when the
    # OmniAuth strategy is initialized.
    stub_request(
      :get,
      'https://mpass-proxy-test.csc.fi/idp/shibboleth'
    ).to_return(status: 200, body: File.new(
      support_filepath('idp_metadata.xml')
    ), headers: {})
  end

  describe '#initialize' do
    subject { get '/auth/mpassid/metadata' }

    it 'should apply the local options and the IdP metadata options' do
      is_expected.to be_successful

      instance = last_request.env['omniauth.strategy']

      # Check the locally set options
      expect(instance.options[:mode]).to eq(:test)
      expect(instance.options[:sp_entity_id]).to eq(
        'https://www.service.fi/auth/mpassid/metadata'
      )
      expect(instance.options[:security]).to include(
        'authn_requests_signed' => true,
        'logout_requests_signed' => false,
        'logout_responses_signed' => false,
        'want_assertions_signed' => false,
        'want_assertions_encrypted' => false,
        'want_name_id' => false,
        'metadata_signed' => false,
        'embed_sign' => false,
        'digest_method' => XMLSecurity::Document::SHA256,
        'signature_method' => XMLSecurity::Document::RSA_SHA256,
        'check_idp_cert_expiration' => false,
        'check_sp_cert_expiration' => false
      )

      # Check the automatically set options
      expect(instance.options[:assertion_consumer_service_url]).to eq(
        'https://www.service.fi/auth/mpassid/callback'
      )

      # Check the most important metadata options
      expect(instance.options[:idp_entity_id]).to eq(
        'https://mpass-proxy-test.csc.fi/idp/shibboleth'
      )
      expect(instance.options[:idp_sso_service_url]).to eq(
        'https://mpass-proxy-test.csc.fi/idp/profile/SAML2/Redirect/SSO'
      )

      idp_cert = <<~CERT
        MIIDRzCCAi+gAwIBAgIUEa1rZub7zJkDkHibduG/qW9jg00wDQYJKoZIhvcNAQEL
        BQAwIjEgMB4GA1UEAwwXbXBhc3MtcHJveHktdGVzdC5jc2MuZmkwHhcNMTUwOTEw
        MDczODAyWhcNMzUwOTEwMDczODAyWjAiMSAwHgYDVQQDDBdtcGFzcy1wcm94eS10
        ZXN0LmNzYy5maTCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAJ+HX7We
        a6NuO2/WlrT9pkEu4aJww6+VjCXS8DPflHSx2i203sa9jYJEc5FwsgpTBm7ph6bw
        bye6HBjm4NOS4rlYQPbqsz0c+czS2a+lf0Nwqajp0okEEwJP58LJB1T3B3ODHQyM
        bpV3p8TE5pLNHGwWTzEDMPWdo1xrx/ESECqlcAQYz8CozkHuPds5rPEuSvsM1MGo
        n4WCCr+Rwb0JkSGvqN2u5PVkxXECrFZ5uRgCBWlP7zNzRSEZVil8oGa3GMEJASUZ
        7Mi+zgcmGgXWMoHMntidgruPTenEpuDAlYWwF5hlBdq6mZsbZRe7+KFX95Lhtgeq
        UgrNkTewYv8eGXkCAwEAAaN1MHMwHQYDVR0OBBYEFCkRzhGNwRh2oh6JhMlvv0Fu
        89cCMFIGA1UdEQRLMEmCF21wYXNzLXByb3h5LXRlc3QuY3NjLmZphi5odHRwczov
        L21wYXNzLXByb3h5LXRlc3QuY3NjLmZpL2lkcC9zaGliYm9sZXRoMA0GCSqGSIb3
        DQEBCwUAA4IBAQAiJ8O6nxnFqqEb4nhYHh8rfjI+8SDxZQX3ZIkijCT/szr+Cbuk
        fmL6i32gsbt3mIIr/Szwq8kdAdRFpO3PWfLNnFvaLG7K6PBHdGHTQGmvBbK790Mn
        SEVeEfQ/hg3W1Wjepq7X+qdDjweuxA3zHYpTqcAPtjCMNkbxERPBhtNgKIylMdAA
        2mRSmYNhiPozszxwHW7HyxuH6o8USM509NQryfAy9MH2oNZZ/IvEjGcVjq2wdfWq
        k1a+3ri+IQ1B/88PDE5hmMtlZf2/OMhppas4+iPERqZWjmNfA60bmmQXtJhcPIQe
        ZWp3lK/V4V8CrYmdEvURbyHhfURHavuR50t5
      CERT

      prefix = "\n"
      suffix = '                    '
      expect(instance.options[:idp_cert]).to eq("#{prefix}#{idp_cert}#{suffix}")
    end

    context 'with production mode' do
      let(:mode) { :production }

      it 'should hit the production metadata URL' do
        # Note that this needs to return an actual metadata XML because
        # otherwise the strategy initialization will fail. We'll just return
        # the testing metadata since we are only testing that it hits the
        # correct endpoint.
        stub_metadata = stub_request(
          :get,
          'https://mpass-proxy.csc.fi/idp/shibboleth'
        ).to_return(status: 200, body: File.new(
          support_filepath('idp_metadata.xml')
        ), headers: {})

        is_expected.to be_successful
        assert_requested(stub_metadata)
      end
    end
  end

  describe 'GET /auth/mpassid' do
    subject { get '/auth/mpassid' }

    it 'should sign the request' do
      is_expected.to be_redirect

      location = URI.parse(last_response.location)
      query = Rack::Utils.parse_query location.query
      expect(query).to have_key('SAMLRequest')
      expect(query).to have_key('Signature')
      expect(query).to have_key('SigAlg')
    end

    it 'should create a valid SAML authn request signature' do
      is_expected.to be_redirect

      location = URI.parse(last_response.location)
      query = Rack::Utils.parse_query location.query

      algorithm = query['SigAlg']
      expect(algorithm).to eq('http://www.w3.org/2001/04/xmldsig-more#rsa-sha256')

      url_string = OneLogin::RubySaml::Utils.build_query(
        type: 'SAMLRequest',
        data: query['SAMLRequest'],
        sig_alg: algorithm
      )
      sign_algorithm = XMLSecurity::BaseDocument.new.algorithm(algorithm)
      private_key = OneLogin::RubySaml::Utils.format_private_key(File.read(private_key_file))
      signature = OpenSSL::PKey::RSA.new(private_key).sign(sign_algorithm.new, url_string)
      expect(Base64.decode64(query['Signature'])).to eq(signature)
    end

    it 'should create a valid SAML authn request' do
      is_expected.to be_redirect

      location = URI.parse(last_response.location)
      expect(location.scheme).to eq('https')
      expect(location.host).to eq('mpass-proxy-test.csc.fi')
      expect(location.path).to eq('/idp/profile/SAML2/Redirect/SSO')

      query = Rack::Utils.parse_query location.query

      xml = OmniAuth::MPASSid::Test::Utility.inflate_xml(query['SAMLRequest'])
      request = REXML::Document.new(xml)
      expect(request.root).not_to be_nil

      acs = request.root.attributes['AssertionConsumerServiceURL']
      dest = request.root.attributes['Destination']
      ii = request.root.attributes['IssueInstant']

      expect(acs).to eq('https://www.service.fi/auth/mpassid/callback')
      expect(dest).to eq('https://mpass-proxy-test.csc.fi/idp/profile/SAML2/Redirect/SSO')
      expect(ii).to match(/[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z/)

      issuer = request.root.elements['saml:Issuer']
      expect(issuer.text).to eq('https://www.service.fi/auth/mpassid/metadata')
    end

    context 'without certificate' do
      let(:certificate_file) { nil }
      let(:private_key_file) { nil }

      it 'should not sign the request' do
        is_expected.to be_redirect

        location = URI.parse(last_response.location)
        query = Rack::Utils.parse_query location.query
        expect(query).to have_key('SAMLRequest')
        expect(query).not_to have_key('Signature')
        expect(query).not_to have_key('SigAlg')
      end
    end

    context 'with extra parameters' do
      subject { get '/auth/mpassid?extra=param' }

      it 'should not add any extra parameters to the redirect assertion consumer service URL' do
        is_expected.to be_redirect

        location = URI.parse(last_response.location)
        query = Rack::Utils.parse_query location.query

        xml = OmniAuth::MPASSid::Test::Utility.inflate_xml(query['SAMLRequest'])
        request = REXML::Document.new(xml)
        acs = request.root.attributes['AssertionConsumerServiceURL']

        expect(acs).to eq('https://www.service.fi/auth/mpassid/callback')
      end
    end

    context 'with lang parameter' do
      shared_examples '' do
        specify { expect(true).to eq true }
      end

      shared_examples 'lang added' do |request_locale, expected_locale|
        subject { get "/auth/mpassid?lang=#{request_locale}" }

        it do
          is_expected.to be_redirect

          location = URI.parse(last_response.location)
          expect(location.query).to match(/&lang=#{expected_locale}$/)
        end
      end

      context 'when set to fi' do
        it_behaves_like 'lang added', 'fi', 'fi'
      end

      context 'when set to fi-FI' do
        it_behaves_like 'lang added', 'fi-FI', 'fi'
      end

      context 'when set to sv' do
        it_behaves_like 'lang added', 'sv', 'sv'
      end

      context 'when set to sv_SE' do
        it_behaves_like 'lang added', 'sv_SE', 'sv'
      end

      context 'when set to en_GB' do
        it_behaves_like 'lang added', 'en_GB', 'fi'
      end

      context 'when set to et' do
        it_behaves_like 'lang added', 'et', 'fi'
      end

      context 'when set to de-DE' do
        it_behaves_like 'lang added', 'de-DE', 'fi'
      end

      context 'when set to nb_NO' do
        it_behaves_like 'lang added', 'nb_NO', 'fi'
      end
    end
  end

  describe 'POST /auth/mpassid/callback' do
    subject { last_response }

    let(:xml) { :authn_response_unsigned }

    context 'when the response is valid' do
      let(:saml_options) do
        {
          mode: mode,
          sp_entity_id: sp_entity_id,
          idp_cert: sign_certificate.to_pem,
          idp_cert_multi: {
            signing: [sign_certificate.to_pem]
          }
        }
      end

      let(:custom_saml_attributes) { [] }

      # Use local certificate and private key for signing because otherwise the
      # locally signed SAMLResponse's signature cannot be properly validated as
      # we cannot sign it using the actual environments private key which is
      # unknown.
      let(:sign_certgen) { OmniAuth::MPASSid::Test::CertificateGenerator.new }
      let(:sign_certificate) { sign_certgen.certificate }
      let(:sign_private_key) { sign_certgen.private_key }

      before :each do
        allow(Time).to receive(:now).and_return(
          Time.utc(2022, 1, 9, 10, 49, 0)
        )

        raw_xml_file = support_filepath("#{xml}.xml")
        xml_signed = begin
          if custom_saml_attributes.empty?
            OmniAuth::MPASSid::Test::Utility.signed_xml(
              raw_xml_file,
              sign_certificate: sign_certificate,
              sign_private_key: sign_private_key
            )
          else
            xml_io = IO.read(raw_xml_file)
            doc = Nokogiri::XML::Document.parse(xml_io)
            statements_node = doc.root.at_xpath(
              '//saml2:Assertion//saml2:AttributeStatement',
              saml2: 'urn:oasis:names:tc:SAML:2.0:assertion'
            )
            custom_saml_attributes.each do |attr|
              attr_def = described_class.default_options[:possible_request_attributes].find do |ra|
                ra[:friendly_name] == attr[:friendly_name]
              end
              next unless attr_def

              attr_node = statements_node.at_xpath(
                "saml2:Attribute[@Name='#{attr_def[:name]}']",
                saml2: 'urn:oasis:names:tc:SAML:2.0:assertion'
              )
              if attr_node.nil?
                attr_node = Nokogiri::XML::Node.new('saml2:Attribute', doc)
                attr_node['FriendlyName'] = attr_def[:friendly_name]
                attr_node['Name'] = attr_def[:name]
                attr_node['NameFormat'] = attr_def[:name_format]

                statements_node.add_child(attr_node)
              else
                attr_node.children.remove
              end

              if attr[:value].nil?
                attr_node.remove
              else
                attr_node.add_child(
                  "<saml2:AttributeValue>#{attr[:value]}</saml2:AttributeValue>"
                )
              end
            end

            OmniAuth::MPASSid::Test::Utility.signed_xml_from_string(
              doc.to_s,
              sign_certificate: sign_certificate,
              sign_private_key: sign_private_key
            )
          end
        end

        saml_response = Base64.encode64(xml_signed)

        post(
          '/auth/mpassid/callback',
          'SAMLResponse' => saml_response
        )
      end

      it 'should set the info hash correctly' do
        expect(auth_hash['info'].to_hash).to eq(
          'first_name' => 'Testi1',
          'last_name' => 'Oppilas1',
          'location' => 'Demolan koulut Oy',
          'name' => 'Testi1 Oppilas1'
        )
      end

      it 'should set the raw info to all attributes' do
        expect(auth_hash['extra']['raw_info'].all.to_hash).to eq(
          'urn:mpass.id:educationProvider' => ['Demolan koulut Oy'],
          'urn:mpass.id:educationProviderId' => ['1.2.246.562.10.12345678907'],
          'urn:mpass.id:educationProviderInfo' => ['1.2.246.562.10.12345678907;Demolan koulut Oy'],
          'urn:mpass.id:uid' => ['MPASSOID.c6329e82913e265b3a79c11a043fdab8b06b1a9e'],
          'urn:mpass.id:role' => ['1.2.246.562.10.12345678907;99900;7B;Oppilas'],
          'urn:mpass.id:role_v1.1' => ['Demola;99900;7B;Oppilas'],
          'urn:mpass.id:school' => ['Demolan koulu'],
          'urn:mpass.id:schoolCode' => ['99900'],
          'urn:mpass.id:schoolInfo' => ['99900;Demolan koulu'],
          'urn:mpass.id:class' => ['7B'],
          'urn:mpass.id:classLevel' => ['7'],
          'urn:oid:1.3.6.1.4.1.16161.1.1.27' => ['1.2.246.562.24.10000000016'],
          'urn:oid:2.5.4.4' => ['Oppilas1'],
          'urn:oid:2.5.4.42' => ['Testi1'],
          'fingerprint' => '1B:0A:82:7D:3D:76:7B:49:66:06:52:03:0A:10:69:A6:9B:07:48:A8'
        )
      end

      it 'should set the saml attributes to the extra hash' do
        expect(auth_hash['extra']['saml_attributes'].to_hash).to eq(
          'funet_person_learner_id' => '1.2.246.562.24.10000000016',
          'given_name' => 'Testi1',
          'first_names' => 'Testi1',
          'last_name' => 'Oppilas1',
          'school_code' => ['99900'],
          'school_name' => ['Demolan koulu'],
          'class' => ['7B'],
          'class_level' => ['7'],
          'provider_id' => ['1.2.246.562.10.12345678907'],
          'provider_name' => ['Demolan koulut Oy'],
          'role' => ['1.2.246.562.10.12345678907;99900;7B;Oppilas'],
          'role_name' => nil
        )
      end

      it 'should set the response_object to the response object from ruby_saml response' do
        expect(auth_hash['extra']['response_object']).to be_kind_of(OneLogin::RubySaml::Response)
      end

      describe '#response_object' do
        subject { instance.response_object }

        let(:instance) { last_request.env['omniauth.strategy'] }

        it 'should return the response object' do
          is_expected.to be_a(OneLogin::RubySaml::Response)
          is_expected.to be_is_valid
        end
      end

      it 'should set the uid from the correct SAML attribute' do
        expect(auth_hash['uid']).to eq('MPASSOID.c6329e82913e265b3a79c11a043fdab8b06b1a9e')
      end
    end
  end

  describe 'GET /auth/mpassid/metadata' do
    subject { get '/auth/mpassid/metadata' }

    let(:response_xml) { Nokogiri::XML(last_response.body) }
    let(:request_attribute_nodes) do
      response_xml.xpath('//md:EntityDescriptor//md:SPSSODescriptor//md:AttributeConsumingService//md:RequestedAttribute')
    end
    let(:request_attributes) do
      request_attribute_nodes.map do |node|
        {
          friendly_name: node['FriendlyName'],
          name: node['Name']
        }
      end
    end

    before do
      is_expected.to be_successful
    end

    it 'should add the correct request attributes' do
      expect(request_attributes).to match_array(
        [
          {friendly_name: 'mpassUsername', name: 'urn:mpass.id:uid'},
          {friendly_name: 'learnerId', name: 'urn:oid:1.3.6.1.4.1.16161.1.1.27'},
          {friendly_name: 'givenName', name: 'urn:oid:2.5.4.42'},
          {friendly_name: 'firstName', name: 'http://eidas.europa.eu/attributes/naturalperson/CurrentGivenName'},
          {friendly_name: 'sn', name: 'urn:oid:2.5.4.4'},
          {friendly_name: 'mpassSchoolCode', name: 'urn:mpass.id:schoolCode'},
          {friendly_name: 'school', name: 'urn:mpass.id:school'},
          {friendly_name: 'mpassSchoolInfo', name: 'urn:mpass.id:schoolInfo'},
          {friendly_name: 'mpassClass', name: 'urn:mpass.id:class'},
          {friendly_name: 'ecaGroup', name: 'urn:educloudalliance.org:group'},
          {friendly_name: 'mpassClassLevel', name: 'urn:mpass.id:classLevel'},
          {friendly_name: 'ecaRole', name: 'urn:educloudalliance.org:role'},
          {friendly_name: 'mpassRole', name: 'urn:mpass.id:role'},
          {friendly_name: 'mpassEducationProviderOid', name: 'urn:mpass.id:educationProviderId'},
          {friendly_name: 'mpassEducationProviderName', name: 'urn:mpass.id:educationProvider'},
          {friendly_name: 'mpassEducationProviderInfo', name: 'urn:mpass.id:educationProviderInfo'}
        ]
      )
    end
  end
end
