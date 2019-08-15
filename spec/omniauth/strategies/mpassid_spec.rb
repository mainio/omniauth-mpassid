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
      sp_entity_id: sp_entity_id
    }
  end
  let(:mode) { :test }
  let(:sp_entity_id) { 'https://www.service.fi/auth/mpassid/metadata' }
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
        'authn_requests_signed' => false,
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
      expect(instance.options[:idp_sso_target_url]).to eq(
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

    it 'should not sign the request' do
      is_expected.to be_redirect

      location = URI.parse(last_response.location)
      query = Rack::Utils.parse_query location.query
      expect(query).to have_key('SAMLRequest')
      expect(query).not_to have_key('Signature')
      expect(query).not_to have_key('SigAlg')
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
          Time.utc(2019, 8, 14, 22, 35, 0)
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
          'first_name' => 'Pekka-Testi',
          'last_name' => 'Virtanen',
          'location' => 'Demojärvi',
          'name' => 'Pekka-Testi Virtanen'
        )
      end

      it 'should set the raw info to all attributes' do
        expect(auth_hash['extra']['raw_info'].all.to_hash).to eq(
          'urn:educloudalliance.org:OID' => ['MPASSOID.53b1af17cb284998638b5'],
          'urn:mpass.id:role' => ['Demojärvi;00000;9A;Oppilas'],
          'urn:oid:2.5.4.4' => ['Virtanen'],
          'urn:mpass.id:schoolCode' => ['00000'],
          'urn:educloudalliance.org:legacyCryptId' => ['f0ba7691aeff3ef2302d6edce5303641'],
          'urn:mpass.id:class' => ['9A'],
          'urn:mpass.id:legacyCryptId' => ['f0ba7691aeff3ef2302d6edce5303641@ldap_test'],
          'urn:mpass.id:legacyCryptIde' => ['d0ce1363bd6fd86f4de9311d7e1026ac125b8f9ce918fa38f1cb6dad80ea4bc5@ldap_test'],
          'urn:oid:1.3.6.1.4.1.16161.1.1.27' => ['1.2.246.562.24.90000000001'],
          'urn:educloudalliance.org:municipality' => ['Demojärvi'],
          'urn:educloudalliance.org:group' => ['9A'],
          'urn:mpass.id:municipalityCode' => ['1'],
          'urn:educloudalliance.org:role' => ['Oppilas'],
          'urn:mpass.id:uid' => ['MPASSOID.53b1af17cb284998638b5'],
          'urn:educloudalliance.org:structuredRole' => ['Demojärvi;;9A;Oppilas'],
          'urn:oid:2.5.4.42' => ['Pekka-Testi'],
          'urn:mpass.id:municipality' => ['Demojärvi'],
          'fingerprint' => '1B:0A:82:7D:3D:76:7B:49:66:06:52:03:0A:10:69:A6:9B:07:48:A8'
        )
      end

      it 'should set the saml attributes to the extra hash' do
        expect(auth_hash['extra']['saml_attributes'].to_hash).to eq(
          'given_name' => 'Pekka-Testi',
          'first_names' => nil,
          'last_name' => 'Virtanen',
          'municipality_code' => ['1'],
          'municipality_name' => ['Demojärvi'],
          'school_code' => ['00000'],
          'school_name' => nil,
          'class' => ['9A'],
          'class_level' => nil,
          'role' => ['Demojärvi;00000;9A;Oppilas'],
          'role_name' => ['Oppilas'],
          'funet_person_learner_id' => '1.2.246.562.24.90000000001'
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
        expect(auth_hash['uid']).to eq('MPASSOID.53b1af17cb284998638b5')
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
          {friendly_name: nil, name: 'urn:mpass.id:uid'},
          {friendly_name: nil, name: 'urn:oid:1.3.6.1.4.1.16161.1.1.27'},
          {friendly_name: 'givenName', name: 'urn:oid:2.5.4.42'},
          {friendly_name: 'firstName', name: 'http://eidas.europa.eu/attributes/naturalperson/CurrentGivenName'},
          {friendly_name: 'sn', name: 'urn:oid:2.5.4.4'},
          {friendly_name: 'municipalityCode', name: 'urn:mpass.id:municipalityCode'},
          {friendly_name: nil, name: 'urn:mpass.id:municipality'},
          {friendly_name: 'ecaMunicipality', name: 'urn:educloudalliance.org:municipality'},
          {friendly_name: nil, name: 'urn:mpass.id:schoolCode'},
          {friendly_name: 'school', name: 'urn:mpass.id:school'},
          {friendly_name: nil, name: 'urn:mpass.id:class'},
          {friendly_name: 'ecaGroup', name: 'urn:educloudalliance.org:group'},
          {friendly_name: nil, name: 'urn:mpass.id:classLevel'},
          {friendly_name: 'ecaRole', name: 'urn:educloudalliance.org:role'},
          {friendly_name: nil, name: 'urn:mpass.id:role'},
          {friendly_name: 'ecaStructuredRole', name: 'urn:educloudalliance.org:structuredRole'}
        ]
      )
    end
  end
end
