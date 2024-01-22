# OmniAuth MPASSid (SAML 2.0)

[![Build Status](https://github.com/mainio/omniauth-mpassid/actions/workflows/ci_omniauth_mpassid.yml/badge.svg)](https://github.com/mainio/omniauth-mpassid/actions)
[![codecov](https://codecov.io/gh/mainio/omniauth-mpassid/branch/master/graph/badge.svg)](https://codecov.io/gh/mainio/omniauth-mpassid)

This is an unofficial OmniAuth strategy for authenticating with the MPASSid
identification service used by comprehensive schools and secondary education
facilities in Finland. This gem is mostly a configuration wrapper around
[`omniauth-saml`](https://github.com/omniauth/omniauth-saml) which uses
[`ruby-saml`](https://github.com/onelogin/ruby-saml) for SAML 2.0 based
authentication implementation with identity providers, such as MPASSid.

The gem can be used to hook Ruby/Rails applications to the MPASSid
identification service. It does not provide any strong authorization features
out of the box, as it does not know anything about the application users, but
those can be implemented using this gem and the data provided by the MPASSid
identification responses.

The gem has been developed by [Mainio Tech](https://www.mainiotech.fi/).

The development has been sponsored by the
[City of Helsinki](https://www.hel.fi/).

The MPASSid service is owned by the Ministry of the Education and Culture in
Finland and operated by CSC - Tieteen tietotekniikan keskus Oy. Neither of these
parties are related to this gem in any way, nor do they provide technical
support for it. Please contact the gem maintainers in case you find any issues
with it.

## Preparation

In order to start using the MPASSid authentication endpoints, you will need to
send a join request to the MPASSid operator for them to configure the identity
provider server for your service. Please refer to the MPASSid documentation on
how to join the service:

https://wiki.eduuni.fi/display/CSCMPASSID/Testipalveluun+liittyminen

Follow the instructions for the SAML2 protocol.

The details that you need to send to MPASSid are similar to the following
information (apply to your service's domain) for non-Rails+Devise applications:

- SAML2 entity ID: https://www.service.fi/auth/mpassid/metadata
- Callback URL (ACS): https://www.service.fi/auth/mpassid/callback

### Rails and Devise

When applying this gem to Rails and Devise, the URLs can also include a path
prefix to separate the scope of the authentication requests. For example, if
you are using a `:user` scope with Devise, the URLs would look like following:

- SAML2 entity ID: https://www.service.fi/users/auth/mpassid/metadata
- Callback URL (ACS): https://www.service.fi/users/auth/mpassid/callback

## Installation and Configuration

This gem has been only tested and used with Rails applications using Devise, so
this installation guide only covers that part. In case you are interested to
learn how you can use this with other frameworks, please refer to the
[`omniauth-saml`](https://github.com/omniauth/omniauth-saml) documentation and
apply it to your needs (changing the strategy name to `:mpassid` and strategy
class to `OmniAuth::Strategies::MPASSid`).

To install this gem, add the following to your Gemfile:

```ruby
gem 'omniauth-mpassid'
```

For configuring the strategy for Devise, add the following in your
`config/initializers/devise.rb` file:

```ruby
Devise.setup do |config|
  config.omniauth :mpassid,
    # The mode needs to be either :production or :test depending on which
    # MPASSid enviroment you want to hook into. Please note that you will need
    # to complete the preparation phases even for the test environment.
    mode: :test, # :production (default, can be omitted) or :test
    # The service provider entity ID that needs to match the ID you have sent to
    # the MPASSid operator with your joining request.
    sp_entity_id: 'https://www.service.fi/auth/mpassid/metadata'
end
```

## Testing

Once the gem is installed and configured properly, it can be tested with the
test accounts available at:

https://wiki.eduuni.fi/display/OPHPALV/Test+accounts+available+for+testing

## Identification Responses

The user's data is transmitted from MPASSid in the SAML authentication
response. This data will be available in the OmniAuth
[extra hash](https://github.com/omniauth/omniauth/wiki/Auth-Hash-Schema#schema-10-and-later).

In order to access the response data, you can fetch the OmniAuth extra has and
the corresponding user data in the OmniAuth callback handler, e.g. in Rails
Devise controllers as follows:

```ruby
def saml_attributes
  raw_hash = request.env["omniauth.auth"]
  extra_hash = raw_hash[:extra]

  extra_hash[:saml_attributes]
end
```

### Personal Information Transmitted From MPASSid

The user's personal information transmitted from MPASSid can be found under
the `:saml_attributes` key in the OmniAuth extra hash described above.

This attributes hash will contain the keys described in this following
sub-sections.

See also the MPASSid data models documentation for more information:

https://wiki.eduuni.fi/display/OPHPALV/MPASSid%3An+tietomalli

The attributes can be either single or multi type defining whether they can
have a single or multiple values. The single type values are strings and multi
type values are arrays of string when the value exists in the SAML response.
When the value was not returned from the identity provider's endpoint, the value
is `nil` for both types.

#### `:given_name`

- SAML URI: urn:oid:2.5.4.42
- SAML FriendlyName: givenName
- Type: Single (`String`)

The given name of the user.

#### `:first_name`

- SAML URI: urn:mpass.id:nickname
- SAML FriendlyName: nickname
- Type: Single (`String`)

The first name / calling name / nickname of the user.

#### `:last_name`

- SAML URI: urn:oid:2.5.4.4
- SAML FriendlyName: sn
- Type: Single (`String`)

The last/family name of the user.

#### `:provider_info`

- SAML URI: urn:mpass.id:educationProviderInfo
- SAML FriendlyName: mpassEducationProviderInfo
- Type: Multi (`Array<String>`)

Information about the educational provider, each value contains multiple fields
separated with a semicolon (`;`) character.

For instance `1.2.246.562.10.494695390410;Virallinen nimi`.

The description of the fields:

1. The educational provider's OID as specified at the link below (`KOULUTUSTOIMIJA`)
2. The educational provider's name as specified at the link below

The OIDs and information for these OIDs can be found from:

https://virkailija.opintopolku.fi/organisaatio-service/swagger-ui/index.html

#### `:school_info`

- SAML URI: urn:mpass.id:schoolInfo
- SAML FriendlyName: mpassSchoolInfo
- Type: Multi (`Array<String>`)

Information about the school, each value contains multiple fields separated with
a semicolon (`;`) character.

The values are provided in both of the following formats as separate values:

- `30076;Mansikkalan testi peruskoulu`
- `1.2.246.562.99.00000000002;Mansikkalan testi peruskoulu`

##### First format

The first value format specifies the national educational institution code as
the first column separated with a semicolon (`;`) as specified at the national
educational institution registry.

For the list of codes, see:

- JSON format: https://virkailija.opintopolku.fi/koodisto-service/rest/json/oppilaitosnumero/koodi
- XML format: https://virkailija.opintopolku.fi/koodisto-service/rest/oppilaitosnumero/koodi

An example for a single school code (04647), JSON format:

https://virkailija.opintopolku.fi/koodisto-service/rest/codeelement/oppilaitosnumero_04647

##### Second format

The second value format specifies the OID of the educational institution as
the first column separated with a semicolon (`;`). These values are specified
at (filter with `OPPILAITOS`):

https://virkailija.opintopolku.fi/organisaatio-service/swagger-ui/index.html

#### `:class_level`

- SAML URI: urn:mpass.id:classLevel
- SAML FriendlyName: N/A
- Type: Single (`String`)

The class level information (0-10) of the authenticated user.

For instance 8 or 3.

For further information, see:

https://www.stat.fi/meta/kas/vuosiluokka.html

This information is available for pre-primary education and comprehensive
education students.

This information is not available for secondary level students (upper secondary
education or vocational education).

#### `:learning_materials_charge`

- SAML URI: urn:mpass.id:classLevel
- SAML FriendlyName: N/A
- Type: Multi (`Array<String>`)

Specifies for secondary level education pupils whether their learning materials
are paid or not, each value contains multiple fields separated with a semicolon
(`;`) character.

The values are provided in both of the following formats as separate values:

- `0;00000`
- `0;1.2.246.562.99.00000000003`

Similarly to the `:school_info` field, the values are provided with the national
educational institution code as well as the educational institution's OID.

The first column specifies the value for the field which is explained as
follows:

- `0` = Learning material is free for the pupil
- `1` = Learning material is paid for the pupil

#### `:role`

- SAML URI: one of the following (first found attribute)
  * urn:mpass.id:role
  * urn:educloudalliance.org:structuredRole
- SAML FriendlyName: one of the following (first found attribute)
  * N/A
  * ecaStructuredRole
- Type: Multi (`Array<String>`)

The roles of the user in four parts, divided with a semicolon (;) character.
First municipality, followed by school code, group and role in the group.

For instance `1.2.246.562.99.00000000001;00000;1A;Oppilas;1;1.2.246.562.99.00000000003;`.

Each value consists of the following fields:

1. Educational provider OID (e.g. `1.2.246.562.99.00000000001`)
2. National educational institution code (e.g. `00000`)
3. Class or group information of the pupil (e.g. `1A`)
4. Role of the user (e.g. `Oppilas`)
5. Role code of the user (e.g. `1`)
6. Educational institution OID (e.g. `1.2.246.562.99.00000000003`)
7. The office / branch OID (similar format as other OIDs, can be also empty)

The OIDs for the educational provider (`KOULUTUSTOIMIJA`), educational
institution (`OPPILAITOS`) and office / branch (`TOIMIPISTE`) can be found from:

https://virkailija.opintopolku.fi/organisaatio-service/swagger-ui/index.html

#### `:learner_id`

- SAML URI: urn:oid:1.3.6.1.4.1.16161.1.1.27
- SAML FriendlyName: learnerId
- Type: Single (`String`)

11-digit identifier, which may be used to identify a person while storing,
managing or transferring personal data.

See:

https://wiki.eduuni.fi/display/CSCHAKA/funetEduPersonSchema2dot2#funetEduPersonSchema2dot2-funetEduPersonLearnerId

#### `:original_issuer`

Information about the user's home organization that is relying the information
to MPASSid. This information is added by the Finnish National Agency for
Education.

For instance `1.2.246.562.99.00000000001`.

## License

MIT, see [LICENSE](LICENSE).
