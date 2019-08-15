# OmniAuth MPASSid (SAML 2.0)

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
sub-sections. The keys marked as `(undocumented)` are not described in the
MPASSid's own documentation but are available at least in some SAML responses.

See also the MPASSid data models documentation for more information:

https://wiki.eduuni.fi/display/CSCMPASSID/Data+models

The attributes can be either single or multi type defining whether they can
have a single or multiple values. The single type values are strings and multi
type values are arrays of string when the value exists in the SAML response.
When the value was not returned from the identity provider's endpoint, the value
is `nil` for both types.

#### `:given_name`

- SAML URI: urn:oid:2.5.4.42
- SAML FriendlyName: givenName
- Type: Single (`String`)

The first/given name of the user.

#### `:first_names`

- SAML URI: http://eidas.europa.eu/attributes/naturalperson/CurrentGivenName
- SAML FriendlyName: firstName
- Type: Single (`String`)

All the first/given names of the user.

#### `:last_name`

- SAML URI: urn:oid:2.5.4.4
- SAML FriendlyName: sn
- Type: Single (`String`)

The last/family name of the user.

#### `:municipality_code`

- SAML URI: urn:mpass.id:municipalityCode
- SAML FriendlyName: municipalityCode
- Type: Multi (`Array`)

The municipality codes of the authenticated user.

See:

http://tilastokeskus.fi/meta/luokitukset/kunta/001-2017/index.html

#### `:municipality_name`

- SAML URI: one of the following (first found attribute)
  * urn:mpass.id:municipality
  * urn:educloudalliance.org:municipality
- SAML FriendlyName: one of the following (first found attribute)
  * N/A
  * ecaMunicipality
- Type: Multi (`Array`)

The human-readable names of the municipalities of the authenticated user.

#### `:school_code`

- SAML URI: urn:mpass.id:municipalityCode
- SAML FriendlyName: N/A
- Type: Multi (`Array`)

The school codes of the authenticated user.

See (JSON format):

For the list of codes, see:

- JSON format: https://virkailija.opintopolku.fi/koodisto-service/rest/json/oppilaitosnumero/koodi
- XML format: https://virkailija.opintopolku.fi/koodisto-service/rest/oppilaitosnumero/koodi

An example for a single school code (04647), JSON format:

https://virkailija.opintopolku.fi/koodisto-service/rest/codeelement/oppilaitosnumero_04647

#### `:school_name`

- SAML URI: urn:mpass.id:school
- SAML FriendlyName: school
- Type: Multi (`Array`)

The human-readable names of the schools of the authenticated user.

#### `:class`

- SAML URI: one of the following (first found attribute)
  * urn:mpass.id:class
  * urn:educloudalliance.org:group
- SAML FriendlyName: one of the following (first found attribute)
  * N/A
  * ecaGroup
- Type: Multi (`Array`)

The class/group-information of the authenticated user.

For instance: 8A or 3B.

#### `:class_level`

- SAML URI: urn:mpass.id:classLevel
- SAML FriendlyName: N/A
- Type: Multi (`Array`)

The class/level-information of the authenticated user.

For instance 8 or 3.

#### `:role`

- SAML URI: one of the following (first found attribute)
  * urn:mpass.id:role
  * urn:educloudalliance.org:structuredRole
- SAML FriendlyName: one of the following (first found attribute)
  * N/A
  * ecaStructuredRole
- Type: Multi (`Array`)

The roles of the user in four parts, divided with a semicolon (;) character.
First municipality, followed by school code, group and role in the group.

For instance Helsinki;32132;9A;Oppilas.

#### `:role_name` (undocumented)

- SAML URI: urn:educloudalliance.org:role
- SAML FriendlyName: ecaRole
- Type: Multi (`Array`)

NOTE: This attribute is undocumented by MPASSid.

The human readable names of the role (in Finnish).

For instance Oppilas.

#### `:funet_person_learner_id` (undocumented)

- SAML URI: urn:oid:1.3.6.1.4.1.16161.1.1.27
- SAML FriendlyName: N/A
- Type: Single (`String`)

NOTE: This attribute is undocumented by MPASSid.

11-digit identifier, which may be used to identify a person while storing,
managing or transferring personal data.

See:

https://wiki.eduuni.fi/display/CSCHAKA/funetEduPersonSchema2dot2#funetEduPersonSchema2dot2-funetEduPersonLearnerId

## License

MIT, see [LICENSE](LICENSE).
