# frozen_string_literal: true

lib = File.expand_path('lib', __dir__)
$LOAD_PATH.unshift(lib) unless $LOAD_PATH.include?(lib)
require 'omniauth-mpassid/version'

Gem::Specification.new do |spec|
  spec.name = 'omniauth-mpassid'
  spec.version = OmniAuth::MPASSid::VERSION
  spec.required_ruby_version = ">= 2.5"
  spec.authors = ['Antti Hukkanen']
  spec.email = ['antti.hukkanen@mainiotech.fi']

  spec.summary = 'Provides an MPASSid strategy for OmniAuth.'
  spec.description = 'MPASSid identification service integration for OmniAuth.'
  spec.homepage = 'https://github.com/mainio/omniauth-mpassid'
  spec.license = 'MIT'
  spec.metadata = {
    'rubygems_mfa_required' => 'true'
  }
  spec.required_ruby_version = '>= 2.6'

  spec.files = Dir[
    '{lib}/**/*',
    'LICENSE',
    'Rakefile',
    'README.md'
  ]

  spec.require_paths = ['lib']

  spec.add_dependency 'omniauth-saml', '~> 2.0'

  # Basic development dependencies
  spec.add_development_dependency 'rake', '~> 13.0'
  spec.add_development_dependency 'rspec', '~> 3.9'

  # Testing the requests
  spec.add_development_dependency 'rack-test', '~> 1.1.0'
  spec.add_development_dependency 'webmock', '~> 3.6', '>= 3.6.2'
  spec.add_development_dependency 'xmlenc', '~> 0.7.1'

  # Code coverage
  spec.add_development_dependency 'simplecov', '~> 0.19.0'
end
