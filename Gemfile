# frozen_string_literal: true

source 'https://rubygems.org'

group :development do
  gem 'rubocop'
end

group :test do
  gem 'simplecov-cobertura'
end

group :development, :test do
  # Basic development dependencies
  gem 'rake', '~> 13.1'
  gem 'rspec', '~> 3.13'

  # Testing the requests
  gem 'rack-test', '~> 2.1.0'
  gem 'webmock', '~> 3.20'
  gem 'xmlenc', '~> 0.8.0'

  # Code coverage
  gem 'simplecov', '~> 0.22.0'
end

# CVE-2019-5477
gem 'nokogiri', '>= 1.10.4'

gemspec
