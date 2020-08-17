# -*- encoding: utf-8 -*-
require File.expand_path('../lib/omniauth-django/version', __FILE__)

Gem::Specification.new do |gem|
  gem.authors       = ["Oleksandr Shyshatskyi"]
  gem.email         = ["shalal545@gmail.com"]
  gem.description   = %q{Official OmniAuth strategy for django.}
  gem.summary       = %q{Official OmniAuth strategy for django.}
  gem.homepage      = "https://github.com/Monstrofil/omniauth-django"
  gem.license       = "MIT"

  gem.executables   = `git ls-files -- bin/*`.split("\n").map{ |f| File.basename(f) }
  gem.files         = `git ls-files`.split("\n")
  gem.test_files    = `git ls-files -- {test,spec,features}/*`.split("\n")
  gem.name          = "omniauth-django"
  gem.require_paths = ["lib"]
  gem.version       = OmniAuth::Django::VERSION

  gem.add_dependency 'omniauth', '~> 1.5'
  gem.add_dependency 'omniauth-oauth2', '>= 1.4.0', '< 2.0'
  gem.add_development_dependency 'rspec', '~> 3.5'
  gem.add_development_dependency 'rack-test'
  gem.add_development_dependency 'simplecov'
  gem.add_development_dependency 'webmock'
end
