require 'digitalocean_spaces_api/version'
require 'digitalocean_spaces_api/mixins/actions'

module DigitaloceanSpacesApi
  class << self
    attr_accessor :configuration
  end

  def self.configure
    self.configuration ||= Configuration.new
    yield(configuration)
  end

  class Configuration
    attr_accessor :api_key,
                  :secret_key,
                  :default_region

    def initialize
      @api_key = ''
      @secret_key = ''
      @default_region = 'nyc3'
    end
  end
end
