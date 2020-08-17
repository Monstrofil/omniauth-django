require 'omniauth-oauth2'

module OmniAuth
  module Strategies
    class Django < OmniAuth::Strategies::OAuth2
      option :client_options, {
        :site => 'https://api.parkingdp.online/openid/',
        :authorize_url => 'https://api.parkingdp.online/openid/authorize/',
        :token_url => 'https://api.parkingdp.online/openid/token/'
      }

      def request_phase
        super
      end

      def authorize_params
        super.tap do |params|
          %w[scope client_options].each do |v|
            if request.params[v]
              params[v.to_sym] = request.params[v]
            end
          end
        end
      end

      uid { raw_info['nickname'] }

      info do
        {
          'name' => raw_info['nickname'],
          'email' => raw_info['email'],
        }
      end

      extra do
        {}
      end

      def raw_info
        access_token.options[:mode] = :header
        p access_token.get('userinfo').parsed
        @raw_info ||= access_token.get('userinfo').parsed
      end

      def callback_url
        full_host + script_name + callback_path
      end
    end
  end
end

OmniAuth.config.add_camelization 'django', 'Django'