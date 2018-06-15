module DigitaloceanSpacesApi
  module Actions # extend ActiveSupport::Concern

    require 'openssl'
    require 'digest'
    require 'base64'
    require 'net/http'

    def _parameters
      params
    end

    def mime_type
      _parameters[:mime_type] || ""
    end

    def content
      return "" if _parameters[:content].nil?
      return _parameters[:content] unless _parameters[:base64]

      Base64.decode64(_parameters[:content])
    end

    def path
      return "" if _parameters[:path].nil?
      URI.encode(_parameters[:path])
    end

    def host
      "#{bucket}.#{region}.digitaloceanspaces.com"
    end

    def bucket
      _parameters[:bucket]
    end

    def region
      _parameters[:region] || DigitaloceanSpacesApi.configuration.default_region
    end

    # constants

    def aws_key
      DigitaloceanSpacesApi.configuration.api_key
    end

    def aws_secret
      DigitaloceanSpacesApi.configuration.secret_key
    end

    def service_name
      "s3"
    end

    def uri
      URI.parse("https://#{host}/#{path}" )
    end

    def signed_put_headers
      "content-length;content-type;host;x-amz-content-sha256;x-amz-date"
    end

    def signed_get_headers
      "content-disposition;host;x-amz-content-sha256;x-amz-date"
    end


    # API METHODS
    #
    # http://www.nokogiri.org/tutorials/parsing_an_html_xml_document.html

    def render_object(disposition = "inline")
      http = Net::HTTP.new(uri.host, uri.port)
      http.use_ssl = true

      req = Net::HTTP::Get.new( uri.path, request_headers("GET", signed_get_headers) )
      response = http.request(req, content)

      send_data response.body, :type => response.content_type, :disposition => disposition #'inline'
    end

    def upload_object
      begin
        http = Net::HTTP.new(uri.host, uri.port)
        http.use_ssl = true

        req = Net::HTTP::Put.new( uri.path, request_headers("PUT", signed_put_headers) )
        http.request(req, content)
      rescue Exception => e
        return e
      end

      # Net::HTTPForbidden - signatures don't match
      # Net::HTTPOK - success
    end

    # AUTHORIZATION SIGNATURE

    def canonical_headers(header_keys, date)
      keys  = header_keys.split(";")
      h = {}
      h["content-disposition"] = "inline" if keys.include? 'content-disposition'
      h["content-length"] = "#{content.length.to_s}" if keys.include? 'content-length'
      h["content-type"] = "#{content_type}" if keys.include? 'content-type'
      h["host"] = "#{host}" if keys.include? 'host'
      h["x-amz-content-sha256"] = "#{Digest::SHA256.hexdigest(content)}" if keys.include? 'x-amz-content-sha256'
      h["x-amz-date"] = "#{date}" if keys.include? 'x-amz-date'
      h
    end

    def canonical_request(method, canonical)
      req = []
      req << method
      req << "/#{path}"
      req << ""
      req << canonical.map{|k,v| "#{k}:#{v}"}.join("\n") + "\n"
      req << canonical.map{|k,v| "#{k}"}.join(";")
      req << "#{Digest::SHA256.hexdigest(content)}"
      str = req.join("\n")

      # puts "******"
      # puts str
      # puts "******"

      Digest::SHA256.hexdigest(str)
    end

    def request_headers(method, header_keys)
      current_dt = DateTime.now
      policy_date = current_dt.utc.strftime("%Y%m%d")
      x_amz_date = current_dt.utc.strftime("%Y%m%dT%H%M%SZ")

      x_amz_algorithm = "AWS4-HMAC-SHA256"
      x_amz_credential = "#{aws_key}/#{policy_date}/#{region}/#{service_name}/aws4_request"

      ch = canonical_headers(header_keys, x_amz_date)

      sts = string_to_sign(x_amz_date, policy_date, region)
      sts = sts + canonical_request(method, ch)

      x_amz_signature = get_signature( policy_date, region, sts )

      ch['Authorization'] = "#{x_amz_algorithm} Credential=#{x_amz_credential}, SignedHeaders=#{header_keys}, Signature=#{x_amz_signature}"

      ch
    end

    def string_to_sign(date, date2, region)
      "AWS4-HMAC-SHA256\n" + date + "\n" + date2 + "/" + region + "/#{service_name}/aws4_request\n"
    end

    def get_signature_key( key, date_stamp, region_name, service_name )
      k_date = OpenSSL::HMAC.digest('sha256', "AWS4" + key, date_stamp)
      k_region = OpenSSL::HMAC.digest('sha256', k_date, region_name)
      k_service = OpenSSL::HMAC.digest('sha256', k_region, service_name)
      k_signing = OpenSSL::HMAC.digest('sha256', k_service, "aws4_request")
      k_signing
    end

    def get_signature( policy_date, s3_region, encoded_policy )
      signature_key = get_signature_key(aws_secret, policy_date , s3_region, service_name)
      OpenSSL::HMAC.hexdigest('sha256', signature_key, encoded_policy )
    end

  end
end
