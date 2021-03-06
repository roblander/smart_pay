require_relative 'hmac_calculator'

module SmartPay
  class Request
    
    TEST_URL = "https://test.barclaycardsmartpay.com/hpp/pay.shtml"
    LIVE_URL = "https://live.barclaycardsmartpay.com/hpp/pay.shtml" 
    ORDERED_KEYS = [:payment_amount, :currency_code, :ship_before_date, :merchant_reference,
      :skin_code, :merchant_account, :session_validity, :shopper_email, :shopper_reference,
      :allowed_methods, :blocked_methods, :shopper_statement, :billing_address_type]

    def initialize(shared_key, parameters = {})
      @shared_key = shared_key
      @url_options = parameters
      @parameters = SmartPay.ordered_parameters(ORDERED_KEYS, parameters) 
    end
    
    def hmac_signature
      SmartPay::HmacCalculator.new(@shared_key, @parameters).signature
    end

    def redirect_url
      url_string = @url_options.inject({}) do |result, (key, value)|
        result[key.to_s.camelize] = value
        result
      end.merge(merchantSig: self.hmac_signature).to_query

      self.request_url + "?" + url_string
    end

    def request_url
      SmartPay.test_mode ? TEST_URL : LIVE_URL
    end
  end
end
