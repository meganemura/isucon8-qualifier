require 'oj'

class OjEncoder

  def initialize
    # ::Oj.default_options = {:mode => :compat }
    ::Oj.default_options = {:mode => :compat, use_to_json: true }
  end

  def encode(value)
    ::Oj.dump(value)
  end

end
